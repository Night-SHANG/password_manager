use std::fs::{self, File, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};

use base64::{
    Engine as _,
    engine::general_purpose::{STANDARD, URL_SAFE},
};
use fernet::Fernet;
use pbkdf2::pbkdf2_hmac_array;
use rusqlite::{Connection, OpenFlags, OptionalExtension};
use serde::Deserialize;
use sha2::{Digest, Sha256};
use sha2_legacy::Sha256 as LegacySha256;
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

use crate::import::{
    ImportBatch, ImportCleanupFailure, MAX_IMPORT_BYTES, NormalizedImportItem, content_fingerprint,
    read_chunks, read_source_file_with, sidecar_path, work_to_result,
};
use crate::operations::{WorkError, WorkResult};
use crate::{AppError, Result};

const LEGACY_PBKDF2_ITERATIONS: u32 = 480_000;

#[derive(Deserialize, Zeroize, ZeroizeOnDrop)]
struct LegacyVaultEnvelope {
    salt: String,
    passwords: String,
}

#[derive(Default, Deserialize, Zeroize, ZeroizeOnDrop)]
struct LegacyVaultItem {
    #[serde(default)]
    name: String,
    #[serde(default)]
    website: String,
    #[serde(default)]
    username: String,
    #[serde(default)]
    password: String,
}
// A partially decoded SQL row is owned before any later fallible column access.
#[derive(Default, Zeroize, ZeroizeOnDrop)]
struct LegacyDbRow {
    id: i64,
    name: String,
    website: String,
    username: String,
    password: String,
    category: String,
    notes: String,
    favorite: bool,
}

fn parse_legacy_plaintext(plaintext: &mut Zeroizing<Vec<u8>>) -> Result<Vec<LegacyVaultItem>> {
    let result = serde_json::from_slice(plaintext)
        .map_err(|_| AppError::Migration("旧 vault.enc 解密内容不是有效的密码列表".into()));
    plaintext.as_mut_slice().zeroize();
    result
}

pub fn stage_vault_enc(path: &Path, master_password: &str) -> Result<ImportBatch> {
    work_to_result(stage_vault_enc_with(path, master_password, &mut || Ok(())))
}

pub(super) fn stage_vault_enc_with(
    path: &Path,
    master_password: &str,
    checkpoint: &mut impl FnMut() -> WorkResult<()>,
) -> WorkResult<ImportBatch> {
    let bytes = read_source_file_with(path, checkpoint)?;
    checkpoint()?;
    let envelope: LegacyVaultEnvelope = serde_json::from_slice(&bytes)
        .map_err(|_| AppError::Migration("旧 vault.enc 外层格式无效".into()))?;
    checkpoint()?;
    let cipher = legacy_cipher(master_password, &envelope.salt)?;
    checkpoint()?;
    let token_bytes = Zeroizing::new(
        STANDARD
            .decode(envelope.passwords.as_bytes())
            .map_err(|_| AppError::Migration("旧 vault.enc token 编码无效".into()))?,
    );
    let token = std::str::from_utf8(&token_bytes)
        .map_err(|_| AppError::Migration("旧 vault.enc Fernet token 不是 UTF-8".into()))?;
    let mut plaintext = Zeroizing::new(
        cipher
            .decrypt(token)
            .map_err(|_| AppError::Migration("旧 vault.enc 主密码错误或密文已损坏".into()))?,
    );
    checkpoint()?;
    let legacy_items = parse_legacy_plaintext(&mut plaintext)?;
    let provider = "legacy-vault-enc".to_string();
    let mut items = Vec::new();
    items
        .try_reserve_exact(legacy_items.len())
        .map_err(|_| AppError::Input("导入条目缓冲区内存不足".into()))?;
    let mut invalid_rows = 0;
    for mut item in legacy_items {
        checkpoint()?;
        if item.password.is_empty()
            || (item.name.trim().is_empty() && item.website.trim().is_empty())
        {
            invalid_rows += 1;
            continue;
        }
        let name = if item.name.trim().is_empty() {
            item.website.clone()
        } else {
            std::mem::take(&mut item.name)
        };
        let category = "其他".to_string();
        let fingerprint = content_fingerprint(
            &name,
            &item.website,
            &item.username,
            &item.password,
            "",
            &category,
            false,
        );
        items.push(NormalizedImportItem {
            provider: provider.clone(),
            source_stable_id: None,
            name,
            website: std::mem::take(&mut item.website),
            username: std::mem::take(&mut item.username),
            password: std::mem::take(&mut item.password),
            notes: String::new(),
            category,
            favorite: false,
            fingerprint,
        });
    }
    checkpoint()?;
    Ok(ImportBatch {
        provider,
        source_digest: crate::security::sha256(&bytes),
        items,
        invalid_rows,
    })
}

pub fn stage_passwords_db(path: &Path, master_password: &str) -> Result<ImportBatch> {
    work_to_result(stage_passwords_db_with(path, master_password, &mut || {
        Ok(())
    }))
}

pub(super) fn stage_passwords_db_with(
    path: &Path,
    master_password: &str,
    checkpoint: &mut impl FnMut() -> WorkResult<()>,
) -> WorkResult<ImportBatch> {
    let snapshot = copy_sqlite_snapshot_with(path, MAX_IMPORT_BYTES, checkpoint)?;
    let result =
        stage_sqlite_snapshot(&snapshot.path, snapshot.digest, master_password, checkpoint);
    // All SQLite handles close before explicit snapshot disposition is reported.
    // Cleanup failure wins even if analysis failed or cancellation was requested.
    snapshot.finish(result)
}

fn stage_sqlite_snapshot(
    path: &Path,
    digest: [u8; 32],
    master_password: &str,
    checkpoint: &mut impl FnMut() -> WorkResult<()>,
) -> WorkResult<ImportBatch> {
    checkpoint()?;
    let conn = Connection::open_with_flags(
        path,
        OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NO_MUTEX,
    )
    .map_err(|_| AppError::Migration("旧 passwords.db 快照无法打开".into()))?;
    let salt = Zeroizing::new(
        conn.query_row(
            "SELECT value FROM vault_meta WHERE key = 'salt'",
            [],
            |row| row.get::<_, String>(0),
        )
        .optional()
        .map_err(|_| AppError::Migration("旧 passwords.db salt 无法读取".into()))?
        .ok_or_else(|| AppError::Migration("旧 passwords.db 缺少 salt".into()))?,
    );
    // The salt is guarded before the next fallible query, not just on success.
    let verify = Zeroizing::new(
        conn.query_row(
            "SELECT value FROM vault_meta WHERE key = 'verify'",
            [],
            |row| row.get::<_, String>(0),
        )
        .optional()
        .map_err(|_| AppError::Migration("旧 passwords.db verify 无法读取".into()))?
        .ok_or_else(|| AppError::Migration("旧 passwords.db 缺少 verify".into()))?,
    );
    checkpoint()?;
    let cipher = legacy_cipher(master_password, &salt)?;
    checkpoint()?;
    let verification = decrypt_legacy_text(&cipher, &verify)
        .map_err(|_| AppError::Migration("旧 passwords.db 主密码错误或验证数据损坏".into()))?;
    if verification.as_str() != "verify" {
        return Err(AppError::Migration("旧 passwords.db 主密码验证失败".into()).into());
    }
    drop(verification);
    let decoded_salt = Zeroizing::new(
        STANDARD
            .decode(salt.as_bytes())
            .map_err(|_| AppError::Migration("旧 passwords.db salt 编码无效".into()))?,
    );
    let mut namespace_hash = Sha256::new();
    namespace_hash.update(b"password-manager:legacy-db-identity:v1\0");
    namespace_hash.update(decoded_salt.as_slice());
    let namespace = namespace_hash
        .finalize()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    let mut statement = conn.prepare(
        "SELECT id, name, website, username, password, category, notes, is_favorite FROM entries ORDER BY id ASC"
    ).map_err(|_| AppError::Migration("旧 passwords.db 条目无法读取".into()))?;
    let rows = statement
        .query_map([], |row| {
            let mut value = LegacyDbRow::default();
            value.id = row.get(0)?;
            value.name = row.get::<_, Option<String>>(1)?.unwrap_or_default();
            value.website = row.get::<_, Option<String>>(2)?.unwrap_or_default();
            value.username = row.get::<_, Option<String>>(3)?.unwrap_or_default();
            value.password = row.get(4)?;
            value.category = row.get::<_, Option<String>>(5)?.unwrap_or_default();
            if value.category.trim().is_empty() {
                value.category = "其他".into();
            }
            value.notes = row.get::<_, Option<String>>(6)?.unwrap_or_default();
            value.favorite = row.get::<_, i64>(7)? != 0;
            Ok(value)
        })
        .map_err(|_| AppError::Migration("旧 passwords.db 查询无法执行".into()))?;
    let provider = "legacy-passwords-db".to_string();
    let mut items = Vec::new();
    let mut invalid_rows = 0;
    for row in rows {
        checkpoint()?;
        let mut row = match row {
            Ok(row) => row,
            Err(_) => {
                invalid_rows += 1;
                continue;
            }
        };
        let mut password = match decrypt_legacy_text(&cipher, &row.password) {
            Ok(value) => value,
            Err(_) => {
                invalid_rows += 1;
                continue;
            }
        };
        if password.is_empty() || (row.name.trim().is_empty() && row.website.trim().is_empty()) {
            invalid_rows += 1;
            continue;
        }
        let name = if row.name.trim().is_empty() {
            row.website.clone()
        } else {
            std::mem::take(&mut row.name)
        };
        let fingerprint = content_fingerprint(
            &name,
            &row.website,
            &row.username,
            &password,
            &row.notes,
            &row.category,
            row.favorite,
        );
        items
            .try_reserve(1)
            .map_err(|_| AppError::Input("导入条目缓冲区内存不足".into()))?;
        items.push(NormalizedImportItem {
            provider: provider.clone(),
            source_stable_id: Some(format!("db:{namespace}:entry:{}", row.id)),
            name,
            website: std::mem::take(&mut row.website),
            username: std::mem::take(&mut row.username),
            password: std::mem::take(&mut *password),
            notes: std::mem::take(&mut row.notes),
            category: std::mem::take(&mut row.category),
            favorite: row.favorite,
            fingerprint,
        });
    }
    checkpoint()?;
    Ok(ImportBatch {
        provider,
        source_digest: digest,
        items,
        invalid_rows,
    })
}

fn legacy_cipher(master_password: &str, salt_b64: &str) -> Result<Fernet> {
    let salt = Zeroizing::new(
        STANDARD
            .decode(salt_b64.as_bytes())
            .map_err(|_| AppError::Migration("旧保险库 PBKDF2 salt 编码无效".into()))?,
    );
    if salt.len() != 16 {
        return Err(AppError::Migration("旧保险库 PBKDF2 salt 长度无效".into()));
    }
    let raw_key = Zeroizing::new(pbkdf2_hmac_array::<LegacySha256, 32>(
        master_password.as_bytes(),
        &salt,
        LEGACY_PBKDF2_ITERATIONS,
    ));
    let encoded_key = Zeroizing::new(URL_SAFE.encode(raw_key.as_slice()));
    Fernet::new(&encoded_key).ok_or_else(|| AppError::Migration("无法构造旧 Fernet 密钥".into()))
}

fn decrypt_legacy_text(cipher: &Fernet, outer_b64: &str) -> Result<Zeroizing<String>> {
    let token_bytes = Zeroizing::new(
        STANDARD
            .decode(outer_b64.as_bytes())
            .map_err(|_| AppError::Migration("旧 Fernet token 编码无效".into()))?,
    );
    let token = std::str::from_utf8(&token_bytes)
        .map_err(|_| AppError::Migration("旧 Fernet token 不是 UTF-8".into()))?;
    let mut plaintext = Zeroizing::new(
        cipher
            .decrypt(token)
            .map_err(|_| AppError::Migration("旧 Fernet 密文无法解密".into()))?,
    );
    decode_legacy_utf8(&mut plaintext)
}

fn decode_legacy_utf8(plaintext: &mut Zeroizing<Vec<u8>>) -> Result<Zeroizing<String>> {
    let result = std::str::from_utf8(plaintext)
        .map(|text| Zeroizing::new(text.to_owned()))
        .map_err(|_| AppError::Migration("旧 Fernet 解密文本不是 UTF-8".into()));
    plaintext.as_mut_slice().zeroize();
    result
}

struct SqliteSnapshot {
    directory: Option<PathBuf>,
    path: PathBuf,
    digest: [u8; 32],
}
impl SqliteSnapshot {
    fn finish<T>(mut self, result: WorkResult<T>) -> WorkResult<T> {
        // Disarm before cleanup: failure is retained and never retried by Drop.
        let directory = self.directory.take().expect("owned snapshot directory");
        if fs::remove_dir_all(&directory).is_err() {
            return Err(WorkError::Failure(AppError::ImportCleanup(Box::new(
                ImportCleanupFailure::new(directory),
            ))));
        }
        result
    }
}
impl Drop for SqliteSnapshot {
    fn drop(&mut self) {
        // Emergency unwind only. Ordinary terminal paths always call finish.
        // Physical erasure and library-internal buffers are not guaranteed.
        if let Some(directory) = self.directory.take()
            && fs::remove_dir_all(&directory).is_err()
        {
            crate::import::retain_snapshot_cleanup_failure(directory);
        }
    }
}

fn copy_sqlite_snapshot_with(
    path: &Path,
    limit: u64,
    checkpoint: &mut impl FnMut() -> WorkResult<()>,
) -> WorkResult<SqliteSnapshot> {
    checkpoint()?;
    let temp = tempfile::Builder::new()
        .prefix("password-manager-legacy-db-")
        .tempdir()
        .map_err(|error| AppError::io(std::env::temp_dir(), error))?;
    let directory = temp.keep();
    #[cfg(test)]
    tests::snapshot_created(&directory);
    let mut snapshot = SqliteSnapshot {
        path: directory.join("passwords.db"),
        directory: Some(directory),
        digest: [0; 32],
    };
    let result = (|| {
        let mut hash = Sha256::new();
        for suffix in ["", "-wal", "-shm"] {
            checkpoint()?;
            let source = sidecar_path(path, suffix);
            let mut input = match File::open(&source) {
                Ok(file) => file,
                Err(error)
                    if !suffix.is_empty() && error.kind() == std::io::ErrorKind::NotFound =>
                {
                    continue;
                }
                Err(error) => return Err(AppError::io(source, error).into()),
            };
            let destination = sidecar_path(&snapshot.path, suffix);
            let mut output = OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&destination)
                .map_err(|error| AppError::io(destination.clone(), error))?;
            if !suffix.is_empty() {
                hash.update(suffix.as_bytes());
            }
            read_chunks(&mut input, limit, checkpoint, &mut |chunk| {
                output
                    .write_all(chunk)
                    .map_err(|error| AppError::io(destination.clone(), error))?;
                hash.update(chunk);
                Ok(())
            })?;
        }
        checkpoint()?;
        snapshot.digest = hash.finalize().into();
        Ok(())
    })();
    match result {
        Ok(()) => Ok(snapshot),
        Err(error) => snapshot.finish(Err(error)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    thread_local! { static CREATED_SNAPSHOTS: std::cell::RefCell<Vec<PathBuf>> = const { std::cell::RefCell::new(Vec::new()) }; }
    pub(super) fn snapshot_created(path: &Path) {
        CREATED_SNAPSHOTS.with(|paths| paths.borrow_mut().push(path.to_path_buf()));
    }
    fn take_created_snapshots() -> Vec<PathBuf> {
        CREATED_SNAPSHOTS.with(|paths| std::mem::take(&mut *paths.borrow_mut()))
    }

    #[test]
    fn legacy_pbkdf2_fernet_round_trip_matches_python_shape() {
        let password = "test-master";
        let salt = [7u8; 16];
        let salt_b64 = STANDARD.encode(salt);
        let cipher = legacy_cipher(password, &salt_b64).unwrap();
        let token = cipher.encrypt(b"verify");
        let outer = STANDARD.encode(token.as_bytes());

        assert_eq!(
            decrypt_legacy_text(&cipher, &outer).unwrap().as_str(),
            "verify"
        );
    }
    #[test]
    fn controlled_import_malformed_legacy_json_wipes_plaintext() {
        let mut plaintext = Zeroizing::new(b"[{\"password\":\"synthetic-sentinel\", bad".to_vec());
        let original_len = plaintext.len();
        let result = parse_legacy_plaintext(&mut plaintext);
        assert!(result.is_err());
        assert_eq!(
            plaintext.len(),
            original_len,
            "live initialized slice must remain observable for the wipe witness"
        );
        assert!(plaintext.iter().all(|byte| *byte == 0));
        assert!(
            !result
                .err()
                .unwrap()
                .to_string()
                .contains("synthetic-sentinel")
        );
    }

    #[test]
    fn controlled_import_sqlite_each_file_has_individual_limit() {
        for oversized in ["", "-wal", "-shm"] {
            let dir = tempfile::tempdir().unwrap();
            let path = dir.path().join("passwords.db");
            for suffix in ["", "-wal", "-shm"] {
                fs::write(
                    sidecar_path(&path, suffix),
                    vec![1u8; if suffix == oversized { 128 } else { 127 }],
                )
                .unwrap();
            }
            assert!(matches!(
                copy_sqlite_snapshot_with(&path, 127, &mut || Ok(())),
                Err(WorkError::Failure(_))
            ));
        }
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("passwords.db");
        for suffix in ["", "-wal", "-shm"] {
            fs::write(sidecar_path(&path, suffix), vec![1u8; 127]).unwrap();
        }
        let snapshot = copy_sqlite_snapshot_with(&path, 127, &mut || Ok(()))
            .ok()
            .expect("per-file accepted, not total cap");
        let root = snapshot.directory.as_ref().unwrap().clone();
        snapshot.finish(Ok(())).ok().expect("explicit cleanup");
        assert!(!root.exists());
    }

    #[test]
    fn controlled_import_snapshot_digest_preserves_exact_original_stream() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("passwords.db");
        fs::write(&path, b"db").unwrap();
        fs::write(sidecar_path(&path, "-wal"), b"wal").unwrap();
        fs::write(sidecar_path(&path, "-shm"), b"shm").unwrap();
        let snapshot = copy_sqlite_snapshot_with(&path, 127, &mut || Ok(()))
            .ok()
            .expect("snapshot");
        assert_eq!(
            snapshot.digest,
            crate::security::sha256(b"db-walwal-shmshm")
        );
        snapshot.finish(Ok(())).ok().expect("cleanup");
    }

    #[test]
    fn controlled_import_snapshot_cleanup_failure_outranks_cancel() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("passwords.db");
        fs::write(&path, b"db").unwrap();
        let snapshot = copy_sqlite_snapshot_with(&path, 127, &mut || Ok(()))
            .ok()
            .expect("snapshot");
        let root = snapshot.directory.as_ref().unwrap().clone();
        fs::remove_dir_all(&root).unwrap();
        fs::write(&root, b"retained synthetic marker").unwrap();
        let result: WorkResult<()> = snapshot.finish(Err(WorkError::Cancelled));
        assert!(
            matches!(result,Err(WorkError::Failure(AppError::ImportCleanup(failure))) if failure.path() == root)
        );
        assert!(root.exists());
        fs::remove_file(root).unwrap();
    }

    #[test]
    fn controlled_import_invalid_legacy_utf8_wipes_plaintext() {
        let mut bytes = Zeroizing::new(vec![b's', b'e', b'c', b'r', b'e', b't', 0xff]);
        let original_len = bytes.len();
        let error = decode_legacy_utf8(&mut bytes).unwrap_err();
        assert_eq!(
            bytes.len(),
            original_len,
            "live initialized slice must remain observable for the wipe witness"
        );
        assert!(bytes.iter().all(|byte| *byte == 0));
        assert!(!error.to_string().contains("secret"));
    }

    #[test]
    fn controlled_import_cancel_at_every_snapshot_copy_checkpoint_cleans_directory() {
        take_created_snapshots();
        let dir = tempfile::tempdir().unwrap();
        let source = dir.path().join("passwords.db");
        for suffix in ["", "-wal", "-shm"] {
            fs::write(sidecar_path(&source, suffix), vec![1u8; 70_000]).unwrap();
        }
        let mut count = 0;
        let snapshot = copy_sqlite_snapshot_with(&source, 70_000, &mut || {
            count += 1;
            Ok(())
        })
        .ok()
        .expect("baseline capture");
        snapshot.finish(Ok(())).ok().expect("baseline cleanup");
        assert!(take_created_snapshots().iter().all(|path| !path.exists()));
        for stop in 1..=count {
            let mut checks = 0;
            assert!(
                matches!(
                    copy_sqlite_snapshot_with(&source, 70_000, &mut || {
                        checks += 1;
                        if checks == stop {
                            Err(WorkError::Cancelled)
                        } else {
                            Ok(())
                        }
                    }),
                    Err(WorkError::Cancelled)
                ),
                "checkpoint {stop}"
            );
            assert!(take_created_snapshots().iter().all(|path| !path.exists()));
        }
    }

    #[test]
    fn controlled_import_panic_cleanup_failure_has_terminal_metadata_owner() {
        assert!(crate::import::take_snapshot_cleanup_failure().is_none());
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("passwords.db");
        fs::write(&path, b"db").unwrap();
        let snapshot = copy_sqlite_snapshot_with(&path, 127, &mut || Ok(()))
            .ok()
            .expect("snapshot");
        let root = snapshot.directory.as_ref().unwrap().clone();
        fs::remove_dir_all(&root).unwrap();
        fs::write(&root, b"retained synthetic marker").unwrap();
        drop(snapshot);
        let failure = crate::import::take_snapshot_cleanup_failure()
            .expect("emergency cleanup retained warning");
        assert_eq!(failure.path(), root);
        assert!(crate::import::take_snapshot_cleanup_failure().is_none());
        assert!(root.exists());
        fs::remove_file(root).unwrap();
    }
}
