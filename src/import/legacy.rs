use std::fs;
use std::path::{Path, PathBuf};

use base64::{
    Engine as _,
    engine::general_purpose::{STANDARD, URL_SAFE},
};
use fernet::Fernet;
use pbkdf2::{pbkdf2_hmac_array, sha2::Sha256 as LegacySha256};
use rusqlite::{Connection, OpenFlags, OptionalExtension};
use serde::Deserialize;
use zeroize::Zeroize;

use crate::import::{
    ImportBatch, NormalizedImportItem, content_fingerprint, read_source_file, sidecar_path,
    source_digest,
};
use crate::{AppError, Result};

const LEGACY_PBKDF2_ITERATIONS: u32 = 480_000;

#[derive(Debug, Deserialize)]
struct LegacyVaultEnvelope {
    salt: String,
    passwords: String,
}

#[derive(Debug, Default, Deserialize)]
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

pub fn stage_vault_enc(path: &Path, master_password: &str) -> Result<ImportBatch> {
    let bytes = read_source_file(path)?;
    let envelope: LegacyVaultEnvelope = serde_json::from_slice(&bytes)?;
    let cipher = legacy_cipher(master_password, &envelope.salt)?;

    let token_bytes = STANDARD.decode(envelope.passwords.as_bytes())?;
    let token = std::str::from_utf8(&token_bytes)
        .map_err(|error| AppError::migration(format!("旧 vault.enc Fernet token 不是 UTF-8：{error}")))?;

    let mut plaintext = cipher
        .decrypt(token)
        .map_err(|_| AppError::Migration("旧 vault.enc 主密码错误或密文已损坏".to_string()))?;
    let legacy_items: Vec<LegacyVaultItem> = serde_json::from_slice(&plaintext)?;
    plaintext.zeroize();

    let provider = "legacy-vault-enc".to_string();
    let mut items = Vec::with_capacity(legacy_items.len());
    let mut invalid_rows = 0;

    for item in legacy_items {
        if item.password.is_empty()
            || (item.name.trim().is_empty() && item.website.trim().is_empty())
        {
            invalid_rows += 1;
            continue;
        }

        let name = if item.name.trim().is_empty() {
            item.website.clone()
        } else {
            item.name
        };
        let category = "其他".to_string();
        let favorite = false;
        let fingerprint = content_fingerprint(
            &name,
            &item.website,
            &item.username,
            &item.password,
            "",
            &category,
            favorite,
        );

        items.push(NormalizedImportItem {
            provider: provider.clone(),
            source_stable_id: None,
            name,
            website: item.website,
            username: item.username,
            password: item.password,
            notes: String::new(),
            category,
            favorite,
            fingerprint,
        });
    }

    Ok(ImportBatch {
        provider,
        source_digest: crate::security::sha256(&bytes),
        items,
        invalid_rows,
    })
}

pub fn stage_passwords_db(path: &Path, master_password: &str) -> Result<ImportBatch> {
    let (_snapshot_guard, snapshot) = copy_sqlite_snapshot(path)?;
    let digest = source_digest(&snapshot, true)?;
    let conn = Connection::open_with_flags(
        &snapshot,
        OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NO_MUTEX,
    )
    .map_err(AppError::migration)?;

    let salt: Option<String> = conn
        .query_row(
            "SELECT value FROM vault_meta WHERE key = 'salt'",
            [],
            |row| row.get(0),
        )
        .optional()
        .map_err(AppError::migration)?;

    let verify: Option<String> = conn
        .query_row(
            "SELECT value FROM vault_meta WHERE key = 'verify'",
            [],
            |row| row.get(0),
        )
        .optional()
        .map_err(AppError::migration)?;

    let salt = salt.ok_or_else(|| AppError::Migration("旧 passwords.db 缺少 salt".to_string()))?;
    let verify = verify.ok_or_else(|| AppError::Migration("旧 passwords.db 缺少 verify".to_string()))?;
    let cipher = legacy_cipher(master_password, &salt)?;

    let mut verification = decrypt_legacy_text(&cipher, &verify)
        .map_err(|_| AppError::Migration("旧 passwords.db 主密码错误或验证数据损坏".to_string()))?;

    if verification != "verify" {
        verification.zeroize();
        return Err(AppError::Migration(
            "旧 passwords.db 主密码验证失败".to_string(),
        ));
    }
    verification.zeroize();

    let mut statement = conn
        .prepare(
            "SELECT id, name, website, username, password, category, notes, is_favorite
             FROM entries ORDER BY id ASC",
        )
        .map_err(AppError::migration)?;

    let rows = statement
        .query_map([], |row| {
            Ok(LegacyDbRow {
                id: row.get(0)?,
                name: row.get::<_, Option<String>>(1)?.unwrap_or_default(),
                website: row.get::<_, Option<String>>(2)?.unwrap_or_default(),
                username: row.get::<_, Option<String>>(3)?.unwrap_or_default(),
                password: row.get(4)?,
                category: row
                    .get::<_, Option<String>>(5)?
                    .filter(|value| !value.trim().is_empty())
                    .unwrap_or_else(|| "其他".to_string()),
                notes: row.get::<_, Option<String>>(6)?.unwrap_or_default(),
                favorite: row.get::<_, i64>(7)? != 0,
            })
        })
        .map_err(AppError::migration)?;

    let provider = "legacy-passwords-db".to_string();
    let mut items = Vec::new();
    let mut invalid_rows = 0;

    for row in rows {
        let row = match row {
            Ok(row) => row,
            Err(_) => {
                invalid_rows += 1;
                continue;
            }
        };

        let password = match decrypt_legacy_text(&cipher, &row.password) {
            Ok(password) => password,
            Err(_) => {
                invalid_rows += 1;
                continue;
            }
        };

        if password.is_empty()
            || (row.name.trim().is_empty() && row.website.trim().is_empty())
        {
            invalid_rows += 1;
            continue;
        }

        let name = if row.name.trim().is_empty() {
            row.website.clone()
        } else {
            row.name
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

        items.push(NormalizedImportItem {
            provider: provider.clone(),
            source_stable_id: Some(format!("entry:{}", row.id)),
            name,
            website: row.website,
            username: row.username,
            password,
            notes: row.notes,
            category: row.category,
            favorite: row.favorite,
            fingerprint,
        });
    }

    Ok(ImportBatch {
        provider,
        source_digest: digest,
        items,
        invalid_rows,
    })
}

fn legacy_cipher(master_password: &str, salt_b64: &str) -> Result<Fernet> {
    let salt = STANDARD.decode(salt_b64.as_bytes())?;
    if salt.len() != 16 {
        return Err(AppError::Migration(
            "旧保险库 PBKDF2 salt 长度无效".to_string(),
        ));
    }

    let mut raw_key =
        pbkdf2_hmac_array::<LegacySha256, 32>(master_password.as_bytes(), &salt, LEGACY_PBKDF2_ITERATIONS);
    let mut encoded_key = URL_SAFE.encode(raw_key);
    raw_key.zeroize();

    let cipher = Fernet::new(&encoded_key)
        .ok_or_else(|| AppError::Migration("无法构造旧 Fernet 密钥".to_string()))?;
    encoded_key.zeroize();
    Ok(cipher)
}

fn decrypt_legacy_text(cipher: &Fernet, outer_b64: &str) -> Result<String> {
    let token_bytes = STANDARD.decode(outer_b64.as_bytes())?;
    let token = std::str::from_utf8(&token_bytes)
        .map_err(|error| AppError::migration(format!("旧 Fernet token 不是 UTF-8：{error}")))?;
    let plaintext = cipher
        .decrypt(token)
        .map_err(|_| AppError::Migration("旧 Fernet 密文无法解密".to_string()))?;
    String::from_utf8(plaintext).map_err(AppError::migration)
}

fn copy_sqlite_snapshot(path: &Path) -> Result<(tempfile::TempDir, PathBuf)> {
    let temp = tempfile::Builder::new()
        .prefix("password-manager-legacy-db-")
        .tempdir()
        .map_err(|error| AppError::io(std::env::temp_dir(), error))?;

    let snapshot = temp.path().join("passwords.db");
    fs::copy(path, &snapshot).map_err(|error| AppError::io(path.to_path_buf(), error))?;

    for suffix in ["-wal", "-shm"] {
        let source = sidecar_path(path, suffix);
        if source.exists() {
            let destination = sidecar_path(&snapshot, suffix);
            fs::copy(&source, &destination)
                .map_err(|error| AppError::io(source.clone(), error))?;
        }
    }

    Ok((temp, snapshot))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn legacy_pbkdf2_fernet_round_trip_matches_python_shape() {
        let password = "test-master";
        let salt = [7u8; 16];
        let salt_b64 = STANDARD.encode(salt);
        let cipher = legacy_cipher(password, &salt_b64).unwrap();
        let token = cipher.encrypt(b"verify");
        let outer = STANDARD.encode(token.as_bytes());

        assert_eq!(decrypt_legacy_text(&cipher, &outer).unwrap(), "verify");
    }
}
