pub mod csv;
pub mod legacy;
pub mod plan;

use std::fs::File;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use crate::operations::{WorkControl, WorkError, WorkResult};
use sha2::{Digest, Sha256};
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

use crate::{AppError, Result};

#[derive(Debug, thiserror::Error)]
#[error(
    "legacy import temporary snapshot cleanup failed; encrypted source and plaintext metadata may remain at {path}"
)]
pub struct ImportCleanupFailure {
    path: PathBuf,
}
impl ImportCleanupFailure {
    pub fn path(&self) -> &Path {
        &self.path
    }
    pub(crate) fn new(path: PathBuf) -> Self {
        Self { path }
    }
}

thread_local! {
    // Metadata only, on the executing worker. The runner takes this immediately
    // after unwind; no plaintext owner, disk retry, or extra job is scheduled.
    static SNAPSHOT_CLEANUP_FAILURE: std::cell::RefCell<Option<ImportCleanupFailure>> = const { std::cell::RefCell::new(None) };
}
pub(crate) fn take_snapshot_cleanup_failure() -> Option<ImportCleanupFailure> {
    SNAPSHOT_CLEANUP_FAILURE.with(|failure| failure.borrow_mut().take())
}
pub(super) fn retain_snapshot_cleanup_failure(path: PathBuf) {
    SNAPSHOT_CLEANUP_FAILURE.with(|failure| {
        let mut pending = failure.borrow_mut();
        if pending.is_none() {
            *pending = Some(ImportCleanupFailure::new(path));
        }
    });
}

pub const MAX_IMPORT_BYTES: u64 = 64 * 1024 * 1024;

#[derive(Clone, PartialEq, Eq, Zeroize, ZeroizeOnDrop)]
pub struct NormalizedImportItem {
    pub provider: String,
    pub source_stable_id: Option<String>,
    pub name: String,
    pub website: String,
    pub username: String,
    pub password: String,
    pub notes: String,
    pub category: String,
    pub favorite: bool,
    pub fingerprint: [u8; 32],
}

impl std::fmt::Debug for NormalizedImportItem {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("NormalizedImportItem")
            .field("content", &"[REDACTED]")
            .finish()
    }
}

#[derive(Debug, Default)]
pub struct ImportParseResult {
    pub provider: String,
    pub items: Vec<NormalizedImportItem>,
    pub invalid_rows: usize,
}

#[derive(Debug)]
pub struct ImportBatch {
    pub provider: String,
    pub source_digest: [u8; 32],
    pub items: Vec<NormalizedImportItem>,
    pub invalid_rows: usize,
}

pub fn stage_path(path: &Path, master_password: Option<&str>) -> Result<ImportBatch> {
    work_to_result(stage_path_with(path, master_password, &mut || Ok(())))
}

pub(crate) fn stage_path_controlled(
    path: &Path,
    master_password: Option<&str>,
    control: &WorkControl,
) -> WorkResult<ImportBatch> {
    stage_path_with(path, master_password, &mut || control.checkpoint())
}

fn stage_path_with(
    path: &Path,
    master_password: Option<&str>,
    checkpoint: &mut impl FnMut() -> WorkResult<()>,
) -> WorkResult<ImportBatch> {
    checkpoint()?;
    let extension = path
        .extension()
        .and_then(|value| value.to_str())
        .unwrap_or_default()
        .to_ascii_lowercase();
    if extension == "db" || looks_like_sqlite(path)? {
        let password = master_password
            .ok_or_else(|| AppError::Input("旧 passwords.db 需要原主密码".to_string()))?;
        return legacy::stage_passwords_db_with(path, password, checkpoint);
    }
    if extension == "enc" {
        let password = master_password
            .ok_or_else(|| AppError::Input("旧 vault.enc 需要原主密码".to_string()))?;
        return legacy::stage_vault_enc_with(path, password, checkpoint);
    }
    csv::parse_path_with(path, checkpoint)
}

pub(super) fn work_to_result<T>(result: WorkResult<T>) -> Result<T> {
    match result {
        Ok(value) => Ok(value),
        Err(WorkError::Failure(error)) => Err(error),
        Err(WorkError::Cancelled) => Err(AppError::Input("导入已取消".into())),
    }
}

const IMPORT_CHUNK_BYTES: usize = 32 * 1024;

// The cap applies to the bytes actually read, regardless of metadata or a
// concurrently growing source. Never ask the reader for more than cap + 1.
pub(super) fn read_chunks<R: Read>(
    reader: &mut R,
    limit: u64,
    checkpoint: &mut impl FnMut() -> WorkResult<()>,
    consume: &mut impl FnMut(&[u8]) -> WorkResult<()>,
) -> WorkResult<()> {
    let mut chunk = Zeroizing::new([0u8; IMPORT_CHUNK_BYTES]);
    let mut remaining = limit;
    loop {
        checkpoint()?;
        let requested = if remaining < IMPORT_CHUNK_BYTES as u64 {
            remaining as usize + 1
        } else {
            IMPORT_CHUNK_BYTES
        };
        let read = match reader.read(&mut chunk[..requested]) {
            Err(error) if error.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(error) => return Err(AppError::io(PathBuf::from("import source"), error).into()),
            Ok(read) => read,
        };
        if read == 0 {
            return Ok(());
        }
        if read as u64 > remaining {
            return Err(AppError::Input(format!(
                "导入文件超过 {} MiB 安全上限",
                MAX_IMPORT_BYTES / (1024 * 1024)
            ))
            .into());
        }
        checkpoint()?;
        consume(&chunk[..read])?;
        chunk.zeroize();
        remaining -= read as u64;
    }
}

fn read_bounded<R: Read>(
    reader: &mut R,
    limit: u64,
    checkpoint: &mut impl FnMut() -> WorkResult<()>,
) -> WorkResult<Zeroizing<Vec<u8>>> {
    let mut bytes = Zeroizing::new(Vec::new());
    read_chunks(reader, limit, checkpoint, &mut |chunk| {
        let needed = bytes
            .len()
            .checked_add(chunk.len())
            .ok_or_else(|| AppError::Input("导入源缓冲区长度无效".into()))?;
        if needed > bytes.capacity() {
            // Reserve into a fresh guarded allocation rather than reallocating a
            // live plaintext Vec and freeing its old allocation without a wipe.
            let capacity = bytes
                .capacity()
                .saturating_mul(2)
                .max(needed)
                .min(limit as usize);
            let mut replacement = Zeroizing::new(Vec::new());
            replacement
                .try_reserve_exact(capacity)
                .map_err(|_| AppError::Input("导入源缓冲区内存不足".into()))?;
            replacement.extend_from_slice(&bytes);
            std::mem::swap(&mut bytes, &mut replacement);
            // The superseded guarded owner wipes its entire old allocation here.
        }
        bytes.extend_from_slice(chunk);
        Ok(())
    })?;
    Ok(bytes)
}

pub(super) fn read_source_file_with(
    path: &Path,
    checkpoint: &mut impl FnMut() -> WorkResult<()>,
) -> WorkResult<Zeroizing<Vec<u8>>> {
    checkpoint()?;
    let mut file = File::open(path).map_err(|error| AppError::io(path.to_path_buf(), error))?;
    read_bounded(&mut file, MAX_IMPORT_BYTES, checkpoint)
}

pub(crate) fn sidecar_path(path: &Path, suffix: &str) -> PathBuf {
    let mut value = path.as_os_str().to_os_string();
    value.push(suffix);
    PathBuf::from(value)
}

pub(crate) fn content_fingerprint(
    name: &str,
    website: &str,
    username: &str,
    password: &str,
    notes: &str,
    category: &str,
    favorite: bool,
) -> [u8; 32] {
    let mut hash = Sha256::new();
    hash.update(b"password-manager:import-content:v2\0");
    for value in [name, website, username, password, notes, category] {
        hash.update((value.len() as u64).to_be_bytes());
        hash.update(value.as_bytes());
    }
    hash.update([u8::from(favorite)]);
    hash.finalize().into()
}

// The old delimiter encoding is usable only for unambiguous current content.
// A local edit can otherwise retain an old digest by moving a delimiter across
// a field boundary. Stream both encodings without allocating plaintext copies.
pub(crate) fn compatible_legacy_fingerprint(fields: [&str; 6], favorite: bool) -> Option<[u8; 32]> {
    if fields.iter().any(|value| value.contains('\u{1f}')) {
        return None;
    }
    let mut hash = Sha256::new();
    for value in fields {
        hash.update(value.as_bytes());
        hash.update([0x1f]);
    }
    hash.update(if favorite { b"1\x1f" } else { b"0\x1f" });
    Some(hash.finalize().into())
}

pub(crate) fn weak_identity_key(website: &str, username: &str) -> (String, String) {
    let trimmed = website.trim();
    let site = url::Url::parse(trimmed)
        .or_else(|_| url::Url::parse(&format!("https://{trimmed}")))
        .ok()
        .map(|parsed| {
            let host = parsed.host_str().unwrap_or_default().to_ascii_lowercase();
            let path = parsed.path().trim_end_matches('/');
            if path.is_empty() {
                host
            } else {
                format!("{host}{path}")
            }
        })
        .unwrap_or_else(|| trimmed.to_ascii_lowercase());

    (site, username.trim().to_string())
}

pub(crate) fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

fn looks_like_sqlite(path: &Path) -> Result<bool> {
    let mut file = File::open(path).map_err(|error| AppError::io(path.to_path_buf(), error))?;
    let mut header = Zeroizing::new([0u8; 16]);
    let read = file
        .read(&mut header[..])
        .map_err(|error| AppError::io(path.to_path_buf(), error))?;
    Ok(read == header.len() && &header[..] == b"SQLite format 3\0")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn password_notes_boundary_is_unambiguous() {
        assert_ne!(
            content_fingerprint("n", "w", "u", "p\u{1f}q", "r", "c", false),
            content_fingerprint("n", "w", "u", "p", "q\u{1f}r", "c", false),
        );
    }

    #[test]
    fn controlled_import_growing_source_reads_only_limit_plus_one() {
        struct Growing {
            consumed: usize,
        }
        impl Read for Growing {
            fn read(&mut self, target: &mut [u8]) -> std::io::Result<usize> {
                target.fill(b's');
                self.consumed += target.len();
                Ok(target.len())
            }
        }
        let mut source = Growing { consumed: 0 };
        assert!(matches!(
            read_bounded(&mut source, 127, &mut || Ok(())),
            Err(WorkError::Failure(_))
        ));
        assert_eq!(source.consumed, 128);
    }

    #[test]
    fn controlled_import_accepts_exact_limit_and_cancels_before_next_chunk() {
        let input = vec![b'x'; 65_536];
        let bytes = read_bounded(&mut input.as_slice(), 65_536, &mut || Ok(()))
            .ok()
            .expect("accepted limit");
        assert_eq!(&*bytes, &input);
        let mut checks = 0;
        let result = read_bounded(&mut input.as_slice(), 65_536, &mut || {
            checks += 1;
            if checks >= 2 {
                Err(WorkError::Cancelled)
            } else {
                Ok(())
            }
        });
        assert!(matches!(result, Err(WorkError::Cancelled)));
    }

    #[test]
    fn controlled_import_debug_does_not_reveal_secret_fields() {
        let item = NormalizedImportItem {
            provider: "synthetic".into(),
            source_stable_id: None,
            name: "entry".into(),
            website: "https://example.test".into(),
            username: "user".into(),
            password: "synthetic-password-sentinel".into(),
            notes: "synthetic-notes-sentinel".into(),
            category: "other".into(),
            favorite: false,
            fingerprint: [0; 32],
        };
        let debug = format!("{item:?}");
        assert!(!debug.contains("synthetic-password-sentinel"));
        assert!(!debug.contains("synthetic-notes-sentinel"));
    }
}
