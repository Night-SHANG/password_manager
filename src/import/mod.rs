pub mod csv;
pub mod legacy;
pub mod plan;

use std::fs::File;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::security::sha256;
use crate::{AppError, Result};

pub const MAX_IMPORT_BYTES: u64 = 64 * 1024 * 1024;

#[derive(Debug, Clone, Zeroize, ZeroizeOnDrop)]
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
    let extension = path
        .extension()
        .and_then(|value| value.to_str())
        .unwrap_or_default()
        .to_ascii_lowercase();

    if extension == "db" || looks_like_sqlite(path)? {
        let password = master_password
            .ok_or_else(|| AppError::Input("旧 passwords.db 需要原主密码".to_string()))?;
        return legacy::stage_passwords_db(path, password);
    }

    if extension == "enc" {
        let password = master_password
            .ok_or_else(|| AppError::Input("旧 vault.enc 需要原主密码".to_string()))?;
        return legacy::stage_vault_enc(path, password);
    }

    csv::parse_path(path)
}

pub(crate) fn read_source_file(path: &Path) -> Result<Vec<u8>> {
    let mut file = File::open(path).map_err(|error| AppError::io(path.to_path_buf(), error))?;
    let metadata = file
        .metadata()
        .map_err(|error| AppError::io(path.to_path_buf(), error))?;

    if metadata.len() > MAX_IMPORT_BYTES {
        return Err(AppError::Input(format!(
            "导入文件超过 {} MiB 安全上限",
            MAX_IMPORT_BYTES / (1024 * 1024)
        )));
    }

    let mut bytes = Vec::with_capacity(metadata.len() as usize);
    file.read_to_end(&mut bytes)
        .map_err(|error| AppError::io(path.to_path_buf(), error))?;
    Ok(bytes)
}

pub(crate) fn source_digest(path: &Path, include_sqlite_sidecars: bool) -> Result<[u8; 32]> {
    let mut material = read_source_file(path)?;

    if include_sqlite_sidecars {
        for suffix in ["-wal", "-shm"] {
            let sidecar = sidecar_path(path, suffix);
            if sidecar.exists() {
                material.extend_from_slice(suffix.as_bytes());
                material.extend_from_slice(&read_source_file(&sidecar)?);
            }
        }
    }

    Ok(sha256(&material))
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
    let favorite_text = if favorite { "1" } else { "0" };
    let mut canonical = Vec::new();

    for value in [
        name,
        website,
        username,
        password,
        notes,
        category,
        favorite_text,
    ] {
        canonical.extend_from_slice(value.as_bytes());
        canonical.push(0x1f);
    }

    sha256(&canonical)
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
    let mut header = [0u8; 16];
    let read = file
        .read(&mut header)
        .map_err(|error| AppError::io(path.to_path_buf(), error))?;
    Ok(read == header.len() && &header == b"SQLite format 3\0")
}
