use std::fs::{self, File};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use base64::{Engine as _, engine::general_purpose::STANDARD_NO_PAD};
use serde::{Deserialize, Serialize};
use uuid::Uuid;
use zeroize::Zeroize;

use crate::domain::{
    BODY_SCHEMA_VERSION, EntryDraft, EntryRecord, SecretEnvelope, SecretPayload, VaultBody,
};
use crate::platform;
use crate::security::{
    self, KdfConfig, NONCE_LEN, SALT_LEN, VaultKeys, derive_kek, open, random_array, seal,
};
use crate::{AppError, Result};

const MAGIC: &str = "PMVAULT";
const FORMAT_VERSION: u32 = 1;
const MAX_VAULT_BYTES: u64 = 64 * 1024 * 1024;

#[derive(Debug, Clone, Serialize, Deserialize)]
struct PublicHeader {
    magic: String,
    format_version: u32,
    vault_id: Uuid,
    revision: u64,
    kdf: String,
    kdf_params: KdfConfig,
    kdf_salt: String,
    wrap_nonce: String,
    wrapped_vault_key: String,
}

#[derive(Debug, Serialize, Deserialize)]
struct VaultFile {
    #[serde(flatten)]
    header: PublicHeader,
    body_nonce: String,
    body_ciphertext: String,
}

pub struct VaultSession {
    path: PathBuf,
    header: PublicHeader,
    body: VaultBody,
    keys: VaultKeys,
    source_hash: [u8; 32],
}

impl VaultSession {
    pub fn create(path: impl Into<PathBuf>, master_password: &str) -> Result<Self> {
        let path = path.into();
        if path.exists() {
            return Err(AppError::AlreadyExists);
        }
        if master_password.is_empty() {
            return Err(AppError::Input("主密码不能为空".to_string()));
        }

        let kdf_params = KdfConfig::default().validate()?;
        let salt = random_array::<SALT_LEN>()?;
        let wrap_nonce = random_array::<NONCE_LEN>()?;
        let vault_key = random_array::<32>()?;
        let vault_id = Uuid::new_v4();

        let mut kek = derive_kek(master_password, &salt, kdf_params)?;
        let wrap_aad = keywrap_aad(vault_id, kdf_params, &salt);
        let wrapped_vault_key = seal(&kek, &wrap_nonce, &wrap_aad, &vault_key)?;
        kek.zeroize();

        let header = PublicHeader {
            magic: MAGIC.to_string(),
            format_version: FORMAT_VERSION,
            vault_id,
            revision: 1,
            kdf: "argon2id".to_string(),
            kdf_params,
            kdf_salt: b64(&salt),
            wrap_nonce: b64(&wrap_nonce),
            wrapped_vault_key: b64(&wrapped_vault_key),
        };

        let keys = VaultKeys::from_vault_key(vault_key)?;
        let body = VaultBody::default();
        let bytes = encode_file(&header, &body, &keys)?;
        let verification: VaultFile = serde_json::from_slice(&bytes)?;
        let verified_body = decode_body(&verification, &keys)?;
        if verified_body != body {
            return Err(AppError::InvalidVault(
                "initial vault verification mismatch",
            ));
        }

        let temp = temp_path_for(&path);
        write_temp_file(&temp, &bytes)?;
        platform::atomic_replace(&path, &temp, None)?;

        Ok(Self {
            path,
            header,
            body,
            keys,
            source_hash: security::sha256(&bytes),
        })
    }

    pub fn open(path: impl Into<PathBuf>, master_password: &str) -> Result<Self> {
        let path = path.into();
        let bytes = read_bounded(&path)?;
        let file: VaultFile = serde_json::from_slice(&bytes)?;
        validate_header(&file.header)?;

        let salt = decode_array::<SALT_LEN>(&file.header.kdf_salt)?;
        let wrap_nonce = decode_array::<NONCE_LEN>(&file.header.wrap_nonce)?;
        let wrapped_key = STANDARD_NO_PAD.decode(&file.header.wrapped_vault_key)?;

        let mut kek = derive_kek(master_password, &salt, file.header.kdf_params)?;
        let wrap_aad = keywrap_aad(file.header.vault_id, file.header.kdf_params, &salt);
        let mut unwrapped = open(&kek, &wrap_nonce, &wrap_aad, &wrapped_key)?;
        kek.zeroize();

        if unwrapped.len() != 32 {
            unwrapped.zeroize();
            return Err(AppError::InvalidVault(
                "wrapped vault key length is invalid",
            ));
        }

        let mut vault_key = [0u8; 32];
        vault_key.copy_from_slice(&unwrapped);
        unwrapped.zeroize();

        let keys = VaultKeys::from_vault_key(vault_key)?;
        let body = decode_body(&file, &keys)?;
        if body.schema_version != BODY_SCHEMA_VERSION {
            return Err(AppError::UnsupportedSchema(body.schema_version));
        }

        Ok(Self {
            path,
            header: file.header,
            body,
            keys,
            source_hash: security::sha256(&bytes),
        })
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn vault_id(&self) -> Uuid {
        self.header.vault_id
    }

    pub fn revision(&self) -> u64 {
        self.header.revision
    }

    pub fn entries(&self) -> &[EntryRecord] {
        &self.body.entries
    }

    pub fn active_entries(&self) -> impl Iterator<Item = &EntryRecord> {
        self.body.entries.iter().filter(|entry| !entry.is_deleted())
    }

    pub fn add_entry(&mut self, draft: EntryDraft) -> Result<Uuid> {
        let id = Uuid::new_v4();
        let now = now_unix();
        let secret = self.seal_secret(id, &draft.secret)?;

        self.body.entries.push(EntryRecord {
            id,
            name: draft.name,
            website: draft.website,
            username: draft.username,
            category: draft.category,
            favorite: draft.favorite,
            secret,
            provenance: draft.provenance,
            created_at_unix: now,
            updated_at_unix: now,
            deleted_at_unix: None,
        });

        Ok(id)
    }

    pub fn reveal_secret(&self, id: Uuid) -> Result<SecretPayload> {
        let entry = self
            .body
            .entries
            .iter()
            .find(|entry| entry.id == id)
            .ok_or_else(|| AppError::Input("找不到该条目".to_string()))?;
        self.open_secret(entry)
    }

    pub fn move_to_recycle_bin(&mut self, id: Uuid) -> Result<()> {
        let now = now_unix();
        let entry = self
            .body
            .entries
            .iter_mut()
            .find(|entry| entry.id == id)
            .ok_or_else(|| AppError::Input("找不到该条目".to_string()))?;
        entry.deleted_at_unix = Some(now);
        entry.updated_at_unix = now;
        Ok(())
    }

    pub fn restore_from_recycle_bin(&mut self, id: Uuid) -> Result<()> {
        let now = now_unix();
        let entry = self
            .body
            .entries
            .iter_mut()
            .find(|entry| entry.id == id)
            .ok_or_else(|| AppError::Input("找不到该条目".to_string()))?;
        entry.deleted_at_unix = None;
        entry.updated_at_unix = now;
        Ok(())
    }

    pub fn save(&mut self) -> Result<()> {
        if self.path.exists() {
            let current = read_bounded(&self.path)?;
            if security::sha256(&current) != self.source_hash {
                return Err(AppError::ExternalChange);
            }
        }

        let mut next_header = self.header.clone();
        next_header.revision = next_header.revision.saturating_add(1);
        let bytes = encode_file(&next_header, &self.body, &self.keys)?;

        let verification: VaultFile = serde_json::from_slice(&bytes)?;
        let verified_body = decode_body(&verification, &self.keys)?;
        if verified_body != self.body {
            return Err(AppError::InvalidVault("pre-save verification mismatch"));
        }

        let temp = temp_path_for(&self.path);
        write_temp_file(&temp, &bytes)?;

        let backup = backup_path_for(&self.path);
        platform::atomic_replace(&self.path, &temp, Some(&backup))?;

        self.header = next_header;
        self.source_hash = security::sha256(&bytes);
        Ok(())
    }

    fn seal_secret(&self, id: Uuid, secret: &SecretPayload) -> Result<SecretEnvelope> {
        let nonce = random_array::<NONCE_LEN>()?;
        let aad = entry_aad(self.header.vault_id, id);
        let mut plaintext = serde_json::to_vec(secret)?;
        let ciphertext = seal(&self.keys.secret_key, &nonce, &aad, &plaintext)?;
        plaintext.zeroize();

        Ok(SecretEnvelope { nonce, ciphertext })
    }

    fn open_secret(&self, entry: &EntryRecord) -> Result<SecretPayload> {
        let aad = entry_aad(self.header.vault_id, entry.id);
        let mut plaintext = open(
            &self.keys.secret_key,
            &entry.secret.nonce,
            &aad,
            &entry.secret.ciphertext,
        )?;
        let secret = serde_json::from_slice(&plaintext)?;
        plaintext.zeroize();
        Ok(secret)
    }
}

fn validate_header(header: &PublicHeader) -> Result<()> {
    if header.magic != MAGIC {
        return Err(AppError::InvalidVault("magic header mismatch"));
    }
    if header.format_version != FORMAT_VERSION {
        return Err(AppError::UnsupportedVersion(header.format_version));
    }
    if header.kdf != "argon2id" {
        return Err(AppError::InvalidVault("unsupported KDF"));
    }
    header.kdf_params.validate()?;
    Ok(())
}

fn keywrap_aad(vault_id: Uuid, kdf: KdfConfig, salt: &[u8]) -> Vec<u8> {
    format!(
        "{MAGIC}|v{FORMAT_VERSION}|{vault_id}|argon2id|{}|{}|{}|{}",
        kdf.memory_kib,
        kdf.iterations,
        kdf.parallelism,
        b64(salt)
    )
    .into_bytes()
}

fn body_aad(header: &PublicHeader) -> Vec<u8> {
    format!(
        "{}|{}|{}|{}|{}|{}|{}|{}|{}|{}",
        header.magic,
        header.format_version,
        header.vault_id,
        header.revision,
        header.kdf,
        header.kdf_params.memory_kib,
        header.kdf_params.iterations,
        header.kdf_params.parallelism,
        header.kdf_salt,
        header.wrapped_vault_key,
    )
    .into_bytes()
}

fn entry_aad(vault_id: Uuid, entry_id: Uuid) -> Vec<u8> {
    format!("password-manager|entry-secret|v1|{vault_id}|{entry_id}").into_bytes()
}

fn encode_file(header: &PublicHeader, body: &VaultBody, keys: &VaultKeys) -> Result<Vec<u8>> {
    let nonce = random_array::<NONCE_LEN>()?;
    let mut plaintext = serde_json::to_vec(body)?;
    let ciphertext = seal(&keys.vault_key, &nonce, &body_aad(header), &plaintext)?;
    plaintext.zeroize();

    serde_json::to_vec(&VaultFile {
        header: header.clone(),
        body_nonce: b64(&nonce),
        body_ciphertext: b64(&ciphertext),
    })
    .map_err(AppError::from)
}

fn decode_body(file: &VaultFile, keys: &VaultKeys) -> Result<VaultBody> {
    let nonce = decode_array::<NONCE_LEN>(&file.body_nonce)?;
    let ciphertext = STANDARD_NO_PAD.decode(&file.body_ciphertext)?;
    let mut plaintext = open(
        &keys.vault_key,
        &nonce,
        &body_aad(&file.header),
        &ciphertext,
    )?;
    let body = serde_json::from_slice(&plaintext)?;
    plaintext.zeroize();
    Ok(body)
}

fn b64(bytes: &[u8]) -> String {
    STANDARD_NO_PAD.encode(bytes)
}

fn decode_array<const N: usize>(value: &str) -> Result<[u8; N]> {
    let bytes = STANDARD_NO_PAD.decode(value)?;
    if bytes.len() != N {
        return Err(AppError::InvalidVault("encoded field has invalid length"));
    }
    let mut out = [0u8; N];
    out.copy_from_slice(&bytes);
    Ok(out)
}

fn read_bounded(path: &Path) -> Result<Vec<u8>> {
    let mut file = File::open(path).map_err(|e| AppError::io(path.to_path_buf(), e))?;
    let metadata = file
        .metadata()
        .map_err(|e| AppError::io(path.to_path_buf(), e))?;
    if metadata.len() > MAX_VAULT_BYTES {
        return Err(AppError::InvalidVault("vault exceeds size limit"));
    }

    let mut bytes = Vec::with_capacity(metadata.len() as usize);
    file.read_to_end(&mut bytes)
        .map_err(|e| AppError::io(path.to_path_buf(), e))?;
    Ok(bytes)
}

fn write_temp_file(path: &Path, bytes: &[u8]) -> Result<()> {
    let mut file = File::create(path).map_err(|e| AppError::io(path.to_path_buf(), e))?;
    file.write_all(bytes)
        .map_err(|e| AppError::io(path.to_path_buf(), e))?;
    file.sync_all()
        .map_err(|e| AppError::io(path.to_path_buf(), e))?;
    Ok(())
}

fn temp_path_for(path: &Path) -> PathBuf {
    let name = path
        .file_name()
        .and_then(|value| value.to_str())
        .unwrap_or("vault.pmvault");
    path.with_file_name(format!(".{name}.tmp-{}", std::process::id()))
}

fn backup_path_for(path: &Path) -> PathBuf {
    let name = path
        .file_name()
        .and_then(|value| value.to_str())
        .unwrap_or("vault.pmvault");
    path.with_file_name(format!("{name}.bak"))
}

fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}
