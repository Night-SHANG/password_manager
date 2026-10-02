use std::fs;

use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use base64::{Engine as _, engine::general_purpose::STANDARD_NO_PAD};
use serde::{Deserialize, Serialize};
use uuid::Uuid;
use zeroize::{Zeroize, Zeroizing};

use crate::domain::{
    BODY_SCHEMA_VERSION, EntryDraft, EntryRecord, SecretEnvelope, SecretPayload, VaultBody,
};
use crate::platform;
use crate::security::{
    self, KdfConfig, NONCE_LEN, SALT_LEN, VaultKeys, derive_kek, open, random_array, seal,
};
use crate::{AppError, Result};

mod bounded;
pub mod recovery;
pub mod transaction;

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
    instance_id: Uuid,
    import_epoch: Uuid,
    path: PathBuf,
    header: PublicHeader,
    body: VaultBody,
    keys: VaultKeys,
    source_hash: [u8; 32],
    source_identity: crate::platform::file_transaction::Identity,
    write_invalid: bool,
    maintenance_warning: Option<String>,
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
        let vault_key = Zeroizing::new(random_array::<32>()?);
        let vault_id = Uuid::new_v4();

        let mut kek = Zeroizing::new(derive_kek(master_password, &salt, kdf_params)?);
        let wrap_aad = keywrap_aad(vault_id, kdf_params, &salt);
        let wrapped_vault_key = seal(&kek, &wrap_nonce, &wrap_aad, &vault_key[..])?;
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

        let keys = VaultKeys::from_vault_key(*vault_key)?;
        let body = VaultBody::default();
        let bytes = encode_file(&header, &body, &keys)?;
        verify_encoded_bytes(&bytes, &header, &body, &keys)?;

        let temp = tempfile::TempPath::from_path(temp_path_for(&path));
        write_temp_file(&temp, &bytes)?;
        platform::atomic_create_new(&path, temp)?;
        #[cfg(test)]
        tests::run_after_publish_hook();

        let (persisted, source_identity) = bounded::read_identified(&path, MAX_VAULT_BYTES)?;
        // Another writer may have replaced the published path. Verification
        // failure must not delete a destination whose ownership is unproven.
        verify_encoded_bytes(&persisted, &header, &body, &keys)?;

        Ok(Self {
            instance_id: Uuid::new_v4(),
            import_epoch: Uuid::new_v4(),
            source_identity,
            path: recovery::normalized_destination_path(&path)?,
            write_invalid: false,
            maintenance_warning: None,
            header,
            body,
            keys,
            source_hash: security::sha256(&persisted),
        })
    }

    pub fn open(path: impl Into<PathBuf>, master_password: &str) -> Result<Self> {
        let path = path.into();
        let (bytes, source_identity) = bounded::read_identified(&path, MAX_VAULT_BYTES)?;
        Self::from_captured(path, master_password, &bytes, source_identity)
    }

    fn from_captured(
        path: PathBuf,
        master_password: &str,
        bytes: &[u8],
        source_identity: crate::platform::file_transaction::Identity,
    ) -> Result<Self> {
        let file: VaultFile = serde_json::from_slice(bytes)?;
        validate_header(&file.header)?;

        let salt = decode_array::<SALT_LEN>(&file.header.kdf_salt)?;
        let wrap_nonce = decode_array::<NONCE_LEN>(&file.header.wrap_nonce)?;
        let wrapped_key = STANDARD_NO_PAD.decode(&file.header.wrapped_vault_key)?;

        let mut kek = Zeroizing::new(derive_kek(master_password, &salt, file.header.kdf_params)?);
        let wrap_aad = keywrap_aad(file.header.vault_id, file.header.kdf_params, &salt);
        let mut unwrapped = Zeroizing::new(open(&kek, &wrap_nonce, &wrap_aad, &wrapped_key)?);
        kek.zeroize();

        if unwrapped.len() != 32 {
            unwrapped.zeroize();
            return Err(AppError::InvalidVault(
                "wrapped vault key length is invalid",
            ));
        }

        let mut vault_key = Zeroizing::new([0u8; 32]);
        vault_key.copy_from_slice(&unwrapped);
        unwrapped.zeroize();

        let keys = VaultKeys::from_vault_key(*vault_key)?;
        let body = decode_body(&file, &keys)?;
        if body.schema_version != BODY_SCHEMA_VERSION {
            return Err(AppError::UnsupportedSchema(body.schema_version));
        }

        Ok(Self {
            instance_id: Uuid::new_v4(),
            import_epoch: Uuid::new_v4(),
            source_identity,
            path: recovery::normalized_destination_path(&path)?,
            write_invalid: false,
            maintenance_warning: None,
            header: file.header,
            body,
            keys,
            source_hash: security::sha256(bytes),
        })
    }

    pub(crate) fn import_binding(&self) -> (Uuid, Uuid) {
        (self.instance_id, self.import_epoch)
    }

    pub(crate) fn consume_import_preview(&mut self) {
        // Successful no-op/deferred commits consume previews too. In memory
        // only: reopening always gets a different session binding.
        self.import_epoch = Uuid::new_v4();
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

    pub fn categories(&self) -> &[String] {
        &self.body.categories
    }

    pub fn entry(&self, id: Uuid) -> Option<&EntryRecord> {
        self.body.entries.iter().find(|entry| entry.id == id)
    }

    pub fn active_entries(&self) -> impl Iterator<Item = &EntryRecord> {
        self.body.entries.iter().filter(|entry| !entry.is_deleted())
    }

    /// Storage-owned traversal: no ID lookup and no arbitrary-entry decrypt API.
    pub(crate) fn active_entries_with_secrets(
        &self,
    ) -> impl Iterator<Item = Result<(&EntryRecord, SecretPayload)>> {
        self.body
            .entries
            .iter()
            .inspect(|_| {
                #[cfg(test)]
                export_probe::visit();
            })
            .filter(|entry| !entry.is_deleted())
            .map(|entry| {
                #[cfg(test)]
                export_probe::decrypt();
                self.open_secret(entry).map(|secret| (entry, secret))
            })
    }

    pub fn add_entry(&mut self, draft: EntryDraft) -> Result<Uuid> {
        self.ensure_category(&draft.category);
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

    pub fn update_entry(&mut self, id: Uuid, draft: EntryDraft) -> Result<()> {
        self.ensure_category(&draft.category);
        let sealed = self.seal_secret(id, &draft.secret)?;
        let index = self
            .body
            .entries
            .iter()
            .position(|entry| entry.id == id)
            .ok_or_else(|| AppError::Input("找不到该条目".to_string()))?;

        let previous_provenance = self.body.entries[index].provenance.clone();
        let entry = &mut self.body.entries[index];
        entry.name = draft.name;
        entry.website = draft.website;
        entry.username = draft.username;
        entry.category = draft.category;
        entry.favorite = draft.favorite;
        entry.secret = sealed;
        entry.provenance = draft.provenance.or(previous_provenance);
        entry.updated_at_unix = now_unix();
        Ok(())
    }

    pub fn reveal_secret(&self, id: Uuid) -> Result<SecretPayload> {
        #[cfg(test)]
        export_probe::lookup();
        let entry = self
            .body
            .entries
            .iter()
            .find(|entry| entry.id == id)
            .ok_or_else(|| AppError::Input("找不到该条目".to_string()))?;
        self.open_secret(entry)
    }

    pub fn set_favorite(&mut self, id: Uuid, favorite: bool) -> Result<()> {
        let entry = self
            .body
            .entries
            .iter_mut()
            .find(|entry| entry.id == id)
            .ok_or_else(|| AppError::Input("找不到该条目".to_string()))?;
        entry.favorite = favorite;
        entry.updated_at_unix = now_unix();
        Ok(())
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

    pub fn permanently_delete(&mut self, id: Uuid) -> Result<()> {
        let index = self
            .body
            .entries
            .iter()
            .position(|entry| entry.id == id && entry.is_deleted())
            .ok_or_else(|| AppError::Input("只能永久删除回收站中的条目".to_string()))?;
        self.body.entries.remove(index);
        Ok(())
    }

    pub fn save(&mut self) -> Result<()> {
        self.ensure_maintenance_ready()?;
        if self.write_invalid {
            return Err(AppError::ExternalChange);
        }
        let mut next_header = self.header.clone();
        next_header.revision = next_header
            .revision
            .checked_add(1)
            .ok_or(AppError::InvalidVault("revision overflow"))?;
        let bytes = encode_file(&next_header, &self.body, &self.keys)?;
        let result = transaction::commit(
            transaction::SourceExpectation {
                target: &self.path,
                hash: self.source_hash,
                identity: self.source_identity,
            },
            &bytes,
            |old| self.verify_baseline(old),
            |new| verify_encoded_bytes(new, &next_header, &self.body, &self.keys),
        );
        match result {
            Ok(receipt) => {
                self.header = next_header;
                self.source_hash = receipt.hash;
                self.source_identity = receipt.identity;
                self.maintenance_warning = receipt.warning;
                Ok(())
            }
            Err(error) => {
                if error.invalidates_session() {
                    self.write_invalid = true;
                    self.consume_import_preview();
                }
                Err(error)
            }
        }
    }

    fn ensure_maintenance_ready(&self) -> Result<()> {
        if let Some(warning) = &self.maintenance_warning {
            return Err(transaction::maintenance_failure(
                transaction::SourceExpectation {
                    target: &self.path,
                    hash: self.source_hash,
                    identity: self.source_identity,
                },
                warning,
            ));
        }
        Ok(())
    }

    pub fn maintenance_warning(&self) -> Option<&str> {
        self.maintenance_warning.as_deref()
    }

    fn verify_baseline(&self, bytes: &[u8]) -> Result<()> {
        if security::sha256(bytes) != self.source_hash {
            return Err(AppError::ExternalChange);
        }
        let file: VaultFile = serde_json::from_slice(bytes)?;
        validate_header(&file.header)?;
        if file.header.vault_id != self.header.vault_id
            || file.header.revision != self.header.revision
        {
            return Err(AppError::ExternalChange);
        }
        let body = decode_body(&file, &self.keys)?;
        if body.schema_version != BODY_SCHEMA_VERSION {
            return Err(AppError::UnsupportedSchema(body.schema_version));
        }
        Ok(())
    }

    /// Explicitly confirmed overwrite is bound to this active destination session.
    /// The returned session was authenticated from captured bytes and verified by
    /// the transaction; callers must not reopen the pathname to adopt it.
    pub fn restore_over_current(&mut self, source: &Path, master_password: &str) -> Result<Self> {
        self.ensure_maintenance_ready()?;
        if self.write_invalid {
            return Err(AppError::ExternalChange);
        }
        if same_path(source, &self.path) {
            return Err(AppError::Input("恢复源与目标不能是同一个文件".into()));
        }
        let (bytes, source_identity) = bounded::read_identified(source, MAX_VAULT_BYTES)?;
        let mut candidate = Self::from_captured(
            source.to_path_buf(),
            master_password,
            &bytes,
            source_identity,
        )?;
        let result = transaction::commit(
            transaction::SourceExpectation {
                target: &self.path,
                hash: self.source_hash,
                identity: self.source_identity,
            },
            &bytes,
            |old| self.verify_baseline(old),
            |new| verify_encoded_bytes(new, &candidate.header, &candidate.body, &candidate.keys),
        );
        match result {
            Ok(receipt) => {
                candidate.path = self.path.clone();
                candidate.source_hash = receipt.hash;
                candidate.source_identity = receipt.identity;
                candidate.maintenance_warning = receipt.warning;
                self.write_invalid = true;
                self.consume_import_preview();
                Ok(candidate)
            }
            Err(error) => {
                if error.invalidates_session() {
                    self.write_invalid = true;
                    self.consume_import_preview();
                }
                Err(error)
            }
        }
    }

    pub fn verify_current_file(&self) -> Result<()> {
        if self.write_invalid {
            return Err(AppError::ExternalChange);
        }
        let verification = (|| {
            let (bytes, identity) = bounded::read_identified(&self.path, MAX_VAULT_BYTES)?;
            if identity != self.source_identity || security::sha256(&bytes) != self.source_hash {
                return Err(AppError::ExternalChange);
            }
            verify_encoded_bytes(&bytes, &self.header, &self.body, &self.keys)
        })();
        verification.map_err(|error| {
            transaction::current_source_failure(
                transaction::SourceExpectation {
                    target: &self.path,
                    hash: self.source_hash,
                    identity: self.source_identity,
                },
                error,
            )
        })
    }

    pub fn export_encrypted_backup(&self, destination: &Path) -> Result<()> {
        if same_path(&self.path, destination) {
            return Err(AppError::Input("备份目标不能与当前保险库相同".to_string()));
        }
        if destination.exists() {
            return Err(AppError::AlreadyExists);
        }

        let bytes = read_bounded(&self.path)?;
        if security::sha256(&bytes) != self.source_hash {
            return Err(AppError::ExternalChange);
        }

        let temp = tempfile::TempPath::from_path(temp_path_for(destination));
        write_temp_file(&temp, &bytes)?;
        platform::atomic_create_new(destination, temp)?;
        #[cfg(test)]
        tests::run_after_publish_hook();

        let copied = read_bounded(destination)?;
        if security::sha256(&copied) != self.source_hash {
            // Preserve the path: it may now belong to another writer.
            return Err(AppError::InvalidVault(
                "encrypted backup verification failed",
            ));
        }

        Ok(())
    }

    pub fn restore_encrypted_backup(
        source: &Path,
        destination: &Path,
        master_password: &str,
        overwrite: bool,
    ) -> Result<()> {
        if same_path(source, destination) {
            return Err(AppError::Input("恢复源与目标不能是同一个文件".to_string()));
        }
        if destination.exists() && !overwrite {
            return Err(AppError::AlreadyExists);
        }

        if overwrite {
            return Err(AppError::Input(
                "覆盖恢复需要当前目标会话；请使用已确认的 restore_over_current，或恢复到新文件"
                    .into(),
            ));
        }
        let (bytes, source_identity) = bounded::read_identified(source, MAX_VAULT_BYTES)?;
        let verified = Self::from_captured(
            source.to_path_buf(),
            master_password,
            &bytes,
            source_identity,
        )?;
        let temp = tempfile::TempPath::from_path(temp_path_for(destination));
        write_temp_file(&temp, &bytes)?;
        platform::atomic_create_new(destination, temp)?;
        #[cfg(test)]
        tests::run_after_publish_hook();
        let copied = read_bounded(destination)?;
        if copied != bytes {
            return Err(AppError::InvalidVault(
                "restored encrypted backup failed verification",
            ));
        }
        verify_encoded_bytes(&copied, &verified.header, &verified.body, &verified.keys)
    }

    pub(crate) fn body(&self) -> &VaultBody {
        &self.body
    }

    pub(crate) fn body_mut(&mut self) -> &mut VaultBody {
        &mut self.body
    }

    pub(crate) fn snapshot_body(&self) -> VaultBody {
        self.body.clone()
    }

    pub(crate) fn restore_body(&mut self, body: VaultBody) {
        self.body = body;
    }

    fn seal_secret(&self, id: Uuid, secret: &SecretPayload) -> Result<SecretEnvelope> {
        let nonce = random_array::<NONCE_LEN>()?;
        let aad = entry_aad(self.header.vault_id, id);
        let mut plaintext = Zeroizing::new(serde_json::to_vec(secret)?);
        let ciphertext = seal(&self.keys.secret_key, &nonce, &aad, &plaintext)?;
        plaintext.zeroize();

        Ok(SecretEnvelope { nonce, ciphertext })
    }

    fn open_secret(&self, entry: &EntryRecord) -> Result<SecretPayload> {
        let aad = entry_aad(self.header.vault_id, entry.id);
        let mut plaintext = Zeroizing::new(open(
            &self.keys.secret_key,
            &entry.secret.nonce,
            &aad,
            &entry.secret.ciphertext,
        )?);
        let secret = serde_json::from_slice(&plaintext)?;
        plaintext.zeroize();
        Ok(secret)
    }

    fn ensure_category(&mut self, category: &str) {
        if !category.trim().is_empty() && !self.body.categories.iter().any(|item| item == category)
        {
            self.body.categories.push(category.to_string());
        }
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
        "{}|{}|{}|{}|{}|{}|{}|{}|{}|{}|{}",
        header.magic,
        header.format_version,
        header.vault_id,
        header.revision,
        header.kdf,
        header.kdf_params.memory_kib,
        header.kdf_params.iterations,
        header.kdf_params.parallelism,
        header.kdf_salt,
        header.wrap_nonce,
        header.wrapped_vault_key,
    )
    .into_bytes()
}

fn entry_aad(vault_id: Uuid, entry_id: Uuid) -> Vec<u8> {
    format!("password-manager|entry-secret|v1|{vault_id}|{entry_id}").into_bytes()
}

fn encode_file(header: &PublicHeader, body: &VaultBody, keys: &VaultKeys) -> Result<Vec<u8>> {
    let nonce = random_array::<NONCE_LEN>()?;
    let mut plaintext = Zeroizing::new(serde_json::to_vec(body)?);
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
    let mut plaintext = Zeroizing::new(open(
        &keys.vault_key,
        &nonce,
        &body_aad(&file.header),
        &ciphertext,
    )?);
    let body = serde_json::from_slice(&plaintext)?;
    plaintext.zeroize();
    Ok(body)
}

fn verify_encoded_bytes(
    bytes: &[u8],
    expected_header: &PublicHeader,
    expected_body: &VaultBody,
    keys: &VaultKeys,
) -> Result<()> {
    let file: VaultFile = serde_json::from_slice(bytes)?;
    validate_header(&file.header)?;

    if file.header.vault_id != expected_header.vault_id
        || file.header.revision != expected_header.revision
        || file.header.kdf_salt != expected_header.kdf_salt
        || file.header.wrap_nonce != expected_header.wrap_nonce
        || file.header.wrapped_vault_key != expected_header.wrapped_vault_key
    {
        return Err(AppError::InvalidVault(
            "persisted header verification mismatch",
        ));
    }

    let decoded = decode_body(&file, keys)?;
    if decoded != *expected_body {
        return Err(AppError::InvalidVault(
            "persisted body verification mismatch",
        ));
    }
    Ok(())
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
    bounded::read(path, MAX_VAULT_BYTES)
}

fn write_temp_file(path: &Path, bytes: &[u8]) -> Result<()> {
    if let Some(parent) = path.parent().filter(|p| !p.as_os_str().is_empty()) {
        fs::create_dir_all(parent).map_err(|e| AppError::io(parent, e))?;
    }
    bounded::write_new(path, bytes)?;
    #[cfg(test)]
    tests::run_before_publish_hook();
    Ok(())
}

fn temp_path_for(path: &Path) -> PathBuf {
    let name = path
        .file_name()
        .and_then(|value| value.to_str())
        .unwrap_or("vault.pmvault");
    path.with_file_name(format!(".{name}.tmp-{}", Uuid::new_v4()))
}

fn same_path(left: &Path, right: &Path) -> bool {
    match (left.canonicalize(), right.canonicalize()) {
        (Ok(left), Ok(right)) => left == right,
        _ => left == right,
    }
}

fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

#[cfg(test)]
mod tests {
    use std::cell::RefCell;

    use super::*;

    thread_local! {
        static BEFORE_PUBLISH: RefCell<Option<Box<dyn FnOnce()>>> = RefCell::new(None);
        static AFTER_PUBLISH: RefCell<Option<Box<dyn FnOnce()>>> = RefCell::new(None);
    }

    pub(super) fn run_before_publish_hook() {
        let hook = BEFORE_PUBLISH.with(|slot| slot.borrow_mut().take());
        if let Some(hook) = hook {
            hook();
        }
    }

    pub(super) fn run_after_publish_hook() {
        let hook = AFTER_PUBLISH.with(|slot| slot.borrow_mut().take());
        if let Some(hook) = hook {
            hook();
        }
    }

    fn create_competing_destination_before_publish(destination: PathBuf) {
        BEFORE_PUBLISH.with(|slot| {
            *slot.borrow_mut() = Some(Box::new(move || {
                assert!(!destination.exists());
                fs::write(destination, b"another writer's file").unwrap();
            }));
        });
    }

    fn replace_destination_after_publish(destination: PathBuf) {
        AFTER_PUBLISH.with(|slot| {
            *slot.borrow_mut() = Some(Box::new(move || {
                assert!(destination.exists());
                let competing = destination.with_file_name("competing-file.tmp");
                fs::write(&competing, b"another writer's replacement").unwrap();
                fs::remove_file(&destination).unwrap();
                fs::rename(&competing, &destination).unwrap();
            }));
        });
    }

    fn contains_bytes(root: &Path, expected: &[u8]) -> bool {
        fs::read_dir(root)
            .unwrap()
            .filter_map(|entry| entry.ok())
            .any(|entry| {
                if entry.file_type().unwrap().is_dir() {
                    contains_bytes(&entry.path(), expected)
                } else {
                    fs::read(entry.path()).is_ok_and(|bytes| bytes == expected)
                }
            })
    }

    #[test]
    fn transaction_success_keeps_independent_previous_encrypted_bytes() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("synthetic.pmvault");
        let mut vault = VaultSession::create(&path, "synthetic-only").unwrap();
        let before = fs::read(&path).unwrap();
        vault
            .add_entry(EntryDraft::login("New", "", "", "synthetic"))
            .unwrap();
        vault.save().unwrap();
        assert_ne!(fs::read(&path).unwrap(), before);
        assert!(
            contains_bytes(dir.path(), &before),
            "previous encrypted bytes were lost"
        );
    }

    #[test]
    fn transaction_final_recheck_preserves_prepublication_competitor() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("synthetic.pmvault");
        let mut vault = VaultSession::create(&path, "synthetic-only").unwrap();
        let target = path.clone();
        BEFORE_PUBLISH.with(|slot| {
            *slot.borrow_mut() = Some(Box::new(move || {
                fs::write(target, b"prepublication competing file").unwrap();
            }))
        });
        assert!(vault.save().is_err());
        assert_eq!(fs::read(path).unwrap(), b"prepublication competing file");
    }

    #[test]
    fn transaction_postpublication_conflict_retains_evidence_without_rollback() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("synthetic.pmvault");
        let mut vault = VaultSession::create(&path, "synthetic-only").unwrap();
        let before = fs::read(&path).unwrap();
        replace_destination_after_publish(path.clone());
        let error = vault.save().unwrap_err();
        assert!(
            error.to_string().contains("recovery"),
            "must explicitly require recovery: {error}"
        );
        assert_eq!(fs::read(path).unwrap(), b"another writer's replacement");
        assert!(contains_bytes(dir.path(), &before));
    }

    #[test]
    fn create_preserves_destination_replaced_after_publish() {
        let dir = tempfile::tempdir().unwrap();
        let destination = dir.path().join("new.pmvault");
        replace_destination_after_publish(destination.clone());

        let result = VaultSession::create(&destination, "synthetic-master");

        assert!(matches!(result, Err(AppError::Json(_))));
        assert_eq!(
            fs::read(destination).unwrap(),
            b"another writer's replacement"
        );
        assert_eq!(fs::read_dir(dir.path()).unwrap().count(), 1);
    }

    #[test]
    fn backup_preserves_destination_replaced_after_publish() {
        let dir = tempfile::tempdir().unwrap();
        let source = dir.path().join("source.pmvault");
        let destination = dir.path().join("backup.pmvault");
        let vault = VaultSession::create(&source, "synthetic-master").unwrap();
        let original = fs::read(&source).unwrap();
        replace_destination_after_publish(destination.clone());

        let result = vault.export_encrypted_backup(&destination);

        assert!(matches!(result, Err(AppError::InvalidVault(_))));
        assert_eq!(
            fs::read(destination).unwrap(),
            b"another writer's replacement"
        );
        assert_eq!(fs::read(source).unwrap(), original);
        assert_eq!(fs::read_dir(dir.path()).unwrap().count(), 2);
    }

    #[test]
    fn create_preserves_destination_created_before_publish() {
        let dir = tempfile::tempdir().unwrap();
        let destination = dir.path().join("new.pmvault");
        create_competing_destination_before_publish(destination.clone());

        let result = VaultSession::create(&destination, "synthetic-master");

        assert_eq!(fs::read(&destination).unwrap(), b"another writer's file");
        assert!(matches!(result, Err(AppError::AlreadyExists)));
        assert_eq!(fs::read_dir(dir.path()).unwrap().count(), 1);
    }

    #[test]
    fn backup_preserves_destination_created_before_publish() {
        let dir = tempfile::tempdir().unwrap();
        let source = dir.path().join("source.pmvault");
        let destination = dir.path().join("backup.pmvault");
        let vault = VaultSession::create(&source, "synthetic-master").unwrap();
        let original = fs::read(&source).unwrap();
        create_competing_destination_before_publish(destination.clone());

        let result = vault.export_encrypted_backup(&destination);

        assert_eq!(fs::read(&destination).unwrap(), b"another writer's file");
        assert!(matches!(result, Err(AppError::AlreadyExists)));
        assert_eq!(fs::read(&source).unwrap(), original);
        assert_eq!(fs::read_dir(dir.path()).unwrap().count(), 2);
    }

    #[test]
    fn restore_preserves_destination_created_before_publish() {
        let dir = tempfile::tempdir().unwrap();
        let source = dir.path().join("source.pmvault");
        let destination = dir.path().join("restored.pmvault");
        VaultSession::create(&source, "synthetic-master").unwrap();
        let original = fs::read(&source).unwrap();
        create_competing_destination_before_publish(destination.clone());

        let result = VaultSession::restore_encrypted_backup(
            &source,
            &destination,
            "synthetic-master",
            false,
        );

        assert_eq!(fs::read(&destination).unwrap(), b"another writer's file");
        assert!(matches!(result, Err(AppError::AlreadyExists)));
        assert_eq!(fs::read(&source).unwrap(), original);
        assert_eq!(fs::read_dir(dir.path()).unwrap().count(), 2);
    }

    #[test]
    fn restore_preserves_directory_created_before_publish() {
        let dir = tempfile::tempdir().unwrap();
        let source = dir.path().join("source.pmvault");
        let destination = dir.path().join("restored.pmvault");
        VaultSession::create(&source, "synthetic-master").unwrap();
        let original = fs::read(&source).unwrap();
        let competing_directory = destination.clone();
        BEFORE_PUBLISH.with(|slot| {
            *slot.borrow_mut() = Some(Box::new(move || {
                assert!(!competing_directory.exists());
                fs::create_dir(&competing_directory).unwrap();
                fs::write(competing_directory.join("keep.txt"), b"keep").unwrap();
            }));
        });

        let result = VaultSession::restore_encrypted_backup(
            &source,
            &destination,
            "synthetic-master",
            false,
        );

        assert!(result.is_err());
        assert_eq!(fs::read(destination.join("keep.txt")).unwrap(), b"keep");
        assert_eq!(fs::read(&source).unwrap(), original);
        assert_eq!(fs::read_dir(dir.path()).unwrap().count(), 2);
    }

    #[cfg(unix)]
    #[test]
    fn restore_preserves_dangling_symlink_created_before_publish() {
        let dir = tempfile::tempdir().unwrap();
        let source = dir.path().join("source.pmvault");
        let destination = dir.path().join("restored.pmvault");
        let link_target = dir.path().join("missing.pmvault");
        VaultSession::create(&source, "synthetic-master").unwrap();
        let original = fs::read(&source).unwrap();
        let competing_link = destination.clone();
        let competing_link_target = link_target.clone();
        BEFORE_PUBLISH.with(|slot| {
            *slot.borrow_mut() = Some(Box::new(move || {
                assert!(!competing_link.exists());
                std::os::unix::fs::symlink(competing_link_target, competing_link).unwrap();
            }));
        });

        let result = VaultSession::restore_encrypted_backup(
            &source,
            &destination,
            "synthetic-master",
            false,
        );

        assert!(matches!(result, Err(AppError::AlreadyExists)));
        assert_eq!(fs::read_link(destination).unwrap(), link_target);
        assert!(!link_target.exists());
        assert_eq!(fs::read(&source).unwrap(), original);
        assert_eq!(fs::read_dir(dir.path()).unwrap().count(), 2);
    }

    #[test]
    fn restore_preserves_destination_replaced_after_publish() {
        let dir = tempfile::tempdir().unwrap();
        let source = dir.path().join("source.pmvault");
        let destination = dir.path().join("restored.pmvault");
        VaultSession::create(&source, "synthetic-master").unwrap();
        let original = fs::read(&source).unwrap();
        replace_destination_after_publish(destination.clone());

        let result = VaultSession::restore_encrypted_backup(
            &source,
            &destination,
            "synthetic-master",
            false,
        );

        assert!(matches!(result, Err(AppError::InvalidVault(_))));
        assert_eq!(
            fs::read(destination).unwrap(),
            b"another writer's replacement"
        );
        assert_eq!(fs::read(&source).unwrap(), original);
        assert_eq!(fs::read_dir(dir.path()).unwrap().count(), 2);
    }

    fn assert_restore_preserves_valid_replacement_after_publish(change_body: bool) {
        let dir = tempfile::tempdir().unwrap();
        let source = dir.path().join("source.pmvault");
        let destination = dir.path().join("restored.pmvault");
        let competing = dir.path().join("competing.pmvault");
        let vault = VaultSession::create(&source, "synthetic-master").unwrap();
        let original = fs::read(&source).unwrap();
        let mut competing_body = vault.body.clone();
        if change_body {
            competing_body.categories.push("Another writer".to_string());
        }
        let competing_bytes = encode_file(&vault.header, &competing_body, &vault.keys).unwrap();
        assert_ne!(competing_bytes, original);
        fs::write(&competing, &competing_bytes).unwrap();
        let competing_vault = VaultSession::open(&competing, "synthetic-master").unwrap();
        assert_eq!(competing_vault.vault_id(), vault.vault_id());
        assert_eq!(competing_vault.revision(), vault.revision());
        assert_eq!(competing_vault.body, competing_body);
        let competing_destination = destination.clone();
        AFTER_PUBLISH.with(|slot| {
            *slot.borrow_mut() = Some(Box::new(move || {
                assert!(competing_destination.exists());
                fs::remove_file(&competing_destination).unwrap();
                fs::rename(&competing, &competing_destination).unwrap();
            }));
        });

        let result = VaultSession::restore_encrypted_backup(
            &source,
            &destination,
            "synthetic-master",
            false,
        );

        assert!(matches!(result, Err(AppError::InvalidVault(_))));
        assert_eq!(fs::read(destination).unwrap(), competing_bytes);
        assert_eq!(fs::read(&source).unwrap(), original);
        assert_eq!(fs::read_dir(dir.path()).unwrap().count(), 2);
    }

    #[test]
    fn restore_rejects_same_identity_and_revision_divergent_contents_after_publish() {
        assert_restore_preserves_valid_replacement_after_publish(true);
    }

    #[test]
    fn restore_rejects_reencrypted_same_contents_after_publish() {
        assert_restore_preserves_valid_replacement_after_publish(false);
    }

    #[test]
    fn create_preserves_directory_created_before_publish() {
        let dir = tempfile::tempdir().unwrap();
        let destination = dir.path().join("new.pmvault");
        let competing_directory = destination.clone();
        BEFORE_PUBLISH.with(|slot| {
            *slot.borrow_mut() = Some(Box::new(move || {
                fs::create_dir(&competing_directory).unwrap();
                fs::write(competing_directory.join("keep.txt"), b"keep").unwrap();
            }));
        });

        assert!(VaultSession::create(&destination, "synthetic-master").is_err());
        assert_eq!(fs::read(destination.join("keep.txt")).unwrap(), b"keep");
        assert_eq!(fs::read_dir(dir.path()).unwrap().count(), 1);
    }

    #[test]
    fn new_vault_and_backup_publish_complete_bytes_without_temporary_files() {
        let dir = tempfile::tempdir().unwrap();
        let parent = dir.path().join("nested 保险库");
        let source = parent.join("source.pmvault");
        let destination = parent.join("backup.pmvault");

        let vault = VaultSession::create(&source, "synthetic-master").unwrap();
        vault.export_encrypted_backup(&destination).unwrap();

        assert_eq!(fs::read(&source).unwrap(), fs::read(&destination).unwrap());
        assert_eq!(fs::read_dir(&parent).unwrap().count(), 2);
        let reopened = VaultSession::open(destination, "synthetic-master").unwrap();
        assert_eq!(reopened.vault_id(), vault.vault_id());
    }

    #[cfg(unix)]
    #[test]
    fn create_does_not_replace_dangling_symlink() {
        let dir = tempfile::tempdir().unwrap();
        let destination = dir.path().join("new.pmvault");
        let link_target = dir.path().join("missing.pmvault");
        std::os::unix::fs::symlink(&link_target, &destination).unwrap();

        let result = VaultSession::create(&destination, "synthetic-master");

        assert!(matches!(result, Err(AppError::AlreadyExists)));
        assert_eq!(fs::read_link(destination).unwrap(), link_target);
        assert!(!link_target.exists());
        assert_eq!(fs::read_dir(dir.path()).unwrap().count(), 1);
    }

    #[cfg(unix)]
    #[test]
    fn backup_does_not_replace_dangling_symlink() {
        let dir = tempfile::tempdir().unwrap();
        let source = dir.path().join("source.pmvault");
        let destination = dir.path().join("backup.pmvault");
        let link_target = dir.path().join("missing.pmvault");
        let vault = VaultSession::create(&source, "synthetic-master").unwrap();
        let original = fs::read(&source).unwrap();
        std::os::unix::fs::symlink(&link_target, &destination).unwrap();

        let result = vault.export_encrypted_backup(&destination);

        assert!(matches!(result, Err(AppError::AlreadyExists)));
        assert_eq!(fs::read_link(destination).unwrap(), link_target);
        assert!(!link_target.exists());
        assert_eq!(fs::read(source).unwrap(), original);
        assert_eq!(fs::read_dir(dir.path()).unwrap().count(), 2);
    }
}

#[cfg(test)]
mod transaction_tests;

#[cfg(test)]
pub(crate) mod export_probe {
    use std::cell::Cell;
    thread_local! { static COUNTS: Cell<(usize, usize, usize)> = const { Cell::new((0,0,0)) }; }
    pub fn reset() {
        COUNTS.with(|c| c.set((0, 0, 0)));
    }
    pub fn counts() -> (usize, usize, usize) {
        COUNTS.with(Cell::get)
    }
    pub(super) fn visit() {
        COUNTS.with(|c| {
            let (v, d, l) = c.get();
            c.set((v + 1, d, l));
        });
    }
    pub(super) fn decrypt() {
        COUNTS.with(|c| {
            let (v, d, l) = c.get();
            c.set((v, d + 1, l));
        });
    }
    pub(super) fn lookup() {
        COUNTS.with(|c| {
            let (v, d, l) = c.get();
            c.set((v, d, l + 1));
        });
    }
}
