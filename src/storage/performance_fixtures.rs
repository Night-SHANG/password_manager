//! Synthetic measurement inputs only. This module is excluded from production.
//! Private canonical v1 helpers build fixtures; no fake KDF or key is installed.
use super::*;

pub(crate) const HIGH_MEMORY_KDF: KdfConfig = KdfConfig {
    memory_kib: 1_048_576,
    iterations: 3,
    parallelism: 1,
};
const TARGET_MARGIN: u64 = 48 * 1024;
const TARGET_TOLERANCE: u64 = 8 * 1024;

struct Candidate {
    header: PublicHeader,
    body: VaultBody,
    keys: VaultKeys,
}

fn candidate(master_password: &str, config: KdfConfig) -> Result<Candidate> {
    if master_password.is_empty() {
        return Err(AppError::Input(
            "synthetic fixture password required".into(),
        ));
    }
    let config = config.validate()?;
    let salt = random_array::<SALT_LEN>()?;
    let wrap_nonce = random_array::<NONCE_LEN>()?;
    let vault_key = Zeroizing::new(random_array::<32>()?);
    let vault_id = Uuid::new_v4();
    // The production guarded, caller-owned Argon2 scratch is used exactly once.
    let mut kek = Zeroizing::new(derive_kek(master_password, &salt, config)?);
    let wrapped_key = seal(
        &kek,
        &wrap_nonce,
        &keywrap_aad(vault_id, config, &salt),
        &vault_key[..],
    )?;
    kek.zeroize();
    Ok(Candidate {
        header: PublicHeader {
            magic: MAGIC.into(),
            format_version: FORMAT_VERSION,
            vault_id,
            revision: 1,
            kdf: "argon2id".into(),
            kdf_params: config,
            kdf_salt: b64(&salt),
            wrap_nonce: b64(&wrap_nonce),
            wrapped_vault_key: b64(&wrapped_key),
        },
        body: VaultBody::default(),
        keys: VaultKeys::from_vault_key(*vault_key)?,
    })
}

fn parents(path: &Path) -> Result<()> {
    if let Some(parent) = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
    {
        fs::create_dir_all(parent).map_err(|error| AppError::io(parent, error))?;
    }
    Ok(())
}

fn persist_fixture(
    path: &Path,
    candidate: Candidate,
    bytes: Zeroizing<Vec<u8>>,
) -> Result<VaultSession> {
    if bytes.len() as u64 > MAX_VAULT_BYTES {
        return Err(AppError::InvalidVault(
            "synthetic fixture exceeds size limit",
        ));
    }
    verify_encoded_bytes(&bytes, &candidate.header, &candidate.body, &candidate.keys)?;
    parents(path)?;
    // Exclusive synthetic final-file creation. No production publisher bypass
    // is exposed: this entire module and its consumers are cfg(test)-only.
    bounded::write_new(path, &bytes)?;
    let (persisted, identity) = bounded::read_identified(path, MAX_VAULT_BYTES)?;
    let persisted = Zeroizing::new(persisted);
    if persisted.as_slice() != bytes.as_slice() {
        return Err(AppError::InvalidVault(
            "synthetic fixture changed after write",
        ));
    }
    verify_encoded_bytes(
        &persisted,
        &candidate.header,
        &candidate.body,
        &candidate.keys,
    )?;
    // Adopt retained candidate keys after exact readback instead of deriving a
    // second KEK merely to manufacture the fixture's initial session.
    Ok(VaultSession {
        instance_id: Uuid::new_v4(),
        import_epoch: Uuid::new_v4(),
        path: recovery::normalized_destination_path(path)?,
        header: candidate.header,
        body: candidate.body,
        keys: candidate.keys,
        source_hash: security::sha256(&persisted),
        source_identity: identity,
        write_invalid: false,
        maintenance_warning: None,
    })
}

pub(crate) fn create_synthetic_vault(
    path: &Path,
    master_password: &str,
    config: KdfConfig,
) -> Result<VaultSession> {
    if path.exists() {
        return Err(AppError::AlreadyExists);
    }
    let candidate = candidate(master_password, config)?;
    let bytes = Zeroizing::new(encode_file(
        &candidate.header,
        &candidate.body,
        &candidate.keys,
    )?);
    persist_fixture(path, candidate, bytes)
}

fn encrypted_notes(candidate: &Candidate, id: Uuid, notes_len: usize) -> Result<EntryRecord> {
    let secret = SecretPayload::new("synthetic-password-only", "x".repeat(notes_len));
    let plaintext = Zeroizing::new(serde_json::to_vec(&secret)?);
    let nonce = random_array::<NONCE_LEN>()?;
    let ciphertext = seal(
        &candidate.keys.secret_key,
        &nonce,
        &entry_aad(candidate.header.vault_id, id),
        &plaintext,
    )?;
    Ok(EntryRecord {
        id,
        name: "Synthetic near-limit entry".into(),
        website: "https://synthetic.invalid".into(),
        username: "synthetic".into(),
        category: "其他".into(),
        favorite: false,
        secret: SecretEnvelope { nonce, ciphertext },
        provenance: None,
        created_at_unix: 1,
        updated_at_unix: 1,
        deleted_at_unix: None,
    })
}

pub(crate) fn build_near_limit_vault(
    path: &Path,
    master_password: &str,
    config: KdfConfig,
) -> Result<(VaultSession, usize)> {
    if path.exists() {
        return Err(AppError::AlreadyExists);
    }
    let mut candidate = candidate(master_password, config)?;
    let id = Uuid::new_v4();
    let target = MAX_VAULT_BYTES - TARGET_MARGIN;
    // Inner ciphertext serializes as JSON u8 numbers: uniform bytes average
    // 914/256 characters including commas, followed by outer base64's 4/3.
    // This estimates *fixture size only*, never acceptance or crypto behavior.
    let mut notes_len = usize::try_from(target * 768 / 3656)
        .map_err(|_| AppError::Input("synthetic fixture size overflow".into()))?;
    for _ in 0..8 {
        // Discard the previous encrypted record before constructing another.
        // Each attempt has fresh entry and body nonces; the KDF is not repeated.
        candidate.body.entries.clear();
        let entry = encrypted_notes(&candidate, id, notes_len)?;
        candidate.body.entries.push(entry);
        let bytes = Zeroizing::new(encode_file(
            &candidate.header,
            &candidate.body,
            &candidate.keys,
        )?);
        let actual = bytes.len() as u64;
        if actual.abs_diff(target) <= TARGET_TOLERANCE {
            let len = bytes.len();
            return persist_fixture(path, candidate, bytes).map(|session| (session, len));
        }
        let adjustment = usize::try_from(actual.abs_diff(target) * 768 / 3656)
            .map_err(|_| AppError::Input("synthetic fixture size overflow".into()))?
            .max(1);
        notes_len = if actual > target {
            notes_len.checked_sub(adjustment)
        } else {
            notes_len.checked_add(adjustment)
        }
        .ok_or_else(|| AppError::Input("synthetic fixture size overflow".into()))?;
        // bytes drops/zeroizes here; no encoded-candidate backlog is retained.
    }
    Err(AppError::Input(
        "synthetic near-limit size did not converge".into(),
    ))
}

pub(crate) fn write_overlimit_copy(source: &Path, destination: &Path) -> Result<usize> {
    let mut bytes = Zeroizing::new(bounded::read(source, MAX_VAULT_BYTES)?);
    let length = usize::try_from(MAX_VAULT_BYTES + 1)
        .map_err(|_| AppError::Input("synthetic fixture size overflow".into()))?;
    let additional = length - bytes.len();
    bytes
        .try_reserve_exact(additional)
        .map_err(|_| AppError::Input("synthetic fixture allocation failed".into()))?;
    // Trailing JSON whitespace preserves the otherwise valid encrypted v1 file.
    // Its physical length alone exceeds the *unchanged* public reader limit.
    bytes.resize(length, b' ');
    parents(destination)?;
    bounded::write_new(destination, &bytes)?;
    Ok(length)
}

/// Hold the real cooperative save lock for a synthetic vault. Resolve the
/// private namespace here rather than recreating its sidecar naming in App tests.
#[cfg(test)]
pub(crate) fn hold_synthetic_save_lock(
    destination: &Path,
) -> Result<crate::platform::file_transaction::Lock> {
    let path = recovery::Namespace::new(destination)?.lock();
    crate::platform::file_transaction::Lock::acquire(&path)
        .map_err(|error| AppError::io(&path, error))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ordinary_kdf() -> KdfConfig {
        KdfConfig {
            memory_kib: 8192,
            iterations: 1,
            parallelism: 1,
        }
    }

    #[test]
    fn configured_fixture_reopens_with_canonical_header_and_aad() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("synthetic.pmvault");
        let config = ordinary_kdf();
        let session = create_synthetic_vault(&path, "synthetic-only", config).unwrap();
        assert_eq!(session.header.kdf_params.memory_kib, config.memory_kib);
        assert_eq!(session.header.kdf_params.iterations, config.iterations);
        let reopened = VaultSession::open(&path, "synthetic-only").unwrap();
        assert_eq!(reopened.vault_id(), session.vault_id());
        assert_eq!(reopened.body(), session.body());
        assert_eq!(HIGH_MEMORY_KDF.validate().unwrap().memory_kib, 1_048_576);
    }

    #[test]
    fn configured_fixture_does_not_clobber_an_existing_destination() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("synthetic.pmvault");
        fs::write(&path, b"synthetic existing file").unwrap();
        assert!(matches!(
            create_synthetic_vault(&path, "synthetic-only", ordinary_kdf()),
            Err(AppError::AlreadyExists)
        ));
        assert_eq!(fs::read(path).unwrap(), b"synthetic existing file");
    }

    #[test]
    #[ignore = "large synthetic final performance fixture; run serialized in release mode"]
    fn near_limit_fixture_uses_encrypted_notes_and_overlimit_copy_rejects() {
        let directory = tempfile::tempdir().unwrap();
        let source = directory.path().join("near-limit.pmvault");
        let (session, length) =
            build_near_limit_vault(&source, "synthetic-only", ordinary_kdf()).unwrap();
        let margin = MAX_VAULT_BYTES - length as u64;
        assert!((40 * 1024..=56 * 1024).contains(&margin));
        assert_eq!(fs::metadata(&source).unwrap().len(), length as u64);
        assert_eq!(session.entries().len(), 1);
        assert!(session.entries()[0].name.len() < 64);
        assert!(
            session
                .categories()
                .iter()
                .all(|category| category.len() < 64)
        );
        assert!(
            session
                .reveal_secret(session.entries()[0].id)
                .unwrap()
                .notes
                .len()
                > 1_000_000
        );
        session.verify_current_file().unwrap();
        let oversized = directory.path().join("over-limit.pmvault");
        assert_eq!(
            write_overlimit_copy(&source, &oversized).unwrap() as u64,
            MAX_VAULT_BYTES + 1
        );
        assert!(matches!(
            VaultSession::open(&oversized, "synthetic-only"),
            Err(AppError::InvalidVault("file exceeds size limit"))
        ));
    }
}
