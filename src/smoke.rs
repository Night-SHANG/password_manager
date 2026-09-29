use std::fs;

use crate::domain::EntryDraft;
use crate::services::{PasswordGeneratorOptions, generate_password};
use crate::storage::VaultSession;
use crate::{AppError, Result};

pub fn run_release_smoke() -> Result<()> {
    let temp = tempfile::tempdir().map_err(|error| {
        AppError::io(std::env::temp_dir().join("password-manager-smoke"), error)
    })?;

    let vault_path = temp.path().join("smoke.pmvault");
    let backup_path = temp.path().join("smoke-backup.pmvault");
    let restored_path = temp.path().join("smoke-restored.pmvault");

    let master_password = generate_password(PasswordGeneratorOptions {
        length: 32,
        ..PasswordGeneratorOptions::default()
    })?;
    let entry_password = generate_password(PasswordGeneratorOptions {
        length: 32,
        ..PasswordGeneratorOptions::default()
    })?;

    let mut vault = VaultSession::create(&vault_path, &master_password)?;
    let entry_id = vault.add_entry(EntryDraft::login(
        "Release smoke",
        "https://example.test",
        "smoke-user",
        &entry_password,
    ))?;
    vault.save()?;
    vault.verify_current_file()?;

    let reopened = VaultSession::open(&vault_path, &master_password)?;
    let secret = reopened.reveal_secret(entry_id)?;
    if secret.password != entry_password {
        return Err(AppError::Input(
            "release smoke secret roundtrip mismatch".to_string(),
        ));
    }

    reopened.export_encrypted_backup(&backup_path)?;
    VaultSession::restore_encrypted_backup(&backup_path, &restored_path, &master_password, false)?;

    let restored = VaultSession::open(&restored_path, &master_password)?;
    if restored.vault_id() != reopened.vault_id() || restored.revision() != reopened.revision() {
        return Err(AppError::Input(
            "release smoke backup identity mismatch".to_string(),
        ));
    }

    let restored_secret = restored.reveal_secret(entry_id)?;
    if restored_secret.password != entry_password {
        return Err(AppError::Input(
            "release smoke restored secret mismatch".to_string(),
        ));
    }

    drop(restored_secret);
    drop(restored);
    drop(secret);
    drop(reopened);
    drop(vault);

    for path in [&vault_path, &backup_path, &restored_path] {
        if path.exists() {
            fs::remove_file(path).map_err(|error| AppError::io(path.to_path_buf(), error))?;
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::run_release_smoke;

    #[test]
    fn release_smoke_roundtrips_vault_and_backup() {
        run_release_smoke().unwrap();
    }
}
