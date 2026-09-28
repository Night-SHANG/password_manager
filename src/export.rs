use std::fs::{self, File, OpenOptions};
use std::path::Path;

use crate::storage::VaultSession;
use crate::{AppError, Result};

#[derive(Debug, Clone, Copy)]
pub struct PlaintextExportAcknowledgement(());

impl PlaintextExportAcknowledgement {
    pub fn user_confirmed_risk() -> Self {
        Self(())
    }
}

pub fn export_plaintext_csv(
    vault: &VaultSession,
    destination: &Path,
    _acknowledgement: PlaintextExportAcknowledgement,
) -> Result<usize> {
    if destination.exists() {
        return Err(AppError::AlreadyExists);
    }

    if let Some(parent) = destination.parent()
        && !parent.as_os_str().is_empty()
    {
        fs::create_dir_all(parent)
            .map_err(|error| AppError::io(parent.to_path_buf(), error))?;
    }

    let file = OpenOptions::new()
        .create_new(true)
        .write(true)
        .open(destination)
        .map_err(|error| AppError::io(destination.to_path_buf(), error))?;

    let result = write_csv(vault, destination, file);
    if result.is_err() {
        let _ = fs::remove_file(destination);
    }
    result
}

fn write_csv(vault: &VaultSession, destination: &Path, file: File) -> Result<usize> {
    let mut writer = csv::WriterBuilder::new()
        .has_headers(true)
        .from_writer(file);

    writer.write_record(["name", "url", "username", "password", "category", "notes"])?;

    let mut count = 0;
    for entry in vault.active_entries() {
        let secret = vault.reveal_secret(entry.id)?;
        writer.write_record([
            entry.name.as_str(),
            entry.website.as_str(),
            entry.username.as_str(),
            secret.password.as_str(),
            entry.category.as_str(),
            secret.notes.as_str(),
        ])?;
        count += 1;
    }

    writer
        .flush()
        .map_err(|error| AppError::io(destination.to_path_buf(), error))?;
    writer
        .get_ref()
        .sync_all()
        .map_err(|error| AppError::io(destination.to_path_buf(), error))?;

    Ok(count)
}
