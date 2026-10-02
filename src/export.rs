//! Direct-to-final plaintext CSV. Failure retains output; Drop never performs I/O.
use sha2::{Digest, Sha256};
use std::fs::File;
use std::io;
use std::path::{Path, PathBuf};

use crate::platform::file_transaction as files;
use crate::storage::VaultSession;
use crate::{AppError, Result};

mod encoder;
#[path = "export/io.rs"]
mod file_io;
use encoder::{Encoder, SecretBytes};
use file_io::{ExportIo, SystemIo};
#[cfg(test)]
pub(crate) mod tests;

#[derive(Debug, Clone, Copy)]
pub struct PlaintextExportAcknowledgement(());
impl PlaintextExportAcknowledgement {
    pub fn user_confirmed_risk() -> Self {
        Self(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Stage {
    Resolve,
    CreateParents,
    CreateOutput,
    IdentifyOutput,
    WriteHeader,
    RevealEntry,
    WriteRow,
    Flush,
    Sync,
    VerifyOutput,
    VerifyPath,
}

/// Deliberately excludes OS/debug/decoder strings which can contain user data.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Cause {
    Io {
        kind: io::ErrorKind,
        code: Option<i32>,
    },
    SecretUnavailable,
    IdentityChanged,
    LengthChanged,
    DigestChanged,
    LengthOverflow,
    InvalidBuffer,
}
impl From<io::Error> for Cause {
    fn from(error: io::Error) -> Self {
        Self::Io {
            kind: error.kind(),
            code: error.raw_os_error(),
        }
    }
}
impl std::fmt::Display for Cause {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Io { kind, code } => write!(f, "I/O {kind:?} (OS code {code:?})"),
            Self::SecretUnavailable => f.write_str("entry secret could not be decoded"),
            Self::IdentityChanged => f.write_str("output identity does not match"),
            Self::LengthChanged => f.write_str("output length does not match"),
            Self::DigestChanged => f.write_str("output content does not match"),
            Self::LengthOverflow => f.write_str("output length exceeds supported range"),
            Self::InvalidBuffer => f.write_str("serializer buffer is too small"),
        }
    }
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ObservedTarget {
    SameOwnedFileAtTarget,
    TargetMissing,
    TargetDifferent,
    Unobserved,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Observation {
    pub target: ObservedTarget,
    pub error: Option<Cause>,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OutputDisposition {
    NotCreated,
    MayRemain { observation: Observation },
}
#[derive(Debug, Clone, thiserror::Error)]
#[error("CSV export failed at {stage:?}: {cause}; target: {target}; disposition: {output:?}")]
pub struct ExportFailure {
    pub target: PathBuf,
    pub stage: Stage,
    pub cause: Cause,
    pub output: OutputDisposition,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct StepFailure {
    stage: Stage,
    cause: Cause,
}

pub fn export_plaintext_csv(
    vault: &VaultSession,
    destination: &Path,
    _acknowledgement: PlaintextExportAcknowledgement,
) -> Result<usize> {
    export_with(vault, destination, &SystemIo)
        .map_err(|failure| AppError::Export(Box::new(failure)))
}

fn export_with(
    vault: &VaultSession,
    destination: &Path,
    io: &impl ExportIo,
) -> std::result::Result<usize, ExportFailure> {
    let mut target = destination.to_path_buf();
    let pre_failure = |target: PathBuf, stage, cause| ExportFailure {
        target,
        stage,
        cause,
        output: OutputDisposition::NotCreated,
    };
    if !target.is_absolute() {
        target = std::env::current_dir()
            .map_err(|e| pre_failure(target.clone(), Stage::Resolve, Cause::from(e)))?
            .join(target);
    }
    if destination.as_os_str().is_empty() {
        return Err(pre_failure(
            target,
            Stage::Resolve,
            io::Error::new(io::ErrorKind::InvalidInput, "empty path").into(),
        ));
    }
    file_io::validate_destination(&target)
        .map_err(|e| pre_failure(target.clone(), Stage::Resolve, e.into()))?;
    io.parents(&target)
        .map_err(|e| pre_failure(target.clone(), Stage::CreateParents, e.into()))?;
    let file = io
        .create(&target)
        .map_err(|e| pre_failure(target.clone(), Stage::CreateOutput, e.into()))?;
    // Ownership/disposition is installed before the first fallible identification.
    let mut owner = OwnedCsvOutput {
        file,
        target,
        io,
        identity: None,
        length: 0,
        hash: Sha256::new(),
        failure: None,
    };
    #[cfg(test)]
    tests::run_after_create();
    match owner.write_vault(vault) {
        Ok(count) => Ok(count),
        Err(primary) => {
            let observation = owner.observe();
            Err(ExportFailure {
                target: owner.target.clone(),
                stage: primary.stage,
                cause: primary.cause,
                output: OutputDisposition::MayRemain { observation },
            })
        }
    }
}

struct OwnedCsvOutput<'a, I: ExportIo> {
    file: File,
    target: PathBuf,
    io: &'a I,
    identity: Option<files::Identity>,
    length: u64,
    hash: Sha256,
    failure: Option<StepFailure>,
}
impl<I: ExportIo> OwnedCsvOutput<'_, I> {
    fn live(&self) -> std::result::Result<(), StepFailure> {
        self.failure.map_or(Ok(()), Err)
    }
    fn fail(&mut self, stage: Stage, cause: Cause) -> StepFailure {
        *self.failure.get_or_insert(StepFailure { stage, cause })
    }
    fn checked<T>(
        &mut self,
        stage: Stage,
        result: io::Result<T>,
    ) -> std::result::Result<T, StepFailure> {
        result.map_err(|error| self.fail(stage, error.into()))
    }
    fn emit(&mut self, mut bytes: &[u8], stage: Stage) -> std::result::Result<(), StepFailure> {
        self.live()?;
        let new_length = self
            .length
            .checked_add(bytes.len() as u64)
            .ok_or_else(|| self.fail(stage, Cause::LengthOverflow))?;
        let emitted = bytes;
        while !bytes.is_empty() {
            match self.io.write(&mut self.file, bytes) {
                Ok(0) => {
                    return Err(self.fail(stage, io::Error::from(io::ErrorKind::WriteZero).into()));
                }
                Ok(count) => bytes = &bytes[count..],
                Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
                Err(error) => return Err(self.fail(stage, error.into())),
            }
        }
        self.hash.update(emitted);
        self.length = new_length;
        Ok(())
    }
    fn write_vault(&mut self, vault: &VaultSession) -> std::result::Result<usize, StepFailure> {
        self.live()?;
        self.identity = Some(self.checked(Stage::IdentifyOutput, self.io.identity(&self.file))?);
        let mut encoder = Encoder::<8192>::new()?;
        encoder.record(
            ["name", "url", "username", "password", "category", "notes"],
            |bytes| self.emit(bytes, Stage::WriteHeader),
        )?;
        let mut count = 0;
        for pair in vault.active_entries_with_secrets() {
            let (entry, secret) =
                pair.map_err(|_| self.fail(Stage::RevealEntry, Cause::SecretUnavailable))?;
            encoder.record(
                [
                    &entry.name,
                    &entry.website,
                    &entry.username,
                    &secret.password,
                    &entry.category,
                    &secret.notes,
                ],
                |bytes| self.emit(bytes, Stage::WriteRow),
            )?;
            count += 1;
        }
        encoder.finish(|bytes| self.emit(bytes, Stage::WriteRow))?;
        let result = self.io.flush(&mut self.file);
        self.checked(Stage::Flush, result)?;
        self.checked(Stage::Sync, self.io.sync(&self.file))?;
        self.verify()?;
        Ok(count)
    }
    fn identified(&mut self, stage: Stage) -> std::result::Result<File, StepFailure> {
        let file = self.checked(stage, self.io.open(&self.target))?;
        let identity = self.checked(stage, self.io.identity(&file))?;
        if Some(identity) != self.identity {
            return Err(self.fail(stage, Cause::IdentityChanged));
        }
        Ok(file)
    }
    fn check_length(&mut self, file: &File, stage: Stage) -> std::result::Result<(), StepFailure> {
        let length = self.checked(stage, self.io.length(file))?;
        if length != self.length {
            return Err(self.fail(stage, Cause::LengthChanged));
        }
        Ok(())
    }
    fn verify(&mut self) -> std::result::Result<(), StepFailure> {
        self.live()?;
        let mut file = self.identified(Stage::VerifyOutput)?;
        self.check_length(&file, Stage::VerifyOutput)?;
        let mut buffer = SecretBytes::<8192>::new();
        let mut actual_hash = Sha256::new();
        let mut remaining = self.length;
        // At most expected length + one byte, even if an external actor appends.
        loop {
            let limit = if remaining >= buffer.bytes.len() as u64 {
                buffer.bytes.len()
            } else {
                remaining as usize + 1
            };
            let read = match self.io.read(&mut file, &mut buffer.bytes[..limit]) {
                Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
                result => self.checked(Stage::VerifyOutput, result)?,
            };
            if read == 0 {
                if remaining != 0 {
                    return Err(self.fail(Stage::VerifyOutput, Cause::LengthChanged));
                }
                break;
            }
            if read as u64 > remaining {
                return Err(self.fail(Stage::VerifyOutput, Cause::LengthChanged));
            }
            actual_hash.update(&buffer.bytes[..read]);
            zeroize::Zeroize::zeroize(&mut buffer.bytes);
            remaining -= read as u64;
        }
        let mut expected = SecretBytes::<32>::new();
        let mut actual = SecretBytes::<32>::new();
        // Finalize directly into owned arrays; do not leave an ordinary digest copy.
        std::mem::take(&mut self.hash).finalize_into((&mut expected.bytes).into());
        actual_hash.finalize_into((&mut actual.bytes).into());
        if expected.bytes != actual.bytes {
            return Err(self.fail(Stage::VerifyOutput, Cause::DigestChanged));
        }
        let identity = self.checked(Stage::VerifyOutput, self.io.identity(&file))?;
        if Some(identity) != self.identity {
            return Err(self.fail(Stage::VerifyOutput, Cause::IdentityChanged));
        }
        self.check_length(&file, Stage::VerifyOutput)?;
        let checkpoint = self.identified(Stage::VerifyPath)?;
        self.check_length(&checkpoint, Stage::VerifyPath)
    }
    fn observe(&self) -> Observation {
        let result = self
            .io
            .open(&self.target)
            .and_then(|file| self.io.identity(&file));
        match result {
            Ok(id) => Observation {
                target: if self.identity == Some(id) {
                    ObservedTarget::SameOwnedFileAtTarget
                } else if self.identity.is_some() {
                    ObservedTarget::TargetDifferent
                } else {
                    ObservedTarget::Unobserved
                },
                error: None,
            },
            Err(error) => Observation {
                target: if error.kind() == io::ErrorKind::NotFound {
                    ObservedTarget::TargetMissing
                } else {
                    ObservedTarget::Unobserved
                },
                error: Some(error.into()),
            },
        }
    }
}
// No Drop implementation: File closes; sha2's zeroize feature wipes its state.
// No application-initiated flush, retry, pathname scan, rename, or deletion.
