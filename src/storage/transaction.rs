//! One synchronous transaction for all existing-vault publication. No rollback.
//! Source checks are observations, not CAS against noncooperating writers.
use super::recovery::{
    CurrentObservation, FileRecord, Namespace, Record, RecoveryArtifact, RecoveryInfo,
};
use super::{MAX_VAULT_BYTES, bounded};
use crate::platform::file_transaction::{self as native, Identity};
use crate::{AppError, Result, security};
use std::fs;
use std::path::{Path, PathBuf};
use uuid::Uuid;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Disposition {
    Busy,
    Unchanged,
    ExternalConflict,
    RecoveryRequired,
    MaintenanceRequired,
}
impl std::fmt::Display for Disposition {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::Busy => "其他保存正在进行，请稍后重试",
            Self::Unchanged => "本次未发布新文件，请检查提示后重试",
            Self::ExternalConflict => "磁盘文件已变化，请重新打开或恢复副本到新位置",
            Self::RecoveryRequired => {
                "存储状态未确认，需恢复（recovery required）；请保留目录并恢复选定副本到新位置"
            }
            Self::MaintenanceRequired => "备份维护未完成；请保留目录并恢复选定副本到新位置",
        })
    }
}
#[derive(Debug, Clone, thiserror::Error)]
#[error("{disposition}（阶段 {stage}）：{primary}")]
pub struct PersistFailure {
    pub disposition: Disposition,
    pub stage: String,
    pub primary: String,
    pub secondary: Vec<String>,
    pub recovery: RecoveryInfo,
}
impl PersistFailure {
    pub fn invalidates_session(&self) -> bool {
        matches!(
            self.disposition,
            Disposition::ExternalConflict
                | Disposition::RecoveryRequired
                | Disposition::MaintenanceRequired
        )
    }
}
pub(super) struct SourceExpectation<'a> {
    pub target: &'a Path,
    pub hash: [u8; 32],
    pub identity: Identity,
}
pub(super) struct CommitReceipt {
    pub hash: [u8; 32],
    pub identity: Identity,
    pub warning: Option<String>,
}

/// Cleanup only known exclusively created, still-matching prepublication objects.
/// Once `retain` is set, Drop is inert even if the OS reports failure.
struct Staging {
    path: PathBuf,
    identity: Identity,
    files: Vec<(&'static str, FileRecord)>,
    retain: bool,
}
impl Staging {
    fn new(ns: &Namespace, id: Uuid) -> Result<Self> {
        let path = ns.directory(id);
        let mut builder = fs::DirBuilder::new();
        #[cfg(unix)]
        {
            use std::os::unix::fs::DirBuilderExt;
            builder.mode(0o700);
        }
        builder.create(&path).map_err(|e| AppError::io(&path, e))?;
        let directory = native::open_directory(&path).map_err(|e| AppError::io(&path, e))?;
        let identity = native::identity(&directory, false).map_err(|e| AppError::io(&path, e))?;
        Ok(Self {
            path,
            identity,
            files: Vec::new(),
            retain: false,
        })
    }
    fn write(&mut self, name: &'static str, bytes: &[u8]) -> Result<FileRecord> {
        let path = self.path.join(name);
        bounded::write_new(&path, bytes)?;
        let record = FileRecord::capture(&path)?;
        self.files.push((name, record.clone()));
        Ok(record)
    }
}
impl Drop for Staging {
    fn drop(&mut self) {
        if self.retain {
            return;
        }
        let safe = (|| -> Result<()> {
            let directory =
                native::open_directory(&self.path).map_err(|e| AppError::io(&self.path, e))?;
            if native::identity(&directory, false).map_err(|e| AppError::io(&self.path, e))?
                != self.identity
            {
                return Err(AppError::InvalidVault("staging directory changed"));
            }
            let children = fs::read_dir(&self.path).map_err(|e| AppError::io(&self.path, e))?;
            let mut count = 0;
            for child in children {
                count += 1;
                if count > self.files.len() {
                    return Err(AppError::InvalidVault("unexpected staging child"));
                }
                let child = child.map_err(|e| AppError::io(&self.path, e))?;
                let Some((_, expected)) = self
                    .files
                    .iter()
                    .find(|(name, _)| child.file_name() == *name)
                else {
                    return Err(AppError::InvalidVault("unexpected staging child"));
                };
                expected.matches(&child.path())?;
            }
            Ok(())
        })();
        if safe.is_ok() {
            for (name, _) in &self.files {
                if fs::remove_file(self.path.join(name)).is_err() {
                    return;
                }
            }
            let _ = fs::remove_dir(&self.path);
        }
    }
}
fn observation(
    target: &Path,
    old: [u8; 32],
    candidate: [u8; 32],
) -> (CurrentObservation, Vec<String>) {
    match bounded::read(target, MAX_VAULT_BYTES) {
        Ok(bytes) if security::sha256(&bytes) == old => {
            (CurrentObservation::ExpectedOld, Vec::new())
        }
        Ok(bytes) if security::sha256(&bytes) == candidate => {
            (CurrentObservation::ExpectedCandidate, Vec::new())
        }
        Ok(_) => (CurrentObservation::Other, Vec::new()),
        Err(error) => {
            let current = if matches!(&error,AppError::Io {source,..} if source.kind() == std::io::ErrorKind::NotFound)
            {
                CurrentObservation::Missing
            } else {
                CurrentObservation::Unreadable
            };
            (
                current,
                vec![format!("current-file observation failed: {error}")],
            )
        }
    }
}

fn failure(
    expectation: &SourceExpectation<'_>,
    candidate: [u8; 32],
    disposition: Disposition,
    stage: &str,
    error: impl std::fmt::Display,
    directory: Option<&Path>,
) -> AppError {
    let mut artifacts = Vec::new();
    if let Some(directory) = directory {
        for (name, role) in [
            ("previous.pmvault", "independent preimage"),
            ("candidate.pmvault", "intended candidate"),
            ("publish.pmvault", "publication slot"),
            ("displaced.pmvault", "actual displaced file"),
        ] {
            artifacts.push(RecoveryArtifact {
                role: role.into(),
                path: directory.join(name),
            });
        }
    }
    let (current, secondary) = observation(expectation.target, expectation.hash, candidate);
    AppError::Persist(Box::new(PersistFailure {
        disposition,
        stage: stage.into(),
        primary: error.to_string(),
        secondary,
        recovery: RecoveryInfo {
            destination: expectation.target.to_path_buf(),
            stage: stage.into(),
            current,
            artifacts,
            detail: "请保留整个目录，验证选定加密副本后恢复到新文件。未执行自动回滚。".into(),
        },
    }))
}

pub(super) fn current_source_failure(
    expectation: SourceExpectation<'_>,
    error: AppError,
) -> AppError {
    failure(
        &expectation,
        expectation.hash,
        Disposition::ExternalConflict,
        "current source verification",
        error,
        None,
    )
}
pub(super) fn maintenance_failure(expectation: SourceExpectation<'_>, warning: &str) -> AppError {
    failure(
        &expectation,
        expectation.hash,
        Disposition::MaintenanceRequired,
        "previous maintenance warning",
        warning,
        None,
    )
}

pub(super) fn unchanged_after_failure(
    error: &native::PublishError,
    record: &Record,
    target: &Path,
    directory: &Path,
    windows_backup: bool,
) -> bool {
    error.documented_no_progress
        && record.old.matches(target).is_ok()
        && record
            .publish
            .matches(&directory.join("publish.pmvault"))
            .is_ok()
        && (!windows_backup
            || !directory
                .join("displaced.pmvault")
                .try_exists()
                .unwrap_or(true))
}

pub(super) fn commit(
    expectation: SourceExpectation<'_>,
    candidate: &[u8],
    verify_old: impl Fn(&[u8]) -> Result<()>,
    verify_new: impl Fn(&[u8]) -> Result<()>,
) -> Result<CommitReceipt> {
    if candidate.len() as u64 > MAX_VAULT_BYTES {
        return Err(failure(
            &expectation,
            expectation.hash,
            Disposition::Unchanged,
            "candidate size",
            AppError::InvalidVault("candidate exceeds size limit"),
            None,
        ));
    }
    let hash = security::sha256(candidate);
    let ns = Namespace::new(expectation.target).map_err(|e| {
        failure(
            &expectation,
            hash,
            Disposition::ExternalConflict,
            "destination",
            e,
            None,
        )
    })?;
    let _lock = native::Lock::acquire(&ns.lock()).map_err(|e| {
        let kind = if e.kind() == std::io::ErrorKind::WouldBlock {
            Disposition::Busy
        } else {
            Disposition::Unchanged
        };
        failure(&expectation, hash, kind, "cooperative lock", e, None)
    })?;
    let parent = native::open_directory(&ns.parent).map_err(|e| {
        failure(
            &expectation,
            hash,
            Disposition::ExternalConflict,
            "parent",
            e,
            None,
        )
    })?;
    native::supported_parent(&parent, &ns.parent).map_err(|e| {
        failure(
            &expectation,
            hash,
            Disposition::ExternalConflict,
            "filesystem capability",
            e,
            None,
        )
    })?;
    let previous = ns.ready().map_err(|e| {
        failure(
            &expectation,
            hash,
            Disposition::MaintenanceRequired,
            "backup maintenance",
            e,
            None,
        )
    })?;
    let (old, identity) = bounded::read_identified(&ns.target, MAX_VAULT_BYTES).map_err(|e| {
        failure(
            &expectation,
            hash,
            Disposition::ExternalConflict,
            "source read",
            e,
            None,
        )
    })?;
    if identity != expectation.identity || security::sha256(&old) != expectation.hash {
        return Err(failure(
            &expectation,
            hash,
            Disposition::ExternalConflict,
            "source check",
            "source changed",
            None,
        ));
    }
    verify_old(&old).map_err(|e| {
        failure(
            &expectation,
            hash,
            Disposition::ExternalConflict,
            "source authentication",
            e,
            None,
        )
    })?;
    verify_new(candidate).map_err(|e| {
        failure(
            &expectation,
            hash,
            Disposition::Unchanged,
            "candidate authentication",
            e,
            None,
        )
    })?;
    let id = Uuid::new_v4();
    let mut staging = Staging::new(&ns, id).map_err(|e| {
        failure(
            &expectation,
            hash,
            Disposition::Unchanged,
            "staging",
            e,
            None,
        )
    })?;
    let staged = (|| -> Result<Record> {
        let previous = staging.write("previous.pmvault", &old)?;
        verify_old(&bounded::read(
            &staging.path.join("previous.pmvault"),
            MAX_VAULT_BYTES,
        )?)?;
        let candidate_record = staging.write("candidate.pmvault", candidate)?;
        let publish = staging.write("publish.pmvault", candidate)?;
        verify_new(&bounded::read(
            &staging.path.join("publish.pmvault"),
            MAX_VAULT_BYTES,
        )?)?;
        let record = Record {
            version: 1,
            transaction: id,
            destination_key: ns.key.clone(),
            directory_identity: staging.identity,
            old: FileRecord {
                hash: expectation.hash,
                size: old.len() as u64,
                identity,
            },
            previous,
            candidate: candidate_record,
            publish,
        };
        staging.write("receipt.json", &serde_json::to_vec(&record)?)?;
        Ok(record)
    })()
    .map_err(|e| {
        failure(
            &expectation,
            hash,
            Disposition::Unchanged,
            "staging verification",
            e,
            None,
        )
    })?;
    let transaction = native::open_directory(&staging.path).map_err(|e| {
        failure(
            &expectation,
            hash,
            Disposition::Unchanged,
            "staging directory",
            e,
            None,
        )
    })?;
    native::sync_directory(&transaction)
        .and_then(|()| native::sync_directory(&parent))
        .map_err(|e| {
            failure(
                &expectation,
                hash,
                Disposition::Unchanged,
                "staging sync",
                e,
                None,
            )
        })?;
    #[cfg(test)]
    super::tests::run_before_publish_hook();
    let final_check = FileRecord::capture(&ns.target).and_then(|record| {
        if record == staged.old {
            Ok(())
        } else {
            Err(AppError::ExternalChange)
        }
    });
    if let Err(e) = final_check {
        return Err(failure(
            &expectation,
            hash,
            Disposition::ExternalConflict,
            "final source check",
            e,
            None,
        ));
    }
    #[cfg(test)]
    test_hook(Point::BeforePublish).map_err(|e| {
        failure(
            &expectation,
            hash,
            Disposition::Unchanged,
            "before publish",
            e,
            None,
        )
    })?;
    // The one-way RAII boundary MUST precede the first publication attempt.
    staging.retain = true;
    let publication = native::publish(&ns.target, &parent, &staging.path, &transaction);
    if let Err(error) = publication {
        let unchanged =
            unchanged_after_failure(&error, &staged, &ns.target, &staging.path, cfg!(windows));
        return Err(failure(
            &expectation,
            hash,
            if unchanged {
                Disposition::Unchanged
            } else {
                Disposition::RecoveryRequired
            },
            "publication",
            error.message,
            Some(&staging.path),
        ));
    }
    #[cfg(test)]
    super::tests::run_after_publish_hook();
    #[cfg(test)]
    test_hook(Point::AfterPublish).map_err(|e| {
        failure(
            &expectation,
            hash,
            Disposition::RecoveryRequired,
            "after publication",
            e,
            Some(&staging.path),
        )
    })?;
    #[cfg(test)]
    test_hook(Point::BeforeVerify).map_err(|e| {
        failure(
            &expectation,
            hash,
            Disposition::RecoveryRequired,
            "before verification",
            e,
            Some(&staging.path),
        )
    })?;
    let verification = (|| -> Result<Identity> {
        let (displaced, displaced_id) = bounded::read_identified(
            &staging.path.join(native::displaced_name()),
            MAX_VAULT_BYTES,
        )?;
        if security::sha256(&displaced) != expectation.hash || displaced_id != expectation.identity
        {
            return Err(AppError::InvalidVault(
                "actual displaced file differs from expected source",
            ));
        }
        verify_old(&displaced)?;
        staged
            .previous
            .matches(&staging.path.join("previous.pmvault"))?;
        let (live, live_id) = bounded::read_identified(&ns.target, MAX_VAULT_BYTES)?;
        if live != candidate || live_id != staged.publish.identity {
            return Err(AppError::InvalidVault(
                "published file differs from intended candidate",
            ));
        }
        verify_new(&live)?;
        #[cfg(test)]
        test_hook(Point::Sync)?;
        // Flush supported file contents and (Linux) both changed directories.
        native::open_regular(&ns.target, true)
            .and_then(|file| file.sync_all())
            .map_err(|e| AppError::io(&ns.target, e))?;
        native::sync_directory(&transaction)
            .and_then(|()| native::sync_directory(&parent))
            .map_err(|e| AppError::io(&ns.parent, e))?;
        #[cfg(test)]
        test_hook(Point::AfterSync)?;
        // The verified checkpoint is after required synchronization. A writer
        // arriving during the flush must not be accepted as our live candidate.
        let (final_live, final_id) = bounded::read_identified(&ns.target, MAX_VAULT_BYTES)?;
        if final_live != candidate || final_id != live_id {
            return Err(AppError::InvalidVault(
                "live file changed during required synchronization",
            ));
        }
        verify_new(&final_live)?;
        Ok(final_id)
    })();
    let identity = verification.map_err(|e| {
        failure(
            &expectation,
            hash,
            Disposition::RecoveryRequired,
            "postpublication verification",
            e,
            Some(&staging.path),
        )
    })?;
    // Nothing after this checkpoint is allowed to report a failed save.
    let warning = ns.register(&staged, previous).err().map(|e| {
        format!("文件已验证保存；备份维护未完成：{e}。请保留目录，通过恢复副本到新位置继续使用。")
    });
    Ok(CommitReceipt {
        hash,
        identity,
        warning,
    })
}

#[cfg(test)]
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(crate) enum Point {
    BeforePublish,
    AfterPublish,
    BeforeVerify,
    Sync,
    AfterSync,
    BeforeRegister,
    AfterRegister,
    Cleanup,
    AfterRetire,
    CleanDescriptorSync,
    FinalDirectorySync,
    FinalParentSync,
    WitnessCreate,
    WitnessSync,
    WitnessRemove,
}
#[cfg(test)]
type TestHook = (Point, Box<dyn FnOnce() -> Result<()>>);
#[cfg(test)]
thread_local! { static HOOK: std::cell::RefCell<Option<TestHook>> = std::cell::RefCell::new(None); }
#[cfg(test)]
pub(crate) fn set_hook(point: Point, hook: impl FnOnce() -> Result<()> + 'static) {
    HOOK.with(|slot| *slot.borrow_mut() = Some((point, Box::new(hook))));
}
#[cfg(test)]
pub(crate) fn test_hook(point: Point) -> Result<()> {
    let hook = HOOK.with(|slot| {
        let mut slot = slot.borrow_mut();
        if slot.as_ref().is_some_and(|(p, _)| *p == point) {
            slot.take()
        } else {
            None
        }
    });
    if let Some((_, hook)) = hook {
        hook()?;
    }
    Ok(())
}
