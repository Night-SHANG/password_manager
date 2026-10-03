//! One process-local lane for expensive vault work. No secret data is metadata.
use std::time::Instant;
use uuid::Uuid;

pub(crate) mod authority;

macro_rules! identity {
    ($name:ident) => {
        #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
        pub(crate) struct $name(Uuid);
        impl $name {
            pub(crate) fn fresh() -> Self {
                Self(Uuid::new_v4())
            }
        }
    };
}
identity!(OperationId);
identity!(SecurityEpoch);
identity!(FormGeneration);
identity!(DisplayGeneration);

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) struct SessionBinding {
    pub instance: Uuid,
    pub import_epoch: Uuid,
    pub vault_id: Uuid,
    pub revision: u64,
    pub source_hash: [u8; 32],
    pub source_identity: crate::platform::file_transaction::Identity,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) struct ContextStamp {
    pub epoch: SecurityEpoch,
    pub form: FormGeneration,
    pub display: DisplayGeneration,
    pub session: Option<SessionBinding>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct PreparedBinding {
    pub prepared_id: Uuid,
    pub operation: OperationId,
    pub session: Option<SessionBinding>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum OperationKind {
    InspectRecovery,
    Open,
    Create,
    VerifyCurrent,
    MutateAndSave,
    AnalyzeImport,
    ApplyImport,
    Backup,
    RestoreCurrent,
    RestoreNew,
    ExportCsv,
    Dispose,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Phase {
    Preparing,
    Ready,
    Committing,
    Finished,
    Draining,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum WorkPhase {
    Reading,
    ReadingEntries,
    Deriving,
    Analyzing,
    PreparingSave,
    Publishing,
    Cleaning,
}
#[derive(Debug, Clone, Copy)]
pub(crate) struct Progress {
    pub phase: WorkPhase,
    pub completed: usize,
    pub total: Option<usize>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum RevokeReason {
    Manual,
    Idle,
    #[cfg(any(windows, test))]
    Native,
    MonitorFailed,
    Close,
    WorkerFailed,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum TerminalSummary {
    Read,
    Cancelled,
    Verified,
    Rejected,
    Recovery,
    CsvRisk,
    WorkerFailed,
}

#[derive(Debug, Clone, Copy)]
pub(crate) struct LiveSession {
    pub binding: SessionBinding,
    pub deadline: Instant,
}

#[cfg(test)]
mod tests;

pub(crate) mod jobs;
pub(crate) mod runner;
use zeroize::Zeroizing;

pub(crate) type WorkResult<T> = std::result::Result<T, WorkError>;
pub(crate) enum WorkError {
    Cancelled,
    Failure(crate::AppError),
}
impl From<crate::AppError> for WorkError {
    fn from(error: crate::AppError) -> Self {
        Self::Failure(error)
    }
}

pub(crate) struct WorkControl {
    pub(crate) authority: std::sync::Arc<authority::Coordinator>,
    pub(crate) id: OperationId,
    pub(crate) worker: Option<std::sync::Weak<runner::Shared>>,
}
impl WorkControl {
    pub(crate) fn progress(&self, phase: WorkPhase, completed: usize, total: Option<usize>) {
        self.authority.record_progress(
            self.id,
            Progress {
                phase,
                completed,
                total,
            },
            Instant::now(),
        );
    }
    pub(crate) fn checkpoint(&self) -> WorkResult<()> {
        if let Some(worker) = self.worker.as_ref().and_then(|weak| weak.upgrade()) {
            worker.fail_closed_if_poisoned();
        }
        self.authority
            .checkpoint(self.id, Instant::now())
            .map_err(|_| WorkError::Cancelled)
    }
}

pub(crate) enum OperationInput {
    InspectRecovery {
        path: std::path::PathBuf,
    },
    Open {
        path: std::path::PathBuf,
        password: Zeroizing<String>,
    },
    Create {
        path: std::path::PathBuf,
        password: Zeroizing<String>,
        confirmation: Zeroizing<String>,
    },
    VerifyCurrent {
        session: crate::storage::VaultSession,
    },
    MutateAndSave {
        session: crate::storage::VaultSession,
        mutation: VaultMutation,
    },
    AnalyzeImport {
        session: crate::storage::VaultSession,
        path: std::path::PathBuf,
        password: Zeroizing<String>,
        old_preview: Option<crate::import::plan::ImportPreview>,
    },
    ApplyImport {
        session: crate::storage::VaultSession,
        preview: crate::import::plan::ImportPreview,
        options: crate::import::plan::ImportApplyOptions,
    },
    Backup {
        session: crate::storage::VaultSession,
        destination: std::path::PathBuf,
    },
    RestoreCurrent {
        session: crate::storage::VaultSession,
        source: std::path::PathBuf,
        password: Zeroizing<String>,
    },
    RestoreNew {
        source: std::path::PathBuf,
        destination: std::path::PathBuf,
        password: Zeroizing<String>,
    },
    ExportCsv {
        session: crate::storage::VaultSession,
        destination: std::path::PathBuf,
        acknowledgement: crate::export::PlaintextExportAcknowledgement,
    },
    Dispose,
    #[cfg(test)]
    Test(Box<dyn FnOnce(&WorkControl) -> OperationPayload + Send>),
}

pub(crate) struct OperationPayload {
    pub session: Option<crate::storage::VaultSession>,
    pub preview: Option<crate::import::plan::ImportPreview>,
    pub value: OperationValue,
    pub ui_index: Option<crate::app::view_index::ViewIndex>,
    #[cfg(test)]
    pub test_owner: Option<Box<dyn Send>>,
}
impl OperationPayload {
    pub(crate) fn empty() -> Self {
        Self {
            session: None,
            preview: None,
            value: OperationValue::None,
            ui_index: None,
            #[cfg(test)]
            test_owner: None,
        }
    }
}

/// Fixed shape: detached UI owners are disposed on the same lane, not queued as
/// additional jobs. Iced Content stays UI-local and is never in this bundle.
#[derive(Default)]
pub(crate) struct RetiredUi {
    pub session: Option<crate::storage::VaultSession>,
    pub preview: Option<crate::import::plan::ImportPreview>,
    pub passwords: [Option<Zeroizing<String>>; 4],
    pub editor_secrets: Option<(Zeroizing<String>, Zeroizing<String>)>,
    pub ui_index: Option<crate::app::view_index::ViewIndex>,
    pub filtered_entries: Option<Vec<usize>>,
    pub recovery_password: Option<Zeroizing<String>>,
    pub cut_secrets: Option<(Zeroizing<String>, Zeroizing<String>)>,
    #[cfg(test)]
    pub test_owner: Option<Box<dyn Send>>,
}

pub(crate) struct PanicContext {
    pub csv_target: Option<std::path::PathBuf>,
    pub encrypted_target: Option<std::path::PathBuf>,
}
impl OperationInput {
    pub(crate) fn panic_context(&self) -> PanicContext {
        let csv_target = match self {
            Self::ExportCsv { destination, .. } => Some(destination.clone()),
            _ => None,
        };
        let encrypted_target = match self {
            Self::Create { path, .. } => Some(path.clone()),
            Self::MutateAndSave { session, .. }
            | Self::ApplyImport { session, .. }
            | Self::RestoreCurrent { session, .. } => Some(session.path().to_path_buf()),
            Self::Backup { destination, .. } | Self::RestoreNew { destination, .. } => {
                Some(destination.clone())
            }
            _ => None,
        };
        PanicContext {
            csv_target,
            encrypted_target,
        }
    }
}

pub(crate) enum TerminalOutcome {
    ReadFinished,
    CsvFinished {
        count: usize,
    },
    VerifiedCommit {
        maintenance: Option<String>,
    },
    Rejected(crate::AppError),
    CancelledBeforeClaim,
    WorkerFailed {
        claimed: bool,
        context: PanicContext,
        snapshot_cleanup: Option<crate::import::ImportCleanupFailure>,
    },
}
impl TerminalOutcome {
    pub(crate) fn summary(&self) -> TerminalSummary {
        match self {
            Self::ReadFinished => TerminalSummary::Read,
            Self::CsvFinished { .. } => TerminalSummary::Verified,
            Self::VerifiedCommit { .. } => TerminalSummary::Verified,
            Self::Rejected(error) => {
                if matches!(error,crate::AppError::Export(failure) if matches!(failure.output,crate::export::OutputDisposition::MayRemain{..}))
                {
                    TerminalSummary::CsvRisk
                } else if error.invalidates_session()
                    || matches!(error, crate::AppError::ImportCleanup(_))
                {
                    TerminalSummary::Recovery
                } else {
                    TerminalSummary::Rejected
                }
            }
            Self::CancelledBeforeClaim => TerminalSummary::Cancelled,
            Self::WorkerFailed { .. } => TerminalSummary::WorkerFailed,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum OperationSignal {
    PhaseChanged(OperationId),
    Finished(OperationId),
    Drained(OperationId),
}

pub(crate) enum OperationValue {
    None,
    Entry(Uuid),
    Mutation(MutationEffect),
    ImportReport(crate::import::plan::ImportApplyReport),
    ImportRetry(crate::import::plan::ImportApplyOptions),
    ExportCount(usize),
    Recovery(crate::storage::recovery::RecoveryListing),
    OutputPath(std::path::PathBuf),
}
pub(crate) enum VaultMutation {
    Upsert {
        id: Option<Uuid>,
        draft: Box<crate::domain::EntryDraft>,
    },
    Favorite(Uuid, bool),
    Recycle(Uuid),
    RestoreEntry(Uuid),
    DeleteEntry(Uuid),
    AddCategory(String),
    MoveCategory(String, bool),
    DeleteCategory(String),
}

#[derive(Clone, Copy)]
pub(crate) enum MutationEffect {
    Favorite,
    Recycle,
    Restore,
    DeleteEntry,
    AddCategory,
    MoveCategory,
    DeleteCategory,
}

impl OperationInput {
    fn kind(&self) -> Option<OperationKind> {
        Some(match self {
            Self::InspectRecovery { .. } => OperationKind::InspectRecovery,
            Self::Open { .. } => OperationKind::Open,
            Self::Create { .. } => OperationKind::Create,
            Self::VerifyCurrent { .. } => OperationKind::VerifyCurrent,
            Self::MutateAndSave { .. } => OperationKind::MutateAndSave,
            Self::AnalyzeImport { .. } => OperationKind::AnalyzeImport,
            Self::ApplyImport { .. } => OperationKind::ApplyImport,
            Self::Backup { .. } => OperationKind::Backup,
            Self::RestoreCurrent { .. } => OperationKind::RestoreCurrent,
            Self::RestoreNew { .. } => OperationKind::RestoreNew,
            Self::ExportCsv { .. } => OperationKind::ExportCsv,
            Self::Dispose => OperationKind::Dispose,
            #[cfg(test)]
            Self::Test(_) => return None,
        })
    }
    fn session_binding(&self) -> Option<SessionBinding> {
        match self {
            Self::VerifyCurrent { session }
            | Self::MutateAndSave { session, .. }
            | Self::AnalyzeImport { session, .. }
            | Self::ApplyImport { session, .. }
            | Self::Backup { session, .. }
            | Self::RestoreCurrent { session, .. }
            | Self::ExportCsv { session, .. } => Some(session.operation_binding()),
            _ => None,
        }
    }
}

impl RetiredUi {
    pub(crate) fn is_empty(&self) -> bool {
        #[cfg(test)]
        if self.test_owner.is_some() {
            return false;
        }
        self.session.is_none()
            && self.preview.is_none()
            && self.ui_index.is_none()
            && self.filtered_entries.is_none()
            && self
                .passwords
                .iter()
                .all(|p| p.as_ref().is_none_or(|s| s.capacity() == 0))
            && self
                .editor_secrets
                .as_ref()
                .is_none_or(|(a, b)| a.capacity() == 0 && b.capacity() == 0)
            && self
                .cut_secrets
                .as_ref()
                .is_none_or(|(a, b)| a.capacity() == 0 && b.capacity() == 0)
            && self
                .recovery_password
                .as_ref()
                .is_none_or(|p| p.capacity() == 0)
    }
}
