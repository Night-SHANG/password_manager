use std::path::PathBuf;

#[derive(Debug, thiserror::Error)]
pub enum AppError {
    #[error("I/O error at {path}: {source}")]
    Io {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },

    #[error("vault JSON is invalid: {0}")]
    Json(#[from] serde_json::Error),

    #[error("CSV is invalid: {0}")]
    Csv(#[from] csv::Error),

    #[error("base64 data is invalid: {0}")]
    Base64(#[from] base64::DecodeError),

    #[error("cryptographic operation failed: {0}")]
    Crypto(&'static str),

    #[error("unsupported vault format version: {0}")]
    UnsupportedVersion(u32),

    #[error("unsupported body schema version: {0}")]
    UnsupportedSchema(u32),

    #[error("vault is invalid: {0}")]
    InvalidVault(&'static str),

    #[error("KDF parameters are outside the accepted safety bounds")]
    InvalidKdf,

    #[error(transparent)]
    Persist(Box<crate::storage::transaction::PersistFailure>),

    #[error(transparent)]
    Export(Box<crate::export::ExportFailure>),

    #[error("the vault changed on disk after it was opened")]
    ExternalChange,

    #[error("target vault already exists")]
    AlreadyExists,

    #[error(transparent)]
    ImportCleanup(Box<crate::import::ImportCleanupFailure>),

    #[error("migration failed: {0}")]
    Migration(String),

    #[error("input error: {0}")]
    Input(String),

    #[error("platform operation failed: {0}")]
    Platform(String),
}

impl AppError {
    pub fn invalidates_session(&self) -> bool {
        matches!(self, Self::ExternalChange)
            || matches!(self, Self::Persist(failure) if failure.invalidates_session())
    }

    pub fn io(path: impl Into<PathBuf>, source: std::io::Error) -> Self {
        Self::Io {
            path: path.into(),
            source,
        }
    }

    pub fn migration(error: impl std::fmt::Display) -> Self {
        Self::Migration(error.to_string())
    }
}

pub type Result<T> = std::result::Result<T, AppError>;
