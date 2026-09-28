pub mod csv;

use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, ZeroizeOnDrop};

#[derive(Debug, Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
pub struct NormalizedImportItem {
    pub provider: String,
    pub source_stable_id: Option<String>,
    pub name: String,
    pub website: String,
    pub username: String,
    pub password: String,
    pub notes: String,
    pub category: String,
    pub fingerprint: [u8; 32],
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ImportClass {
    New,
    ExactDuplicate,
    UpdateCandidate { existing_id: uuid::Uuid },
    Conflict { existing_id: uuid::Uuid },
    Invalid,
}

#[derive(Debug, Default)]
pub struct ImportParseResult {
    pub items: Vec<NormalizedImportItem>,
    pub invalid_rows: usize,
}
