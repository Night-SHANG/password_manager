use serde::{Deserialize, Serialize};
use uuid::Uuid;
use zeroize::{Zeroize, ZeroizeOnDrop};

pub const BODY_SCHEMA_VERSION: u32 = 1;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct VaultBody {
    pub schema_version: u32,
    pub entries: Vec<EntryRecord>,
    pub categories: Vec<String>,
}

impl Default for VaultBody {
    fn default() -> Self {
        Self {
            schema_version: BODY_SCHEMA_VERSION,
            entries: Vec::new(),
            categories: vec!["其他".to_string()],
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct EntryRecord {
    pub id: Uuid,
    pub name: String,
    pub website: String,
    pub username: String,
    pub category: String,
    pub favorite: bool,
    pub secret: SecretEnvelope,
    pub provenance: Option<ImportProvenance>,
    pub created_at_unix: u64,
    pub updated_at_unix: u64,
    pub deleted_at_unix: Option<u64>,
}

impl EntryRecord {
    pub fn is_deleted(&self) -> bool {
        self.deleted_at_unix.is_some()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SecretEnvelope {
    pub nonce: [u8; 24],
    pub ciphertext: Vec<u8>,
}

#[derive(Debug, Serialize, Deserialize, PartialEq, Eq, Zeroize, ZeroizeOnDrop)]
pub struct SecretPayload {
    pub password: String,
    pub notes: String,
}

impl SecretPayload {
    pub fn new(password: impl Into<String>, notes: impl Into<String>) -> Self {
        Self {
            password: password.into(),
            notes: notes.into(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ImportProvenance {
    pub provider: String,
    pub source_stable_id: Option<String>,
    pub last_import_fingerprint: [u8; 32],
    pub last_imported_at_unix: u64,
}

#[derive(Debug)]
pub struct EntryDraft {
    pub name: String,
    pub website: String,
    pub username: String,
    pub category: String,
    pub favorite: bool,
    pub secret: SecretPayload,
    pub provenance: Option<ImportProvenance>,
}

impl EntryDraft {
    pub fn login(
        name: impl Into<String>,
        website: impl Into<String>,
        username: impl Into<String>,
        password: impl Into<String>,
    ) -> Self {
        Self {
            name: name.into(),
            website: website.into(),
            username: username.into(),
            category: "其他".to_string(),
            favorite: false,
            secret: SecretPayload::new(password, ""),
            provenance: None,
        }
    }
}
