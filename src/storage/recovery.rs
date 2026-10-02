//! Read-only evidence listing and bounded, provenance-checked success retention.
//! Receipts describe encrypted files. They never authenticate a vault or authorize
//! adoption. A selected copy must still be opened with its password.
use super::{MAX_VAULT_BYTES, bounded};
use crate::platform::file_transaction::{self as native, Identity};
use crate::{AppError, Result, security};
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::{Path, PathBuf};
use uuid::Uuid;

const RECORD_LIMIT: u64 = 16 * 1024;
const MAX_SCAN: usize = 4096;
const MAX_RECORDS: usize = 64;
const ROLES: [&str; 5] = [
    "receipt.json",
    "previous.pmvault",
    "candidate.pmvault",
    "publish.pmvault",
    "displaced.pmvault",
];

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CurrentObservation {
    ExpectedOld,
    ExpectedCandidate,
    Other,
    Missing,
    Unreadable,
}
impl std::fmt::Display for CurrentObservation {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::ExpectedOld => "与原文件一致",
            Self::ExpectedCandidate => "与预期新文件一致（完整事务未确认）",
            Self::Other => "文件已变化",
            Self::Missing => "当前文件缺失",
            Self::Unreadable => "当前文件无法读取或类型不支持",
        })
    }
}
#[derive(Debug, Clone)]
pub struct RecoveryArtifact {
    pub role: String,
    pub path: PathBuf,
}
#[derive(Debug, Clone)]
pub struct RecoveryInfo {
    pub destination: PathBuf,
    pub stage: String,
    pub current: CurrentObservation,
    pub artifacts: Vec<RecoveryArtifact>,
    pub detail: String,
}
#[derive(Debug, Clone, Default)]
pub struct RecoveryListing {
    pub artifacts: Vec<RecoveryArtifact>,
    pub maintenance_required: bool,
    pub detail: String,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct FileRecord {
    pub hash: [u8; 32],
    pub size: u64,
    pub identity: Identity,
}
impl FileRecord {
    pub fn capture(path: &Path) -> Result<Self> {
        let (bytes, identity) = bounded::read_identified(path, MAX_VAULT_BYTES)?;
        Ok(Self {
            hash: security::sha256(&bytes),
            size: bytes.len() as u64,
            identity,
        })
    }
    pub fn matches(&self, path: &Path) -> Result<()> {
        let (bytes, identity) = bounded::read_identified(path, self.size.min(MAX_VAULT_BYTES))?;
        if bytes.len() as u64 != self.size
            || identity != self.identity
            || security::sha256(&bytes) != self.hash
        {
            return Err(AppError::InvalidVault(
                "owned file identity or content changed",
            ));
        }
        Ok(())
    }
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Record {
    pub version: u32,
    pub transaction: Uuid,
    pub destination_key: String,
    pub directory_identity: Identity,
    pub old: FileRecord,
    pub previous: FileRecord,
    pub candidate: FileRecord,
    pub publish: FileRecord,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Owned {
    pub transaction: Uuid,
    pub directory_identity: Identity,
    pub receipt_hash: [u8; 32],
    pub previous: FileRecord,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Descriptor {
    version: u32,
    destination_key: String,
    pub current: Owned,
    pub retiring: Option<Owned>,
    #[serde(skip)]
    observed: Option<FileRecord>,
}

pub(super) struct Namespace {
    pub target: PathBuf,
    pub parent: PathBuf,
    pub key: String,
}
impl Namespace {
    pub fn new(target: &Path) -> Result<Self> {
        let name = target
            .file_name()
            .ok_or_else(|| AppError::Input("vault filename required".into()))?;
        let parent = target
            .parent()
            .filter(|p| !p.as_os_str().is_empty())
            .unwrap_or(Path::new("."));
        let parent = parent.canonicalize().map_err(|e| AppError::io(parent, e))?;
        let digest = security::sha256(name.as_encoded_bytes());
        let key = digest.iter().map(|byte| format!("{byte:02x}")).collect();
        Ok(Self {
            target: parent.join(name),
            parent,
            key,
        })
    }
    pub fn prefix(&self) -> String {
        format!(".pmvault-{}", self.key)
    }
    pub fn lock(&self) -> PathBuf {
        self.parent.join(format!("{}.lock", self.prefix()))
    }
    pub fn directory(&self, id: Uuid) -> PathBuf {
        self.parent.join(format!("{}.txn-{id}", self.prefix()))
    }
    fn descriptor(&self) -> PathBuf {
        self.parent.join(format!("{}.success.json", self.prefix()))
    }
    fn pending(&self) -> PathBuf {
        self.parent
            .join(format!("{}.success.pending.json", self.prefix()))
    }
    fn maintenance_witness(&self) -> PathBuf {
        self.parent.join(format!("{}.maintenance", self.prefix()))
    }
    pub fn transaction_paths(&self) -> Result<Vec<PathBuf>> {
        let prefix = format!("{}.txn-", self.prefix());
        let entries = fs::read_dir(&self.parent).map_err(|e| AppError::io(&self.parent, e))?;
        let mut paths = Vec::new();
        for (index, entry) in entries.enumerate() {
            if index >= MAX_SCAN {
                return Err(AppError::Input(
                    "recovery scan limit reached; inspect the vault folder before saving".into(),
                ));
            }
            let entry = entry.map_err(|e| AppError::io(&self.parent, e))?;
            if entry.file_name().to_string_lossy().starts_with(&prefix) {
                if paths.len() == MAX_RECORDS {
                    return Err(AppError::Input(
                        "too many recovery records; inspect the vault folder before saving".into(),
                    ));
                }
                paths.push(entry.path());
            }
        }
        Ok(paths)
    }
    pub fn read_descriptor(&self) -> Result<Option<Descriptor>> {
        match fs::symlink_metadata(self.descriptor()) {
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(AppError::io(self.descriptor(), e)),
            Ok(_) => {
                let (bytes, identity) = bounded::read_identified(&self.descriptor(), RECORD_LIMIT)?;
                let mut value: Descriptor = serde_json::from_slice(&bytes)?;
                value.observed = Some(FileRecord {
                    hash: security::sha256(&bytes),
                    size: bytes.len() as u64,
                    identity,
                });
                if value.version != 1 || value.destination_key != self.key {
                    return Err(AppError::InvalidVault(
                        "invalid successful backup descriptor",
                    ));
                }
                Ok(Some(value))
            }
        }
    }
    /// Called under the sidecar lock, before creating more recovery material.
    pub fn ready(&self) -> Result<Option<Descriptor>> {
        match fs::symlink_metadata(self.maintenance_witness()) {
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => (),
            Err(error) => return Err(AppError::io(self.maintenance_witness(), error)),
            Ok(_) => return Err(maintenance()),
        }
        if self
            .pending()
            .try_exists()
            .map_err(|e| AppError::io(self.pending(), e))?
        {
            return Err(maintenance());
        }
        let descriptor = self.read_descriptor()?;
        if let Some(d) = &descriptor {
            if d.retiring.is_some() {
                return Err(maintenance());
            }
            self.validate_owned(&d.current, true)?;
        }
        let allowed = descriptor
            .as_ref()
            .map(|d| self.directory(d.current.transaction));
        if self
            .transaction_paths()?
            .iter()
            .any(|p| Some(p) != allowed.as_ref())
        {
            return Err(maintenance());
        }
        Ok(descriptor)
    }
    fn validate_owned(&self, owned: &Owned, clean: bool) -> Result<Record> {
        let directory = self.directory(owned.transaction);
        let dir = native::open_directory(&directory).map_err(|e| AppError::io(&directory, e))?;
        if native::identity(&dir, false).map_err(|e| AppError::io(&directory, e))?
            != owned.directory_identity
        {
            return Err(maintenance());
        }
        let receipt = bounded::read(&directory.join("receipt.json"), RECORD_LIMIT)?;
        if security::sha256(&receipt) != owned.receipt_hash {
            return Err(maintenance());
        }
        let record: Record = serde_json::from_slice(&receipt)?;
        if record.version != 1
            || record.transaction != owned.transaction
            || record.destination_key != self.key
            || record.directory_identity != owned.directory_identity
            || record.previous != owned.previous
        {
            return Err(maintenance());
        }
        owned
            .previous
            .matches(&directory.join("previous.pmvault"))?;
        for (index, entry) in fs::read_dir(&directory)
            .map_err(|e| AppError::io(&directory, e))?
            .enumerate()
        {
            if index >= ROLES.len() {
                return Err(maintenance());
            }
            let entry = entry.map_err(|e| AppError::io(&directory, e))?;
            let name = entry.file_name();
            let Some(name) = name.to_str() else {
                return Err(maintenance());
            };
            if !ROLES.contains(&name)
                || (clean && !["receipt.json", "previous.pmvault"].contains(&name))
            {
                return Err(maintenance());
            }
            if !entry
                .file_type()
                .map_err(|e| AppError::io(entry.path(), e))?
                .is_file()
            {
                return Err(maintenance());
            }
            match name {
                "candidate.pmvault" => record.candidate.matches(&entry.path())?,
                "publish.pmvault" | "displaced.pmvault" => record.old.matches(&entry.path())?,
                _ => (),
            }
        }
        Ok(record)
    }
    fn write_descriptor(
        &self,
        descriptor: &mut Descriptor,
        expected: Option<&Descriptor>,
    ) -> Result<()> {
        // Metadata is not a vault CAS. Under the managed-namespace contract,
        // preserve any observed foreign/modified descriptor rather than rename
        // over it merely because its pathname looks like ours.
        if let Some(expected) = expected {
            expected
                .observed
                .as_ref()
                .ok_or_else(maintenance)?
                .matches(&self.descriptor())?;
        } else {
            match fs::symlink_metadata(self.descriptor()) {
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => (),
                _ => return Err(maintenance()),
            }
        }
        let bytes = serde_json::to_vec(descriptor)?;
        bounded::write_new(&self.pending(), &bytes)?;
        native::replace_descriptor(&self.pending(), &self.descriptor())
            .map_err(|e| AppError::io(self.descriptor(), e))?;
        let (persisted, identity) = bounded::read_identified(&self.descriptor(), RECORD_LIMIT)?;
        if persisted != bytes {
            return Err(maintenance());
        }
        descriptor.observed = Some(FileRecord {
            hash: security::sha256(&persisted),
            size: persisted.len() as u64,
            identity,
        });
        let parent =
            native::open_directory(&self.parent).map_err(|e| AppError::io(&self.parent, e))?;
        #[cfg(test)]
        if descriptor.retiring.is_none() {
            super::transaction::test_hook(super::transaction::Point::CleanDescriptorSync)?;
        }
        native::sync_directory(&parent).map_err(|e| AppError::io(&self.parent, e))
    }
    /// A failure is a warning AFTER a verified commit. The next save is blocked.
    pub fn register(&self, record: &Record, previous: Option<Descriptor>) -> Result<()> {
        #[cfg(test)]
        super::transaction::test_hook(super::transaction::Point::BeforeRegister)?;
        let directory = self.directory(record.transaction);
        let owned = Owned {
            transaction: record.transaction,
            directory_identity: record.directory_identity,
            receipt_hash: security::sha256(&bounded::read(
                &directory.join("receipt.json"),
                RECORD_LIMIT,
            )?),
            previous: record.previous.clone(),
        };
        self.validate_owned(&owned, false)?;
        // This fixed, bounded witness outlives every fallible descriptor,
        // cleanup and required sync checkpoint. It has no Drop cleanup.
        #[cfg(test)]
        super::transaction::test_hook(super::transaction::Point::WitnessCreate)?;
        let witness_path = self.maintenance_witness();
        bounded::write_new(
            &witness_path,
            format!("maintenance-v1:{}\n", record.transaction).as_bytes(),
        )?;
        let witness = FileRecord::capture(&witness_path)?;
        let parent =
            native::open_directory(&self.parent).map_err(|e| AppError::io(&self.parent, e))?;
        #[cfg(test)]
        super::transaction::test_hook(super::transaction::Point::WitnessSync)?;
        native::sync_directory(&parent).map_err(|e| AppError::io(&self.parent, e))?;
        let mut descriptor = Descriptor {
            version: 1,
            destination_key: self.key.clone(),
            current: owned,
            retiring: previous.as_ref().map(|d| d.current.clone()),
            observed: None,
        };
        self.write_descriptor(&mut descriptor, previous.as_ref())?;
        #[cfg(test)]
        super::transaction::test_hook(super::transaction::Point::AfterRegister)?;
        descriptor
            .observed
            .as_ref()
            .ok_or_else(maintenance)?
            .matches(&self.descriptor())?;
        // Validate every child BEFORE removing any redundant or superseded file.
        self.validate_owned(&descriptor.current, false)?;
        for name in ["candidate.pmvault", native::displaced_name()] {
            #[cfg(test)]
            super::transaction::test_hook(super::transaction::Point::Cleanup)?;
            fs::remove_file(directory.join(name))
                .map_err(|e| AppError::io(directory.join(name), e))?;
        }
        if let Some(old) = &descriptor.retiring {
            self.validate_owned(old, true)?;
            let olddir = self.directory(old.transaction);
            for name in ["previous.pmvault", "receipt.json"] {
                fs::remove_file(olddir.join(name))
                    .map_err(|e| AppError::io(olddir.join(name), e))?;
            }
            fs::remove_dir(&olddir).map_err(|e| AppError::io(&olddir, e))?;
            #[cfg(test)]
            super::transaction::test_hook(super::transaction::Point::AfterRetire)?;
            let registered = descriptor.clone();
            descriptor.retiring = None;
            self.write_descriptor(&mut descriptor, Some(&registered))?;
        }
        let dir = native::open_directory(&directory).map_err(|e| AppError::io(&directory, e))?;
        #[cfg(test)]
        super::transaction::test_hook(super::transaction::Point::FinalDirectorySync)?;
        native::sync_directory(&dir).map_err(|e| AppError::io(&directory, e))?;
        let parent =
            native::open_directory(&self.parent).map_err(|e| AppError::io(&self.parent, e))?;
        #[cfg(test)]
        super::transaction::test_hook(super::transaction::Point::FinalParentSync)?;
        native::sync_directory(&parent).map_err(|e| AppError::io(&self.parent, e))?;
        witness.matches(&witness_path)?;
        #[cfg(test)]
        super::transaction::test_hook(super::transaction::Point::WitnessRemove)?;
        fs::remove_file(&witness_path).map_err(|e| AppError::io(&witness_path, e))?;
        // No fallible required operation follows readiness. We intentionally do
        // not claim durable witness removal: a power loss can resurrect it and
        // conservatively request maintenance, never bypass a failed checkpoint.
        Ok(())
    }
}
fn maintenance() -> AppError {
    AppError::Input("storage maintenance required: inspect retained encrypted copies and restore a selected authenticated copy to a NEW file before continuing".into())
}

pub(super) fn normalized_destination_path(path: &Path) -> Result<PathBuf> {
    #[cfg(windows)]
    {
        match fs::symlink_metadata(path) {
            Ok(_) => {
                // Reject final reparse/hardlink types before normalizing an existing
                // spelling. Never globally fold case: Windows directories may
                // be case-sensitive and distinct files must keep distinct keys.
                native::open_regular(path, false).map_err(|e| AppError::io(path, e))?;
                let canonical = path.canonicalize().map_err(|e| AppError::io(path, e))?;
                return Ok(Namespace::new(&canonical)?.target);
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => (),
            Err(error) => return Err(AppError::io(path, error)),
        }
    }
    // A missing target has no final handle to normalize; retain the last known
    // filename and physical parent so interrupted-publication evidence is usable.
    Ok(Namespace::new(path)?.target)
}

pub fn inspect(destination: &Path) -> Result<RecoveryListing> {
    let destination = normalized_destination_path(destination)?;
    let ns = Namespace::new(&destination)?;
    let mut listing = RecoveryListing::default();
    let descriptor = ns.read_descriptor();
    let clean = ns.ready().is_ok();
    let registered = descriptor
        .as_ref()
        .ok()
        .and_then(|d| d.as_ref())
        .map(|d| ns.directory(d.current.transaction));
    let paths = ns.transaction_paths()?;
    for path in paths {
        let dir_meta = fs::symlink_metadata(&path).map_err(|e| AppError::io(&path, e))?;
        if !dir_meta.is_dir() || dir_meta.file_type().is_symlink() {
            listing.artifacts.push(RecoveryArtifact {
                role: "未分类对象（不跟随链接）".into(),
                path,
            });
            listing.maintenance_required = true;
            continue;
        }
        let initial_count = listing.artifacts.len();
        // Only fixed role paths, no receipt-provided paths, no recursive traversal.
        for role in ROLES.iter().filter(|&&role| role != "receipt.json") {
            let candidate = path.join(role);
            if fs::symlink_metadata(&candidate).is_ok() {
                let label = if *role == "previous.pmvault" && registered.as_ref() == Some(&path) {
                    "已登记上次加密副本（恢复前仍需密码验证）"
                } else {
                    match *role {
                        "previous.pmvault" => "原文件独立副本（待验证）",
                        "candidate.pmvault" => "预期新文件（待验证）",
                        _ => "实际移位/发布副本（待验证）",
                    }
                };
                listing.artifacts.push(RecoveryArtifact {
                    role: label.into(),
                    path: candidate,
                });
            }
        }
        if initial_count == listing.artifacts.len() {
            listing.artifacts.push(RecoveryArtifact {
                role: "未分类事务目录（不自动清理；请选择目录内加密文件或其他备份）".into(),
                path: path.clone(),
            });
        }
        if registered.as_ref() != Some(&path) {
            listing.maintenance_required = true;
        }
    }
    listing.maintenance_required |= !clean;
    let legacy = destination.with_file_name(format!(
        "{}.bak",
        destination
            .file_name()
            .unwrap_or_default()
            .to_string_lossy()
    ));
    if fs::symlink_metadata(&legacy).is_ok() {
        listing.artifacts.push(RecoveryArtifact {
            role: "旧 .bak 文件（未验证，不自动采用或删除）".into(),
            path: legacy,
        });
    }
    listing.detail = if listing.maintenance_required { "发现未解决的存储材料；当前路径不保证仍为旧文件。请保留整个目录，选择副本验证后恢复到新位置。" } else { "副本只读；请自行选择并输入对应主密码，恢复到不存在的新文件。" }.into();
    Ok(listing)
}
