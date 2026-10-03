use std::collections::{BTreeMap, BTreeSet};

use uuid::Uuid;

use crate::domain::{EntryDraft, ImportProvenance, ImportSourceRecord, SecretPayload, VaultBody};
use crate::import::{
    ImportBatch, NormalizedImportItem, compatible_legacy_fingerprint, content_fingerprint,
    now_unix, weak_identity_key, work_to_result,
};
#[cfg(test)]
use crate::operations::WorkError;
use crate::operations::{WorkControl, WorkResult};
use crate::storage::VaultSession;
use crate::{AppError, Result};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ImportClass {
    New,
    SourceDuplicate { original_row: usize },
    ExactDuplicate { existing_id: Uuid },
    UpdateCandidate { existing_id: Uuid },
    LocallyDeleted { existing_ids: Vec<Uuid> },
    Conflict { existing_ids: Vec<Uuid> },
}

#[derive(Debug)]
pub struct ImportPreviewRow {
    item: NormalizedImportItem,
    class: ImportClass,
    resolution_candidates: BTreeSet<Uuid>,
    resolution_candidate_ids: Vec<Uuid>,
}

#[derive(Debug)]
pub struct ImportPreview {
    id: Uuid,
    session_binding: (Uuid, Uuid),
    vault_id: Uuid,
    revision: u64,
    body: VaultBody,
    provider: String,
    source_digest: [u8; 32],
    same_source_file: bool,
    invalid_rows: usize,
    rows: Vec<ImportPreviewRow>,
    exact_dependencies: BTreeMap<usize, Uuid>,
    summary: ImportPreviewSummary,
    unresolved_count: usize,
    display_rows: Vec<usize>,
    body_index: BTreeMap<Uuid, BodyEntryState>,
}

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct ImportPreviewSummary {
    pub new: usize,
    pub exact_duplicates: usize,
    pub source_duplicates: usize,
    pub update_candidates: usize,
    pub locally_deleted: usize,
    pub conflicts: usize,
    pub invalid: usize,
}

impl ImportPreviewRow {
    pub fn item(&self) -> &NormalizedImportItem {
        &self.item
    }
    pub fn class(&self) -> &ImportClass {
        &self.class
    }
    pub fn resolution_candidate_ids(&self) -> &[Uuid] {
        &self.resolution_candidate_ids
    }
}

impl ImportPreview {
    pub(crate) fn matches_session_context(&self, vault: &VaultSession) -> bool {
        self.session_binding == vault.import_binding()
            && self.vault_id == vault.vault_id()
            && self.revision == vault.revision()
            && self.body == *vault.body()
    }
    pub fn id(&self) -> Uuid {
        self.id
    }
    pub fn rows(&self) -> &[ImportPreviewRow] {
        &self.rows
    }
    pub fn same_source_file(&self) -> bool {
        self.same_source_file
    }

    pub fn allows_resolution(&self, index: usize, resolution: &ConflictResolution) -> bool {
        let Some(row) = self.rows.get(index) else {
            return false;
        };
        let deleted = match &row.class {
            ImportClass::Conflict { .. } => false,
            ImportClass::LocallyDeleted { .. } => true,
            _ => return false,
        };
        match resolution {
            ConflictResolution::KeepLocal | ConflictResolution::KeepBoth => true,
            ConflictResolution::UseImported(id) => {
                row.resolution_candidates.contains(id)
                    && self
                        .body_index
                        .get(id)
                        .is_some_and(|state| state.has_state(deleted))
            }
        }
    }

    pub fn summary(&self) -> ImportPreviewSummary {
        self.summary
    }
    /// Initial required conflict/deleted decisions, cached during worker analysis.
    pub fn unresolved_count(&self) -> usize {
        self.unresolved_count
    }
    pub fn display_rows(&self) -> &[usize] {
        &self.display_rows
    }
}

#[cfg(test)]
fn preview_metadata(
    rows: &mut [ImportPreviewRow],
    invalid: usize,
) -> (ImportPreviewSummary, usize, Vec<usize>) {
    preview_metadata_with(rows, invalid, &mut || Ok(()))
        .unwrap_or_else(|_| panic!("reference metadata"))
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConflictResolution {
    KeepLocal,
    UseImported(Uuid),
    KeepBoth,
}

#[derive(Debug)]
pub struct ImportApplyOptions {
    pub preview_id: Uuid,
    pub apply_update_candidates: bool,
    pub conflict_resolutions: BTreeMap<usize, ConflictResolution>,
}

impl ImportApplyOptions {
    pub fn for_preview(preview: &ImportPreview) -> Self {
        Self {
            preview_id: preview.id(),
            apply_update_candidates: false,
            conflict_resolutions: BTreeMap::new(),
        }
    }
}

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct ImportApplyReport {
    pub added: usize,
    pub updated: usize,
    pub skipped: usize,
    pub conflicts_unresolved: usize,
    pub updates_deferred: usize,
    pub locally_deleted_deferred: usize,
    pub invalid: usize,
}

// Accepted bodies may contain repeated IDs. Selection uses ANY matching row's
// state, while application retains VaultSession::entry's FIRST-row semantics.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct BodyEntryState {
    first_deleted: bool,
    any_active: bool,
    any_deleted: bool,
}
impl BodyEntryState {
    fn new(deleted: bool) -> Self {
        Self {
            first_deleted: deleted,
            any_active: !deleted,
            any_deleted: deleted,
        }
    }
    fn include(&mut self, deleted: bool) {
        self.any_active |= !deleted;
        self.any_deleted |= deleted;
    }
    fn has_state(self, deleted: bool) -> bool {
        if deleted {
            self.any_deleted
        } else {
            self.any_active
        }
    }
}
fn build_body_index(
    body: &VaultBody,
    checkpoint: &mut impl FnMut() -> WorkResult<()>,
) -> WorkResult<BTreeMap<Uuid, BodyEntryState>> {
    let mut index: BTreeMap<Uuid, BodyEntryState> = BTreeMap::new();
    for entry in &body.entries {
        checkpoint()?;
        index
            .entry(entry.id)
            .and_modify(|state| state.include(entry.is_deleted()))
            .or_insert_with(|| BodyEntryState::new(entry.is_deleted()));
    }
    Ok(index)
}

type WeakIdentity = (String, String);
type WeakSourceGroup = (String, WeakIdentity);
type WeakSourceFingerprint = (String, WeakIdentity, [u8; 32]);

struct ExistingSnapshot {
    id: Uuid,
    weak_key: WeakIdentity,
    fingerprint: [u8; 32],
    legacy_fingerprint: Option<[u8; 32]>,
    provenance: Option<ImportProvenance>,
    deleted: bool,
}

pub(crate) struct PreparedImport {
    pub(crate) report: ImportApplyReport,
    pub(crate) changed: bool,
    original: VaultBody,
    candidate: VaultBody,
    session_binding: (Uuid, Uuid),
    vault_id: Uuid,
    revision: u64,
}
impl PreparedImport {
    fn same_session_body(&self, vault: &VaultSession) -> bool {
        vault.import_binding().0 == self.session_binding.0
            && vault.vault_id() == self.vault_id
            && vault.body() == &self.candidate
    }
    pub(crate) fn finish_success(self, vault: &mut VaultSession) -> Result<ImportApplyReport> {
        let expected_revision = self.revision.checked_add(u64::from(self.changed));
        if !self.same_session_body(vault)
            || vault.import_binding() != self.session_binding
            || Some(vault.revision()) != expected_revision
        {
            return Err(AppError::Input("导入完成状态不属于准备时的保险库".into()));
        }
        vault.consume_import_preview();
        Ok(self.report)
    }
    pub(crate) fn restore_original(self, vault: &mut VaultSession) -> Result<()> {
        // A save failure can revoke the import epoch, but never advances revision.
        // Do not clobber a different session, a newer body, or verified publication.
        if !self.same_session_body(vault) || vault.revision() != self.revision {
            return Err(AppError::Input(
                "导入原始状态不能恢复到已改变的保险库".into(),
            ));
        }
        vault.restore_body(self.original);
        Ok(())
    }
}
pub(crate) fn build_preview_controlled(
    vault: &VaultSession,
    batch: ImportBatch,
    control: &WorkControl,
) -> WorkResult<ImportPreview> {
    build_preview_with(vault, batch, &mut || control.checkpoint(), Some(control))
}
pub(crate) fn prepare_application(
    vault: &mut VaultSession,
    preview: &ImportPreview,
    options: &ImportApplyOptions,
    control: &WorkControl,
) -> WorkResult<PreparedImport> {
    prepare_application_with(vault, preview, options, &mut || control.checkpoint())
}
fn prepare_application_with(
    vault: &mut VaultSession,
    preview: &ImportPreview,
    options: &ImportApplyOptions,
    checkpoint: &mut impl FnMut() -> WorkResult<()>,
) -> WorkResult<PreparedImport> {
    checkpoint()?;
    validate_application(vault, preview, options, checkpoint)?;
    let original = vault.snapshot_body();
    match apply_preview_inner(vault, preview, options, checkpoint) {
        Ok((report, changed)) => Ok(PreparedImport {
            report,
            changed,
            candidate: vault.snapshot_body(),
            original,
            session_binding: vault.import_binding(),
            vault_id: vault.vault_id(),
            revision: vault.revision(),
        }),
        Err(error) => {
            vault.restore_body(original);
            Err(error)
        }
    }
}

#[cfg(test)]
thread_local! { static CLASSIFIER_EXAMINED: std::cell::Cell<usize> = const { std::cell::Cell::new(0) }; }
fn examined() {
    #[cfg(test)]
    CLASSIFIER_EXAMINED.with(|value| value.set(value.get() + 1));
}

#[cfg(test)]
#[derive(Default, Debug, Clone, Copy, PartialEq, Eq)]
struct ClassifierIndexWork {
    strong_visits: usize,
    unscoped_visits: usize,
    fingerprint_visits: usize,
    weak_visits: usize,
    fingerprint_probes: usize,
    materialized: usize,
}
#[cfg(test)]
thread_local! {
    static CLASSIFIER_INDEX_WORK: std::cell::Cell<ClassifierIndexWork> = const {
        std::cell::Cell::new(ClassifierIndexWork {
            strong_visits: 0, unscoped_visits: 0, fingerprint_visits: 0,
            weak_visits: 0, fingerprint_probes: 0, materialized: 0,
        })
    };
}
#[derive(Clone, Copy)]
enum CandidateWorkBucket {
    Strong,
    Unscoped,
    Fingerprint,
    Weak,
}
fn index_bucket_visit(_bucket: CandidateWorkBucket) {
    #[cfg(test)]
    CLASSIFIER_INDEX_WORK.with(|count| {
        let mut work = count.get();
        match _bucket {
            CandidateWorkBucket::Strong => work.strong_visits += 1,
            CandidateWorkBucket::Unscoped => work.unscoped_visits += 1,
            CandidateWorkBucket::Fingerprint => work.fingerprint_visits += 1,
            CandidateWorkBucket::Weak => work.weak_visits += 1,
        }
        count.set(work);
    });
}
fn index_candidate_materialized() {
    #[cfg(test)]
    CLASSIFIER_INDEX_WORK.with(|count| {
        let mut work = count.get();
        work.materialized += 1;
        count.set(work);
    });
}

#[derive(Default)]
struct ExistingIndex {
    strong: BTreeMap<(String, String), Vec<usize>>,
    weak: BTreeMap<(String, String), Vec<usize>>,
    fingerprint: BTreeMap<[u8; 32], Vec<usize>>,
}
impl ExistingIndex {
    #[cfg(test)]
    fn new(existing: &[ExistingSnapshot]) -> Self {
        Self::new_with(existing, &mut || Ok(())).unwrap_or_else(|_| panic!("synchronous index"))
    }
    fn new_with(
        existing: &[ExistingSnapshot],
        checkpoint: &mut impl FnMut() -> WorkResult<()>,
    ) -> WorkResult<Self> {
        let mut index = Self::default();
        for (position, snapshot) in existing.iter().enumerate() {
            checkpoint()?;
            index
                .weak
                .entry(snapshot.weak_key.clone())
                .or_default()
                .push(position);
            index
                .fingerprint
                .entry(snapshot.fingerprint)
                .or_default()
                .push(position);
            if let Some(provenance) = &snapshot.provenance
                && let Some(stable_id) = &provenance.source_stable_id
            {
                index
                    .strong
                    .entry((provenance.provider.clone(), stable_id.clone()))
                    .or_default()
                    .push(position);
            }
        }
        Ok(index)
    }
    fn candidate_positions(
        &self,
        item: &NormalizedImportItem,
        existing: &[ExistingSnapshot],
    ) -> BTreeSet<usize> {
        let mut positions = BTreeSet::new();
        if let Some(id) = &item.source_stable_id {
            if let Some(strong) = self.strong.get(&(item.provider.clone(), id.clone())) {
                positions.extend(
                    strong
                        .iter()
                        .inspect(|_| index_bucket_visit(CandidateWorkBucket::Strong)),
                );
                // Original classification returns for every nonempty exact strong tier.
                // Keep every physical position in that tier, including repeated UUIDs.
                return positions;
            }
            if item.provider == "legacy-passwords-db" {
                let unscoped = id
                    .strip_prefix("db:")
                    .and_then(|scoped| scoped.split_once(":entry:"))
                    .map(|(_, row)| format!("entry:{row}"))
                    .or_else(|| id.starts_with("entry:").then(|| id.clone()));
                if let Some(unscoped) = unscoped
                    && let Some(legacy) = self.strong.get(&(item.provider.clone(), unscoped))
                {
                    positions.extend(
                        legacy
                            .iter()
                            .inspect(|_| index_bucket_visit(CandidateWorkBucket::Unscoped)),
                    );
                    return positions;
                }
            }
        }
        if let Some(exact) = self.fingerprint.get(&item.fingerprint)
            && exact.iter().any(|&position| {
                #[cfg(test)]
                CLASSIFIER_INDEX_WORK.with(|count| {
                    let mut work = count.get();
                    work.fingerprint_probes += 1;
                    count.set(work);
                });
                compatible_identity(item, &existing[position])
            })
        {
            // A compatible active exact or deleted exact tier always precedes weak
            // identity. The unchanged classifier chooses active/deleted/order.
            positions.extend(
                exact
                    .iter()
                    .inspect(|_| index_bucket_visit(CandidateWorkBucket::Fingerprint)),
            );
            return positions;
        }
        if let Some(weak) = self
            .weak
            .get(&weak_identity_key(&item.website, &item.username))
        {
            positions.extend(
                weak.iter()
                    .inspect(|_| index_bucket_visit(CandidateWorkBucket::Weak)),
            );
        }
        positions
    }
}
fn classify_item_indexed(
    item: &NormalizedImportItem,
    existing: &[ExistingSnapshot],
    index: &ExistingIndex,
) -> ImportClass {
    // The old precedence/equality logic examines only candidates that can affect
    // the result. Ordered source positions preserve the previous candidate order.
    let candidates: Vec<_> = index
        .candidate_positions(item, existing)
        .into_iter()
        .map(|position| {
            index_candidate_materialized();
            &existing[position]
        })
        .collect();
    classify_candidates(item, &candidates)
}

pub fn build_preview(vault: &VaultSession, batch: ImportBatch) -> Result<ImportPreview> {
    work_to_result(build_preview_with(vault, batch, &mut || Ok(()), None))
}
fn build_preview_with(
    vault: &VaultSession,
    batch: ImportBatch,
    checkpoint: &mut impl FnMut() -> WorkResult<()>,
    control: Option<&WorkControl>,
) -> WorkResult<ImportPreview> {
    checkpoint()?;
    let same_source_file = vault
        .body()
        .import_history
        .iter()
        .any(|record| record.source_digest == batch.source_digest);

    let mut existing = Vec::new();
    for (entry_index, pair) in vault.all_entries_with_secrets().enumerate() {
        if let Some(control) = control {
            control.progress(
                crate::operations::WorkPhase::ReadingEntries,
                entry_index,
                Some(vault.entries().len()),
            );
        }
        checkpoint()?;
        let (entry, secret) = pair?;
        existing.push(ExistingSnapshot {
            id: entry.id,
            weak_key: weak_identity_key(&entry.website, &entry.username),
            fingerprint: content_fingerprint(
                &entry.name,
                &entry.website,
                &entry.username,
                &secret.password,
                &secret.notes,
                &entry.category,
                entry.favorite,
            ),
            legacy_fingerprint: compatible_legacy_fingerprint(
                [
                    &entry.name,
                    &entry.website,
                    &entry.username,
                    &secret.password,
                    &secret.notes,
                    &entry.category,
                ],
                entry.favorite,
            ),
            provenance: entry.provenance.clone(),
            deleted: entry.is_deleted(),
        });
    }

    checkpoint()?;
    let existing_index = ExistingIndex::new_with(&existing, checkpoint)?;
    let mut rows: Vec<ImportPreviewRow> = Vec::new();
    rows.try_reserve_exact(batch.items.len())
        .map_err(|_| AppError::Input("导入预览缓冲区内存不足".into()))?;
    let mut weak_fingerprints: BTreeMap<WeakSourceFingerprint, Vec<usize>> = BTreeMap::new();
    let mut strong_rows: BTreeMap<(String, String), usize> = BTreeMap::new();
    let mut weak_rows: BTreeMap<WeakSourceGroup, Vec<usize>> = BTreeMap::new();
    let total_rows = batch.items.len();
    for mut item in batch.items {
        if let Some(control) = control {
            control.progress(
                crate::operations::WorkPhase::Analyzing,
                rows.len(),
                Some(total_rows),
            );
        }
        checkpoint()?;
        item.fingerprint = content_fingerprint(
            &item.name,
            &item.website,
            &item.username,
            &item.password,
            &item.notes,
            &item.category,
            item.favorite,
        );
        let index = rows.len();
        let mut class = classify_item_indexed(&item, &existing, &existing_index);
        if let Some(stable_id) = &item.source_stable_id {
            let key = (item.provider.clone(), stable_id.clone());
            if let Some(&original_row) = strong_rows.get(&key) {
                if rows[original_row].item != item {
                    return Err(AppError::Input(format!(
                        "导入第 {}、{} 行的稳定标识重复且内容不同",
                        original_row + 1,
                        index + 1
                    ))
                    .into());
                }
                class = ImportClass::SourceDuplicate { original_row };
            } else {
                strong_rows.insert(key, index);
            }
        } else {
            let key = (
                item.provider.clone(),
                weak_identity_key(&item.website, &item.username),
            );
            let fingerprints = weak_fingerprints
                .entry((key.0.clone(), key.1.clone(), item.fingerprint))
                .or_default();
            if let Some(&original_row) = fingerprints
                .iter()
                .find(|&&previous| rows[previous].item == item)
            {
                class = ImportClass::SourceDuplicate { original_row };
            } else {
                fingerprints.push(index);
                weak_rows.entry(key).or_default().push(index);
            }
        }
        rows.push(ImportPreviewRow {
            item,
            class,
            resolution_candidates: BTreeSet::new(),
            resolution_candidate_ids: Vec::new(),
        });
    }
    // Classify the entire weak group before any commit: source order is never
    // authority to select one of several different values for an identity.
    for ((_, key), group) in weak_rows.iter().filter(|(_, group)| group.len() > 1) {
        checkpoint()?;
        let candidates: Vec<_> = existing_index
            .weak
            .get(key)
            .into_iter()
            .flatten()
            .map(|&position| &existing[position])
            .collect();
        let class = if !candidates.is_empty() && candidates.iter().all(|snapshot| snapshot.deleted)
        {
            ImportClass::LocallyDeleted {
                existing_ids: candidates.iter().map(|snapshot| snapshot.id).collect(),
            }
        } else {
            ImportClass::Conflict {
                existing_ids: candidates
                    .iter()
                    .filter(|snapshot| !snapshot.deleted)
                    .map(|snapshot| snapshot.id)
                    .collect(),
            }
        };
        for &index in group {
            checkpoint()?;
            rows[index].class = class.clone();
        }
    }

    checkpoint()?;
    let exact_dependencies = reconcile_exact_matches_with(&mut rows, checkpoint)?;
    checkpoint()?;

    let (summary, unresolved_count, display_rows) =
        preview_metadata_with(&mut rows, batch.invalid_rows, checkpoint)?;
    let body_index = build_body_index(vault.body(), checkpoint)?;
    fill_resolution_candidate_ids(&mut rows, &body_index, checkpoint)?;
    checkpoint()?;
    Ok(ImportPreview {
        summary,
        unresolved_count,
        display_rows,
        body_index,
        exact_dependencies,
        id: Uuid::new_v4(),
        session_binding: vault.import_binding(),
        vault_id: vault.vault_id(),
        revision: vault.revision(),
        body: vault.snapshot_body(),
        provider: batch.provider,
        source_digest: batch.source_digest,
        same_source_file,
        invalid_rows: batch.invalid_rows,
        rows,
    })
}

#[cfg(test)]
fn build_preview_reference_with(
    vault: &VaultSession,
    batch: ImportBatch,
    checkpoint: &mut impl FnMut() -> WorkResult<()>,
) -> WorkResult<ImportPreview> {
    checkpoint()?;
    let same_source_file = vault
        .body()
        .import_history
        .iter()
        .any(|record| record.source_digest == batch.source_digest);

    let mut existing = Vec::new();
    // Retain the original lookup semantics, including accepted duplicate IDs:
    // metadata is from each row, secrets come from the first matching UUID.
    for entry in vault.entries() {
        checkpoint()?;
        let secret = vault.reveal_secret(entry.id)?;
        existing.push(ExistingSnapshot {
            id: entry.id,
            weak_key: weak_identity_key(&entry.website, &entry.username),
            fingerprint: content_fingerprint(
                &entry.name,
                &entry.website,
                &entry.username,
                &secret.password,
                &secret.notes,
                &entry.category,
                entry.favorite,
            ),
            legacy_fingerprint: compatible_legacy_fingerprint(
                [
                    &entry.name,
                    &entry.website,
                    &entry.username,
                    &secret.password,
                    &secret.notes,
                    &entry.category,
                ],
                entry.favorite,
            ),
            provenance: entry.provenance.clone(),
            deleted: entry.is_deleted(),
        });
    }

    let mut rows: Vec<ImportPreviewRow> = Vec::with_capacity(batch.items.len());
    let mut strong_rows: BTreeMap<(String, String), usize> = BTreeMap::new();
    let mut weak_rows: BTreeMap<WeakSourceGroup, Vec<usize>> = BTreeMap::new();
    for mut item in batch.items {
        checkpoint()?;
        item.fingerprint = content_fingerprint(
            &item.name,
            &item.website,
            &item.username,
            &item.password,
            &item.notes,
            &item.category,
            item.favorite,
        );
        let index = rows.len();
        let mut class = classify_item_reference(&item, &existing);
        if let Some(stable_id) = &item.source_stable_id {
            let key = (item.provider.clone(), stable_id.clone());
            if let Some(&original_row) = strong_rows.get(&key) {
                if rows[original_row].item != item {
                    return Err(AppError::Input(format!(
                        "导入第 {}、{} 行的稳定标识重复且内容不同",
                        original_row + 1,
                        index + 1
                    ))
                    .into());
                }
                class = ImportClass::SourceDuplicate { original_row };
            } else {
                strong_rows.insert(key, index);
            }
        } else {
            let key = (
                item.provider.clone(),
                weak_identity_key(&item.website, &item.username),
            );
            let group = weak_rows.entry(key).or_default();
            if let Some(&original_row) = group.iter().find(|&&previous| rows[previous].item == item)
            {
                class = ImportClass::SourceDuplicate { original_row };
            } else {
                group.push(index);
            }
        }
        rows.push(ImportPreviewRow {
            item,
            class,
            resolution_candidates: BTreeSet::new(),
            resolution_candidate_ids: Vec::new(),
        });
    }
    // Classify the entire weak group before any commit: source order is never
    // authority to select one of several different values for an identity.
    for group in weak_rows.values().filter(|group| group.len() > 1) {
        for &index in group {
            let key = weak_identity_key(&rows[index].item.website, &rows[index].item.username);
            let candidates: Vec<_> = existing
                .iter()
                .filter(|snapshot| snapshot.weak_key == key)
                .collect();
            rows[index].class =
                if !candidates.is_empty() && candidates.iter().all(|snapshot| snapshot.deleted) {
                    ImportClass::LocallyDeleted {
                        existing_ids: candidates.iter().map(|snapshot| snapshot.id).collect(),
                    }
                } else {
                    ImportClass::Conflict {
                        existing_ids: candidates
                            .iter()
                            .filter(|snapshot| !snapshot.deleted)
                            .map(|snapshot| snapshot.id)
                            .collect(),
                    }
                };
        }
    }

    checkpoint()?;
    let exact_dependencies = reconcile_exact_matches(&mut rows);
    checkpoint()?;

    let (summary, unresolved_count, display_rows) = preview_metadata(&mut rows, batch.invalid_rows);
    let body_index = build_body_index(vault.body(), checkpoint)?;
    fill_resolution_candidate_ids(&mut rows, &body_index, checkpoint)?;
    checkpoint()?;
    Ok(ImportPreview {
        summary,
        unresolved_count,
        display_rows,
        body_index,
        exact_dependencies,
        id: Uuid::new_v4(),
        session_binding: vault.import_binding(),
        vault_id: vault.vault_id(),
        revision: vault.revision(),
        body: vault.snapshot_body(),
        provider: batch.provider,
        source_digest: batch.source_digest,
        same_source_file,
        invalid_rows: batch.invalid_rows,
        rows,
    })
}

fn fill_resolution_candidate_ids(
    rows: &mut [ImportPreviewRow],
    body_index: &BTreeMap<Uuid, BodyEntryState>,
    checkpoint: &mut impl FnMut() -> WorkResult<()>,
) -> WorkResult<()> {
    for row in rows {
        checkpoint()?;
        let (ids, deleted) = match &row.class {
            ImportClass::Conflict { existing_ids } => (existing_ids.as_slice(), false),
            ImportClass::LocallyDeleted { existing_ids } => (existing_ids.as_slice(), true),
            _ => continue,
        };
        row.resolution_candidate_ids
            .try_reserve_exact(ids.len())
            .map_err(|_| AppError::Input("导入候选显示索引内存不足".into()))?;
        for &id in ids {
            checkpoint()?;
            if body_index
                .get(&id)
                .is_some_and(|state| state.has_state(deleted))
            {
                row.resolution_candidate_ids.push(id);
            }
        }
    }
    Ok(())
}

fn preview_metadata_with(
    rows: &mut [ImportPreviewRow],
    invalid: usize,
    checkpoint: &mut impl FnMut() -> WorkResult<()>,
) -> WorkResult<(ImportPreviewSummary, usize, Vec<usize>)> {
    let mut summary = ImportPreviewSummary {
        invalid,
        ..ImportPreviewSummary::default()
    };
    let mut display_rows = Vec::new();
    display_rows
        .try_reserve_exact(rows.len())
        .map_err(|_| AppError::Input("导入显示索引内存不足".into()))?;
    for (index, row) in rows.iter_mut().enumerate() {
        checkpoint()?;
        match &row.class {
            ImportClass::New => summary.new += 1,
            ImportClass::SourceDuplicate { .. } => summary.source_duplicates += 1,
            ImportClass::ExactDuplicate { .. } => summary.exact_duplicates += 1,
            ImportClass::UpdateCandidate { .. } => {
                summary.update_candidates += 1;
                display_rows.push(index);
            }
            ImportClass::LocallyDeleted { existing_ids }
            | ImportClass::Conflict { existing_ids } => {
                if matches!(row.class, ImportClass::LocallyDeleted { .. }) {
                    summary.locally_deleted += 1;
                } else {
                    summary.conflicts += 1;
                }
                display_rows.push(index);
                for &id in existing_ids {
                    checkpoint()?;
                    row.resolution_candidates.insert(id);
                }
            }
        }
    }
    Ok((
        summary,
        summary.locally_deleted + summary.conflicts,
        display_rows,
    ))
}

// Exact matches remain dependencies on the original snapshot; another row can
// replace their content or claim an incompatible source identity.
fn reconcile_exact_matches_with(
    rows: &mut [ImportPreviewRow],
    checkpoint: &mut impl FnMut() -> WorkResult<()>,
) -> WorkResult<BTreeMap<usize, Uuid>> {
    let mut exact_dependencies = BTreeMap::new();
    for (index, row) in rows.iter().enumerate() {
        checkpoint()?;
        if let ImportClass::ExactDuplicate { existing_id } = row.class {
            exact_dependencies.insert(index, existing_id);
        }
    }
    let mut strong_claims: BTreeMap<Uuid, BTreeSet<(String, String)>> = BTreeMap::new();
    for (&index, &id) in &exact_dependencies {
        checkpoint()?;
        let item = &rows[index].item;
        if let Some(stable_id) = &item.source_stable_id {
            strong_claims
                .entry(id)
                .or_default()
                .insert((item.provider.clone(), stable_id.clone()));
        }
    }
    let mut possible_writers: BTreeMap<Uuid, Vec<usize>> = BTreeMap::new();
    for (index, row) in rows.iter().enumerate() {
        checkpoint()?;
        let targets = match &row.class {
            ImportClass::UpdateCandidate { existing_id } => std::slice::from_ref(existing_id),
            ImportClass::Conflict { existing_ids }
            | ImportClass::LocallyDeleted { existing_ids } => existing_ids.as_slice(),
            _ => &[],
        };
        for &id in targets {
            checkpoint()?;
            possible_writers.entry(id).or_default().push(index);
        }
    }
    for (&index, &id) in &exact_dependencies {
        checkpoint()?;
        let ambiguous_identity = strong_claims
            .get(&id)
            .is_some_and(|claims| claims.len() > 1);
        let mut may_replace_match = false;
        if let Some(writers) = possible_writers.get(&id) {
            for &writer in writers {
                checkpoint()?;
                if invalidates_exact_match(&rows[index].item, &rows[writer].item) {
                    may_replace_match = true;
                    break;
                }
            }
        }
        if ambiguous_identity || may_replace_match {
            rows[index].class = ImportClass::Conflict {
                existing_ids: vec![id],
            };
        }
    }
    Ok(exact_dependencies)
}

#[cfg(test)]
fn reconcile_exact_matches(rows: &mut [ImportPreviewRow]) -> BTreeMap<usize, Uuid> {
    reconcile_exact_matches_with(rows, &mut || Ok(()))
        .unwrap_or_else(|_| panic!("reference reconciliation"))
}

fn invalidates_exact_match(
    exact: &NormalizedImportItem,
    replacement: &NormalizedImportItem,
) -> bool {
    exact.fingerprint != replacement.fingerprint
        || (exact.source_stable_id.is_some()
            && (exact.provider != replacement.provider
                || exact.source_stable_id != replacement.source_stable_id))
}

pub fn apply_preview(
    vault: &mut VaultSession,
    preview: &ImportPreview,
    options: &ImportApplyOptions,
) -> Result<ImportApplyReport> {
    let prepared = work_to_result(prepare_application_with(
        vault,
        preview,
        options,
        &mut || Ok(()),
    ))?;
    if prepared.changed
        && let Err(error) = vault.save()
    {
        // Preserve the storage error's verified/uncertain disposition.
        prepared.restore_original(vault)?;
        return Err(error);
    }
    prepared.finish_success(vault)
}

fn validate_application(
    vault: &VaultSession,
    preview: &ImportPreview,
    options: &ImportApplyOptions,
    checkpoint: &mut impl FnMut() -> WorkResult<()>,
) -> WorkResult<()> {
    checkpoint()?;
    if options.preview_id != preview.id || !preview.matches_session_context(vault) {
        return Err(AppError::Input("导入预览已失效，请重新分析源文件".to_string()).into());
    }
    for (&index, resolution) in &options.conflict_resolutions {
        checkpoint()?;
        if !preview.allows_resolution(index, resolution) {
            return Err(AppError::Input("导入决定不属于当前预览行或候选状态".to_string()).into());
        }
    }
    let mut targets = BTreeMap::new();
    for (index, row) in preview.rows.iter().enumerate() {
        checkpoint()?;
        let target = match &row.class {
            ImportClass::UpdateCandidate { existing_id } if options.apply_update_candidates => {
                Some((*existing_id, false))
            }
            ImportClass::Conflict { .. } | ImportClass::LocallyDeleted { .. } => {
                match options.conflict_resolutions.get(&index) {
                    Some(ConflictResolution::UseImported(id)) => Some((
                        *id,
                        matches!(&row.class, ImportClass::LocallyDeleted { .. }),
                    )),
                    _ => None,
                }
            }
            _ => None,
        };
        if let Some((id, deleted)) = target {
            if preview.body_index.get(&id).map(|state| state.first_deleted) != Some(deleted) {
                return Err(AppError::Input("导入候选条目状态已改变".to_string()).into());
            }
            if targets.insert(id, index).is_some() {
                return Err(
                    AppError::Input("多个导入行不能同时写入同一本地条目".to_string()).into(),
                );
            }
        }
    }
    let mut skipped_strong_identities = BTreeMap::new();
    for (&index, &id) in &preview.exact_dependencies {
        checkpoint()?;
        let row = &preview.rows[index];
        if let Some(&writer) = targets.get(&id)
            && invalidates_exact_match(&row.item, &preview.rows[writer].item)
            && !options.conflict_resolutions.contains_key(&index)
        {
            return Err(AppError::Input(
                "导入将替换另一行的匹配条目，请先选择跳过该行或导入为独立条目".to_string(),
            )
            .into());
        }
        // Defense in depth if future classification changes miss an alias.
        if matches!(row.class, ImportClass::ExactDuplicate { .. })
            && let Some(stable_id) = &row.item.source_stable_id
        {
            let identity = (&row.item.provider, stable_id);
            if skipped_strong_identities
                .insert(id, identity)
                .is_some_and(|previous| previous != identity)
            {
                return Err(
                    AppError::Input("不同来源标识不能自动跳过到同一本地条目".to_string()).into(),
                );
            }
        }
    }
    Ok(())
}

fn apply_preview_inner(
    vault: &mut VaultSession,
    preview: &ImportPreview,
    options: &ImportApplyOptions,
    checkpoint: &mut impl FnMut() -> WorkResult<()>,
) -> WorkResult<(ImportApplyReport, bool)> {
    checkpoint()?;
    let mut report = ImportApplyReport {
        invalid: preview.invalid_rows,
        ..ImportApplyReport::default()
    };
    let now = now_unix();

    for (index, row) in preview.rows.iter().enumerate() {
        checkpoint()?;
        match &row.class {
            ImportClass::New => {
                vault.add_entry(import_draft(&row.item, preview.source_digest, now))?;
                report.added += 1;
            }
            ImportClass::ExactDuplicate { .. } | ImportClass::SourceDuplicate { .. } => {
                report.skipped += 1;
            }
            ImportClass::UpdateCandidate { existing_id } => {
                if options.apply_update_candidates {
                    vault.update_entry(
                        *existing_id,
                        import_draft(&row.item, preview.source_digest, now),
                    )?;
                    report.updated += 1;
                } else {
                    report.updates_deferred += 1;
                }
            }
            ImportClass::LocallyDeleted { existing_ids } => {
                let Some(resolution) = options.conflict_resolutions.get(&index) else {
                    report.locally_deleted_deferred += 1;
                    continue;
                };

                match resolution {
                    ConflictResolution::KeepLocal => report.skipped += 1,
                    ConflictResolution::KeepBoth => {
                        vault.add_entry(import_draft(&row.item, preview.source_digest, now))?;
                        report.added += 1;
                    }
                    ConflictResolution::UseImported(existing_id) => {
                        if !existing_ids.contains(existing_id) {
                            return Err(AppError::Input(
                                "本地删除条目的恢复目标不属于当前候选".to_string(),
                            )
                            .into());
                        }
                        vault.restore_from_recycle_bin(*existing_id)?;
                        vault.update_entry(
                            *existing_id,
                            import_draft(&row.item, preview.source_digest, now),
                        )?;
                        report.updated += 1;
                    }
                }
            }
            ImportClass::Conflict { existing_ids } => {
                let Some(resolution) = options.conflict_resolutions.get(&index) else {
                    report.conflicts_unresolved += 1;
                    continue;
                };

                match resolution {
                    ConflictResolution::KeepLocal => report.skipped += 1,
                    ConflictResolution::KeepBoth => {
                        vault.add_entry(import_draft(&row.item, preview.source_digest, now))?;
                        report.added += 1;
                    }
                    ConflictResolution::UseImported(existing_id) => {
                        if !existing_ids.contains(existing_id) {
                            return Err(AppError::Input(
                                "冲突解决目标不属于当前候选条目".to_string(),
                            )
                            .into());
                        }
                        vault.update_entry(
                            *existing_id,
                            import_draft(&row.item, preview.source_digest, now),
                        )?;
                        report.updated += 1;
                    }
                }
            }
        }
    }

    let fully_resolved = report.conflicts_unresolved == 0
        && report.updates_deferred == 0
        && report.locally_deleted_deferred == 0;
    let already_recorded = vault
        .body()
        .import_history
        .iter()
        .any(|record| record.source_digest == preview.source_digest);

    if fully_resolved && !already_recorded {
        vault.body_mut().import_history.push(ImportSourceRecord {
            provider: preview.provider.clone(),
            source_digest: preview.source_digest,
            imported_at_unix: now,
            source_item_count: preview.rows.len() as u64,
        });
    }

    let changed = report.added > 0 || report.updated > 0 || (fully_resolved && !already_recorded);

    checkpoint()?;
    Ok((report, changed))
}

fn classify_candidates(item: &NormalizedImportItem, existing: &[&ExistingSnapshot]) -> ImportClass {
    if let Some(stable_id) = item.source_stable_id.as_deref() {
        let strong: Vec<&ExistingSnapshot> = existing
            .iter()
            .copied()
            .filter(|snapshot| {
                examined();
                snapshot.provenance.as_ref().is_some_and(|provenance| {
                    provenance.provider == item.provider
                        && provenance.source_stable_id.as_deref() == Some(stable_id)
                })
            })
            .collect();

        if strong.len() == 1 {
            if strong[0].deleted {
                return ImportClass::LocallyDeleted {
                    existing_ids: vec![strong[0].id],
                };
            }
            if item.provider == "legacy-passwords-db"
                && stable_id.starts_with("entry:")
                && strong[0].fingerprint != item.fingerprint
            {
                return ImportClass::Conflict {
                    existing_ids: vec![strong[0].id],
                };
            }
            return classify_known_identity(item, strong[0]);
        }

        if strong.len() > 1 {
            let ids: Vec<Uuid> = strong.iter().map(|snapshot| snapshot.id).collect();
            if strong.iter().all(|snapshot| snapshot.deleted) {
                return ImportClass::LocallyDeleted { existing_ids: ids };
            }
            return ImportClass::Conflict { existing_ids: ids };
        }
    }

    // Old imports did not record a database namespace. Row-number matches
    // remain explicit confirmation candidates even when other fields moved.
    let unscoped_id = item.source_stable_id.as_deref().and_then(|id| {
        id.strip_prefix("db:")
            .and_then(|scoped| scoped.split_once(":entry:"))
            .map(|(_, row)| format!("entry:{row}"))
            .or_else(|| id.starts_with("entry:").then(|| id.to_owned()))
    });
    if item.provider == "legacy-passwords-db"
        && let Some(unscoped_id) = unscoped_id
    {
        let candidates: Vec<_> = existing
            .iter()
            .copied()
            .filter(|snapshot| {
                examined();
                snapshot.provenance.as_ref().is_some_and(|provenance| {
                    provenance.provider == item.provider
                        && provenance.source_stable_id.as_deref() == Some(unscoped_id.as_str())
                })
            })
            .collect();
        if !candidates.is_empty() {
            if candidates.iter().all(|snapshot| snapshot.deleted) {
                return ImportClass::LocallyDeleted {
                    existing_ids: candidates.iter().map(|s| s.id).collect(),
                };
            }
            if candidates.len() == 1
                && !candidates[0].deleted
                && candidates[0].fingerprint == item.fingerprint
            {
                return ImportClass::ExactDuplicate {
                    existing_id: candidates[0].id,
                };
            }
            return ImportClass::Conflict {
                existing_ids: candidates.iter().map(|s| s.id).collect(),
            };
        }
    }

    if let Some(exact) = existing.iter().copied().find(|snapshot| {
        examined();
        !snapshot.deleted
            && snapshot.fingerprint == item.fingerprint
            && compatible_identity(item, snapshot)
    }) {
        return ImportClass::ExactDuplicate {
            existing_id: exact.id,
        };
    }

    let deleted_exact: Vec<Uuid> = existing
        .iter()
        .copied()
        .filter(|snapshot| {
            examined();
            snapshot.deleted
                && snapshot.fingerprint == item.fingerprint
                && compatible_identity(item, snapshot)
        })
        .map(|snapshot| snapshot.id)
        .collect();
    if !deleted_exact.is_empty() {
        return ImportClass::LocallyDeleted {
            existing_ids: deleted_exact,
        };
    }

    let item_weak_key = weak_identity_key(&item.website, &item.username);
    let active_weak: Vec<&ExistingSnapshot> = existing
        .iter()
        .copied()
        .filter(|snapshot| {
            examined();
            !snapshot.deleted && snapshot.weak_key == item_weak_key
        })
        .collect();
    let deleted_weak: Vec<Uuid> = existing
        .iter()
        .copied()
        .filter(|snapshot| {
            examined();
            snapshot.deleted && snapshot.weak_key == item_weak_key
        })
        .map(|snapshot| snapshot.id)
        .collect();

    if active_weak.is_empty() && !deleted_weak.is_empty() {
        return ImportClass::LocallyDeleted {
            existing_ids: deleted_weak,
        };
    }

    match active_weak.as_slice() {
        [] => ImportClass::New,
        [snapshot] => {
            let can_track_weak_update = item.source_stable_id.is_none()
                && snapshot.provenance.as_ref().is_some_and(|provenance| {
                    provenance.provider == item.provider
                        && provenance.source_stable_id.is_none()
                        && unchanged_since_import(snapshot)
                });

            if can_track_weak_update {
                ImportClass::UpdateCandidate {
                    existing_id: snapshot.id,
                }
            } else {
                ImportClass::Conflict {
                    existing_ids: vec![snapshot.id],
                }
            }
        }
        snapshots => ImportClass::Conflict {
            existing_ids: snapshots.iter().map(|snapshot| snapshot.id).collect(),
        },
    }
}

#[cfg(test)]
fn classify_item_reference(
    item: &NormalizedImportItem,
    existing: &[ExistingSnapshot],
) -> ImportClass {
    if let Some(stable_id) = item.source_stable_id.as_deref() {
        let strong: Vec<&ExistingSnapshot> = existing
            .iter()
            .filter(|snapshot| {
                examined();
                snapshot.provenance.as_ref().is_some_and(|provenance| {
                    provenance.provider == item.provider
                        && provenance.source_stable_id.as_deref() == Some(stable_id)
                })
            })
            .collect();

        if strong.len() == 1 {
            if strong[0].deleted {
                return ImportClass::LocallyDeleted {
                    existing_ids: vec![strong[0].id],
                };
            }
            if item.provider == "legacy-passwords-db"
                && stable_id.starts_with("entry:")
                && strong[0].fingerprint != item.fingerprint
            {
                return ImportClass::Conflict {
                    existing_ids: vec![strong[0].id],
                };
            }
            return classify_known_identity(item, strong[0]);
        }

        if strong.len() > 1 {
            let ids: Vec<Uuid> = strong.iter().map(|snapshot| snapshot.id).collect();
            if strong.iter().all(|snapshot| snapshot.deleted) {
                return ImportClass::LocallyDeleted { existing_ids: ids };
            }
            return ImportClass::Conflict { existing_ids: ids };
        }
    }

    // Old imports did not record a database namespace. Row-number matches
    // remain explicit confirmation candidates even when other fields moved.
    let unscoped_id = item.source_stable_id.as_deref().and_then(|id| {
        id.strip_prefix("db:")
            .and_then(|scoped| scoped.split_once(":entry:"))
            .map(|(_, row)| format!("entry:{row}"))
            .or_else(|| id.starts_with("entry:").then(|| id.to_owned()))
    });
    if item.provider == "legacy-passwords-db"
        && let Some(unscoped_id) = unscoped_id
    {
        let candidates: Vec<_> = existing
            .iter()
            .filter(|snapshot| {
                examined();
                snapshot.provenance.as_ref().is_some_and(|provenance| {
                    provenance.provider == item.provider
                        && provenance.source_stable_id.as_deref() == Some(unscoped_id.as_str())
                })
            })
            .collect();
        if !candidates.is_empty() {
            if candidates.iter().all(|snapshot| snapshot.deleted) {
                return ImportClass::LocallyDeleted {
                    existing_ids: candidates.iter().map(|s| s.id).collect(),
                };
            }
            if candidates.len() == 1
                && !candidates[0].deleted
                && candidates[0].fingerprint == item.fingerprint
            {
                return ImportClass::ExactDuplicate {
                    existing_id: candidates[0].id,
                };
            }
            return ImportClass::Conflict {
                existing_ids: candidates.iter().map(|s| s.id).collect(),
            };
        }
    }

    if let Some(exact) = existing.iter().find(|snapshot| {
        examined();
        !snapshot.deleted
            && snapshot.fingerprint == item.fingerprint
            && compatible_identity(item, snapshot)
    }) {
        return ImportClass::ExactDuplicate {
            existing_id: exact.id,
        };
    }

    let deleted_exact: Vec<Uuid> = existing
        .iter()
        .filter(|snapshot| {
            examined();
            snapshot.deleted
                && snapshot.fingerprint == item.fingerprint
                && compatible_identity(item, snapshot)
        })
        .map(|snapshot| snapshot.id)
        .collect();
    if !deleted_exact.is_empty() {
        return ImportClass::LocallyDeleted {
            existing_ids: deleted_exact,
        };
    }

    let item_weak_key = weak_identity_key(&item.website, &item.username);
    let active_weak: Vec<&ExistingSnapshot> = existing
        .iter()
        .filter(|snapshot| {
            examined();
            !snapshot.deleted && snapshot.weak_key == item_weak_key
        })
        .collect();
    let deleted_weak: Vec<Uuid> = existing
        .iter()
        .filter(|snapshot| {
            examined();
            snapshot.deleted && snapshot.weak_key == item_weak_key
        })
        .map(|snapshot| snapshot.id)
        .collect();

    if active_weak.is_empty() && !deleted_weak.is_empty() {
        return ImportClass::LocallyDeleted {
            existing_ids: deleted_weak,
        };
    }

    match active_weak.as_slice() {
        [] => ImportClass::New,
        [snapshot] => {
            let can_track_weak_update = item.source_stable_id.is_none()
                && snapshot.provenance.as_ref().is_some_and(|provenance| {
                    provenance.provider == item.provider
                        && provenance.source_stable_id.is_none()
                        && unchanged_since_import(snapshot)
                });

            if can_track_weak_update {
                ImportClass::UpdateCandidate {
                    existing_id: snapshot.id,
                }
            } else {
                ImportClass::Conflict {
                    existing_ids: vec![snapshot.id],
                }
            }
        }
        snapshots => ImportClass::Conflict {
            existing_ids: snapshots.iter().map(|snapshot| snapshot.id).collect(),
        },
    }
}

fn compatible_identity(item: &NormalizedImportItem, snapshot: &ExistingSnapshot) -> bool {
    match (
        item.source_stable_id.as_ref(),
        snapshot
            .provenance
            .as_ref()
            .and_then(|p| p.source_stable_id.as_ref().map(|id| (&p.provider, id))),
    ) {
        (Some(incoming), Some((provider, existing))) => {
            provider == &item.provider && incoming == existing
        }
        _ => true,
    }
}

fn classify_known_identity(
    item: &NormalizedImportItem,
    snapshot: &ExistingSnapshot,
) -> ImportClass {
    if snapshot.fingerprint == item.fingerprint {
        return ImportClass::ExactDuplicate {
            existing_id: snapshot.id,
        };
    }

    if unchanged_since_import(snapshot) {
        ImportClass::UpdateCandidate {
            existing_id: snapshot.id,
        }
    } else {
        ImportClass::Conflict {
            existing_ids: vec![snapshot.id],
        }
    }
}

fn unchanged_since_import(snapshot: &ExistingSnapshot) -> bool {
    snapshot.provenance.as_ref().is_some_and(|provenance| {
        provenance.last_import_fingerprint == snapshot.fingerprint
            || snapshot.legacy_fingerprint == Some(provenance.last_import_fingerprint)
    })
}

fn import_draft(
    item: &NormalizedImportItem,
    source_digest: [u8; 32],
    imported_at_unix: u64,
) -> EntryDraft {
    EntryDraft {
        name: item.name.clone(),
        website: item.website.clone(),
        username: item.username.clone(),
        category: item.category.clone(),
        favorite: item.favorite,
        secret: SecretPayload::new(item.password.clone(), item.notes.clone()),
        provenance: Some(ImportProvenance {
            provider: item.provider.clone(),
            source_stable_id: item.source_stable_id.clone(),
            last_import_fingerprint: item.fingerprint,
            last_imported_at_unix: imported_at_unix,
            source_digest: Some(source_digest),
        }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    fn item(id: &str, category: &str) -> NormalizedImportItem {
        NormalizedImportItem {
            provider: "synthetic".into(),
            source_stable_id: Some(id.into()),
            name: "Synthetic".into(),
            website: format!("https://{id}.example.test"),
            username: "user".into(),
            password: "synthetic-only".into(),
            notes: "note".into(),
            category: category.into(),
            favorite: false,
            fingerprint: [0; 32],
        }
    }

    fn batch(items: Vec<NormalizedImportItem>, digest: u8) -> ImportBatch {
        ImportBatch {
            provider: "synthetic".into(),
            source_digest: [digest; 32],
            items,
            invalid_rows: 0,
        }
    }

    #[test]
    fn complete_body_mutations_invalidate_preview_without_disk_changes() {
        let dir = tempfile::tempdir().unwrap();
        let mut vault =
            VaultSession::create(dir.path().join("vault.pmvault"), "synthetic-master").unwrap();
        let first = build_preview(&vault, batch(vec![item("first", "initial")], 1)).unwrap();
        apply_preview(&mut vault, &first, &ImportApplyOptions::for_preview(&first)).unwrap();
        let original = vault.snapshot_body();
        let disk = fs::read(vault.path()).unwrap();
        let revision = vault.revision();
        for mutation in 0..5 {
            vault.restore_body(original.clone());
            let preview = build_preview(&vault, batch(vec![item("second", "second")], 2)).unwrap();
            match mutation {
                0 => vault.body_mut().categories.push("unsaved category".into()),
                1 => vault.move_to_recycle_bin(vault.entries()[0].id).unwrap(),
                2 => {
                    vault.body_mut().entries[0]
                        .provenance
                        .as_mut()
                        .unwrap()
                        .source_digest = None
                }
                3 => vault.body_mut().import_history.clear(),
                _ => {
                    let id = vault.entries()[0].id;
                    vault
                        .update_entry(
                            id,
                            EntryDraft::login(
                                "edited",
                                "https://first.example.test",
                                "user",
                                "local-edit",
                            ),
                        )
                        .unwrap();
                }
            }
            let changed = vault.snapshot_body();
            assert!(
                apply_preview(
                    &mut vault,
                    &preview,
                    &ImportApplyOptions::for_preview(&preview)
                )
                .is_err()
            );
            assert_eq!(*vault.body(), changed);
            assert_eq!(vault.revision(), revision);
            assert_eq!(fs::read(vault.path()).unwrap(), disk);
        }
    }

    #[test]
    fn failed_save_restores_complete_body_history_and_revision_preserving_external_disk() {
        let dir = tempfile::tempdir().unwrap();
        let mut vault =
            VaultSession::create(dir.path().join("vault.pmvault"), "synthetic-master").unwrap();
        let first = build_preview(&vault, batch(vec![item("first", "initial")], 1)).unwrap();
        apply_preview(&mut vault, &first, &ImportApplyOptions::for_preview(&first)).unwrap();
        let id = vault.entries()[0].id;
        vault.move_to_recycle_bin(id).unwrap();
        vault.save().unwrap();
        let original = vault.snapshot_body();
        let revision = vault.revision();
        let disk = fs::read(vault.path()).unwrap();
        let preview = build_preview(
            &vault,
            batch(
                vec![
                    item("new", "added category"),
                    item("first", "restored category"),
                ],
                2,
            ),
        )
        .unwrap();
        let mut options = ImportApplyOptions::for_preview(&preview);
        options
            .conflict_resolutions
            .insert(1, ConflictResolution::UseImported(id));
        let mut external = disk.clone();
        external.push(b' ');
        fs::write(vault.path(), &external).unwrap();
        assert!(matches!(
            apply_preview(&mut vault, &preview, &options),
            Err(AppError::Persist(failure)) if failure.disposition == crate::storage::transaction::Disposition::ExternalConflict
        ));
        assert_eq!(*vault.body(), original);
        assert_eq!(vault.revision(), revision);
        assert_eq!(fs::read(vault.path()).unwrap(), external);
        // An external conflict invalidates the session even if old bytes reappear.
        fs::write(vault.path(), disk).unwrap();
        assert!(apply_preview(&mut vault, &preview, &options).is_err());
        assert!(vault.save().is_err());
        vault = VaultSession::open(vault.path(), "synthetic-master").unwrap();
        let fresh = build_preview(
            &vault,
            batch(
                vec![
                    item("new", "added category"),
                    item("first", "restored category"),
                ],
                2,
            ),
        )
        .unwrap();
        let mut options = ImportApplyOptions::for_preview(&fresh);
        options
            .conflict_resolutions
            .insert(1, ConflictResolution::UseImported(id));
        let report = apply_preview(&mut vault, &fresh, &options).unwrap();
        assert_eq!(report.added, 1);
        assert_eq!(report.updated, 1);
        assert_eq!(vault.revision(), revision + 1);
        assert_eq!(vault.body().import_history.len(), 2);
        assert_eq!(vault.active_entries().count(), 2);
    }
    #[test]
    fn review_rejected_exact_dependency_write_preserves_complete_body_and_history() {
        for reverse in [false, true] {
            for explicit in [false, true] {
                let dir = tempfile::tempdir().unwrap();
                let mut vault =
                    VaultSession::create(dir.path().join("vault.pmvault"), "synthetic-master")
                        .unwrap();
                let original = item("A", "initial");
                let first = build_preview(&vault, batch(vec![original.clone()], 1)).unwrap();
                apply_preview(&mut vault, &first, &ImportApplyOptions::for_preview(&first))
                    .unwrap();
                let id = vault.entries()[0].id;
                let mut replacement = original.clone();
                replacement.password = "synthetic-replacement".into();
                replacement.category = "added category".into();
                if explicit {
                    replacement.source_stable_id = Some("B".into());
                }
                let mut exact = original;
                exact.source_stable_id = None;
                let mut rows = vec![replacement, exact];
                if reverse {
                    rows.reverse();
                }
                let preview = build_preview(&vault, batch(rows, 2)).unwrap();
                let before = vault.snapshot_body();
                let revision = vault.revision();
                let disk = fs::read(vault.path()).unwrap();
                let mut options = ImportApplyOptions::for_preview(&preview);
                options.apply_update_candidates = true;
                if explicit {
                    options
                        .conflict_resolutions
                        .insert(usize::from(reverse), ConflictResolution::UseImported(id));
                }
                assert!(apply_preview(&mut vault, &preview, &options).is_err());
                assert_eq!(*vault.body(), before);
                assert_eq!(vault.revision(), revision);
                assert_eq!(fs::read(vault.path()).unwrap(), disk);
            }
        }
    }
    fn import_control(vault: &VaultSession) -> WorkControl {
        use crate::operations::{OperationKind, authority::Coordinator};
        use std::{
            sync::Arc,
            time::{Duration, Instant},
        };
        let authority = Arc::new(Coordinator::new(false));
        let now = Instant::now();
        authority.activate_session(vault.operation_binding(), now + Duration::from_secs(3600));
        let admission = authority
            .try_admit(
                OperationKind::ApplyImport,
                authority.snapshot(now).stamp,
                now,
            )
            .expect("admit");
        WorkControl {
            authority,
            id: admission.id(),
            worker: None,
        }
    }

    #[test]
    fn controlled_import_preparation_never_saves_and_can_restore() {
        let dir = tempfile::tempdir().unwrap();
        let mut vault =
            VaultSession::create(dir.path().join("vault.pmvault"), "synthetic-master").unwrap();
        let original = vault.snapshot_body();
        let disk = fs::read(vault.path()).unwrap();
        let revision = vault.revision();
        let preview = build_preview(&vault, batch(vec![item("new", "category")], 1)).unwrap();
        let control = import_control(&vault);
        let prepared = prepare_application(
            &mut vault,
            &preview,
            &ImportApplyOptions::for_preview(&preview),
            &control,
        )
        .unwrap_or_else(|_| panic!("prepared"));
        assert!(prepared.changed);
        assert_eq!(prepared.report.added, 1);
        assert_eq!(vault.revision(), revision);
        assert_eq!(fs::read(vault.path()).unwrap(), disk);
        assert_eq!(vault.entries().len(), 1);
        prepared.restore_original(&mut vault).unwrap();
        assert_eq!(vault.body(), &original);
    }

    #[test]
    fn controlled_import_success_consumes_even_noop_epoch() {
        let dir = tempfile::tempdir().unwrap();
        let mut vault =
            VaultSession::create(dir.path().join("vault.pmvault"), "synthetic-master").unwrap();
        let preview = build_preview(&vault, batch(vec![], 1)).unwrap();
        apply_preview(
            &mut vault,
            &preview,
            &ImportApplyOptions::for_preview(&preview),
        )
        .unwrap();
        let preview = build_preview(&vault, batch(vec![], 1)).unwrap();
        let control = import_control(&vault);
        let before = vault.import_binding();
        let prepared = prepare_application(
            &mut vault,
            &preview,
            &ImportApplyOptions::for_preview(&preview),
            &control,
        )
        .unwrap_or_else(|_| panic!("prepared noop"));
        assert!(!prepared.changed);
        prepared.finish_success(&mut vault).unwrap();
        assert_ne!(vault.import_binding(), before);
        assert!(
            apply_preview(
                &mut vault,
                &preview,
                &ImportApplyOptions::for_preview(&preview)
            )
            .is_err()
        );
    }

    #[test]
    fn controlled_import_cancelled_preparation_preserves_body() {
        let dir = tempfile::tempdir().unwrap();
        let mut vault =
            VaultSession::create(dir.path().join("vault.pmvault"), "synthetic-master").unwrap();
        let preview = build_preview(&vault, batch(vec![item("new", "category")], 1)).unwrap();
        let control = import_control(&vault);
        let original = vault.snapshot_body();
        control.authority.cancel(control.id);
        assert!(matches!(
            prepare_application(
                &mut vault,
                &preview,
                &ImportApplyOptions::for_preview(&preview),
                &control
            ),
            Err(WorkError::Cancelled)
        ));
        assert_eq!(vault.body(), &original);
    }

    #[test]
    #[ignore = "deterministic synthetic pre-index baseline probe"]
    fn perf_background_import_baseline_quadratic() {
        use std::time::Instant;
        let mut lines = Vec::new();
        for n in [1000usize, 2000, 4000] {
            let existing: Vec<_> = (0..n)
                .map(|index| ExistingSnapshot {
                    id: Uuid::from_u128(index as u128 + 1),
                    weak_key: (format!("site-{index}"), "user".into()),
                    fingerprint: [1; 32],
                    legacy_fingerprint: None,
                    provenance: None,
                    deleted: false,
                })
                .collect();
            CLASSIFIER_EXAMINED.with(|count| count.set(0));
            let started = Instant::now();
            for index in 0..n {
                let mut incoming = item(&format!("new-{index}"), "category");
                incoming.fingerprint = [2; 32];
                assert_eq!(
                    classify_item_reference(&incoming, &existing),
                    ImportClass::New
                );
            }
            let comparisons = CLASSIFIER_EXAMINED.with(|count| count.get());
            assert_eq!(comparisons, 5 * n * n);
            lines.push(format!(
                "n={n},examined={comparisons},elapsed_us={}",
                started.elapsed().as_micros()
            ));
        }
        let output = std::path::Path::new("target/background-perf");
        std::fs::create_dir_all(output).unwrap();
        std::fs::write(output.join("import-baseline.txt"), lines.join("\n")).unwrap();
        println!("{}", lines.join("\n"));
    }

    #[test]
    fn controlled_import_indexed_classifier_differential_randomized_adversarial() {
        let mut random = 0x835ef46a12u64;
        let mut next = || {
            random = random.wrapping_mul(6364136223846793005).wrapping_add(1);
            random
        };
        for round in 0..80 {
            let mut existing = Vec::new();
            for position in 0..80 {
                let key = next() % 12;
                let provider = if next() % 2 == 0 {
                    "legacy-passwords-db"
                } else {
                    "synthetic"
                };
                let stable = match next() % 4 {
                    0 => None,
                    1 => Some(format!("entry:{key}")),
                    2 => Some(format!("db:ns:entry:{key}")),
                    _ => Some(format!("id:{key}")),
                };
                let fingerprint = [(next() % 5) as u8; 32];
                existing.push(ExistingSnapshot {
                    id: Uuid::from_u128(position + 1),
                    weak_key: weak_identity_key(
                        &format!("https://site-{}.example.test/a/", next() % 10),
                        "user",
                    ),
                    fingerprint,
                    legacy_fingerprint: Some([2; 32]),
                    deleted: next() % 3 == 0,
                    provenance: Some(ImportProvenance {
                        provider: provider.into(),
                        source_stable_id: stable,
                        last_import_fingerprint: if next() % 2 == 0 {
                            fingerprint
                        } else {
                            [2; 32]
                        },
                        last_imported_at_unix: 0,
                        source_digest: None,
                    }),
                });
            }
            let index = ExistingIndex::new(&existing);
            for _ in 0..120 {
                let mut incoming = item("id:0", "category");
                incoming.provider = if next() % 2 == 0 {
                    "legacy-passwords-db".into()
                } else {
                    "synthetic".into()
                };
                let key = next() % 12;
                incoming.source_stable_id = match next() % 4 {
                    0 => None,
                    1 => Some(format!("entry:{key}")),
                    2 => Some(format!("db:ns:entry:{key}")),
                    _ => Some(format!("id:{key}")),
                };
                incoming.website = format!("https://site-{}.example.test/a/", next() % 10);
                incoming.fingerprint = [(next() % 5) as u8; 32];
                assert_eq!(
                    classify_item_indexed(&incoming, &existing, &index),
                    classify_item_reference(&incoming, &existing),
                    "deterministic round {round}"
                );
            }
        }
    }

    fn preview_classes(preview: &ImportPreview) -> Vec<ImportClass> {
        preview.rows.iter().map(|row| row.class.clone()).collect()
    }
    type SemanticEntry = (
        String,
        String,
        String,
        String,
        bool,
        bool,
        String,
        String,
        Option<ImportProvenance>,
    );
    fn semantic_entries(vault: &VaultSession) -> Vec<SemanticEntry> {
        vault
            .all_entries_with_secrets()
            .map(|pair| {
                let (entry, secret) = pair.unwrap();
                let mut provenance = entry.provenance.clone();
                if let Some(value) = &mut provenance {
                    value.last_imported_at_unix = 0;
                }
                (
                    entry.name.clone(),
                    entry.website.clone(),
                    entry.username.clone(),
                    entry.category.clone(),
                    entry.favorite,
                    entry.is_deleted(),
                    secret.password.clone(),
                    secret.notes.clone(),
                    provenance,
                )
            })
            .collect()
    }
    #[test]
    fn controlled_import_full_preview_and_application_differential() {
        let dir = tempfile::tempdir().unwrap();
        let mut vault =
            VaultSession::create(dir.path().join("vault.pmvault"), "synthetic-master").unwrap();
        for n in 0..48 {
            let mut source = item(&format!("existing-{n}"), "其他");
            source.website = format!("https://site-{}.example.test/a/", n % 9);
            source.password = format!("synthetic-{n}");
            if n % 3 == 0 {
                source.source_stable_id = None;
            }
            if n % 7 == 0 {
                source.provider = "legacy-passwords-db".into();
                source.source_stable_id = Some(format!("entry:{n}"));
            }
            source.fingerprint = content_fingerprint(
                &source.name,
                &source.website,
                &source.username,
                &source.password,
                &source.notes,
                &source.category,
                source.favorite,
            );
            let id = vault
                .add_entry(import_draft(&source, [1; 32], 123))
                .unwrap();
            if n % 5 == 0 {
                vault.move_to_recycle_bin(id).unwrap();
            }
            if n % 8 == 0 {
                vault
                    .body_mut()
                    .entries
                    .last_mut()
                    .unwrap()
                    .provenance
                    .as_mut()
                    .unwrap()
                    .last_import_fingerprint = [0; 32];
            }
        }
        let baseline = vault.snapshot_body();
        for round in 0..36 {
            vault.restore_body(baseline.clone());
            let mut sources = Vec::new();
            for n in 0..65 {
                let mut source = item(
                    &format!("incoming-{round}-{n}"),
                    if n % 4 == 0 { "分类 🚀" } else { "其他" },
                );
                source.website = format!("https://site-{}.example.test/a/", (n + round) % 15);
                source.password = format!("synthetic-{}", (n + round) % 48);
                if n % 3 != 0 {
                    source.source_stable_id = None;
                }
                if n % 11 == 0 {
                    source.provider = "legacy-passwords-db".into();
                    source.source_stable_id =
                        Some(format!("db:namespace:entry:{}", (n + round) % 48));
                }
                if n % 9 == 0 {
                    source.notes = "长备注 👩🏽‍💻\u{1f}\n空格  ".repeat(8);
                }
                sources.push(source);
            }
            sources.push(sources[2].clone());
            let indexed = build_preview(&vault, batch(sources.clone(), 2)).unwrap();
            let reference = build_preview_reference_with(&vault, batch(sources, 2), &mut || Ok(()))
                .unwrap_or_else(|_| panic!("reference preview"));
            assert_eq!(
                preview_classes(&indexed),
                preview_classes(&reference),
                "round {round}"
            );
            assert_eq!(indexed.summary(), reference.summary());
            let expected_display: Vec<_> = reference
                .rows
                .iter()
                .enumerate()
                .filter_map(|(index, row)| {
                    matches!(
                        row.class,
                        ImportClass::Conflict { .. }
                            | ImportClass::LocallyDeleted { .. }
                            | ImportClass::UpdateCandidate { .. }
                    )
                    .then_some(index)
                })
                .collect();
            assert_eq!(indexed.display_rows(), expected_display);
            for (index, row) in reference.rows.iter().enumerate() {
                let (ids, deleted) = match &row.class {
                    ImportClass::Conflict { existing_ids } => (existing_ids.as_slice(), false),
                    ImportClass::LocallyDeleted { existing_ids } => (existing_ids.as_slice(), true),
                    _ => (&[][..], false),
                };
                let expected_candidates: Vec<_> = ids
                    .iter()
                    .copied()
                    .filter(|id| {
                        vault
                            .entries()
                            .iter()
                            .any(|entry| entry.id == *id && entry.is_deleted() == deleted)
                    })
                    .collect();
                assert_eq!(
                    indexed.rows[index].resolution_candidate_ids(),
                    expected_candidates
                );
                for &id in ids {
                    assert_eq!(
                        indexed.allows_resolution(index, &ConflictResolution::UseImported(id)),
                        expected_candidates.contains(&id)
                    );
                }
            }
            assert_eq!(indexed.exact_dependencies, reference.exact_dependencies);
            assert_eq!(
                indexed.unresolved_count(),
                indexed.summary.conflicts + indexed.summary.locally_deleted
            );
            for (left, right) in indexed.rows.iter().zip(&reference.rows) {
                assert_eq!(left.item, right.item);
            }
            let mut indexed_options = ImportApplyOptions::for_preview(&indexed);
            indexed_options.apply_update_candidates = round % 2 == 0;
            let mut reference_options = ImportApplyOptions::for_preview(&reference);
            reference_options.apply_update_candidates = indexed_options.apply_update_candidates;
            for (row, entry) in indexed.rows.iter().enumerate() {
                if matches!(
                    entry.class,
                    ImportClass::Conflict { .. } | ImportClass::LocallyDeleted { .. }
                ) {
                    let choice = if (row + round) % 3 == 0 {
                        ConflictResolution::KeepBoth
                    } else {
                        ConflictResolution::KeepLocal
                    };
                    indexed_options
                        .conflict_resolutions
                        .insert(row, choice.clone());
                    reference_options.conflict_resolutions.insert(row, choice);
                }
            }
            let prepared =
                prepare_application_with(&mut vault, &indexed, &indexed_options, &mut || Ok(()))
                    .unwrap_or_else(|_| panic!("indexed application"));
            let report = prepared.report;
            let semantics = semantic_entries(&vault);
            let mut history = vault.body().import_history.clone();
            for record in &mut history {
                record.imported_at_unix = 0;
            }
            prepared.restore_original(&mut vault).unwrap();
            let prepared = prepare_application_with(
                &mut vault,
                &reference,
                &reference_options,
                &mut || Ok(()),
            )
            .unwrap_or_else(|_| panic!("reference application"));
            assert_eq!(report, prepared.report);
            assert_eq!(semantics, semantic_entries(&vault));
            let mut reference_history = vault.body().import_history.clone();
            for record in &mut reference_history {
                record.imported_at_unix = 0;
            }
            assert_eq!(history, reference_history);
            prepared.restore_original(&mut vault).unwrap();
        }
    }

    fn priority_source(position: usize) -> NormalizedImportItem {
        let mut incoming = item(&format!("strong-{position}"), "其他");
        incoming.name = format!("Synthetic strong {position}");
        incoming.website = "https://shared.example.test/login".into();
        incoming.username = "shared-user".into();
        incoming.password = format!("synthetic-only-{position}");
        incoming.fingerprint = content_fingerprint(
            &incoming.name,
            &incoming.website,
            &incoming.username,
            &incoming.password,
            &incoming.notes,
            &incoming.category,
            incoming.favorite,
        );
        incoming
    }
    fn priority_snapshot(
        id: u128,
        provider: &str,
        stable_id: Option<&str>,
        fingerprint: [u8; 32],
        deleted: bool,
    ) -> ExistingSnapshot {
        ExistingSnapshot {
            id: Uuid::from_u128(id),
            weak_key: weak_identity_key("https://shared.example.test/login", "shared-user"),
            fingerprint,
            legacy_fingerprint: None,
            provenance: Some(ImportProvenance {
                provider: provider.into(),
                source_stable_id: stable_id.map(str::to_owned),
                last_import_fingerprint: fingerprint,
                last_imported_at_unix: 0,
                source_digest: None,
            }),
            deleted,
        }
    }

    #[test]
    fn controlled_import_priority_shared_weak_exact_reimports_have_linear_work() {
        let mut measured = Vec::new();
        for n in [64usize, 128, 256] {
            let incoming: Vec<_> = (0..n).map(priority_source).collect();
            let existing: Vec<_> = incoming
                .iter()
                .enumerate()
                .map(|(position, row)| {
                    priority_snapshot(
                        position as u128 + 1,
                        &row.provider,
                        row.source_stable_id.as_deref(),
                        row.fingerprint,
                        false,
                    )
                })
                .collect();
            let index = ExistingIndex::new(&existing);
            let reference: Vec<_> = incoming
                .iter()
                .map(|row| classify_item_reference(row, &existing))
                .collect();
            CLASSIFIER_EXAMINED.with(|count| count.set(0));
            CLASSIFIER_INDEX_WORK.with(|count| count.set(ClassifierIndexWork::default()));
            let actual: Vec<_> = incoming
                .iter()
                .map(|row| classify_item_indexed(row, &existing, &index))
                .collect();
            assert_eq!(actual, reference);
            assert_eq!(actual.len(), n);
            assert!(
                actual
                    .iter()
                    .all(|class| matches!(class, ImportClass::ExactDuplicate { .. }))
            );
            let work = CLASSIFIER_INDEX_WORK.with(|count| count.get());
            let predicates = CLASSIFIER_EXAMINED.with(|count| count.get());
            println!(
                "shared_weak_exact,n={n},strong_visits={},unscoped_visits={},fingerprint_visits={},weak_visits={},fingerprint_probes={},materialized={},predicates={predicates}",
                work.strong_visits,
                work.unscoped_visits,
                work.fingerprint_visits,
                work.weak_visits,
                work.fingerprint_probes,
                work.materialized
            );
            measured.push((n, work, predicates));
        }
        for (n, work, predicates) in measured {
            assert_eq!(
                work.weak_visits, 0,
                "strong priority must not enumerate the shared weak bucket; n={n}"
            );
            assert_eq!(
                work.fingerprint_visits, 0,
                "strong priority must not materialize lower fingerprint tier"
            );
            assert_eq!(
                work.fingerprint_probes, 0,
                "strong priority must not probe lower fingerprint tier"
            );
            assert_eq!(work.strong_visits, n);
            assert_eq!(work.unscoped_visits, 0);
            assert_eq!(work.materialized, n);
            assert_eq!(predicates, n);
        }
    }

    #[test]
    fn controlled_import_priority_original_precedence_legacy_duplicates_differential() {
        let mut incoming = priority_source(0);
        incoming.provider = "legacy-passwords-db".into();
        incoming.source_stable_id = Some("db:namespace:entry:7".into());
        incoming.fingerprint = [4; 32];
        let snapshot = |id, stable, fingerprint, deleted| {
            priority_snapshot(id, "legacy-passwords-db", stable, fingerprint, deleted)
        };
        let cases = vec![
            // Lower legacy tier and weak rows occur before authoritative scoped row.
            (
                incoming.clone(),
                vec![
                    snapshot(90, Some("entry:7"), [6; 32], false),
                    snapshot(50, Some("unrelated"), [4; 32], false),
                    snapshot(7, Some("db:namespace:entry:7"), [4; 32], false),
                ],
                ImportClass::ExactDuplicate {
                    existing_id: Uuid::from_u128(7),
                },
            ),
            (
                incoming.clone(),
                vec![
                    snapshot(90, Some("entry:7"), [4; 32], false),
                    snapshot(7, Some("db:namespace:entry:7"), [4; 32], true),
                ],
                ImportClass::LocallyDeleted {
                    existing_ids: vec![Uuid::from_u128(7)],
                },
            ),
            // Repeated physical rows/UUIDs remain ordered and complete.
            (
                incoming.clone(),
                vec![
                    snapshot(90, Some("entry:7"), [4; 32], false),
                    snapshot(7, Some("db:namespace:entry:7"), [4; 32], true),
                    snapshot(7, Some("db:namespace:entry:7"), [9; 32], false),
                ],
                ImportClass::Conflict {
                    existing_ids: vec![Uuid::from_u128(7), Uuid::from_u128(7)],
                },
            ),
            (
                incoming.clone(),
                vec![
                    snapshot(101, Some("entry:7"), [4; 32], true),
                    snapshot(50, Some("unrelated"), [4; 32], false),
                    snapshot(7, Some("entry:7"), [9; 32], false),
                    snapshot(101, Some("entry:7"), [4; 32], true),
                ],
                ImportClass::Conflict {
                    existing_ids: vec![
                        Uuid::from_u128(101),
                        Uuid::from_u128(7),
                        Uuid::from_u128(101),
                    ],
                },
            ),
            (
                incoming.clone(),
                vec![
                    snapshot(50, None, [4; 32], false),
                    snapshot(7, Some("entry:7"), [9; 32], false),
                ],
                ImportClass::Conflict {
                    existing_ids: vec![Uuid::from_u128(7)],
                },
            ),
            (
                incoming.clone(),
                vec![
                    snapshot(101, Some("unrelated"), [4; 32], false),
                    snapshot(50, None, [4; 32], true),
                    snapshot(7, None, [4; 32], false),
                    snapshot(3, None, [4; 32], false),
                ],
                ImportClass::ExactDuplicate {
                    existing_id: Uuid::from_u128(7),
                },
            ),
            (
                incoming.clone(),
                vec![
                    snapshot(101, None, [4; 32], true),
                    snapshot(50, Some("unrelated"), [4; 32], false),
                    snapshot(7, None, [4; 32], true),
                    snapshot(101, None, [4; 32], true),
                ],
                ImportClass::LocallyDeleted {
                    existing_ids: vec![
                        Uuid::from_u128(101),
                        Uuid::from_u128(7),
                        Uuid::from_u128(101),
                    ],
                },
            ),
            // Fingerprint matches are incompatible: weak fallback must still occur.
            (
                incoming.clone(),
                vec![
                    snapshot(101, Some("unrelated"), [4; 32], false),
                    snapshot(50, None, [9; 32], true),
                    snapshot(7, Some("other"), [4; 32], false),
                ],
                ImportClass::Conflict {
                    existing_ids: vec![Uuid::from_u128(101), Uuid::from_u128(7)],
                },
            ),
            {
                let mut unscoped = incoming.clone();
                unscoped.source_stable_id = Some("entry:7".into());
                (
                    unscoped,
                    vec![snapshot(7, Some("entry:7"), [9; 32], false)],
                    ImportClass::Conflict {
                        existing_ids: vec![Uuid::from_u128(7)],
                    },
                )
            },
        ];
        for (case, (row, existing, expected)) in cases.into_iter().enumerate() {
            let reference = classify_item_reference(&row, &existing);
            assert_eq!(
                reference, expected,
                "independent original precedence fixture {case}"
            );
            let index = ExistingIndex::new(&existing);
            assert_eq!(
                classify_item_indexed(&row, &existing, &index),
                reference,
                "indexed precedence and physical candidate order {case}"
            );
        }
    }

    #[test]
    fn controlled_import_priority_full_preview_body_provenance_differential() {
        let dir = tempfile::tempdir().unwrap();
        let mut vault =
            VaultSession::create(dir.path().join("vault.pmvault"), "synthetic-master").unwrap();
        let mut sources: Vec<_> = (0..24).map(priority_source).collect();
        for source in &sources {
            vault.add_entry(import_draft(source, [1; 32], 123)).unwrap();
        }
        sources.push(sources[3].clone());
        let baseline = vault.snapshot_body();
        let reference =
            build_preview_reference_with(&vault, batch(sources.clone(), 2), &mut || Ok(()))
                .unwrap_or_else(|_| panic!("reference priority preview"));
        CLASSIFIER_INDEX_WORK.with(|count| count.set(ClassifierIndexWork::default()));
        let actual = build_preview(&vault, batch(sources, 2)).unwrap();
        let work = CLASSIFIER_INDEX_WORK.with(|count| count.get());
        assert_eq!(preview_classes(&actual), preview_classes(&reference));
        assert_eq!(actual.summary(), reference.summary());
        assert_eq!(actual.display_rows(), reference.display_rows());
        assert_eq!(actual.exact_dependencies, reference.exact_dependencies);
        assert_eq!(actual.body, reference.body);
        assert_eq!(actual.body, baseline);
        assert_eq!(
            actual.rows[24].class,
            ImportClass::SourceDuplicate { original_row: 3 }
        );
        for (left, right) in actual.rows.iter().zip(&reference.rows) {
            assert_eq!(left.item, right.item);
            assert_eq!(
                left.resolution_candidate_ids,
                right.resolution_candidate_ids
            );
        }
        let actual_options = ImportApplyOptions::for_preview(&actual);
        let prepared =
            prepare_application_with(&mut vault, &actual, &actual_options, &mut || Ok(()))
                .unwrap_or_else(|_| panic!("indexed priority preparation"));
        let report = prepared.report;
        assert_eq!(report.skipped, 25);
        assert_eq!(vault.body().entries, baseline.entries);
        let mut actual_body = vault.snapshot_body();
        for record in &mut actual_body.import_history {
            record.imported_at_unix = 0;
        }
        prepared.restore_original(&mut vault).unwrap();
        let reference_options = ImportApplyOptions::for_preview(&reference);
        let prepared =
            prepare_application_with(&mut vault, &reference, &reference_options, &mut || Ok(()))
                .unwrap_or_else(|_| panic!("reference priority preparation"));
        assert_eq!(report, prepared.report);
        let mut reference_body = vault.snapshot_body();
        for record in &mut reference_body.import_history {
            record.imported_at_unix = 0;
        }
        assert_eq!(actual_body, reference_body);
        prepared.restore_original(&mut vault).unwrap();
        assert_eq!(vault.body(), &baseline);
        assert_eq!(
            work.weak_visits, 0,
            "full strong preview must not prepare all shared weak candidates"
        );
        assert_eq!(work.materialized, 25);
    }

    #[test]
    #[ignore = "release shared-weak exact strong-ID classifier hotspot measurements"]
    fn perf_background_import_priority_shared_weak_exact_repeat() {
        use std::time::Instant;
        if cfg!(debug_assertions) {
            panic!("run with --release");
        }

        let memory_kib = || {
            let status = std::fs::read_to_string("/proc/self/status").unwrap_or_default();
            let read = |label: &str| {
                status.lines().find_map(|line| {
                    line.strip_prefix(label)
                        .and_then(|value| value.split_whitespace().next())
                        .and_then(|value| value.parse::<u64>().ok())
                })
            };
            (read("VmRSS:"), read("VmHWM:"))
        };
        let isolated_filter = std::env::args().any(|argument| {
            argument == "perf_background_import_priority_shared_weak_exact_repeat"
                || argument
                    == "import::plan::tests::perf_background_import_priority_shared_weak_exact_repeat"
        });
        let output = std::path::Path::new("target/background-perf");
        std::fs::create_dir_all(output).unwrap();
        let mut lines = vec![
            import_performance_environment(),
            format!(
                "operation=indexed_classifier_N_rows,scenario=distinct_strong_ids_shared_existing_weak_key_exact_repeat,isolated_test_filter={isolated_filter},warmups=3,samples=10,reference_probes_per_size=16,index_build_timed_separately=true,rss_scope=entire_test_process,peak_scope=entire_test_process_cumulative,bytes_scope=logical_fixture_utf8_and_shallow_vec_storage,no_kdf_or_save=true"
            ),
        ];
        for n in [1_000usize, 10_000, 50_000] {
            let memory_before = memory_kib();
            let incoming: Vec<_> = (0..n).map(priority_source).collect();
            let existing: Vec<_> = incoming
                .iter()
                .enumerate()
                .map(|(position, row)| {
                    priority_snapshot(
                        position as u128 + 1,
                        &row.provider,
                        row.source_stable_id.as_deref(),
                        row.fingerprint,
                        false,
                    )
                })
                .collect();
            let normalized_utf8_bytes: usize = incoming
                .iter()
                .map(|row| {
                    row.provider.len()
                        + row.source_stable_id.as_ref().map_or(0, String::len)
                        + row.name.len()
                        + row.website.len()
                        + row.username.len()
                        + row.password.len()
                        + row.notes.len()
                        + row.category.len()
                })
                .sum();
            let snapshot_utf8_bytes: usize = existing
                .iter()
                .map(|row| {
                    row.weak_key.0.len()
                        + row.weak_key.1.len()
                        + row.provenance.as_ref().map_or(0, |provenance| {
                            provenance.provider.len()
                                + provenance.source_stable_id.as_ref().map_or(0, String::len)
                        })
                })
                .sum();
            let fixture_vec_storage_bytes = incoming.capacity()
                * std::mem::size_of::<NormalizedImportItem>()
                + existing.capacity() * std::mem::size_of::<ExistingSnapshot>();
            let started = Instant::now();
            let index = ExistingIndex::new(&existing);
            let index_build_ns = started.elapsed().as_nanos();
            assert_eq!(index.strong.len(), n);
            assert_eq!(index.fingerprint.len(), n);
            assert_eq!(index.weak.len(), 1);
            assert_eq!(index.weak.values().next().unwrap().len(), n);
            let index_position_capacity_bytes = index
                .strong
                .values()
                .chain(index.weak.values())
                .chain(index.fingerprint.values())
                .map(|positions| positions.capacity() * std::mem::size_of::<usize>())
                .sum::<usize>();
            // Bounded independent reference work includes first/last and evenly
            // spaced rows; every measured result is also checked by its exact ID.
            for probe in 0..16 {
                let position = probe * (n - 1) / 15;
                assert_eq!(
                    classify_item_indexed(&incoming[position], &existing, &index),
                    classify_item_reference(&incoming[position], &existing),
                    "reference size={n},position={position}"
                );
            }
            let memory_ready = memory_kib();
            lines.push(format!(
                "fixture,entries={n},rows={n},shared_weak_bucket_len={n},normalized_utf8_bytes={normalized_utf8_bytes},snapshot_utf8_bytes={snapshot_utf8_bytes},fixture_vec_storage_bytes={fixture_vec_storage_bytes},index_position_capacity_bytes={index_position_capacity_bytes},index_build_ns={index_build_ns},memory_before_rss_hwm_kib={memory_before:?},memory_ready_rss_hwm_kib={memory_ready:?},byte_counts_exclude_allocator_and_tree_node_overhead=true"
            ));
            println!("{}", lines.last().unwrap());
            let mut measured_ns = Vec::with_capacity(10);
            let mut warmup_ns = Vec::with_capacity(3);
            for run in 0..13 {
                CLASSIFIER_EXAMINED.with(|count| count.set(0));
                CLASSIFIER_INDEX_WORK.with(|count| count.set(ClassifierIndexWork::default()));
                let memory_before_run = memory_kib();
                let started = Instant::now();
                let classes: Vec<_> = incoming
                    .iter()
                    .map(|row| classify_item_indexed(row, &existing, &index))
                    .collect();
                let elapsed_ns = started.elapsed().as_nanos();
                let work = CLASSIFIER_INDEX_WORK.with(|count| count.get());
                let predicates = CLASSIFIER_EXAMINED.with(|count| count.get());
                let memory_with_output = memory_kib();
                for (position, class) in classes.iter().enumerate() {
                    assert_eq!(
                        class,
                        &ImportClass::ExactDuplicate {
                            existing_id: Uuid::from_u128(position as u128 + 1)
                        }
                    );
                }
                assert_eq!(work.strong_visits, n);
                assert_eq!(work.unscoped_visits, 0);
                assert_eq!(work.fingerprint_visits, 0);
                assert_eq!(work.fingerprint_probes, 0);
                assert_eq!(work.weak_visits, 0);
                assert_eq!(work.materialized, n);
                assert_eq!(predicates, n);
                let output_vec_storage_bytes =
                    classes.capacity() * std::mem::size_of::<ImportClass>();
                drop(classes);
                let memory_after_drop = memory_kib();
                let (kind, sample) = if run < 3 {
                    warmup_ns.push(elapsed_ns);
                    ("warmup", run)
                } else {
                    measured_ns.push(elapsed_ns);
                    ("measured", run - 3)
                };
                lines.push(format!(
                    "run,kind={kind},entries={n},rows={n},sample={sample},elapsed_ns={elapsed_ns},bucket_visits={},strong_visits={},unscoped_visits={},fingerprint_visits={},weak_visits={},fingerprint_probes={},materialized={},predicates={predicates},output_vec_storage_bytes={output_vec_storage_bytes},memory_before_rss_hwm_kib={memory_before_run:?},memory_with_output_rss_hwm_kib={memory_with_output:?},memory_after_drop_rss_hwm_kib={memory_after_drop:?}",
                    work.strong_visits + work.unscoped_visits + work.fingerprint_visits + work.weak_visits,
                    work.strong_visits, work.unscoped_visits, work.fingerprint_visits,
                    work.weak_visits, work.fingerprint_probes, work.materialized,
                ));
                println!("{}", lines.last().unwrap());
            }
            assert_eq!(warmup_ns.len(), 3);
            assert_eq!(measured_ns.len(), 10);
            lines.push(format!(
                "raw_timings,entries={n},warmup_ns={warmup_ns:?},measured_ns={measured_ns:?}"
            ));
            std::fs::write(
                output.join("import-priority-shared-weak-exact-repeat.txt"),
                lines.join("\n"),
            )
            .unwrap();
        }
    }

    #[test]
    fn controlled_import_indexed_mostly_new_has_no_full_snapshot_scan() {
        let n = 2000;
        let existing: Vec<_> = (0..n)
            .map(|position| ExistingSnapshot {
                id: Uuid::from_u128(position as u128 + 1),
                weak_key: (format!("existing-{position}"), "user".into()),
                fingerprint: [1; 32],
                legacy_fingerprint: None,
                provenance: None,
                deleted: false,
            })
            .collect();
        let index = ExistingIndex::new(&existing);
        CLASSIFIER_EXAMINED.with(|count| count.set(0));
        for position in 0..n {
            let mut incoming = item(&format!("new-{position}"), "category");
            incoming.fingerprint = [2; 32];
            assert_eq!(
                classify_item_indexed(&incoming, &existing, &index),
                ImportClass::New
            );
        }
        assert_eq!(CLASSIFIER_EXAMINED.with(|count| count.get()), 0);
    }

    fn import_performance_environment() -> String {
        let head = std::fs::read_to_string(".git/HEAD")
            .ok()
            .and_then(|head| {
                if let Some(reference) = head.trim().strip_prefix("ref: ") {
                    std::fs::read_to_string(std::path::Path::new(".git").join(reference)).ok()
                } else {
                    Some(head)
                }
            })
            .unwrap_or_else(|| "unavailable; see parent exact-SHA record".into());
        let lock = std::fs::read("Cargo.lock")
            .map(|bytes| {
                crate::security::sha256(&bytes)
                    .iter()
                    .map(|byte| format!("{byte:02x}"))
                    .collect::<String>()
            })
            .unwrap_or_else(|_| "unavailable".into());
        let cpu = std::fs::read_to_string("/proc/cpuinfo").unwrap_or_default();
        let model = cpu
            .lines()
            .find(|line| line.starts_with("model name"))
            .unwrap_or("unavailable");
        let cores = cpu
            .lines()
            .filter(|line| line.starts_with("processor"))
            .count();
        let memory = std::fs::read_to_string("/proc/meminfo").unwrap_or_default();
        let ram = memory
            .lines()
            .find(|line| line.starts_with("MemTotal:"))
            .unwrap_or("unavailable");
        let kernel = std::fs::read_to_string("/proc/sys/kernel/osrelease")
            .unwrap_or_else(|_| "unavailable".into());
        let mut source = sha2::Sha256::default();
        for path in [
            "src/import/mod.rs",
            "src/import/csv.rs",
            "src/import/legacy.rs",
            "src/import/plan.rs",
        ] {
            sha2::Digest::update(&mut source, path.as_bytes());
            if let Ok(bytes) = std::fs::read(path) {
                sha2::Digest::update(&mut source, bytes);
            }
        }
        let source_hash = sha2::Digest::finalize(source)
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>();
        format!(
            "head={},working_import_source_sha256={source_hash},lock_sha256={lock},os={},arch={},kernel={},visible_processors={cores},{model},{ram},release={},rustup_toolchain={},max_import_bytes={}",
            head.trim(),
            std::env::consts::OS,
            std::env::consts::ARCH,
            kernel.trim(),
            !cfg!(debug_assertions),
            option_env!("RUSTUP_TOOLCHAIN").unwrap_or("see parent toolchain record"),
            crate::import::MAX_IMPORT_BYTES
        )
    }

    #[test]
    #[ignore = "synthetic 1k/10k/50k indexed analysis measurements; not UI frame evidence"]
    fn perf_background_import_indexed_analysis() {
        use std::time::Instant;
        let dir = tempfile::tempdir().unwrap();
        let started = Instant::now();
        let mut vault =
            VaultSession::create(dir.path().join("vault.pmvault"), "synthetic-master").unwrap();
        let create_us = started.elapsed().as_micros();
        let mut fixtures = Vec::new();
        for n in 0..50_000 {
            let mut source = item(&format!("existing-{n}"), "其他");
            source.name = format!("Synthetic {n}");
            source.password = format!("synthetic-password-{n}");
            if n % 100 == 0 {
                source.notes = "Long Unicode 👩🏽‍💻 备注 空格  ".repeat(40);
            }
            source.fingerprint = content_fingerprint(
                &source.name,
                &source.website,
                &source.username,
                &source.password,
                &source.notes,
                &source.category,
                source.favorite,
            );
            vault
                .add_entry(import_draft(&source, [1; 32], 123))
                .unwrap();
            fixtures.push(source);
        }
        let complete = vault.snapshot_body();
        let output = std::path::Path::new("target/background-perf");
        std::fs::create_dir_all(output).unwrap();
        let mut lines = vec![
            import_performance_environment(),
            format!(
                "default_create_us={create_us},kdf_memory_kib=65536,kdf_iterations=3,kdf_parallelism=1,warmups=3,samples=10"
            ),
        ];
        for size in [1_000usize, 10_000, 50_000] {
            let mut body = complete.clone();
            body.entries.truncate(size);
            vault.restore_body(body);
            for kind in [
                "mostly_new",
                "exact_repeat",
                "mixed_deleted_conflict",
                "repeated_weak",
            ] {
                let mut sources = fixtures[..size].to_vec();
                if kind == "mostly_new" {
                    for (n, source) in sources.iter_mut().enumerate() {
                        source.source_stable_id = Some(format!("new-{n}"));
                        source.website = format!("https://new-{n}.example.test");
                        source.password.push_str("-new");
                    }
                }
                if kind == "mixed_deleted_conflict" {
                    for (n, source) in sources.iter_mut().enumerate() {
                        if n % 5 == 0 {
                            vault.body_mut().entries[n].deleted_at_unix = Some(123);
                        }
                        if n % 3 == 0 {
                            source.password.push_str("-imported");
                        }
                        if n % 7 == 0 {
                            vault.body_mut().entries[n]
                                .provenance
                                .as_mut()
                                .unwrap()
                                .last_import_fingerprint = [0; 32];
                        }
                    }
                }
                if kind == "repeated_weak" {
                    for (n, source) in sources.iter_mut().enumerate() {
                        source.source_stable_id = None;
                        source.website = "https://repeated.example.test".into();
                        source.password = format!("synthetic-distinct-{n}");
                    }
                }
                let bytes: usize = sources
                    .iter()
                    .map(|item| {
                        item.name.len()
                            + item.website.len()
                            + item.username.len()
                            + item.password.len()
                            + item.notes.len()
                            + item.category.len()
                    })
                    .sum();
                for _ in 0..3 {
                    drop(build_preview(&vault, batch(sources.clone(), 2)).unwrap());
                }
                let mut timings = Vec::new();
                let mut predicate_counts = Vec::new();
                let mut resolution_ns = 0;
                for _ in 0..10 {
                    CLASSIFIER_EXAMINED.with(|count| count.set(0));
                    let started = Instant::now();
                    let preview = build_preview(&vault, batch(sources.clone(), 2)).unwrap();
                    timings.push(started.elapsed().as_micros());
                    predicate_counts.push(CLASSIFIER_EXAMINED.with(|count| count.get()));
                    let started = Instant::now();
                    for _ in 0..1000 {
                        std::hint::black_box(preview.summary());
                        std::hint::black_box(preview.unresolved_count());
                        std::hint::black_box(
                            preview.allows_resolution(size / 2, &ConflictResolution::KeepLocal),
                        );
                    }
                    resolution_ns += started.elapsed().as_nanos();
                    drop(preview);
                }
                let peak = std::fs::read_to_string("/proc/self/status")
                    .ok()
                    .and_then(|text| {
                        text.lines()
                            .find(|line| line.starts_with("VmHWM:"))
                            .map(str::to_owned)
                    })
                    .unwrap_or_else(|| "unavailable".into());
                lines.push(format!("kind={kind},entries={size},rows={size},logical_field_bytes={bytes},sample_us={timings:?},candidate_predicates={predicate_counts:?},cached_summary_resolution_1000x10_ns={resolution_ns},process_peak={peak}"));
                println!("{}", lines.last().unwrap());
                // Restore the baseline before the next scenario.
                let mut body = complete.clone();
                body.entries.truncate(size);
                vault.restore_body(body);
            }
        }
        std::fs::write(output.join("import-indexed-analysis.txt"), lines.join("\n")).unwrap();
    }

    #[test]
    fn controlled_import_reconciliation_checks_each_row() {
        let mut rows: Vec<_> = (0..10)
            .map(|position| ImportPreviewRow {
                item: item(&format!("synthetic-{position}"), "category"),
                class: ImportClass::ExactDuplicate {
                    existing_id: Uuid::from_u128(1),
                },
                resolution_candidates: BTreeSet::new(),
                resolution_candidate_ids: Vec::new(),
            })
            .collect();
        let mut checks = 0;
        let result = reconcile_exact_matches_with(&mut rows, &mut || {
            checks += 1;
            if checks == 2 {
                Err(WorkError::Cancelled)
            } else {
                Ok(())
            }
        });
        assert!(matches!(result, Err(WorkError::Cancelled)));
    }
    #[test]
    fn controlled_import_metadata_checks_each_row() {
        let mut rows: Vec<_> = (0..10)
            .map(|position| ImportPreviewRow {
                item: item(&format!("synthetic-{position}"), "category"),
                class: ImportClass::New,
                resolution_candidates: BTreeSet::new(),
                resolution_candidate_ids: Vec::new(),
            })
            .collect();
        let mut checks = 0;
        let result = preview_metadata_with(&mut rows, 0, &mut || {
            checks += 1;
            if checks == 2 {
                Err(WorkError::Cancelled)
            } else {
                Ok(())
            }
        });
        assert!(matches!(result, Err(WorkError::Cancelled)));
    }
    #[test]
    fn controlled_import_cancel_at_every_application_checkpoint_restores_body() {
        let dir = tempfile::tempdir().unwrap();
        let mut vault =
            VaultSession::create(dir.path().join("vault.pmvault"), "synthetic-master").unwrap();
        let baseline = vault.snapshot_body();
        let disk = fs::read(vault.path()).unwrap();
        let revision = vault.revision();
        let preview = build_preview(
            &vault,
            batch(
                (0..12)
                    .map(|n| item(&format!("new-{n}"), "category"))
                    .collect(),
                1,
            ),
        )
        .unwrap();
        let options = ImportApplyOptions::for_preview(&preview);
        let mut count = 0;
        let prepared = prepare_application_with(&mut vault, &preview, &options, &mut || {
            count += 1;
            Ok(())
        })
        .unwrap_or_else(|_| panic!("baseline preparation"));
        prepared.restore_original(&mut vault).unwrap();
        for stop in 1..=count {
            let mut checks = 0;
            assert!(
                matches!(
                    prepare_application_with(&mut vault, &preview, &options, &mut || {
                        checks += 1;
                        if checks == stop {
                            Err(WorkError::Cancelled)
                        } else {
                            Ok(())
                        }
                    }),
                    Err(WorkError::Cancelled)
                ),
                "checkpoint {stop}"
            );
            assert_eq!(vault.body(), &baseline);
            assert_eq!(vault.revision(), revision);
            assert_eq!(fs::read(vault.path()).unwrap(), disk);
        }
    }
    #[test]
    #[ignore = "fresh-process synthetic near/exact/over real 64 MiB source staging measurements"]
    fn perf_background_import_actual_source_limit() {
        use std::{fs::OpenOptions, io::Write, time::Instant};
        use zeroize::Zeroizing;
        const PREFIX:&[u8]=b"name,url,username,password,notes\nSynthetic,https://synthetic.example.test,user,synthetic-password,\"";
        const SUFFIX: &[u8] = b"\"\n";
        const UNIT: &str = "长备注 👩🏽‍💻 café 空格  \n";
        let dir = tempfile::tempdir().unwrap();
        let isolated_filter = std::env::args().any(|argument| {
            argument == "perf_background_import_actual_source_limit"
                || argument == "import::plan::tests::perf_background_import_actual_source_limit"
        });
        let mut lines = vec![
            import_performance_environment(),
            format!(
                "isolated_test_filter={isolated_filter},warmups=3,samples=10,operation=stage_path_csv,rows=1,unicode_notes=true,peak_scope=entire_test_process_cumulative"
            ),
        ];
        for (name, target) in [
            ("near", crate::import::MAX_IMPORT_BYTES - 32_768),
            ("exact", crate::import::MAX_IMPORT_BYTES),
            ("over", crate::import::MAX_IMPORT_BYTES + 1),
        ] {
            let path = dir.path().join(format!("{name}.csv"));
            let mut output = OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&path)
                .unwrap();
            output.write_all(PREFIX).unwrap();
            let note_bytes = target - PREFIX.len() as u64 - SUFFIX.len() as u64;
            let chunk = Zeroizing::new(UNIT.repeat((32 * 1024) / UNIT.len()).into_bytes());
            let mut remaining = note_bytes;
            while remaining >= chunk.len() as u64 {
                output.write_all(&chunk).unwrap();
                remaining -= chunk.len() as u64;
            }
            while remaining >= UNIT.len() as u64 {
                output.write_all(UNIT.as_bytes()).unwrap();
                remaining -= UNIT.len() as u64;
            }
            let padding = Zeroizing::new(vec![b'n'; remaining as usize]);
            output.write_all(&padding).unwrap();
            output.write_all(SUFFIX).unwrap();
            output.sync_all().unwrap();
            drop(output);
            assert_eq!(std::fs::metadata(&path).unwrap().len(), target);
            let mut samples = Vec::new();
            for sample in 0..13 {
                let started = Instant::now();
                let outcome = crate::import::stage_path(&path, None);
                let elapsed = started.elapsed().as_micros();
                if target <= crate::import::MAX_IMPORT_BYTES {
                    let batch = outcome.unwrap();
                    assert_eq!(batch.items.len(), 1);
                    assert_eq!(batch.items[0].notes.len() as u64, note_bytes);
                    assert!(batch.items[0].notes.starts_with(UNIT));
                    assert_eq!(batch.items[0].password, "synthetic-password");
                    drop(batch);
                } else {
                    assert!(
                        matches!(outcome, Err(AppError::Input(_))),
                        "real cap+1 must reject before parser adoption"
                    );
                }
                if sample >= 3 {
                    samples.push(elapsed);
                }
            }
            let peak = std::fs::read_to_string("/proc/self/status")
                .ok()
                .and_then(|text| {
                    text.lines()
                        .find(|line| line.starts_with("VmHWM:"))
                        .map(str::to_owned)
                })
                .unwrap_or_else(|| "unavailable".into());
            lines.push(format!("fixture={name},actual_file_bytes={target},raw_and_parsed_unicode_note_bytes_if_accepted={note_bytes},rows_if_accepted=1,accepted={},stage_sample_us={samples:?},test_process_peak_so_far={peak}",target<=crate::import::MAX_IMPORT_BYTES));
            println!("{}", lines.last().unwrap());
        }
        let output = std::path::Path::new("target/background-perf");
        std::fs::create_dir_all(output).unwrap();
        std::fs::write(output.join("import-source-limit.txt"), lines.join("\n")).unwrap();
    }
    #[test]
    fn controlled_import_display_rows_cache_keeps_original_order() {
        let dir = tempfile::tempdir().unwrap();
        let mut vault =
            VaultSession::create(dir.path().join("vault.pmvault"), "synthetic-master").unwrap();
        let mut sources: Vec<_> = (0..4)
            .map(|n| item(&format!("existing-{n}"), "其他"))
            .collect();
        for source in &mut sources {
            source.fingerprint = content_fingerprint(
                &source.name,
                &source.website,
                &source.username,
                &source.password,
                &source.notes,
                &source.category,
                source.favorite,
            );
            vault.add_entry(import_draft(source, [1; 32], 123)).unwrap();
        }
        let deleted = vault.entries()[2].id;
        vault.move_to_recycle_bin(deleted).unwrap();
        vault.body_mut().entries[1]
            .provenance
            .as_mut()
            .unwrap()
            .last_import_fingerprint = [0; 32];
        sources[0].password.push_str("-imported");
        sources[1].password.push_str("-imported");
        sources.push(item("new", "其他"));
        let preview = build_preview(&vault, batch(sources, 2)).unwrap();
        let expected: Vec<_> = preview
            .rows
            .iter()
            .enumerate()
            .filter_map(|(index, row)| {
                matches!(
                    row.class,
                    ImportClass::Conflict { .. }
                        | ImportClass::LocallyDeleted { .. }
                        | ImportClass::UpdateCandidate { .. }
                )
                .then_some(index)
            })
            .collect();
        assert_eq!(expected, vec![0, 1, 2]);
        assert_eq!(preview.display_rows(), expected);
    }
    #[test]
    fn controlled_import_resolution_candidate_ids_cache_keeps_original_order() {
        let original_ids = vec![
            Uuid::from_u128(101),
            Uuid::from_u128(3),
            Uuid::from_u128(50),
            Uuid::from_u128(7),
        ];
        let mut rows = vec![ImportPreviewRow {
            item: item("synthetic", "category"),
            class: ImportClass::Conflict {
                existing_ids: original_ids.clone(),
            },
            resolution_candidates: BTreeSet::new(),
            resolution_candidate_ids: Vec::new(),
        }];
        // The preview's trusted body state denies the deleted candidate, without
        // sorting or changing the remaining old-classifier candidate order.
        let body_index: BTreeMap<_, _> = original_ids
            .iter()
            .copied()
            .map(|id| (id, BodyEntryState::new(id == Uuid::from_u128(3))))
            .collect();
        fill_resolution_candidate_ids(&mut rows, &body_index, &mut || Ok(()))
            .unwrap_or_else(|_| panic!("candidate cache"));
        assert_eq!(
            rows[0].resolution_candidate_ids(),
            &[
                Uuid::from_u128(101),
                Uuid::from_u128(50),
                Uuid::from_u128(7)
            ]
        );
    }
    fn duplicate_uuid_base(vault: &mut VaultSession) -> VaultBody {
        let mut source = item("duplicate", "其他");
        source.fingerprint = content_fingerprint(
            &source.name,
            &source.website,
            &source.username,
            &source.password,
            &source.notes,
            &source.category,
            source.favorite,
        );
        vault
            .add_entry(import_draft(&source, [1; 32], 123))
            .unwrap();
        vault.snapshot_body()
    }
    fn duplicate_uuid_preview(
        vault: &mut VaultSession,
        baseline: &VaultBody,
        first_deleted: bool,
        deleted_only: bool,
    ) -> ImportPreview {
        let mut body = baseline.clone();
        body.entries[0].deleted_at_unix = first_deleted.then_some(123);
        let mut second = body.entries[0].clone();
        second.deleted_at_unix = (!first_deleted).then_some(123);
        body.entries.push(second);
        if deleted_only {
            for entry in &mut body.entries {
                if !entry.is_deleted() {
                    entry.provenance.as_mut().unwrap().source_stable_id = Some("other".into());
                }
            }
        }
        vault.restore_body(body);
        let mut incoming = item("duplicate", "其他");
        incoming.password.push_str("-imported");
        let preview = build_preview(vault, batch(vec![incoming], 2)).unwrap();
        assert!(
            matches!(preview.rows[0].class, ImportClass::LocallyDeleted { .. }) == deleted_only
        );
        preview
    }
    fn original_resolution_candidate_ids(preview: &ImportPreview, index: usize) -> Vec<Uuid> {
        let (ids, deleted) = match &preview.rows[index].class {
            ImportClass::Conflict { existing_ids } => (existing_ids, false),
            ImportClass::LocallyDeleted { existing_ids } => (existing_ids, true),
            _ => return Vec::new(),
        };
        ids.iter()
            .copied()
            .filter(|id| {
                preview
                    .body
                    .entries
                    .iter()
                    .any(|entry| entry.id == *id && entry.is_deleted() == deleted)
            })
            .collect()
    }
    #[test]
    fn controlled_import_duplicate_uuid_resolution_cache_matches_any_record_state() {
        let dir = tempfile::tempdir().unwrap();
        let mut vault =
            VaultSession::create(dir.path().join("vault.pmvault"), "synthetic-master").unwrap();
        let baseline = duplicate_uuid_base(&mut vault);
        for first_deleted in [false, true] {
            for deleted_only in [false, true] {
                let preview =
                    duplicate_uuid_preview(&mut vault, &baseline, first_deleted, deleted_only);
                let expected = original_resolution_candidate_ids(&preview, 0);
                let id = baseline.entries[0].id;
                assert!(!expected.is_empty());
                assert_eq!(
                    preview.allows_resolution(0, &ConflictResolution::UseImported(id)),
                    expected.contains(&id),
                    "first_deleted={first_deleted},deleted_only={deleted_only}"
                );
                assert_eq!(
                    preview.rows[0].resolution_candidate_ids(),
                    expected,
                    "first_deleted={first_deleted},deleted_only={deleted_only}"
                );
            }
        }
    }
    #[test]
    fn controlled_import_duplicate_uuid_validation_matches_first_record_state() {
        let dir = tempfile::tempdir().unwrap();
        let mut vault =
            VaultSession::create(dir.path().join("vault.pmvault"), "synthetic-master").unwrap();
        let baseline = duplicate_uuid_base(&mut vault);
        let id = baseline.entries[0].id;
        for first_deleted in [true, false] {
            for deleted_only in [false, true] {
                let preview =
                    duplicate_uuid_preview(&mut vault, &baseline, first_deleted, deleted_only);
                // Original allows_resolution accepts ANY matching state, but
                // application validates VaultSession::entry's FIRST record.
                assert!(original_resolution_candidate_ids(&preview, 0).contains(&id));
                let expected = vault
                    .entry(id)
                    .is_some_and(|entry| entry.is_deleted() == deleted_only);
                let mut options = ImportApplyOptions::for_preview(&preview);
                options
                    .conflict_resolutions
                    .insert(0, ConflictResolution::UseImported(id));
                let actual =
                    validate_application(&vault, &preview, &options, &mut || Ok(())).is_ok();
                assert_eq!(
                    actual, expected,
                    "first_deleted={first_deleted},deleted_only={deleted_only}"
                );
            }
        }
    }
    fn duplicate_uuid_distinct_envelopes(vault: &mut VaultSession) -> NormalizedImportItem {
        let mut first = item("first", "其他");
        first.password = "synthetic-first-envelope".into();
        first.fingerprint = content_fingerprint(
            &first.name,
            &first.website,
            &first.username,
            &first.password,
            &first.notes,
            &first.category,
            first.favorite,
        );
        let id = vault.add_entry(import_draft(&first, [1; 32], 123)).unwrap();
        let original = vault.entries()[0].clone();
        let mut second = item("second", "其他");
        second.name = "Synthetic second metadata".into();
        second.password = "synthetic-second-envelope".into();
        second.notes = "synthetic second notes".into();
        second.fingerprint = content_fingerprint(
            &second.name,
            &second.website,
            &second.username,
            &second.password,
            &second.notes,
            &second.category,
            second.favorite,
        );
        vault
            .update_entry(id, import_draft(&second, [2; 32], 124))
            .unwrap();
        let updated = vault.entries()[0].clone();
        assert_eq!(original.id, updated.id);
        assert_ne!(original.secret, updated.secret);
        vault.body_mut().entries = vec![original, updated];
        second
    }
    #[test]
    fn controlled_import_duplicate_uuid_distinct_envelopes_full_preview_matches_original_lookup() {
        let dir = tempfile::tempdir().unwrap();
        let mut vault =
            VaultSession::create(dir.path().join("vault.pmvault"), "synthetic-master").unwrap();
        let incoming = duplicate_uuid_distinct_envelopes(&mut vault);
        let reference =
            build_preview_reference_with(&vault, batch(vec![incoming.clone()], 3), &mut || Ok(()))
                .unwrap_or_else(|_| panic!("original lookup reference"));
        assert!(matches!(
            reference.rows[0].class,
            ImportClass::Conflict { .. }
        ));
        let indexed = build_preview(&vault, batch(vec![incoming], 3)).unwrap();
        assert_eq!(preview_classes(&indexed), preview_classes(&reference));
        assert_eq!(indexed.summary(), reference.summary());
        assert_eq!(indexed.exact_dependencies, reference.exact_dependencies);
    }
    #[test]
    fn controlled_import_duplicate_uuid_source_helper_matches_first_secret_with_exact_counts() {
        let dir = tempfile::tempdir().unwrap();
        let mut vault =
            VaultSession::create(dir.path().join("vault.pmvault"), "synthetic-master").unwrap();
        duplicate_uuid_distinct_envelopes(&mut vault);
        vault.body_mut().entries[1].deleted_at_unix = Some(123);
        crate::storage::export_probe::reset();
        let projected = vault
            .all_entries_with_secrets()
            .collect::<Result<Vec<_>>>()
            .unwrap();
        assert_eq!(crate::storage::export_probe::counts(), (2, 2, 0));
        assert_eq!(projected.len(), 2);
        assert!(projected[1].0.is_deleted());
        for (row, (metadata, secret)) in projected.iter().enumerate() {
            assert_eq!(metadata.name, vault.entries()[row].name);
            let original = vault.reveal_secret(metadata.id).unwrap();
            assert_eq!(
                secret, &original,
                "physical metadata row {row} must retain first-ID secret lookup semantics"
            );
        }
    }
}
