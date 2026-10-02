use std::collections::{BTreeMap, BTreeSet};

use uuid::Uuid;

use crate::domain::{EntryDraft, ImportProvenance, ImportSourceRecord, SecretPayload, VaultBody};
use crate::import::{
    ImportBatch, NormalizedImportItem, compatible_legacy_fingerprint, content_fingerprint,
    now_unix, weak_identity_key,
};
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
}

impl ImportPreview {
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
        let (existing_ids, deleted) = match &row.class {
            ImportClass::Conflict { existing_ids } => (existing_ids, false),
            ImportClass::LocallyDeleted { existing_ids } => (existing_ids, true),
            _ => return false,
        };
        match resolution {
            ConflictResolution::KeepLocal | ConflictResolution::KeepBoth => true,
            ConflictResolution::UseImported(id) => {
                existing_ids.contains(id)
                    && self
                        .body
                        .entries
                        .iter()
                        .any(|entry| entry.id == *id && entry.is_deleted() == deleted)
            }
        }
    }

    pub fn summary(&self) -> ImportPreviewSummary {
        let mut summary = ImportPreviewSummary {
            invalid: self.invalid_rows,
            ..ImportPreviewSummary::default()
        };

        for row in &self.rows {
            match &row.class {
                ImportClass::New => summary.new += 1,
                ImportClass::SourceDuplicate { .. } => summary.source_duplicates += 1,
                ImportClass::ExactDuplicate { .. } => summary.exact_duplicates += 1,
                ImportClass::UpdateCandidate { .. } => summary.update_candidates += 1,
                ImportClass::LocallyDeleted { .. } => summary.locally_deleted += 1,
                ImportClass::Conflict { .. } => summary.conflicts += 1,
            }
        }

        summary
    }
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

struct ExistingSnapshot {
    id: Uuid,
    weak_key: (String, String),
    fingerprint: [u8; 32],
    legacy_fingerprint: Option<[u8; 32]>,
    provenance: Option<ImportProvenance>,
    deleted: bool,
}

pub fn build_preview(vault: &VaultSession, batch: ImportBatch) -> Result<ImportPreview> {
    let same_source_file = vault
        .body()
        .import_history
        .iter()
        .any(|record| record.source_digest == batch.source_digest);

    let mut existing = Vec::new();
    for entry in vault.entries() {
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
    let mut weak_rows: BTreeMap<(String, (String, String)), Vec<usize>> = BTreeMap::new();
    for mut item in batch.items {
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
        let mut class = classify_item(&item, &existing);
        if let Some(stable_id) = &item.source_stable_id {
            let key = (item.provider.clone(), stable_id.clone());
            if let Some(&original_row) = strong_rows.get(&key) {
                if rows[original_row].item != item {
                    return Err(AppError::Input(format!(
                        "导入第 {}、{} 行的稳定标识重复且内容不同",
                        original_row + 1,
                        index + 1
                    )));
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
        rows.push(ImportPreviewRow { item, class });
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

    let exact_dependencies = reconcile_exact_matches(&mut rows);

    Ok(ImportPreview {
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

// Exact matches are dependencies on the initial snapshot, not unconditional
// skips: another row may replace their content or claim a different identity.
fn reconcile_exact_matches(rows: &mut [ImportPreviewRow]) -> BTreeMap<usize, Uuid> {
    let exact_dependencies: BTreeMap<_, _> = rows
        .iter()
        .enumerate()
        .filter_map(|(index, row)| match row.class {
            ImportClass::ExactDuplicate { existing_id } => Some((index, existing_id)),
            _ => None,
        })
        .collect();
    let mut strong_claims: BTreeMap<Uuid, BTreeSet<(String, String)>> = BTreeMap::new();
    for (&index, &id) in &exact_dependencies {
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
        let targets = match &row.class {
            ImportClass::UpdateCandidate { existing_id } => std::slice::from_ref(existing_id),
            ImportClass::Conflict { existing_ids }
            | ImportClass::LocallyDeleted { existing_ids } => existing_ids.as_slice(),
            _ => &[],
        };
        for &id in targets {
            possible_writers.entry(id).or_default().push(index);
        }
    }
    for (&index, &id) in &exact_dependencies {
        let ambiguous_identity = strong_claims
            .get(&id)
            .is_some_and(|claims| claims.len() > 1);
        let may_replace_match = possible_writers.get(&id).is_some_and(|writers| {
            writers
                .iter()
                .any(|&writer| invalidates_exact_match(&rows[index].item, &rows[writer].item))
        });
        if ambiguous_identity || may_replace_match {
            rows[index].class = ImportClass::Conflict {
                existing_ids: vec![id],
            };
        }
    }
    exact_dependencies
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
    validate_application(vault, preview, options)?;
    let original = vault.snapshot_body();
    let result = apply_preview_inner(vault, preview, options);

    match result {
        Ok(report) => {
            vault.consume_import_preview();
            Ok(report)
        }
        Err(error) => {
            vault.restore_body(original);
            Err(error)
        }
    }
}

fn validate_application(
    vault: &VaultSession,
    preview: &ImportPreview,
    options: &ImportApplyOptions,
) -> Result<()> {
    if options.preview_id != preview.id
        || preview.session_binding != vault.import_binding()
        || preview.vault_id != vault.vault_id()
        || preview.revision != vault.revision()
        || preview.body != *vault.body()
    {
        return Err(AppError::Input(
            "导入预览已失效，请重新分析源文件".to_string(),
        ));
    }
    for (&index, resolution) in &options.conflict_resolutions {
        if !preview.allows_resolution(index, resolution) {
            return Err(AppError::Input(
                "导入决定不属于当前预览行或候选状态".to_string(),
            ));
        }
    }
    let mut targets = BTreeMap::new();
    for (index, row) in preview.rows.iter().enumerate() {
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
            if !vault
                .entry(id)
                .is_some_and(|entry| entry.is_deleted() == deleted)
            {
                return Err(AppError::Input("导入候选条目状态已改变".to_string()));
            }
            if targets.insert(id, index).is_some() {
                return Err(AppError::Input(
                    "多个导入行不能同时写入同一本地条目".to_string(),
                ));
            }
        }
    }
    let mut skipped_strong_identities = BTreeMap::new();
    for (&index, &id) in &preview.exact_dependencies {
        let row = &preview.rows[index];
        if let Some(&writer) = targets.get(&id)
            && invalidates_exact_match(&row.item, &preview.rows[writer].item)
            && !options.conflict_resolutions.contains_key(&index)
        {
            return Err(AppError::Input(
                "导入将替换另一行的匹配条目，请先选择跳过该行或导入为独立条目".to_string(),
            ));
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
                return Err(AppError::Input(
                    "不同来源标识不能自动跳过到同一本地条目".to_string(),
                ));
            }
        }
    }
    Ok(())
}

fn apply_preview_inner(
    vault: &mut VaultSession,
    preview: &ImportPreview,
    options: &ImportApplyOptions,
) -> Result<ImportApplyReport> {
    let mut report = ImportApplyReport {
        invalid: preview.invalid_rows,
        ..ImportApplyReport::default()
    };
    let now = now_unix();

    for (index, row) in preview.rows.iter().enumerate() {
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
                            ));
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
                            ));
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

    if changed {
        vault.save()?;
    }

    Ok(report)
}

fn classify_item(item: &NormalizedImportItem, existing: &[ExistingSnapshot]) -> ImportClass {
    if let Some(stable_id) = item.source_stable_id.as_deref() {
        let strong: Vec<&ExistingSnapshot> = existing
            .iter()
            .filter(|snapshot| {
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
        .filter(|snapshot| !snapshot.deleted && snapshot.weak_key == item_weak_key)
        .collect();
    let deleted_weak: Vec<Uuid> = existing
        .iter()
        .filter(|snapshot| snapshot.deleted && snapshot.weak_key == item_weak_key)
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
            Err(AppError::ExternalChange)
        ));
        assert_eq!(*vault.body(), original);
        assert_eq!(vault.revision(), revision);
        assert_eq!(fs::read(vault.path()).unwrap(), external);
        // An unsuccessful save must not consume the preview or mutate its binding.
        fs::write(vault.path(), disk).unwrap();
        let report = apply_preview(&mut vault, &preview, &options).unwrap();
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
}
