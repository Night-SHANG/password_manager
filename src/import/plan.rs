use std::collections::BTreeMap;

use uuid::Uuid;

use crate::domain::{
    EntryDraft, ImportProvenance, ImportSourceRecord, SecretPayload,
};
use crate::import::{
    ImportBatch, NormalizedImportItem, content_fingerprint, now_unix, weak_identity_key,
};
use crate::storage::VaultSession;
use crate::{AppError, Result};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ImportClass {
    New,
    ExactDuplicate { existing_id: Uuid },
    UpdateCandidate { existing_id: Uuid },
    LocallyDeleted { existing_ids: Vec<Uuid> },
    Conflict { existing_ids: Vec<Uuid> },
}

#[derive(Debug)]
pub struct ImportPreviewRow {
    pub item: NormalizedImportItem,
    pub class: ImportClass,
}

#[derive(Debug)]
pub struct ImportPreview {
    pub provider: String,
    pub source_digest: [u8; 32],
    pub same_source_file: bool,
    pub invalid_rows: usize,
    pub rows: Vec<ImportPreviewRow>,
}

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct ImportPreviewSummary {
    pub new: usize,
    pub exact_duplicates: usize,
    pub update_candidates: usize,
    pub locally_deleted: usize,
    pub conflicts: usize,
    pub invalid: usize,
}

impl ImportPreview {
    pub fn summary(&self) -> ImportPreviewSummary {
        let mut summary = ImportPreviewSummary {
            invalid: self.invalid_rows,
            ..ImportPreviewSummary::default()
        };

        for row in &self.rows {
            match &row.class {
                ImportClass::New => summary.new += 1,
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

#[derive(Debug, Default)]
pub struct ImportApplyOptions {
    pub apply_update_candidates: bool,
    pub conflict_resolutions: BTreeMap<usize, ConflictResolution>,
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
            provenance: entry.provenance.clone(),
            deleted: entry.is_deleted(),
        });
    }

    let mut rows = Vec::with_capacity(batch.items.len());
    for item in batch.items {
        let class = classify_item(&item, &existing);
        rows.push(ImportPreviewRow { item, class });
    }

    Ok(ImportPreview {
        provider: batch.provider,
        source_digest: batch.source_digest,
        same_source_file,
        invalid_rows: batch.invalid_rows,
        rows,
    })
}

pub fn apply_preview(
    vault: &mut VaultSession,
    preview: &ImportPreview,
    options: &ImportApplyOptions,
) -> Result<ImportApplyReport> {
    let original = vault.snapshot_body();
    let result = apply_preview_inner(vault, preview, options);

    match result {
        Ok(report) => Ok(report),
        Err(error) => {
            vault.restore_body(original);
            Err(error)
        }
    }
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
            ImportClass::ExactDuplicate { .. } => {
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

    let changed = report.added > 0
        || report.updated > 0
        || (fully_resolved && !already_recorded);

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

    if let Some(exact) = existing
        .iter()
        .find(|snapshot| !snapshot.deleted && snapshot.fingerprint == item.fingerprint)
    {
        return ImportClass::ExactDuplicate {
            existing_id: exact.id,
        };
    }

    let deleted_exact: Vec<Uuid> = existing
        .iter()
        .filter(|snapshot| snapshot.deleted && snapshot.fingerprint == item.fingerprint)
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
                        && provenance.last_import_fingerprint == snapshot.fingerprint
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

fn classify_known_identity(
    item: &NormalizedImportItem,
    snapshot: &ExistingSnapshot,
) -> ImportClass {
    if snapshot.fingerprint == item.fingerprint {
        return ImportClass::ExactDuplicate {
            existing_id: snapshot.id,
        };
    }

    let unchanged_since_import = snapshot
        .provenance
        .as_ref()
        .is_some_and(|provenance| provenance.last_import_fingerprint == snapshot.fingerprint);

    if unchanged_since_import {
        ImportClass::UpdateCandidate {
            existing_id: snapshot.id,
        }
    } else {
        ImportClass::Conflict {
            existing_ids: vec![snapshot.id],
        }
    }
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
