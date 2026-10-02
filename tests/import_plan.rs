use std::fs;

use password_manager::domain::{EntryDraft, SecretPayload};
use password_manager::import::csv;
use password_manager::import::plan::{
    ImportApplyOptions, ImportClass, apply_preview, build_preview,
};
use password_manager::storage::VaultSession;

fn write_csv(dir: &tempfile::TempDir, name: &str, content: &str) -> std::path::PathBuf {
    let path = dir.path().join(name);
    fs::write(&path, content).unwrap();
    path
}

#[test]
fn repeated_google_import_is_idempotent_then_detects_update() {
    let dir = tempfile::tempdir().unwrap();
    let vault_path = dir.path().join("vault.pmvault");
    let csv_path = write_csv(
        &dir,
        "google.csv",
        "name,url,username,password,note
GitHub,https://github.com,ada,old-pass,note
",
    );

    let mut vault = VaultSession::create(&vault_path, "master-password").unwrap();

    let first = build_preview(&vault, csv::parse_path(&csv_path).unwrap()).unwrap();
    assert_eq!(first.summary().new, 1);
    let report = apply_preview(
        &mut vault,
        &first,
        &ImportApplyOptions {
            apply_update_candidates: true,
            ..ImportApplyOptions::for_preview(&first)
        },
    )
    .unwrap();
    assert_eq!(report.added, 1);

    let repeated = build_preview(&vault, csv::parse_path(&csv_path).unwrap()).unwrap();
    assert!(repeated.same_source_file());
    assert!(matches!(
        &repeated.rows()[0].class(),
        ImportClass::ExactDuplicate { .. }
    ));

    fs::write(
        &csv_path,
        "name,url,username,password,note
GitHub,https://github.com,ada,new-pass,note
",
    )
    .unwrap();

    let changed = build_preview(&vault, csv::parse_path(&csv_path).unwrap()).unwrap();
    assert!(matches!(
        &changed.rows()[0].class(),
        ImportClass::UpdateCandidate { .. }
    ));

    let report = apply_preview(
        &mut vault,
        &changed,
        &ImportApplyOptions {
            apply_update_candidates: true,
            ..ImportApplyOptions::for_preview(&changed)
        },
    )
    .unwrap();
    assert_eq!(report.updated, 1);

    let id = vault.active_entries().next().unwrap().id;
    assert_eq!(vault.reveal_secret(id).unwrap().password, "new-pass");
}

#[test]
fn local_and_source_changes_become_conflict() {
    let dir = tempfile::tempdir().unwrap();
    let vault_path = dir.path().join("vault.pmvault");
    let csv_path = write_csv(
        &dir,
        "google.csv",
        "name,url,username,password,note
GitHub,https://github.com,ada,source-v1,note
",
    );

    let mut vault = VaultSession::create(&vault_path, "master-password").unwrap();
    let preview = build_preview(&vault, csv::parse_path(&csv_path).unwrap()).unwrap();
    apply_preview(
        &mut vault,
        &preview,
        &ImportApplyOptions {
            apply_update_candidates: true,
            ..ImportApplyOptions::for_preview(&preview)
        },
    )
    .unwrap();

    let entry = vault.active_entries().next().unwrap().clone();
    vault
        .update_entry(
            entry.id,
            EntryDraft {
                name: entry.name,
                website: entry.website,
                username: entry.username,
                category: entry.category,
                favorite: entry.favorite,
                secret: SecretPayload::new("local-change", "note"),
                provenance: None,
            },
        )
        .unwrap();
    vault.save().unwrap();

    fs::write(
        &csv_path,
        "name,url,username,password,note
GitHub,https://github.com,ada,source-v2,note
",
    )
    .unwrap();

    let preview = build_preview(&vault, csv::parse_path(&csv_path).unwrap()).unwrap();
    assert!(matches!(
        &preview.rows()[0].class(),
        ImportClass::Conflict { .. }
    ));
}

#[test]
fn source_omission_never_deletes_local_entry() {
    let dir = tempfile::tempdir().unwrap();
    let vault_path = dir.path().join("vault.pmvault");
    let csv_path = write_csv(
        &dir,
        "google.csv",
        concat!(
            "name,url,username,password,note
",
            "One,https://one.example,u1,p1,
",
            "Two,https://two.example,u2,p2,
"
        ),
    );

    let mut vault = VaultSession::create(&vault_path, "master-password").unwrap();
    let preview = build_preview(&vault, csv::parse_path(&csv_path).unwrap()).unwrap();
    apply_preview(
        &mut vault,
        &preview,
        &ImportApplyOptions {
            apply_update_candidates: true,
            ..ImportApplyOptions::for_preview(&preview)
        },
    )
    .unwrap();
    assert_eq!(vault.active_entries().count(), 2);

    fs::write(
        &csv_path,
        "name,url,username,password,note
One,https://one.example,u1,p1,
",
    )
    .unwrap();

    let preview = build_preview(&vault, csv::parse_path(&csv_path).unwrap()).unwrap();
    apply_preview(
        &mut vault,
        &preview,
        &ImportApplyOptions::for_preview(&preview),
    )
    .unwrap();
    assert_eq!(vault.active_entries().count(), 2);
}

#[test]
fn failed_import_save_rolls_back_in_memory_changes() {
    let dir = tempfile::tempdir().unwrap();
    let vault_path = dir.path().join("vault.pmvault");
    let csv_path = write_csv(
        &dir,
        "google.csv",
        "name,url,username,password,note
X,https://x.example,u,p,
",
    );

    let mut vault = VaultSession::create(&vault_path, "master-password").unwrap();
    let preview = build_preview(&vault, csv::parse_path(&csv_path).unwrap()).unwrap();

    let mut bytes = fs::read(&vault_path).unwrap();
    bytes.push(b' ');
    fs::write(&vault_path, bytes).unwrap();

    assert!(
        apply_preview(
            &mut vault,
            &preview,
            &ImportApplyOptions {
                apply_update_candidates: true,
                ..ImportApplyOptions::for_preview(&preview)
            },
        )
        .is_err()
    );
    assert_eq!(vault.active_entries().count(), 0);
}

#[test]
fn locally_deleted_imported_item_is_not_silently_resurrected() {
    let dir = tempfile::tempdir().unwrap();
    let vault_path = dir.path().join("vault.pmvault");
    let csv_path = write_csv(
        &dir,
        "google.csv",
        "name,url,username,password,note\nDeleted,https://deleted.example,u,p,\n",
    );

    let mut vault = VaultSession::create(&vault_path, "master-password").unwrap();
    let first = build_preview(&vault, csv::parse_path(&csv_path).unwrap()).unwrap();
    apply_preview(
        &mut vault,
        &first,
        &ImportApplyOptions {
            apply_update_candidates: true,
            ..ImportApplyOptions::for_preview(&first)
        },
    )
    .unwrap();

    let id = vault.active_entries().next().unwrap().id;
    vault.move_to_recycle_bin(id).unwrap();
    vault.save().unwrap();
    assert_eq!(vault.active_entries().count(), 0);

    let preview = build_preview(&vault, csv::parse_path(&csv_path).unwrap()).unwrap();
    assert!(matches!(
        &preview.rows()[0].class(),
        ImportClass::LocallyDeleted { .. }
    ));

    let report = apply_preview(
        &mut vault,
        &preview,
        &ImportApplyOptions::for_preview(&preview),
    )
    .unwrap();
    assert_eq!(report.locally_deleted_deferred, 1);
    assert_eq!(vault.active_entries().count(), 0);
}

fn synthetic_item(
    stable_id: Option<&str>,
    password: &str,
    notes: &str,
) -> password_manager::import::NormalizedImportItem {
    password_manager::import::NormalizedImportItem {
        provider: "synthetic".into(),
        source_stable_id: stable_id.map(str::to_owned),
        name: "Synthetic".into(),
        website: "https://synthetic.example.test".into(),
        username: "user".into(),
        password: password.into(),
        notes: notes.into(),
        category: "其他".into(),
        favorite: false,
        fingerprint: [0; 32],
    }
}

fn batch(
    items: Vec<password_manager::import::NormalizedImportItem>,
) -> password_manager::import::ImportBatch {
    password_manager::import::ImportBatch {
        provider: "synthetic".into(),
        source_digest: [42; 32],
        items,
        invalid_rows: 0,
    }
}

fn old_fingerprint(item: &password_manager::import::NormalizedImportItem) -> [u8; 32] {
    use sha2::{Digest, Sha256};
    let mut hash = Sha256::new();
    for field in [
        &*item.name,
        &*item.website,
        &*item.username,
        &*item.password,
        &*item.notes,
        &*item.category,
        if item.favorite { "1" } else { "0" },
    ] {
        hash.update(field.as_bytes());
        hash.update([0x1f]);
    }
    hash.finalize().into()
}

fn add_with_old_provenance(
    vault: &mut VaultSession,
    item: &password_manager::import::NormalizedImportItem,
    imported_fingerprint: [u8; 32],
) -> uuid::Uuid {
    vault
        .add_entry(EntryDraft {
            name: item.name.clone(),
            website: item.website.clone(),
            username: item.username.clone(),
            category: item.category.clone(),
            favorite: item.favorite,
            secret: SecretPayload::new(&item.password, &item.notes),
            provenance: Some(password_manager::domain::ImportProvenance {
                provider: item.provider.clone(),
                source_stable_id: item.source_stable_id.clone(),
                last_import_fingerprint: imported_fingerprint,
                last_imported_at_unix: 0,
                source_digest: None,
            }),
        })
        .unwrap()
}

#[test]
fn preview_recalculates_public_fingerprint() {
    let dir = tempfile::tempdir().unwrap();
    let mut vault =
        VaultSession::create(dir.path().join("vault.pmvault"), "synthetic-master").unwrap();
    let first = build_preview(&vault, batch(vec![synthetic_item(None, "one", "")])).unwrap();
    apply_preview(&mut vault, &first, &ImportApplyOptions::for_preview(&first)).unwrap();
    let next = build_preview(&vault, batch(vec![synthetic_item(None, "two", "")])).unwrap();
    assert!(matches!(
        next.rows()[0].class(),
        ImportClass::UpdateCandidate { .. }
    ));
}

#[test]
fn old_provenance_cannot_hide_delimiter_local_edits_for_strong_or_weak_identity() {
    for id in [None, Some("row:1")] {
        let dir = tempfile::tempdir().unwrap();
        let mut vault =
            VaultSession::create(dir.path().join("vault.pmvault"), "synthetic-master").unwrap();
        let imported = synthetic_item(id, "p\u{1f}q", "r");
        let local = synthetic_item(id, "p", "q\u{1f}r");
        add_with_old_provenance(&mut vault, &local, old_fingerprint(&imported));
        let next = build_preview(&vault, batch(vec![synthetic_item(id, "new", "r")])).unwrap();
        assert!(matches!(
            next.rows()[0].class(),
            ImportClass::Conflict { .. }
        ));
    }
}

#[test]
fn old_unambiguous_provenance_allows_strong_and_weak_updates() {
    for id in [None, Some("row:1")] {
        let dir = tempfile::tempdir().unwrap();
        let mut vault =
            VaultSession::create(dir.path().join("vault.pmvault"), "synthetic-master").unwrap();
        let imported = synthetic_item(id, "old", "note");
        add_with_old_provenance(&mut vault, &imported, old_fingerprint(&imported));
        let next = build_preview(&vault, batch(vec![synthetic_item(id, "new", "note")])).unwrap();
        assert!(matches!(
            next.rows()[0].class(),
            ImportClass::UpdateCandidate { .. }
        ));
    }
}

#[test]
fn legacy_unscoped_identity_requires_confirmation_and_exact_skip_keeps_old_namespace() {
    let dir = tempfile::tempdir().unwrap();
    let mut vault =
        VaultSession::create(dir.path().join("vault.pmvault"), "synthetic-master").unwrap();
    let mut imported = synthetic_item(Some("entry:1"), "old", "note");
    imported.provider = "legacy-passwords-db".into();
    let id = add_with_old_provenance(&mut vault, &imported, old_fingerprint(&imported));
    let mut same = imported.clone();
    same.fingerprint = old_fingerprint(&same);
    same.source_stable_id = Some(format!("db:{}:entry:1", "a".repeat(64)));
    let exact = build_preview(&vault, batch(vec![same.clone()])).unwrap();
    assert!(matches!(
        exact.rows()[0].class(),
        ImportClass::ExactDuplicate { .. }
    ));
    apply_preview(&mut vault, &exact, &ImportApplyOptions::for_preview(&exact)).unwrap();
    assert_eq!(
        vault
            .entry(id)
            .unwrap()
            .provenance
            .as_ref()
            .unwrap()
            .source_stable_id
            .as_deref(),
        Some("entry:1")
    );
    same.password = "new".into();
    same.website = "https://moved.example.test".into();
    let changed = build_preview(&vault, batch(vec![same])).unwrap();
    assert!(matches!(
        changed.rows()[0].class(),
        ImportClass::Conflict { .. }
    ));
}

#[test]
fn new_control_character_provenance_supports_later_updates() {
    for id in [None, Some("row:1")] {
        let dir = tempfile::tempdir().unwrap();
        let mut vault =
            VaultSession::create(dir.path().join("vault.pmvault"), "synthetic-master").unwrap();
        let first =
            build_preview(&vault, batch(vec![synthetic_item(id, "p\u{1f}q", "r")])).unwrap();
        apply_preview(&mut vault, &first, &ImportApplyOptions::for_preview(&first)).unwrap();
        let next = build_preview(
            &vault,
            batch(vec![synthetic_item(id, "new\u{1f}value", "r")]),
        )
        .unwrap();
        assert!(matches!(
            next.rows()[0].class(),
            ImportClass::UpdateCandidate { .. }
        ));
    }
}

#[test]
fn identical_source_rows_import_once_without_invented_local_ids() {
    let dir = tempfile::tempdir().unwrap();
    let mut vault =
        VaultSession::create(dir.path().join("vault.pmvault"), "synthetic-master").unwrap();
    let item = synthetic_item(None, "one", "note");
    let preview = build_preview(&vault, batch(vec![item.clone(), item])).unwrap();
    assert_eq!(preview.summary().source_duplicates, 1);
    assert!(matches!(
        preview.rows()[1].class(),
        ImportClass::SourceDuplicate { original_row: 0 }
    ));
    let report = apply_preview(
        &mut vault,
        &preview,
        &ImportApplyOptions::for_preview(&preview),
    )
    .unwrap();
    assert_eq!(report.added, 1);
    assert_eq!(report.skipped, 1);
    assert_eq!(vault.entries().len(), 1);
}

#[test]
fn contradictory_strong_source_rows_fail_preview_without_secret_values() {
    let dir = tempfile::tempdir().unwrap();
    let vault = VaultSession::create(dir.path().join("vault.pmvault"), "synthetic-master").unwrap();
    let result = build_preview(
        &vault,
        batch(vec![
            synthetic_item(Some("secret-id"), "secret-one", "note"),
            synthetic_item(Some("secret-id"), "secret-two", "note"),
        ]),
    );
    assert!(result.is_err());
    let message = result.unwrap_err().to_string();
    assert!(message.contains('1') && message.contains('2'));
    assert!(!message.contains("secret-"));
}

#[test]
fn ambiguous_weak_source_rows_are_conflicts_in_both_orders() {
    let dir = tempfile::tempdir().unwrap();
    let vault = VaultSession::create(dir.path().join("vault.pmvault"), "synthetic-master").unwrap();
    for values in [["one", "two"], ["two", "one"]] {
        let preview = build_preview(
            &vault,
            batch(
                values
                    .iter()
                    .map(|p| synthetic_item(None, p, "note"))
                    .collect(),
            ),
        )
        .unwrap();
        assert!(preview.rows().iter().all(|row| matches!(&row.class(), ImportClass::Conflict { existing_ids } if existing_ids.is_empty())));
    }
}

#[test]
fn multiple_writes_to_one_local_uuid_fail_before_any_changes() {
    use password_manager::import::plan::ConflictResolution;
    let dir = tempfile::tempdir().unwrap();
    let mut vault =
        VaultSession::create(dir.path().join("vault.pmvault"), "synthetic-master").unwrap();
    let item = synthetic_item(None, "local", "note");
    let id = add_with_old_provenance(&mut vault, &item, [99; 32]);
    vault.save().unwrap();
    let preview = build_preview(
        &vault,
        batch(vec![
            synthetic_item(Some("a"), "one", "note"),
            synthetic_item(Some("b"), "two", "note"),
        ]),
    )
    .unwrap();
    let mut options = ImportApplyOptions::for_preview(&preview);
    options
        .conflict_resolutions
        .insert(0, ConflictResolution::UseImported(id));
    options
        .conflict_resolutions
        .insert(1, ConflictResolution::UseImported(id));
    let disk = fs::read(vault.path()).unwrap();
    let revision = vault.revision();
    let entries = vault.entries().to_vec();
    assert!(apply_preview(&mut vault, &preview, &options).is_err());
    assert_eq!(vault.entries(), entries);
    assert_eq!(vault.revision(), revision);
    assert_eq!(fs::read(vault.path()).unwrap(), disk);
}

#[test]
fn unsaved_changes_wrong_vault_and_reopened_session_reject_preview() {
    let dir = tempfile::tempdir().unwrap();
    let mut vault =
        VaultSession::create(dir.path().join("vault.pmvault"), "synthetic-master").unwrap();
    let preview = build_preview(&vault, batch(vec![synthetic_item(None, "new", "")])).unwrap();
    let mut reopened = VaultSession::open(vault.path(), "synthetic-master").unwrap();
    assert!(
        apply_preview(
            &mut reopened,
            &preview,
            &ImportApplyOptions::for_preview(&preview)
        )
        .is_err()
    );
    let cloned_path = dir.path().join("copied.pmvault");
    fs::copy(vault.path(), &cloned_path).unwrap();
    let mut cloned = VaultSession::open(&cloned_path, "synthetic-master").unwrap();
    assert!(
        apply_preview(
            &mut cloned,
            &preview,
            &ImportApplyOptions::for_preview(&preview)
        )
        .is_err()
    );
    let mut other =
        VaultSession::create(dir.path().join("other.pmvault"), "synthetic-master").unwrap();
    assert!(
        apply_preview(
            &mut other,
            &preview,
            &ImportApplyOptions::for_preview(&preview)
        )
        .is_err()
    );
    vault
        .add_entry(EntryDraft::login(
            "unsaved",
            "https://other.example.test",
            "u",
            "p",
        ))
        .unwrap();
    assert!(
        apply_preview(
            &mut vault,
            &preview,
            &ImportApplyOptions::for_preview(&preview)
        )
        .is_err()
    );
    assert_eq!(vault.entries().len(), 1);
}

#[test]
fn successful_deferred_application_cannot_replay() {
    let dir = tempfile::tempdir().unwrap();
    let mut vault =
        VaultSession::create(dir.path().join("vault.pmvault"), "synthetic-master").unwrap();
    let item = synthetic_item(None, "old", "note");
    add_with_old_provenance(&mut vault, &item, old_fingerprint(&item));
    vault.save().unwrap();
    let preview = build_preview(&vault, batch(vec![synthetic_item(None, "new", "note")])).unwrap();
    let report = apply_preview(
        &mut vault,
        &preview,
        &ImportApplyOptions::for_preview(&preview),
    )
    .unwrap();
    assert_eq!(report.updates_deferred, 1);
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
fn unrelated_row_and_class_decisions_are_rejected_without_mutation() {
    use password_manager::import::plan::ConflictResolution;
    let dir = tempfile::tempdir().unwrap();
    let mut vault =
        VaultSession::create(dir.path().join("vault.pmvault"), "synthetic-master").unwrap();
    let preview = build_preview(&vault, batch(vec![synthetic_item(None, "new", "")])).unwrap();
    for row in [1, 0] {
        let mut options = ImportApplyOptions::for_preview(&preview);
        options
            .conflict_resolutions
            .insert(row, ConflictResolution::KeepBoth);
        assert!(apply_preview(&mut vault, &preview, &options).is_err());
        assert!(vault.entries().is_empty());
    }
}

#[test]
fn different_strong_identity_is_not_an_exact_duplicate_of_local_content() {
    let dir = tempfile::tempdir().unwrap();
    let mut vault =
        VaultSession::create(dir.path().join("vault.pmvault"), "synthetic-master").unwrap();
    let first = build_preview(
        &vault,
        batch(vec![synthetic_item(Some("first"), "one", "note")]),
    )
    .unwrap();
    apply_preview(&mut vault, &first, &ImportApplyOptions::for_preview(&first)).unwrap();
    let next = build_preview(
        &vault,
        batch(vec![synthetic_item(Some("second"), "one", "note")]),
    )
    .unwrap();
    assert!(matches!(
        next.rows()[0].class(),
        ImportClass::Conflict { .. }
    ));
}

#[test]
fn ambiguous_weak_rows_preserve_explicit_recycle_bin_choices() {
    use password_manager::import::plan::ConflictResolution;
    let dir = tempfile::tempdir().unwrap();
    let mut vault =
        VaultSession::create(dir.path().join("vault.pmvault"), "synthetic-master").unwrap();
    let item = synthetic_item(None, "old", "note");
    let id = add_with_old_provenance(&mut vault, &item, old_fingerprint(&item));
    vault.move_to_recycle_bin(id).unwrap();
    vault.save().unwrap();
    let preview = build_preview(
        &vault,
        batch(vec![
            synthetic_item(None, "one", "note"),
            synthetic_item(None, "two", "note"),
        ]),
    )
    .unwrap();
    assert!(preview.rows().iter().all(|row| matches!(row.class(), ImportClass::LocallyDeleted { existing_ids } if existing_ids == &vec![id])));
    assert!(preview.allows_resolution(0, &ConflictResolution::UseImported(id)));
    let mut options = ImportApplyOptions::for_preview(&preview);
    options
        .conflict_resolutions
        .insert(0, ConflictResolution::UseImported(id));
    options
        .conflict_resolutions
        .insert(1, ConflictResolution::KeepLocal);
    let report = apply_preview(&mut vault, &preview, &options).unwrap();
    assert_eq!(report.updated, 1);
    assert_eq!(report.skipped, 1);
    assert_eq!(vault.active_entries().count(), 1);
    assert_eq!(vault.reveal_secret(id).unwrap().password, "one");
}

#[test]
fn wrong_preview_id_or_uuid_rejects_decisions_and_preserves_vault() {
    use password_manager::import::plan::ConflictResolution;
    let dir = tempfile::tempdir().unwrap();
    let mut vault =
        VaultSession::create(dir.path().join("vault.pmvault"), "synthetic-master").unwrap();
    let item = synthetic_item(None, "local", "note");
    add_with_old_provenance(&mut vault, &item, [99; 32]);
    vault.save().unwrap();
    let preview = build_preview(&vault, batch(vec![synthetic_item(None, "new", "note")])).unwrap();
    let original = vault.entries().to_vec();
    let revision = vault.revision();
    let disk = fs::read(vault.path()).unwrap();
    let mut wrong_id = ImportApplyOptions::for_preview(&preview);
    wrong_id.preview_id = uuid::Uuid::new_v4();
    assert!(apply_preview(&mut vault, &preview, &wrong_id).is_err());
    let mut wrong_target = ImportApplyOptions::for_preview(&preview);
    wrong_target
        .conflict_resolutions
        .insert(0, ConflictResolution::UseImported(uuid::Uuid::new_v4()));
    assert!(apply_preview(&mut vault, &preview, &wrong_target).is_err());
    assert_eq!(vault.entries(), original);
    assert_eq!(vault.revision(), revision);
    assert_eq!(fs::read(vault.path()).unwrap(), disk);
}

#[test]
fn successful_exact_noop_application_cannot_replay() {
    let dir = tempfile::tempdir().unwrap();
    let mut vault =
        VaultSession::create(dir.path().join("vault.pmvault"), "synthetic-master").unwrap();
    let first = build_preview(&vault, batch(vec![synthetic_item(None, "one", "")])).unwrap();
    apply_preview(&mut vault, &first, &ImportApplyOptions::for_preview(&first)).unwrap();
    let preview = build_preview(&vault, batch(vec![synthetic_item(None, "one", "")])).unwrap();
    let revision = vault.revision();
    let options = ImportApplyOptions::for_preview(&preview);
    assert_eq!(
        apply_preview(&mut vault, &preview, &options)
            .unwrap()
            .skipped,
        1
    );
    assert_eq!(vault.revision(), revision);
    assert!(apply_preview(&mut vault, &preview, &options).is_err());
}

#[test]
fn commit_uses_exact_staged_source_when_external_csv_changes() {
    let dir = tempfile::tempdir().unwrap();
    let source = write_csv(
        &dir,
        "source.csv",
        "name,url,username,password,note\nSynthetic,https://synthetic.example.test,user,staged,note\n",
    );
    let mut vault =
        VaultSession::create(dir.path().join("vault.pmvault"), "synthetic-master").unwrap();
    let preview = build_preview(&vault, csv::parse_path(&source).unwrap()).unwrap();
    fs::write(
        &source,
        "name,url,username,password,note\nChanged,https://changed.example.test,user,changed,note\n",
    )
    .unwrap();
    let revision = vault.revision();
    apply_preview(
        &mut vault,
        &preview,
        &ImportApplyOptions::for_preview(&preview),
    )
    .unwrap();
    assert_eq!(vault.revision(), revision + 1);
    assert_eq!(vault.entries()[0].name, "Synthetic");
    assert_eq!(
        vault.reveal_secret(vault.entries()[0].id).unwrap().password,
        "staged"
    );
}

#[test]
fn distinct_strong_source_ids_with_identical_contents_stay_independent() {
    let dir = tempfile::tempdir().unwrap();
    let mut vault =
        VaultSession::create(dir.path().join("vault.pmvault"), "synthetic-master").unwrap();
    let preview = build_preview(
        &vault,
        batch(vec![
            synthetic_item(Some("a"), "one", "note"),
            synthetic_item(Some("b"), "one", "note"),
        ]),
    )
    .unwrap();
    assert_eq!(preview.summary().new, 2);
    assert_eq!(preview.summary().source_duplicates, 0);
    let report = apply_preview(
        &mut vault,
        &preview,
        &ImportApplyOptions::for_preview(&preview),
    )
    .unwrap();
    assert_eq!(report.added, 2);
    assert_ne!(vault.entries()[0].id, vault.entries()[1].id);
}

#[test]
fn no_target_weak_conflicts_support_skip_and_independent_import() {
    use password_manager::import::plan::ConflictResolution;
    let dir = tempfile::tempdir().unwrap();
    let mut vault =
        VaultSession::create(dir.path().join("vault.pmvault"), "synthetic-master").unwrap();
    let preview = build_preview(
        &vault,
        batch(vec![
            synthetic_item(None, "one", "note"),
            synthetic_item(None, "two", "note"),
        ]),
    )
    .unwrap();
    let mut options = ImportApplyOptions::for_preview(&preview);
    options
        .conflict_resolutions
        .insert(0, ConflictResolution::KeepLocal);
    options
        .conflict_resolutions
        .insert(1, ConflictResolution::KeepBoth);
    let report = apply_preview(&mut vault, &preview, &options).unwrap();
    assert_eq!(report.added, 1);
    assert_eq!(report.skipped, 1);
    assert_eq!(
        vault.reveal_secret(vault.entries()[0].id).unwrap().password,
        "two"
    );
}

#[test]
fn mixed_weak_source_conflicts_offer_only_active_targets() {
    use password_manager::import::plan::ConflictResolution;
    let dir = tempfile::tempdir().unwrap();
    let mut vault =
        VaultSession::create(dir.path().join("vault.pmvault"), "synthetic-master").unwrap();
    let item = synthetic_item(None, "local", "note");
    let active = add_with_old_provenance(&mut vault, &item, [99; 32]);
    let deleted = add_with_old_provenance(&mut vault, &item, [99; 32]);
    vault.move_to_recycle_bin(deleted).unwrap();
    vault.save().unwrap();
    let preview = build_preview(
        &vault,
        batch(vec![
            synthetic_item(None, "one", "note"),
            synthetic_item(None, "two", "note"),
        ]),
    )
    .unwrap();
    assert!(preview.rows().iter().all(|row| matches!(row.class(), ImportClass::Conflict { existing_ids } if existing_ids == &vec![active])));
    assert!(!preview.allows_resolution(0, &ConflictResolution::UseImported(deleted)));
    let mut invalid = ImportApplyOptions::for_preview(&preview);
    invalid
        .conflict_resolutions
        .insert(0, ConflictResolution::UseImported(deleted));
    assert!(apply_preview(&mut vault, &preview, &invalid).is_err());
    let mut options = ImportApplyOptions::for_preview(&preview);
    options
        .conflict_resolutions
        .insert(0, ConflictResolution::UseImported(active));
    options
        .conflict_resolutions
        .insert(1, ConflictResolution::KeepLocal);
    assert_eq!(
        apply_preview(&mut vault, &preview, &options)
            .unwrap()
            .updated,
        1
    );
    assert!(vault.entry(deleted).unwrap().is_deleted());
    assert_eq!(vault.reveal_secret(deleted).unwrap().password, "local");
}

#[test]
fn automatic_update_and_explicit_resolution_cannot_write_same_uuid() {
    use password_manager::import::plan::ConflictResolution;
    let dir = tempfile::tempdir().unwrap();
    let mut vault =
        VaultSession::create(dir.path().join("vault.pmvault"), "synthetic-master").unwrap();
    let item = synthetic_item(Some("row:1"), "old", "note");
    let id = add_with_old_provenance(&mut vault, &item, old_fingerprint(&item));
    vault.save().unwrap();
    let preview = build_preview(
        &vault,
        batch(vec![
            synthetic_item(Some("row:1"), "one", "note"),
            synthetic_item(None, "two", "note"),
        ]),
    )
    .unwrap();
    assert!(matches!(
        preview.rows()[0].class(),
        ImportClass::UpdateCandidate { .. }
    ));
    assert!(matches!(
        preview.rows()[1].class(),
        ImportClass::Conflict { .. }
    ));
    let before = vault.entries().to_vec();
    let revision = vault.revision();
    let disk = fs::read(vault.path()).unwrap();
    let mut options = ImportApplyOptions::for_preview(&preview);
    options.apply_update_candidates = true;
    options
        .conflict_resolutions
        .insert(1, ConflictResolution::UseImported(id));
    assert!(apply_preview(&mut vault, &preview, &options).is_err());
    assert_eq!(vault.entries(), before);
    assert_eq!(vault.revision(), revision);
    assert_eq!(fs::read(vault.path()).unwrap(), disk);
}

#[test]
fn identical_strong_rows_collapse_but_preserve_source_row_statistics() {
    let dir = tempfile::tempdir().unwrap();
    let mut vault =
        VaultSession::create(dir.path().join("vault.pmvault"), "synthetic-master").unwrap();
    let item = synthetic_item(Some("row:1"), "one", "note");
    let preview = build_preview(&vault, batch(vec![item.clone(), item.clone(), item])).unwrap();
    assert_eq!(preview.summary().new, 1);
    assert_eq!(preview.summary().source_duplicates, 2);
    let report = apply_preview(
        &mut vault,
        &preview,
        &ImportApplyOptions::for_preview(&preview),
    )
    .unwrap();
    assert_eq!(report.added, 1);
    assert_eq!(report.skipped, 2);
}

#[test]
fn review_exact_skip_dependency_requires_choice_for_automatic_update_in_both_orders() {
    use password_manager::import::plan::ConflictResolution;
    for reverse in [false, true] {
        for apply_updates in [false, true] {
            let dir = tempfile::tempdir().unwrap();
            let mut vault =
                VaultSession::create(dir.path().join("vault.pmvault"), "synthetic-master").unwrap();
            let original = synthetic_item(Some("A"), "X", "note");
            let id = add_with_old_provenance(&mut vault, &original, old_fingerprint(&original));
            vault.save().unwrap();
            let mut rows = vec![
                synthetic_item(Some("A"), "Y", "note"),
                synthetic_item(None, "X", "note"),
            ];
            if reverse {
                rows.reverse();
            }
            let exact_index = usize::from(!reverse);
            let preview = build_preview(&vault, batch(rows.clone())).unwrap();
            assert!(
                matches!(preview.rows()[exact_index].class(), ImportClass::Conflict { existing_ids } if existing_ids == &vec![id])
            );
            let before = vault.entries().to_vec();
            let categories = vault.categories().to_vec();
            let revision = vault.revision();
            let disk = fs::read(vault.path()).unwrap();
            let mut options = ImportApplyOptions::for_preview(&preview);
            options.apply_update_candidates = apply_updates;
            let result = apply_preview(&mut vault, &preview, &options);
            if apply_updates {
                assert!(result.is_err());
            } else {
                let report = result.unwrap();
                assert_eq!(report.updates_deferred, 1);
                assert_eq!(report.conflicts_unresolved, 1);
            }
            assert_eq!(vault.entries(), before);
            assert_eq!(vault.categories(), categories);
            assert_eq!(vault.revision(), revision);
            assert_eq!(fs::read(vault.path()).unwrap(), disk);
            // Deferred successful applies consume a preview, so resolve a fresh one.
            let preview = build_preview(&vault, batch(rows)).unwrap();
            let mut options = ImportApplyOptions::for_preview(&preview);
            options.apply_update_candidates = true;
            options
                .conflict_resolutions
                .insert(exact_index, ConflictResolution::KeepBoth);
            let report = apply_preview(&mut vault, &preview, &options).unwrap();
            assert_eq!(report.updated, 1);
            assert_eq!(report.added, 1);
            let mut passwords: Vec<_> = vault
                .entries()
                .iter()
                .map(|e| vault.reveal_secret(e.id).unwrap().password.clone())
                .collect();
            passwords.sort();
            assert_eq!(passwords, ["X", "Y"]);
        }
    }
}

#[test]
fn review_exact_skip_dependency_requires_choice_for_explicit_overwrite_in_both_orders() {
    use password_manager::import::plan::ConflictResolution;
    for reverse in [false, true] {
        for preserve_both in [false, true] {
            let dir = tempfile::tempdir().unwrap();
            let mut vault =
                VaultSession::create(dir.path().join("vault.pmvault"), "synthetic-master").unwrap();
            let original = synthetic_item(Some("A"), "X", "note");
            let id = add_with_old_provenance(&mut vault, &original, old_fingerprint(&original));
            vault.save().unwrap();
            let mut rows = vec![
                synthetic_item(Some("B"), "Y", "note"),
                synthetic_item(None, "X", "note"),
            ];
            if reverse {
                rows.reverse();
            }
            let writer_index = usize::from(reverse);
            let exact_index = usize::from(!reverse);
            let preview = build_preview(&vault, batch(rows)).unwrap();
            assert!(
                preview
                    .rows()
                    .iter()
                    .all(|row| matches!(row.class(), ImportClass::Conflict { .. }))
            );
            let before = vault.entries().to_vec();
            let disk = fs::read(vault.path()).unwrap();
            let revision = vault.revision();
            let mut options = ImportApplyOptions::for_preview(&preview);
            options
                .conflict_resolutions
                .insert(writer_index, ConflictResolution::UseImported(id));
            assert!(apply_preview(&mut vault, &preview, &options).is_err());
            assert_eq!(vault.entries(), before);
            assert_eq!(vault.revision(), revision);
            assert_eq!(fs::read(vault.path()).unwrap(), disk);
            options.conflict_resolutions.insert(
                exact_index,
                if preserve_both {
                    ConflictResolution::KeepBoth
                } else {
                    ConflictResolution::KeepLocal
                },
            );
            let report = apply_preview(&mut vault, &preview, &options).unwrap();
            assert_eq!(report.updated, 1);
            assert_eq!(report.added, usize::from(preserve_both));
            assert_eq!(vault.reveal_secret(id).unwrap().password, "Y");
            assert_eq!(vault.entries().len(), if preserve_both { 2 } else { 1 });
            if preserve_both {
                assert!(
                    vault
                        .entries()
                        .iter()
                        .any(|e| vault.reveal_secret(e.id).unwrap().password == "X")
                );
            }
        }
    }
}

fn add_weak_or_unprovenanced(vault: &mut VaultSession, with_provenance: bool) -> uuid::Uuid {
    let item = synthetic_item(None, "X", "note");
    if with_provenance {
        return add_with_old_provenance(vault, &item, old_fingerprint(&item));
    }
    vault
        .add_entry(EntryDraft {
            name: item.name.clone(),
            website: item.website.clone(),
            username: item.username.clone(),
            category: item.category.clone(),
            favorite: item.favorite,
            secret: SecretPayload::new("X", "note"),
            provenance: None,
        })
        .unwrap()
}

#[test]
fn review_distinct_strong_ids_cannot_exact_skip_through_one_weak_target() {
    use password_manager::import::plan::ConflictResolution;
    for with_provenance in [false, true] {
        for reverse in [false, true] {
            for overwrite_one in [false, true] {
                let dir = tempfile::tempdir().unwrap();
                let mut vault =
                    VaultSession::create(dir.path().join("vault.pmvault"), "synthetic-master")
                        .unwrap();
                let id = add_weak_or_unprovenanced(&mut vault, with_provenance);
                vault.save().unwrap();
                let mut rows = vec![
                    synthetic_item(Some("A"), "X", "note"),
                    synthetic_item(Some("B"), "X", "note"),
                ];
                if reverse {
                    rows.reverse();
                }
                let preview = build_preview(&vault, batch(rows)).unwrap();
                assert_eq!(preview.summary().exact_duplicates, 0);
                assert_eq!(preview.summary().conflicts, 2);
                assert!(preview.rows().iter().all(|row| matches!(row.class(), ImportClass::Conflict { existing_ids } if existing_ids == &vec![id])));
                let before = vault.entries().to_vec();
                let revision = vault.revision();
                let disk = fs::read(vault.path()).unwrap();
                let mut incomplete = ImportApplyOptions::for_preview(&preview);
                incomplete.apply_update_candidates = with_provenance;
                incomplete
                    .conflict_resolutions
                    .insert(0, ConflictResolution::UseImported(id));
                assert!(apply_preview(&mut vault, &preview, &incomplete).is_err());
                assert_eq!(vault.entries(), before);
                assert_eq!(vault.revision(), revision);
                assert_eq!(fs::read(vault.path()).unwrap(), disk);
                let mut options = ImportApplyOptions::for_preview(&preview);
                options.conflict_resolutions.insert(
                    0,
                    if overwrite_one {
                        ConflictResolution::UseImported(id)
                    } else {
                        ConflictResolution::KeepBoth
                    },
                );
                options
                    .conflict_resolutions
                    .insert(1, ConflictResolution::KeepBoth);
                let report = apply_preview(&mut vault, &preview, &options).unwrap();
                assert_eq!(report.updated, usize::from(overwrite_one));
                assert_eq!(report.added, if overwrite_one { 1 } else { 2 });
                let identities: std::collections::BTreeSet<_> = vault
                    .entries()
                    .iter()
                    .filter_map(|e| {
                        e.provenance
                            .as_ref()
                            .and_then(|p| p.source_stable_id.as_deref())
                    })
                    .collect();
                assert_eq!(identities, std::collections::BTreeSet::from(["A", "B"]));
            }
        }
    }
}

#[test]
fn review_single_strong_identity_compatibility_and_same_id_duplicates_still_skip() {
    for with_provenance in [false, true] {
        let dir = tempfile::tempdir().unwrap();
        let mut vault =
            VaultSession::create(dir.path().join("vault.pmvault"), "synthetic-master").unwrap();
        let id = add_weak_or_unprovenanced(&mut vault, with_provenance);
        vault.save().unwrap();
        for count in [1, 2] {
            let preview = build_preview(
                &vault,
                batch(vec![synthetic_item(Some("A"), "X", "note"); count]),
            )
            .unwrap();
            assert_eq!(preview.summary().exact_duplicates, 1);
            assert_eq!(preview.summary().source_duplicates, count - 1);
            let before = vault.entry(id).unwrap().clone();
            assert_eq!(
                apply_preview(
                    &mut vault,
                    &preview,
                    &ImportApplyOptions::for_preview(&preview)
                )
                .unwrap()
                .skipped,
                count
            );
            assert_eq!(vault.entry(id).unwrap(), &before);
            assert_eq!(vault.entries().len(), 1);
        }
    }
}

#[test]
fn review_explicit_identity_replacement_cannot_silently_consume_another_strong_exact_row() {
    use password_manager::import::plan::ConflictResolution;
    for reverse in [false, true] {
        let dir = tempfile::tempdir().unwrap();
        let mut vault =
            VaultSession::create(dir.path().join("vault.pmvault"), "synthetic-master").unwrap();
        let original = synthetic_item(Some("A"), "X", "note");
        let id = add_with_old_provenance(&mut vault, &original, old_fingerprint(&original));
        vault.save().unwrap();
        let mut rows = vec![original, synthetic_item(Some("B"), "X", "note")];
        if reverse {
            rows.reverse();
        }
        let writer = usize::from(!reverse);
        let formerly_exact = usize::from(reverse);
        let preview = build_preview(&vault, batch(rows)).unwrap();
        let mut options = ImportApplyOptions::for_preview(&preview);
        options
            .conflict_resolutions
            .insert(writer, ConflictResolution::UseImported(id));
        assert!(apply_preview(&mut vault, &preview, &options).is_err());
        options
            .conflict_resolutions
            .insert(formerly_exact, ConflictResolution::KeepBoth);
        let report = apply_preview(&mut vault, &preview, &options).unwrap();
        assert_eq!(report.updated, 1);
        assert_eq!(report.added, 1);
        let identities: std::collections::BTreeSet<_> = vault
            .entries()
            .iter()
            .filter_map(|e| {
                e.provenance
                    .as_ref()
                    .and_then(|p| p.source_stable_id.as_deref())
            })
            .collect();
        assert_eq!(identities, std::collections::BTreeSet::from(["A", "B"]));
    }
}
