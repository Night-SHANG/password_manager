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
            ..ImportApplyOptions::default()
        },
    )
    .unwrap();
    assert_eq!(report.added, 1);

    let repeated = build_preview(&vault, csv::parse_path(&csv_path).unwrap()).unwrap();
    assert!(repeated.same_source_file);
    assert!(matches!(
        &repeated.rows[0].class,
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
        &changed.rows[0].class,
        ImportClass::UpdateCandidate { .. }
    ));

    let report = apply_preview(
        &mut vault,
        &changed,
        &ImportApplyOptions {
            apply_update_candidates: true,
            ..ImportApplyOptions::default()
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
            ..ImportApplyOptions::default()
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
        &preview.rows[0].class,
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
            ..ImportApplyOptions::default()
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
    apply_preview(&mut vault, &preview, &ImportApplyOptions::default()).unwrap();
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
                ..ImportApplyOptions::default()
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
            ..ImportApplyOptions::default()
        },
    )
    .unwrap();

    let id = vault.active_entries().next().unwrap().id;
    vault.move_to_recycle_bin(id).unwrap();
    vault.save().unwrap();
    assert_eq!(vault.active_entries().count(), 0);

    let preview = build_preview(&vault, csv::parse_path(&csv_path).unwrap()).unwrap();
    assert!(matches!(
        &preview.rows[0].class,
        ImportClass::LocallyDeleted { .. }
    ));

    let report = apply_preview(&mut vault, &preview, &ImportApplyOptions::default()).unwrap();
    assert_eq!(report.locally_deleted_deferred, 1);
    assert_eq!(vault.active_entries().count(), 0);
}
