use password_manager::domain::EntryDraft;
use password_manager::export::{PlaintextExportAcknowledgement, export_plaintext_csv};
use password_manager::import::csv;
use password_manager::storage::VaultSession;

#[test]
fn plaintext_csv_export_requires_explicit_ack_type_and_round_trips() {
    let dir = tempfile::tempdir().unwrap();
    let vault_path = dir.path().join("vault.pmvault");
    let export_path = dir.path().join("export.csv");

    let mut vault = VaultSession::create(&vault_path, "master-password").unwrap();
    let mut draft = EntryDraft::login(
        "Synthetic",
        "https://example.test",
        "tester",
        "  synthetic password  ",
    );
    draft.secret.notes = "note,with,commas".to_string();
    vault.add_entry(draft).unwrap();
    vault.save().unwrap();

    let count = export_plaintext_csv(
        &vault,
        &export_path,
        PlaintextExportAcknowledgement::user_confirmed_risk(),
    )
    .unwrap();
    assert_eq!(count, 1);

    let imported = csv::parse_path(&export_path).unwrap();
    assert_eq!(imported.items.len(), 1);
    assert_eq!(imported.items[0].password, "  synthetic password  ");
    assert_eq!(imported.items[0].notes, "note,with,commas");
}
