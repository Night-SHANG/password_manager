use password_manager::domain::EntryDraft;
use password_manager::storage::VaultSession;

#[test]
fn encrypted_backup_restore_preserves_vault_identity() {
    let dir = tempfile::tempdir().unwrap();
    let source = dir.path().join("source.pmvault");
    let backup = dir.path().join("backup.pmvault");
    let restored = dir.path().join("restored.pmvault");

    let mut vault = VaultSession::create(&source, "master-password").unwrap();
    let entry_id = vault
        .add_entry(EntryDraft::login(
            "Synthetic",
            "https://example.test",
            "tester",
            "synthetic-password",
        ))
        .unwrap();
    vault.save().unwrap();

    let vault_id = vault.vault_id();
    let revision = vault.revision();
    vault.export_encrypted_backup(&backup).unwrap();

    VaultSession::restore_encrypted_backup(&backup, &restored, "master-password", false).unwrap();

    let restored = VaultSession::open(&restored, "master-password").unwrap();
    assert_eq!(restored.vault_id(), vault_id);
    assert_eq!(restored.revision(), revision);
    assert_eq!(
        restored.reveal_secret(entry_id).unwrap().password,
        "synthetic-password"
    );
}

#[test]
fn restore_can_atomically_replace_an_existing_vault() {
    let dir = tempfile::tempdir().unwrap();
    let source = dir.path().join("source.pmvault");
    let backup = dir.path().join("backup.pmvault");
    let target = dir.path().join("target.pmvault");

    let mut source_vault = VaultSession::create(&source, "source-master").unwrap();
    source_vault
        .add_entry(EntryDraft::login("Source", "https://source.test", "u", "p"))
        .unwrap();
    source_vault.save().unwrap();
    source_vault.export_encrypted_backup(&backup).unwrap();
    let expected_id = source_vault.vault_id();

    VaultSession::create(&target, "different-master").unwrap();

    VaultSession::restore_encrypted_backup(&backup, &target, "source-master", true).unwrap();

    let restored = VaultSession::open(&target, "source-master").unwrap();
    assert_eq!(restored.vault_id(), expected_id);
    assert_eq!(restored.active_entries().count(), 1);
}
