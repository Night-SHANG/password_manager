use password_manager::domain::EntryDraft;
use password_manager::storage::VaultSession;

#[test]
fn favorite_recycle_restore_and_permanent_delete_persist() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("lifecycle.pmvault");

    let mut vault = VaultSession::create(&path, "master-password").unwrap();
    let id = vault
        .add_entry(EntryDraft::login(
            "Example",
            "https://example.test",
            "user",
            "password",
        ))
        .unwrap();

    vault.set_favorite(id, true).unwrap();
    vault.save().unwrap();

    let reopened = VaultSession::open(&path, "master-password").unwrap();
    assert!(reopened.entry(id).unwrap().favorite);
    drop(reopened);

    vault.move_to_recycle_bin(id).unwrap();
    vault.save().unwrap();
    let reopened = VaultSession::open(&path, "master-password").unwrap();
    assert!(reopened.entry(id).unwrap().is_deleted());
    drop(reopened);

    vault.restore_from_recycle_bin(id).unwrap();
    vault.save().unwrap();
    assert!(!vault.entry(id).unwrap().is_deleted());

    vault.move_to_recycle_bin(id).unwrap();
    vault.permanently_delete(id).unwrap();
    vault.save().unwrap();

    let reopened = VaultSession::open(&path, "master-password").unwrap();
    assert!(reopened.entry(id).is_none());
}

#[test]
fn permanent_delete_requires_recycle_bin_state() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("lifecycle.pmvault");
    let mut vault = VaultSession::create(&path, "master-password").unwrap();
    let id = vault
        .add_entry(EntryDraft::login(
            "Example",
            "https://example.test",
            "user",
            "password",
        ))
        .unwrap();

    assert!(vault.permanently_delete(id).is_err());
    assert!(vault.entry(id).is_some());
}
