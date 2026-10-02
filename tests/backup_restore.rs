use std::fs;

use password_manager::AppError;
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
    let original = fs::read(&source).unwrap();
    let backup_bytes = fs::read(&backup).unwrap();
    let original_file_count = fs::read_dir(dir.path()).unwrap().count();

    VaultSession::restore_encrypted_backup(&backup, &restored, "master-password", false).unwrap();

    assert_eq!(fs::read(&restored).unwrap(), backup_bytes);
    assert_eq!(fs::read(&backup).unwrap(), backup_bytes);
    assert_eq!(fs::read(&source).unwrap(), original);
    assert_eq!(
        fs::read_dir(dir.path()).unwrap().count(),
        original_file_count + 1
    );
    let restored = VaultSession::open(&restored, "master-password").unwrap();
    assert_eq!(restored.vault_id(), vault_id);
    assert_eq!(restored.revision(), revision);
    assert_eq!(
        restored.reveal_secret(entry_id).unwrap().password,
        "synthetic-password"
    );
}

#[test]
fn restore_without_overwrite_preserves_existing_vault() {
    let dir = tempfile::tempdir().unwrap();
    let source = dir.path().join("source.pmvault");
    let target = dir.path().join("target.pmvault");
    VaultSession::create(&source, "source-master").unwrap();
    VaultSession::create(&target, "target-master").unwrap();
    let original_source = fs::read(&source).unwrap();
    let original_target = fs::read(&target).unwrap();

    let result = VaultSession::restore_encrypted_backup(&source, &target, "source-master", false);

    assert!(matches!(result, Err(AppError::AlreadyExists)));
    assert_eq!(fs::read(&target).unwrap(), original_target);
    assert_eq!(fs::read(&source).unwrap(), original_source);
    assert_eq!(fs::read_dir(dir.path()).unwrap().count(), 2);
}

#[test]
fn restore_wrong_password_preserves_source_and_existing_target() {
    let dir = tempfile::tempdir().unwrap();
    let source = dir.path().join("source.pmvault");
    let target = dir.path().join("target.pmvault");
    let missing = dir.path().join("missing.pmvault");
    VaultSession::create(&source, "source-master").unwrap();
    VaultSession::create(&target, "target-master").unwrap();
    let original_source = fs::read(&source).unwrap();
    let original_target = fs::read(&target).unwrap();

    for (destination, overwrite) in [(&target, false), (&target, true), (&missing, false)] {
        assert!(
            VaultSession::restore_encrypted_backup(
                &source,
                destination,
                "wrong-master",
                overwrite,
            )
            .is_err()
        );
        assert_eq!(fs::read(&target).unwrap(), original_target);
        assert_eq!(fs::read(&source).unwrap(), original_source);
        assert!(!missing.exists());
        assert_eq!(fs::read_dir(dir.path()).unwrap().count(), 2);
    }
}

#[test]
fn restore_corrupt_source_preserves_existing_target() {
    let dir = tempfile::tempdir().unwrap();
    let source = dir.path().join("corrupt.pmvault");
    let target = dir.path().join("target.pmvault");
    let missing = dir.path().join("missing.pmvault");
    let corrupt = b"synthetic corrupt backup";
    fs::write(&source, corrupt).unwrap();
    VaultSession::create(&target, "target-master").unwrap();
    let original_target = fs::read(&target).unwrap();

    for (destination, overwrite) in [(&target, false), (&target, true), (&missing, false)] {
        assert!(
            VaultSession::restore_encrypted_backup(
                &source,
                destination,
                "source-master",
                overwrite,
            )
            .is_err()
        );
        assert_eq!(fs::read(&target).unwrap(), original_target);
        assert_eq!(fs::read(&source).unwrap(), corrupt);
        assert!(!missing.exists());
        assert_eq!(fs::read_dir(dir.path()).unwrap().count(), 2);
    }
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
