use std::fs;

use password_manager::domain::EntryDraft;
use password_manager::storage::VaultSession;

#[test]
fn create_save_open_and_reveal_round_trip() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("test.pmvault");

    let mut vault = VaultSession::create(&path, "correct horse battery staple").unwrap();
    let id = vault
        .add_entry(EntryDraft::login(
            "GitHub",
            "https://github.com",
            "ada",
            "hunter2",
        ))
        .unwrap();
    vault.save().unwrap();
    drop(vault);

    let reopened = VaultSession::open(&path, "correct horse battery staple").unwrap();
    assert_eq!(reopened.active_entries().count(), 1);
    let secret = reopened.reveal_secret(id).unwrap();
    assert_eq!(secret.password, "hunter2");
}

#[test]
fn wrong_master_password_fails_closed() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("test.pmvault");
    VaultSession::create(&path, "right-password").unwrap();

    assert!(VaultSession::open(&path, "wrong-password").is_err());
}

#[test]
fn tampered_file_is_rejected() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("test.pmvault");
    VaultSession::create(&path, "password").unwrap();

    let mut bytes = fs::read(&path).unwrap();
    let pos = bytes.len() / 2;
    bytes[pos] ^= 1;
    fs::write(&path, bytes).unwrap();

    assert!(VaultSession::open(&path, "password").is_err());
}

#[test]
fn external_change_blocks_save() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("test.pmvault");
    let mut vault = VaultSession::create(&path, "password").unwrap();

    let mut bytes = fs::read(&path).unwrap();
    bytes.push(b' ');
    fs::write(&path, bytes).unwrap();

    assert!(vault.save().is_err());
}
