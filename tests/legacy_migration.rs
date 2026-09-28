use base64::{
    Engine as _,
    engine::general_purpose::{STANDARD, URL_SAFE},
};
use fernet::Fernet;
use password_manager::import::legacy::{stage_passwords_db, stage_vault_enc};
use password_manager::import::plan::{
    ImportApplyOptions, ImportClass, apply_preview, build_preview,
};
use password_manager::storage::VaultSession;
use pbkdf2::{pbkdf2_hmac_array, sha2::Sha256 as LegacySha256};
use rusqlite::{Connection, params};
use zeroize::Zeroize;

fn legacy_cipher(master_password: &str, salt: &[u8; 16]) -> Fernet {
    let mut raw = pbkdf2_hmac_array::<LegacySha256, 32>(master_password.as_bytes(), salt, 480_000);
    let key = URL_SAFE.encode(raw);
    raw.zeroize();
    Fernet::new(&key).unwrap()
}

fn legacy_encrypt(cipher: &Fernet, plaintext: &str) -> String {
    STANDARD.encode(cipher.encrypt(plaintext.as_bytes()).as_bytes())
}

fn create_legacy_db(path: &std::path::Path, master_password: &str, stored_password: &str) {
    let salt = [9u8; 16];
    let cipher = legacy_cipher(master_password, &salt);

    let conn = Connection::open(path).unwrap();
    conn.execute_batch(
        "
        CREATE TABLE vault_meta (key TEXT PRIMARY KEY, value TEXT NOT NULL);
        CREATE TABLE entries (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT DEFAULT '',
            website TEXT DEFAULT '',
            username TEXT DEFAULT '',
            password TEXT NOT NULL,
            category TEXT DEFAULT '其他',
            notes TEXT DEFAULT '',
            is_favorite INTEGER DEFAULT 0,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL
        );
        ",
    )
    .unwrap();

    conn.execute(
        "INSERT INTO vault_meta (key, value) VALUES (?1, ?2)",
        params!["salt", STANDARD.encode(salt)],
    )
    .unwrap();
    conn.execute(
        "INSERT INTO vault_meta (key, value) VALUES (?1, ?2)",
        params!["verify", legacy_encrypt(&cipher, "verify")],
    )
    .unwrap();
    conn.execute(
        "INSERT INTO entries
         (name, website, username, password, category, notes, is_favorite, created_at, updated_at)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, 1, ?7, ?7)",
        params![
            "Synthetic DB",
            "https://db.example.test",
            "tester",
            legacy_encrypt(&cipher, stored_password),
            "测试",
            "synthetic note",
            "2026-01-01T00:00:00"
        ],
    )
    .unwrap();
}

#[test]
fn synthetic_vault_enc_is_migrated() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("vault.enc");
    let salt = [3u8; 16];
    let cipher = legacy_cipher("old-master", &salt);

    let list = serde_json::json!([
        {
            "name": "Synthetic",
            "website": "https://example.test",
            "username": "tester",
            "password": "synthetic-password"
        }
    ]);
    let token = cipher.encrypt(serde_json::to_string(&list).unwrap().as_bytes());
    let envelope = serde_json::json!({
        "salt": STANDARD.encode(salt),
        "passwords": STANDARD.encode(token.as_bytes())
    });
    std::fs::write(&path, serde_json::to_vec(&envelope).unwrap()).unwrap();

    let batch = stage_vault_enc(&path, "old-master").unwrap();
    assert_eq!(batch.items.len(), 1);
    assert_eq!(batch.items[0].password, "synthetic-password");
    assert!(stage_vault_enc(&path, "wrong-master").is_err());
}

#[test]
fn synthetic_legacy_sqlite_is_read_and_decrypted() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("passwords.db");
    create_legacy_db(&path, "old-master", "synthetic-db-password");

    let batch = stage_passwords_db(&path, "old-master").unwrap();
    assert_eq!(batch.items.len(), 1);
    assert_eq!(batch.items[0].password, "synthetic-db-password");
    assert_eq!(batch.items[0].notes, "synthetic note");
    assert!(batch.items[0].favorite);
    assert_eq!(batch.items[0].source_stable_id.as_deref(), Some("entry:1"));
    assert!(stage_passwords_db(&path, "wrong-master").is_err());
}

#[test]
fn legacy_db_stable_id_supports_true_incremental_update() {
    let dir = tempfile::tempdir().unwrap();
    let old_db = dir.path().join("passwords.db");
    let vault_path = dir.path().join("new.pmvault");
    create_legacy_db(&old_db, "old-master", "source-v1");

    let mut vault = VaultSession::create(&vault_path, "new-master").unwrap();
    let first = build_preview(&vault, stage_passwords_db(&old_db, "old-master").unwrap()).unwrap();
    apply_preview(
        &mut vault,
        &first,
        &ImportApplyOptions {
            apply_update_candidates: true,
            ..ImportApplyOptions::default()
        },
    )
    .unwrap();

    let conn = Connection::open(&old_db).unwrap();
    let salt = [9u8; 16];
    let cipher = legacy_cipher("old-master", &salt);
    conn.execute(
        "UPDATE entries SET password = ?1, updated_at = ?2 WHERE id = 1",
        params![legacy_encrypt(&cipher, "source-v2"), "2026-02-01T00:00:00"],
    )
    .unwrap();
    drop(conn);

    let second = build_preview(&vault, stage_passwords_db(&old_db, "old-master").unwrap()).unwrap();
    assert!(matches!(
        &second.rows[0].class,
        ImportClass::UpdateCandidate { .. }
    ));

    apply_preview(
        &mut vault,
        &second,
        &ImportApplyOptions {
            apply_update_candidates: true,
            ..ImportApplyOptions::default()
        },
    )
    .unwrap();

    let id = vault.active_entries().next().unwrap().id;
    assert_eq!(vault.reveal_secret(id).unwrap().password, "source-v2");
}
