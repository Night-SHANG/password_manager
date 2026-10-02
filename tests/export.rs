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

#[cfg(target_os = "linux")]
#[test]
fn newly_created_csv_has_no_group_or_other_access() {
    use std::os::unix::fs::PermissionsExt;
    let dir = tempfile::tempdir().unwrap();
    let vault =
        VaultSession::create(dir.path().join("synthetic.pmvault"), "synthetic-master").unwrap();
    let target = dir.path().join("private.csv");
    export_plaintext_csv(
        &vault,
        &target,
        PlaintextExportAcknowledgement::user_confirmed_risk(),
    )
    .unwrap();
    assert_eq!(
        std::fs::metadata(target).unwrap().permissions().mode() & 0o077,
        0
    );
}

#[test]
fn csv_exact_bytes_order_filtering_empty_and_nested_unicode_paths() {
    let dir = tempfile::tempdir().unwrap();
    let vault_path = dir.path().join("synthetic.pmvault");
    let mut vault = VaultSession::create(&vault_path, "synthetic-master").unwrap();
    let empty = dir.path().join("empty.csv");
    export_plaintext_csv(
        &vault,
        &empty,
        PlaintextExportAcknowledgement::user_confirmed_risk(),
    )
    .unwrap();
    assert_eq!(
        std::fs::read(empty).unwrap(),
        b"name,url,username,password,category,notes\n"
    );
    for index in 0..5 {
        let mut draft = EntryDraft::login(format!("name-{index}"), "", " 空格 ", "synthetic");
        draft.category = "".into();
        draft.secret.notes = if index == 2 {
            "a,\"b\"\r\n中".into()
        } else {
            "".into()
        };
        let id = vault.add_entry(draft).unwrap();
        if index % 2 == 1 {
            vault.move_to_recycle_bin(id).unwrap();
        }
    }
    let before = std::fs::read(&vault_path).unwrap();
    let target = dir.path().join("新建目录/嵌套/导出.csv");
    assert_eq!(
        export_plaintext_csv(
            &vault,
            &target,
            PlaintextExportAcknowledgement::user_confirmed_risk()
        )
        .unwrap(),
        3
    );
    assert_eq!(std::fs::read(target).unwrap(),"name,url,username,password,category,notes\nname-0,, 空格 ,synthetic,,\nname-2,, 空格 ,synthetic,,\"a,\"\"b\"\"\r\n中\"\nname-4,, 空格 ,synthetic,,\n".as_bytes());
    assert_eq!(std::fs::read(vault_path).unwrap(), before);
}

#[test]
fn existing_target_is_never_overwritten_and_is_not_created_by_this_export() {
    use password_manager::export::OutputDisposition;
    let dir = tempfile::tempdir().unwrap();
    let vault =
        VaultSession::create(dir.path().join("synthetic.pmvault"), "synthetic-master").unwrap();
    let target = dir.path().join("sentinel.csv");
    std::fs::write(&target, b"sentinel").unwrap();
    let error = export_plaintext_csv(
        &vault,
        &target,
        PlaintextExportAcknowledgement::user_confirmed_risk(),
    )
    .unwrap_err();
    let password_manager::AppError::Export(failure) = error else {
        panic!("typed export failure required")
    };
    assert_eq!(failure.output, OutputDisposition::NotCreated);
    assert!(!password_manager::AppError::Export(failure).invalidates_session());
    assert_eq!(std::fs::read(target).unwrap(), b"sentinel");
}
