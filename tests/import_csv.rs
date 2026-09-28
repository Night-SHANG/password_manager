use password_manager::import::csv::parse_reader;

#[test]
fn chrome_reimport_is_stable_at_normalization_layer() {
    let csv = "name,url,username,password,note\nGitHub,https://github.com,ada,pw,note\n";
    let first = parse_reader(csv.as_bytes()).unwrap();
    let second = parse_reader(csv.as_bytes()).unwrap();

    assert_eq!(first.items.len(), 1);
    assert_eq!(first.items[0].fingerprint, second.items[0].fingerprint);
}

#[test]
fn changed_password_changes_fingerprint() {
    let old = parse_reader(
        "name,url,username,password\nGitHub,https://github.com,ada,old\n".as_bytes(),
    )
    .unwrap();
    let new = parse_reader(
        "name,url,username,password\nGitHub,https://github.com,ada,new\n".as_bytes(),
    )
    .unwrap();

    assert_ne!(old.items[0].fingerprint, new.items[0].fingerprint);
}

#[test]
fn source_missing_an_old_row_does_not_encode_deletion_semantics() {
    let csv = "name,url,username,password\nOnlyCurrent,https://current.example,u,pw\n";
    let parsed = parse_reader(csv.as_bytes()).unwrap();

    assert_eq!(parsed.items.len(), 1);
    assert_eq!(parsed.items[0].name, "OnlyCurrent");
}
