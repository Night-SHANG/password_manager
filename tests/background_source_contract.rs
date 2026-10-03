//! Narrow architecture guards complement real-worker behavioral regressions.
//! They are not a proof of thread safety or a substitute for the lifecycle suite.
#[test]
fn gui_vault_publishers_remain_on_owned_operation_path() {
    let sources = [
        ("app", include_str!("../src/app.rs")),
        ("actions", include_str!("../src/app/actions.rs")),
        ("operations", include_str!("../src/app/operations.rs")),
        ("recovery", include_str!("../src/app/recovery.rs")),
        ("export_notice", include_str!("../src/app/export_notice.rs")),
    ];
    for (name, source) in sources {
        // Module-level unit tests intentionally retain synchronous fixture APIs.
        let production = source.split("#[cfg(test)]\nmod tests {").next().unwrap();
        for forbidden in [
            "VaultSession::create(",
            "VaultSession::open(",
            ".prepare_save(",
            ".verify_current_file(",
            ".export_csv(",
            ".backup_to(",
            "plan::build_preview(",
            "plan::apply_preview(",
            "import::stage_path(",
            "recovery::inspect(",
            "transaction::commit(",
        ] {
            assert!(
                !production.contains(forbidden),
                "direct synchronous vault path in {name}: {forbidden}"
            );
        }
    }
}

#[test]
fn runtime_messages_do_not_carry_owned_worker_secrets_or_results() {
    let source = include_str!("../src/app.rs");
    let message = source
        .split("enum Message {")
        .nth(1)
        .unwrap()
        .split("\n}\n")
        .next()
        .unwrap();
    for forbidden in [
        "VaultSession",
        "OperationPayload",
        "OperationInput",
        "ImportPreview",
        "SecretPayload",
        "TerminalOutcome",
    ] {
        assert!(
            !message.contains(forbidden),
            "owned worker data in UI message: {forbidden}"
        );
    }
    assert!(message.contains("OperationSignal"));
    let operations = include_str!("../src/app/operations.rs");
    assert!(operations.contains(".submit_owned(admission, input, retired)"));
    assert!(operations.contains(".claim_adoption(id, current, now)"));
    assert!(!operations.contains("test_cleanup_witness"));
}
