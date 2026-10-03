//! Narrow architecture guards complement real-worker behavioral regressions.
//! They are not a proof of thread safety or a substitute for the lifecycle suite.

const INLINE_TESTS: &str = "#[cfg(test)]\nmod tests {";
const MESSAGE_START: &str = "enum Message {";
const MESSAGE_END: &str = "\n}\n\nimpl std::fmt::Debug for Message {";

fn split_unique<'a>(source: &'a str, marker: &str) -> Result<(&'a str, &'a str), String> {
    let (before, after) = source
        .split_once(marker)
        .ok_or_else(|| format!("missing source boundary: {marker:?}"))?;
    if after.contains(marker) {
        return Err(format!("ambiguous source boundary: {marker:?}"));
    }
    Ok((before, after))
}

fn check_gui_source(source: &str, inline_tests: bool) -> Result<(), String> {
    let source = source.replace("\r\n", "\n");
    // Module-level unit tests intentionally retain synchronous fixture APIs.
    let production = if inline_tests {
        split_unique(&source, INLINE_TESTS)?.0
    } else {
        &source
    };
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
        if production.contains(forbidden) {
            return Err(format!("direct synchronous vault path: {forbidden}"));
        }
    }
    Ok(())
}

fn check_message_source(source: &str) -> Result<(), String> {
    let source = source.replace("\r\n", "\n");
    // Deliberately require the current item boundaries instead of parsing Rust.
    let after_start = split_unique(&source, MESSAGE_START)?.1;
    let message = split_unique(after_start, MESSAGE_END)?.0;
    for forbidden in [
        "VaultSession",
        "OperationPayload",
        "OperationInput",
        "ImportPreview",
        "SecretPayload",
        "TerminalOutcome",
    ] {
        if message.contains(forbidden) {
            return Err(format!("owned worker data in UI message: {forbidden}"));
        }
    }
    if !message.contains("OperationSignal") {
        return Err("missing OperationSignal in UI message".into());
    }
    Ok(())
}

#[test]
fn gui_vault_publishers_remain_on_owned_operation_path() {
    let sources = [
        ("app", include_str!("../src/app.rs"), false),
        ("actions", include_str!("../src/app/actions.rs"), false),
        (
            "operations",
            include_str!("../src/app/operations.rs"),
            false,
        ),
        ("recovery", include_str!("../src/app/recovery.rs"), false),
        (
            "export_notice",
            include_str!("../src/app/export_notice.rs"),
            true,
        ),
    ];
    for (name, source, inline_tests) in sources {
        check_gui_source(source, inline_tests).unwrap_or_else(|error| panic!("{name}: {error}"));
    }
}

#[test]
fn runtime_messages_do_not_carry_owned_worker_secrets_or_results() {
    check_message_source(include_str!("../src/app.rs")).unwrap();
    let operations = include_str!("../src/app/operations.rs");
    assert!(operations.contains(".submit_owned(admission, input, retired)"));
    assert!(operations.contains(".claim_adoption(id, current, now)"));
    assert!(!operations.contains("test_cleanup_witness"));
}

fn gui_fixture(production: &str) -> String {
    format!("{production}\n{INLINE_TESTS}\n    fn fixture() {{ VaultSession::create(); }}\n}}\n")
}

fn message_fixture(variants: &str) -> String {
    format!("{MESSAGE_START}\n    {variants}{MESSAGE_END}\n}}\nstruct Worker(VaultSession);\n")
}

#[test]
fn gui_guard_excludes_test_fixtures_with_lf_and_crlf() {
    for newline in ["\n", "\r\n"] {
        let source = gui_fixture("fn production() {}").replace('\n', newline);
        assert_eq!(check_gui_source(&source, true), Ok(()));
        assert_eq!(check_gui_source("fn production() {}", false), Ok(()));
    }
}

#[test]
fn gui_guard_rejects_forbidden_production_with_lf_and_crlf() {
    for newline in ["\n", "\r\n"] {
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
            let source = gui_fixture(forbidden).replace('\n', newline);
            for (source, inline_tests) in [(forbidden, false), (source.as_str(), true)] {
                assert_eq!(
                    check_gui_source(source, inline_tests),
                    Err(format!("direct synchronous vault path: {forbidden}"))
                );
            }
        }
    }
}

#[test]
fn gui_guard_rejects_missing_or_ambiguous_test_boundary() {
    for newline in ["\n", "\r\n"] {
        for source in [
            "fn production() {}".to_owned(),
            format!("{INLINE_TESTS}\n}}\n{INLINE_TESTS}\n}}\n"),
        ] {
            assert!(check_gui_source(&source.replace('\n', newline), true).is_err());
        }
    }
}

#[test]
fn message_guard_excludes_other_items_with_lf_and_crlf() {
    for newline in ["\n", "\r\n"] {
        let source = message_fixture("OperationSignal(OperationSignal),").replace('\n', newline);
        assert_eq!(check_message_source(&source), Ok(()));
    }
}

#[test]
fn message_guard_rejects_forbidden_variants_with_lf_and_crlf() {
    for newline in ["\n", "\r\n"] {
        for forbidden in [
            "VaultSession",
            "OperationPayload",
            "OperationInput",
            "ImportPreview",
            "SecretPayload",
            "TerminalOutcome",
        ] {
            let source = message_fixture(&format!(
                "OperationSignal(OperationSignal),\n    Owned({forbidden}),"
            ))
            .replace('\n', newline);
            assert_eq!(
                check_message_source(&source),
                Err(format!("owned worker data in UI message: {forbidden}"))
            );
        }
        let source = message_fixture("Tick,").replace('\n', newline);
        assert!(check_message_source(&source).is_err());
    }
}

#[test]
fn message_guard_rejects_missing_or_ambiguous_boundaries() {
    for newline in ["\n", "\r\n"] {
        for source in [
            format!("OperationSignal,{MESSAGE_END}\n}}\n"),
            format!("{MESSAGE_START}\n    OperationSignal,"),
            format!("{MESSAGE_START}\n{MESSAGE_START}\nOperationSignal,{MESSAGE_END}\n}}\n"),
            format!("{MESSAGE_START}\nOperationSignal,{MESSAGE_END}\n}}\n{MESSAGE_END}\n}}\n"),
        ] {
            assert!(check_message_source(&source.replace('\n', newline)).is_err());
        }
    }
}
