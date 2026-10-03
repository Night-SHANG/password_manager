//! Actual App-worker import retry, invalidation, and one-shot epoch regressions.
use super::*;

fn csv_row(path: &std::path::Path, password: &str) {
    let mut writer = csv::Writer::from_path(path).unwrap();
    writer
        .write_record(["name", "url", "username", "password", "note"])
        .unwrap();
    writer
        .write_record([
            "Repeat",
            "https://repeat.example.test",
            "synthetic-user",
            password,
            "synthetic-note",
        ])
        .unwrap();
    writer.flush().unwrap();
}
fn analyze_path(app: &mut App, path: &std::path::Path) -> Uuid {
    app.test_update(Message::OpenImport);
    app.test_update(Message::ImportPathChanged(path.display().to_string()));
    app.test_update(Message::AnalyzeImport);
    let Panel::Import(state) = &app.panel else {
        panic!("import panel");
    };
    state.preview.as_ref().unwrap().id()
}
#[test]
fn import_review_noop_consumes_epoch_without_claiming_verified_disk_write() {
    for external_change in [false, true] {
        let (dir, mut app) = tests::fixture(0);
        let source = dir.path().join("repeat.csv");
        csv_row(&source, "synthetic-original");
        let first = analyze_path(&mut app, &source);
        app.test_update(Message::ApplyImport(first));
        let repeated = analyze_path(&mut app, &source);
        let Panel::Import(state) = &app.panel else {
            panic!("import")
        };
        assert_eq!(
            state.preview.as_ref().unwrap().summary().exact_duplicates,
            1
        );
        let before = app.session.as_ref().unwrap().import_binding();
        let revision = app.session.as_ref().unwrap().revision();
        if external_change {
            std::fs::write(&app.vault_path, b"synthetic external replacement").unwrap();
        }
        let disk = std::fs::read(&app.vault_path).unwrap();
        app.operations.commit_notice = None;
        app.test_update(Message::ApplyImport(repeated));
        assert!(
            app.operations.commit_notice.is_none(),
            "no-op import did not write or verify disk and must not publish a write receipt"
        );
        assert_eq!(std::fs::read(&app.vault_path).unwrap(), disk);
        let session = app.session.as_ref().unwrap();
        assert_eq!(session.revision(), revision);
        assert_ne!(session.import_binding(), before);
        let Panel::Import(state) = &app.panel else {
            panic!("import")
        };
        assert!(state.preview.is_none());
        assert_old_import_messages_cannot_reuse_epoch(&mut app, repeated);
    }
}
#[test]
fn import_review_deferred_update_consumes_epoch_without_write_receipt() {
    let (dir, mut app) = tests::fixture(0);
    let source = dir.path().join("defer.csv");
    csv_row(&source, "synthetic-original");
    let first = analyze_path(&mut app, &source);
    app.test_update(Message::ApplyImport(first));
    csv_row(&source, "synthetic-updated");
    let id = analyze_path(&mut app, &source);
    let Panel::Import(state) = &app.panel else {
        panic!("import")
    };
    assert_eq!(
        state.preview.as_ref().unwrap().summary().update_candidates,
        1
    );
    app.test_update(Message::ImportApplyUpdatesChanged(id, false));
    let before = app.session.as_ref().unwrap().import_binding();
    let revision = app.session.as_ref().unwrap().revision();
    let disk = std::fs::read(&app.vault_path).unwrap();
    app.operations.commit_notice = None;
    app.test_update(Message::ApplyImport(id));
    assert!(
        app.operations.commit_notice.is_none(),
        "deferred import must not claim verified publication"
    );
    assert_eq!(std::fs::read(&app.vault_path).unwrap(), disk);
    let session = app.session.as_ref().unwrap();
    assert_eq!(session.revision(), revision);
    assert_ne!(session.import_binding(), before);
    assert_eq!(
        session
            .reveal_secret(session.entries()[0].id)
            .unwrap()
            .password,
        "synthetic-original"
    );
    let Panel::Import(state) = &app.panel else {
        panic!("import")
    };
    assert!(state.preview.is_none());
    assert_old_import_messages_cannot_reuse_epoch(&mut app, id);
}
#[test]
fn import_review_safe_unchanged_error_returns_same_preview_and_decisions_for_retry() {
    use crate::storage::transaction::{Point, set_worker_hook};
    let (dir, mut app) = tests::fixture(2);
    let ids: Vec<_> = app
        .session
        .as_ref()
        .unwrap()
        .entries()
        .iter()
        .map(|entry| entry.id)
        .collect();
    let source = dir.path().join("conflicts.csv");
    let mut writer = csv::Writer::from_path(&source).unwrap();
    writer
        .write_record(["name", "url", "username", "password", "note"])
        .unwrap();
    for entry in app.session.as_ref().unwrap().entries() {
        writer
            .write_record([
                entry.name.as_str(),
                entry.website.as_str(),
                entry.username.as_str(),
                "synthetic-new-value",
                "new note",
            ])
            .unwrap();
    }
    writer.flush().unwrap();
    drop(writer);
    let id = analyze_path(&mut app, &source);
    let Panel::Import(state) = &app.panel else {
        panic!("import")
    };
    assert_eq!(state.preview.as_ref().unwrap().summary().conflicts, 2);
    app.test_update(Message::SetImportResolution(
        id,
        0,
        ConflictResolution::UseImported(ids[0]),
    ));
    app.test_update(Message::SetImportResolution(
        id,
        1,
        ConflictResolution::KeepLocal,
    ));
    app.test_update(Message::ImportApplyUpdatesChanged(id, false));
    let Panel::Import(state) = &app.panel else {
        panic!("import")
    };
    let decisions = state.resolutions.clone();
    let binding = app.session.as_ref().unwrap().import_binding();
    let revision = app.session.as_ref().unwrap().revision();
    let disk = std::fs::read(&app.vault_path).unwrap();
    set_worker_hook(Point::BeforePublish, || {
        Err(AppError::Platform(
            "synthetic unchanged import failure".into(),
        ))
    });
    app.test_update(Message::ApplyImport(id));
    let Panel::Import(state) = &app.panel else {
        panic!("safe failure must preserve import panel")
    };
    assert_eq!(
        state.preview.as_ref().map(ImportPreview::id),
        Some(id),
        "safe unchanged failure must return the original staged preview owner"
    );
    assert_eq!(state.resolutions, decisions);
    assert!(!state.apply_updates);
    assert_eq!(app.session.as_ref().unwrap().import_binding(), binding);
    assert_eq!(app.session.as_ref().unwrap().revision(), revision);
    assert_eq!(std::fs::read(&app.vault_path).unwrap(), disk);
    std::fs::rename(&source, dir.path().join("source-moved-after-analysis.csv")).unwrap();
    app.test_update(Message::ApplyImport(id));
    assert_eq!(app.session.as_ref().unwrap().revision(), revision + 1);
    assert_eq!(
        app.session
            .as_ref()
            .unwrap()
            .reveal_secret(ids[0])
            .unwrap()
            .password,
        "synthetic-new-value"
    );
    assert_eq!(
        app.session
            .as_ref()
            .unwrap()
            .reveal_secret(ids[1])
            .unwrap()
            .password,
        "synthetic-not-a-real-password"
    );
    let Panel::Import(state) = &app.panel else {
        panic!("import")
    };
    assert!(state.preview.is_none());
    assert!(state.resolutions.is_empty());
    let after = app.session.as_ref().unwrap().import_binding();
    assert_eq!(after.0, binding.0);
    assert_ne!(
        after.1, binding.1,
        "successful retry consumes the original epoch"
    );
    assert_old_import_messages_cannot_reuse_epoch(&mut app, id);
}

fn staged_conflicts() -> (tempfile::TempDir, App, std::path::PathBuf, [Uuid; 2], Uuid) {
    let (dir, mut app) = tests::fixture(2);
    let source = dir.path().join("owned-conflicts.csv");
    let session = app.session.as_ref().unwrap();
    let ids = [session.entries()[0].id, session.entries()[1].id];
    let mut writer = csv::Writer::from_path(&source).unwrap();
    writer
        .write_record(["name", "url", "username", "password", "note"])
        .unwrap();
    for entry in session.entries() {
        writer
            .write_record([
                entry.name.as_str(),
                entry.website.as_str(),
                entry.username.as_str(),
                "synthetic-new-value",
                "new note",
            ])
            .unwrap();
    }
    writer.flush().unwrap();
    drop(writer);
    let id = analyze_path(&mut app, &source);
    let Panel::Import(state) = &app.panel else {
        panic!("import panel")
    };
    assert_eq!(state.preview.as_ref().unwrap().summary().conflicts, 2);
    app.test_update(Message::SetImportResolution(
        id,
        0,
        ConflictResolution::UseImported(ids[0]),
    ));
    app.test_update(Message::SetImportResolution(
        id,
        1,
        ConflictResolution::KeepLocal,
    ));
    app.test_update(Message::ImportApplyUpdatesChanged(id, false));
    (dir, app, source, ids, id)
}

fn assert_no_preview_or_decisions(app: &App) {
    if let Panel::Import(state) = &app.panel {
        assert!(state.preview.is_none(), "retired preview owner reappeared");
        assert!(state.resolutions.is_empty(), "retired decisions reappeared");
    } else {
        assert!(matches!(app.panel, Panel::Vault));
    }
}

fn assert_old_import_messages_cannot_reuse_epoch(app: &mut App, id: Uuid) {
    let session = app.session.as_ref().unwrap();
    let binding = session.operation_binding();
    let revision = session.revision();
    let disk = std::fs::read(session.path()).unwrap();
    let Panel::Import(state) = &app.panel else {
        panic!("check old import messages on a fresh or consumed import panel")
    };
    let apply_updates = state.apply_updates;
    assert_no_preview_or_decisions(app);
    app.test_update(Message::ImportApplyUpdatesChanged(id, !apply_updates));
    app.test_update(Message::SetImportResolution(
        id,
        0,
        ConflictResolution::KeepBoth,
    ));
    app.test_update(Message::ApplyImport(id));
    assert_no_preview_or_decisions(app);
    let Panel::Import(state) = &app.panel else {
        panic!("stale messages must not navigate")
    };
    assert_eq!(state.apply_updates, apply_updates);
    let session = app.session.as_ref().unwrap();
    assert_eq!(session.operation_binding(), binding);
    assert_eq!(session.revision(), revision);
    assert_eq!(std::fs::read(session.path()).unwrap(), disk);
    assert!(
        !app.operation_busy(),
        "stale preview ID admitted another job"
    );
}

#[test]
fn import_review_real_busy_returns_original_owned_preview_and_retries_once() {
    let (dir, mut app, source, ids, id) = staged_conflicts();
    let session = app.session.as_ref().unwrap();
    let binding = session.operation_binding();
    let epoch = session.import_binding();
    let revision = session.revision();
    let disk = std::fs::read(session.path()).unwrap();
    let held = crate::storage::performance_fixtures::hold_synthetic_save_lock(session.path())
        .expect("synthetic fixture must hold the actual native cooperative save lock");
    app.operations.commit_notice = None;
    app.test_update(Message::ApplyImport(id));
    assert!(app.status.contains("其他保存正在进行"), "{}", app.status);
    assert!(app.status.contains("cooperative lock"), "{}", app.status);
    assert!(app.operations.commit_notice.is_none());
    let session = app.session.as_ref().unwrap();
    assert_eq!(session.operation_binding(), binding);
    assert_eq!(session.import_binding(), epoch);
    assert_eq!(session.revision(), revision);
    assert_eq!(std::fs::read(session.path()).unwrap(), disk);
    let Panel::Import(state) = &app.panel else {
        panic!("Busy must keep the retryable import panel")
    };
    let preview = state
        .preview
        .as_ref()
        .expect("Busy must return the original preview owner");
    assert_eq!(preview.id(), id);
    assert!(
        preview.matches_session_context(session),
        "full session/body binding changed"
    );
    assert_eq!(state.resolutions.len(), 2);
    assert_eq!(
        state.resolutions.get(&0),
        Some(&ConflictResolution::UseImported(ids[0]))
    );
    assert_eq!(
        state.resolutions.get(&1),
        Some(&ConflictResolution::KeepLocal)
    );
    assert!(!state.apply_updates);
    assert!(
        !app.operation_busy(),
        "Busy still occupies the worker after real drain"
    );
    drop(held);
    std::fs::rename(&source, dir.path().join("busy-source-moved.csv")).unwrap();
    app.test_update(Message::ApplyImport(id));
    let session = app.session.as_ref().unwrap();
    assert_eq!(session.revision(), revision + 1);
    assert_eq!(session.import_binding().0, epoch.0);
    assert_ne!(
        session.import_binding().1,
        epoch.1,
        "successful retry must consume import epoch"
    );
    assert_eq!(
        session.reveal_secret(ids[0]).unwrap().password,
        "synthetic-new-value"
    );
    assert_eq!(
        session.reveal_secret(ids[1]).unwrap().password,
        "synthetic-not-a-real-password"
    );
    session.verify_current_file().unwrap();
    assert_no_preview_or_decisions(&app);
    assert_old_import_messages_cannot_reuse_epoch(&mut app, id);
}

#[test]
fn import_review_held_safe_retry_is_discarded_after_cancel_or_security_lock() {
    use crate::storage::transaction::{Point, set_worker_hook};
    use std::sync::mpsc;
    for lock in [false, true] {
        let (_dir, mut app, _source, _ids, id) = staged_conflicts();
        let binding = app.session.as_ref().unwrap().operation_binding();
        let epoch = app.session.as_ref().unwrap().import_binding();
        let disk = std::fs::read(&app.vault_path).unwrap();
        let stamp = app
            .operations
            .authority
            .snapshot(std::time::Instant::now())
            .stamp;
        set_worker_hook(Point::BeforePublish, || {
            Err(AppError::Platform(
                "synthetic unchanged retry held before adoption".into(),
            ))
        });
        let (entered_tx, entered_rx) = mpsc::channel();
        let (release_tx, release_rx) = mpsc::channel();
        app.operations
            .service
            .as_ref()
            .unwrap()
            .before_result_ready_for_test(move || {
                entered_tx.send(()).unwrap();
                let _ = release_rx.recv();
            });
        let apply = app.update(Message::ApplyImport(id));
        assert!(apply.units() > 0);
        entered_rx.recv().unwrap();
        assert!(
            app.session.is_none(),
            "Apply's session owner remains on the real worker"
        );
        assert_no_preview_or_decisions(&app);
        let transition = app.update(if lock {
            Message::Lock
        } else {
            Message::CancelPanel
        });
        let current = app.operations.authority.snapshot(std::time::Instant::now());
        assert!(
            current.occupied.is_some(),
            "held result cannot acknowledge cleanup early"
        );
        if lock {
            assert!(current.masked);
            assert_ne!(current.stamp.epoch, stamp.epoch);
        } else {
            assert_ne!(current.stamp.form, stamp.form);
        }
        assert!(matches!(app.panel, Panel::Vault));
        release_tx.send(()).unwrap();
        tests::drain_task(&mut app, Task::batch([apply, transition]));
        assert_no_preview_or_decisions(&app);
        assert!(!app.operation_busy());
        assert_eq!(std::fs::read(&app.vault_path).unwrap(), disk);
        if lock {
            assert!(
                app.session.is_none(),
                "security revoke cannot readopt the old session"
            );
            app.security_monitor_ready = true;
            app.test_update(Message::MasterPasswordChanged(
                "gui-synthetic-master-only".into(),
            ));
            app.test_update(Message::OpenVault);
            let session = app.session.as_ref().unwrap();
            assert_ne!(
                session.import_binding(),
                epoch,
                "fresh unlock cannot reuse retired import binding"
            );
        } else {
            assert_eq!(app.session.as_ref().unwrap().operation_binding(), binding);
        }
        app.test_update(Message::OpenImport);
        assert_old_import_messages_cannot_reuse_epoch(&mut app, id);
    }
}

#[test]
fn import_review_external_target_change_invalidates_retry_preview_and_options() {
    let (_dir, mut app, _source, _ids, id) = staged_conflicts();
    let target = std::path::PathBuf::from(&app.vault_path);
    let competitor = b"synthetic external replacement must be preserved";
    std::fs::write(&target, competitor).unwrap();
    app.operations.commit_notice = None;
    app.test_update(Message::ApplyImport(id));
    assert!(
        app.session.is_none(),
        "external target conflict invalidates the old session"
    );
    assert!(app.operations.commit_notice.is_none());
    assert!(
        app.recovery_notice.is_some(),
        "invalidating target failure must remain visible"
    );
    assert_no_preview_or_decisions(&app);
    assert!(!app.operation_busy());
    assert_eq!(std::fs::read(&target).unwrap(), competitor);
    app.test_update(Message::ImportApplyUpdatesChanged(id, true));
    app.test_update(Message::SetImportResolution(
        id,
        0,
        ConflictResolution::KeepBoth,
    ));
    app.test_update(Message::ApplyImport(id));
    app.test_update(Message::OpenImport);
    assert!(app.session.is_none());
    assert_no_preview_or_decisions(&app);
    assert!(
        !app.operation_busy(),
        "invalidated preview ID must never admit retry"
    );
    assert_eq!(std::fs::read(target).unwrap(), competitor);
}
