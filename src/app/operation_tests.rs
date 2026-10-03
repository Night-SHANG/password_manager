use super::*;

#[test]
fn create_submission_returns_observer_and_leases_owned_inputs() {
    let dir = tempfile::tempdir().unwrap();
    let mut app = App::initial();
    app.security_monitor_ready = true;
    app.vault_path = dir
        .path()
        .join("async-create.pmvault")
        .display()
        .to_string();
    app.master_password = "synthetic-background-only".into();
    app.confirm_password = "synthetic-background-only".into();
    app.creating = true;
    let task = app.update(Message::CreateVault);
    assert!(
        task.units() > 0,
        "create must return a completion observer before KDF/publish finishes"
    );
    assert!(
        app.session.is_none(),
        "candidate must not be adopted in the submit handler"
    );
    assert!(app.master_password.is_empty());
    assert!(app.confirm_password.is_empty());
}
#[test]
fn save_submission_moves_session_without_pausing_logical_idle_authority() {
    let (_dir, mut app) = tests::fixture(0);
    let task = app.update(Message::Save);
    assert!(
        task.units() > 0,
        "verify-current must run on the occupied worker lane"
    );
    assert!(
        app.session.is_none(),
        "session ownership must move to worker"
    );
}

#[test]
fn deferred_monitor_ready_after_native_failure_cannot_restore_authority() {
    use std::sync::Arc;
    let mut app = App::initial();
    let authority = Arc::new(crate::operations::authority::Coordinator::new(true));
    app.operations.service =
        Some(crate::operations::runner::OperationService::new(authority.clone()).unwrap());
    app.operations.authority = authority.clone();
    authority.monitor_ready();
    app.security_monitor_ready = true;
    authority.revoke(
        crate::operations::RevokeReason::MonitorFailed,
        std::time::Instant::now(),
    );
    // The native event has already failed closed; this is an older queued UI Ready.
    let task = app.update(Message::PlatformSecurity(SecurityEvent::MonitorReady));
    assert!(
        !authority.snapshot(std::time::Instant::now()).monitor_ready,
        "deferred UI messages cannot grant native readiness"
    );
    drop(task);
}

#[test]
fn late_csv_retention_blocks_pending_close_until_current_warning() {
    use std::sync::mpsc;
    let (dir, mut app) = tests::fixture(2);
    app.session.as_mut().unwrap().body_mut().entries[1]
        .secret
        .ciphertext
        .clear();
    let target = dir.path().join("late-partial.csv");
    app.test_update(Message::OpenSettings);
    app.test_update(Message::CsvPathChanged(target.display().to_string()));
    app.test_update(Message::ConfirmPlaintextChanged(true));
    let (entered_tx, entered_rx) = mpsc::channel();
    let (release_tx, release_rx) = mpsc::channel();
    crate::export::tests::set_worker_after_create(move || {
        entered_tx.send(()).unwrap();
        release_rx.recv().unwrap();
    });
    let export = app.update(Message::ExportPlaintextCsv);
    entered_rx.recv().unwrap();
    let window = iced::window::Id::unique();
    let close = app.update(Message::CloseRequested(window));
    assert!(app.session.is_none());
    assert!(!app.closing);
    assert!(app.export_notice.is_none());
    assert!(
        !app.operations
            .authority
            .snapshot(std::time::Instant::now())
            .fully_locked
    );
    release_tx.send(()).unwrap();
    let effects = tests::drain_task(&mut app, Task::batch([export, close]));
    assert!(!effects.closes(window));
    assert!(!app.closing);
    let prompt = app
        .export_close_prompt
        .expect("late retained output must require a current close warning");
    assert_eq!(app.export_notice.as_ref().unwrap().failure.target, target);
    assert!(target.exists());
    assert_eq!(
        app.test_update(Message::ConfirmExportExit(
            prompt.request,
            prompt.notice_generation.wrapping_sub(1)
        ))
        .units(),
        0
    );
    let effects = app.test_update(Message::ConfirmExportExit(
        prompt.request,
        prompt.notice_generation,
    ));
    assert!(effects.closes(window));
}

#[test]
fn queued_same_render_password_edit_invalidates_old_submit_without_losing_input_batch() {
    let mut app = App::initial();
    let stamp = app
        .operations
        .authority
        .snapshot(std::time::Instant::now())
        .stamp;
    app.test_update(Message::Ui(
        stamp,
        Box::new(Message::MasterPasswordChanged("first".into())),
    ));
    app.test_update(Message::Ui(
        stamp,
        Box::new(Message::MasterPasswordChanged("first plus second".into())),
    ));
    assert_eq!(app.master_password, "first plus second");
    let effect = app.test_update(Message::Ui(stamp, Box::new(Message::OpenVault)));
    assert_eq!(effect.units(), 0);
    assert!(!app.operation_busy());
    assert!(app.session.is_none());
}

#[test]
fn delayed_csv_observer_cannot_be_overtaken_by_close_shutdown() {
    use std::sync::mpsc;
    let (dir, mut app) = tests::fixture(2);
    app.session.as_mut().unwrap().body_mut().entries[1]
        .secret
        .ciphertext
        .clear();
    app.test_update(Message::OpenSettings);
    app.test_update(Message::CsvPathChanged(
        dir.path().join("delayed-risk.csv").display().to_string(),
    ));
    app.test_update(Message::ConfirmPlaintextChanged(true));
    let (tx, rx) = mpsc::channel();
    let (go_tx, go_rx) = mpsc::channel();
    crate::export::tests::set_worker_after_create(move || {
        tx.send(()).unwrap();
        let _ = go_rx.recv();
    });
    let export = app.update(Message::ExportPlaintextCsv);
    rx.recv().unwrap();
    let id = app.operations.active.as_ref().unwrap().id;
    let window = iced::window::Id::unique();
    let close = app.update(Message::CloseRequested(window));
    go_tx.send(()).unwrap();
    app.operations
        .service
        .as_ref()
        .unwrap()
        .wait_for_drain_for_test(id);
    assert!(
        app.operations
            .authority
            .snapshot(std::time::Instant::now())
            .fully_locked
    );
    // No observer message has been dispatched. This is the exact final-close race.
    app.advance_close();
    let shutdown_started = app.operations.shutdown_started;
    let queued = app.operations.task.take().unwrap_or_else(Task::none);
    let effects = tests::drain_task(&mut app, Task::batch([export, close, queued]));
    assert!(
        !shutdown_started,
        "terminal risk must be consumed before starting clipboard shutdown"
    );
    assert!(!effects.closes(window));
    assert!(app.export_close_prompt.is_some());
}

#[test]
fn stored_result_before_ready_cannot_be_irreversibly_consumed_by_tick() {
    use std::sync::mpsc;
    for opening in [false, true] {
        let (_dir, mut app) = tests::fixture(1);
        if opening {
            app.test_update(Message::Lock);
            app.master_password = "gui-synthetic-master-only".into();
        }
        let (tx, rx) = mpsc::channel();
        let (go_tx, go_rx) = mpsc::channel();
        app.operations
            .service
            .as_ref()
            .unwrap()
            .before_result_ready_for_test(move || {
                tx.send(()).unwrap();
                let _ = go_rx.recv();
            });
        let task = app.update(if opening {
            Message::OpenVault
        } else {
            Message::Save
        });
        assert!(
            app.operations.active.is_some(),
            "request was not admitted; opening={opening}; {:?}",
            app.operations.authority.snapshot(std::time::Instant::now())
        );
        rx.recv_timeout(std::time::Duration::from_secs(30))
            .unwrap_or_else(|error| {
                panic!(
                    "actual worker did not reach held result: {error}; opening={opening}; {:?}",
                    app.operations.authority.snapshot(std::time::Instant::now())
                )
            });
        let tick = app.update(Message::SecurityTick(std::time::Instant::now()));
        let prematurely_finished = app.operations.active.as_ref().unwrap().finished;
        go_tx.send(()).unwrap();
        tests::drain_task(&mut app, Task::batch([task, tick]));
        assert!(
            !prematurely_finished,
            "stored but unready terminal must remain retryable; opening={opening}"
        );
        assert!(app.session.is_some());
    }
}

#[test]
fn old_encrypted_warning_does_not_cover_late_different_warning_on_close() {
    use std::sync::mpsc;
    let (_dir, mut app) = tests::fixture(1);
    app.operations.failure_notice = Some("previous already visible warning".into());
    let (tx, rx) = mpsc::channel();
    let (go_tx, go_rx) = mpsc::channel();
    crate::storage::transaction::set_worker_hook(
        crate::storage::transaction::Point::WitnessRemove,
        move || {
            tx.send(()).unwrap();
            let _ = go_rx.recv();
            Err(AppError::Input("synthetic new maintenance failure".into()))
        },
    );
    let id = app.session.as_ref().unwrap().entries()[0].id;
    app.selected = Some(id);
    let save = app.update(Message::ToggleSelectedFavorite);
    rx.recv().unwrap();
    let window = iced::window::Id::unique();
    let close = app.update(Message::CloseRequested(window));
    go_tx.send(()).unwrap();
    let effects = tests::drain_task(&mut app, Task::batch([save, close]));
    assert!(
        !effects.closes(window),
        "old warning A cannot acknowledge a later distinct encrypted warning B"
    );
    assert!(!app.closing);
    assert!(
        app.operations
            .failure_notice
            .as_deref()
            .unwrap()
            .contains("synthetic new maintenance failure")
    );
    assert!(
        app.test_update(Message::CloseRequested(window))
            .closes(window),
        "a fresh close may acknowledge the now-visible encrypted warning"
    );
}

#[test]
fn completed_startup_inspection_does_not_claim_it_is_still_processing() {
    let dir = tempfile::tempdir().unwrap();
    let mut app = App::initial();
    app.vault_path = dir.path().join("not-created.pmvault").display().to_string();
    app.start_inspection(false);
    app.test_drain_pending();
    assert!(!app.operation_busy());
    assert!(
        !app.status.contains("正在后台处理"),
        "finished startup inspection retained its running status"
    );
}

#[test]
fn worker_spawn_failure_keeps_auth_unavailable_without_disk_effect_or_fake_drain() {
    let dir = tempfile::tempdir().unwrap();
    crate::operations::runner::fail_next_spawn_for_test();
    let mut app = App::initial();
    app.vault_path = dir
        .path()
        .join("never-created.pmvault")
        .display()
        .to_string();
    app.master_password = "synthetic-spawn-failure".into();
    app.confirm_password = "synthetic-spawn-failure".into();
    app.creating = true;
    assert!(
        app.operations.service.is_none(),
        "worker startup failure must remain unavailable"
    );
    let effects = app.test_update(Message::CreateVault);
    assert_eq!(effects.units(), 0);
    assert!(!std::path::Path::new(&app.vault_path).exists());
    let snapshot = app.operations.authority.snapshot(std::time::Instant::now());
    assert!(snapshot.failed && snapshot.masked);
    assert!(snapshot.occupied.is_none());
    assert!(
        !snapshot.fully_locked,
        "unavailable transport must not invent a cleanup witness"
    );
    assert!(app.operations.active.is_none());
}

#[test]
#[ignore = "headless GUI regression; real held CSV worker across busy/masked/locked states"]
fn gui_background_busy_masked_locked_and_late_notice_at_three_sizes() {
    use iced_test::Simulator;
    use std::sync::mpsc;
    for (width, height) in [(960.0, 640.0), (1280.0, 800.0), (1600.0, 900.0)] {
        let (dir, mut app) = tests::fixture(2);
        app.session.as_mut().unwrap().body_mut().entries[1]
            .secret
            .ciphertext
            .clear();
        app.test_update(Message::OpenSettings);
        app.test_update(Message::CsvPathChanged(
            dir.path()
                .join("synthetic-late-output.csv")
                .display()
                .to_string(),
        ));
        app.test_update(Message::ConfirmPlaintextChanged(true));
        let (tx, rx) = mpsc::channel();
        let (go_tx, go_rx) = mpsc::channel();
        crate::export::tests::set_worker_after_create(move || {
            tx.send(()).unwrap();
            let _ = go_rx.recv();
        });
        let task = app.update(Message::ExportPlaintextCsv);
        rx.recv().unwrap();
        let capture = |app: &App, state: &str, label: &str| {
            let mut ui = Simulator::with_size(
                iced_test::core::Settings {
                    default_font: UI_FONT,
                    default_text_size: iced::Pixels(14.0),
                    ..iced_test::core::Settings::default()
                },
                (width, height),
                app.view(),
            );
            assert!(
                ui.find(label).is_ok(),
                "missing {state} state at {width}x{height}"
            );
            let output = std::path::Path::new("target/gui-artifacts");
            std::fs::create_dir_all(output).unwrap();
            let _ = ui
                .snapshot(&app.theme())
                .unwrap()
                .matches_image(output.join(format!("background-{state}-{width}x{height}.png")))
                .unwrap();
        };
        capture(&app, "busy", "正在后台处理");
        let lock = app.update(Message::Lock);
        assert!(
            !app.operations
                .authority
                .snapshot(std::time::Instant::now())
                .fully_locked
        );
        assert!(!app.status.contains("保险库已锁定"));
        capture(&app, "finishing", "已遮蔽，正在完成锁定");
        go_tx.send(()).unwrap();
        tests::drain_task(&mut app, Task::batch([task, lock]));
        assert!(
            app.operations
                .authority
                .snapshot(std::time::Instant::now())
                .fully_locked
        );
        assert!(app.export_notice.is_some());
        assert!(app.operations.active.is_none());
        assert!(!app.status.contains("正在等待处理") && !app.status.contains("正在完成锁定"));
        capture(&app, "locked-late-warning", "解锁密码库");
        let window = iced::window::Id::unique();
        app.test_update(Message::CloseRequested(window));
        assert!(app.export_close_prompt.is_some());
        assert!(!app.closing);
        capture(&app, "close-warning", "保持打开");
    }
}

fn held_worker_activity_deadline(via_update: bool) {
    use std::sync::mpsc;
    use std::time::{Duration, Instant};
    let (_dir, mut app) = tests::fixture(0);
    let old_deadline = app
        .operations
        .authority
        .snapshot(Instant::now())
        .live
        .unwrap()
        .deadline;
    let activity = old_deadline - Duration::from_secs(60);
    let expected = activity + Duration::from_secs(u64::from(app.idle_minutes) * 60);
    let (tx, rx) = mpsc::channel();
    let (go_tx, go_rx) = mpsc::channel();
    app.operations
        .service
        .as_ref()
        .unwrap()
        .before_result_ready_for_test(move || {
            tx.send(()).unwrap();
            let _ = go_rx.recv();
        });
    let task = app.update(Message::Save);
    rx.recv().unwrap();
    let activity_task = if via_update {
        app.update(Message::UserActivity(activity))
    } else {
        app.user_activity(activity);
        Task::none()
    };
    let during = app
        .operations
        .authority
        .snapshot(Instant::now())
        .live
        .unwrap()
        .deadline;
    go_tx.send(()).unwrap();
    tests::drain_task(&mut app, Task::batch([task, activity_task]));
    assert_eq!(
        during, expected,
        "actual activity must reach authority while the session is leased"
    );
    assert_eq!(
        app.operations
            .authority
            .snapshot(Instant::now())
            .live
            .unwrap()
            .deadline,
        expected,
        "result installation must preserve the updated shared deadline, not its admission snapshot"
    );
    assert_eq!(
        app.last_activity, activity,
        "completion is not another activity event"
    );
}
#[test]
fn busy_user_activity_updates_the_real_leased_session_deadline() {
    held_worker_activity_deadline(true);
}
#[test]
fn adoption_preserves_activity_updated_deadline_instead_of_admission_deadline() {
    held_worker_activity_deadline(false);
}

#[test]
fn real_worker_progress_and_completion_preserve_existing_deadline() {
    use std::sync::mpsc;
    use std::time::Instant;
    let (_dir, mut app) = tests::fixture(0);
    let before = app
        .operations
        .authority
        .snapshot(Instant::now())
        .live
        .unwrap()
        .deadline;
    let last_activity = app.last_activity;
    let (tx, rx) = mpsc::channel();
    let (go_tx, go_rx) = mpsc::channel();
    app.operations
        .service
        .as_ref()
        .unwrap()
        .before_result_ready_for_test(move || {
            tx.send(()).unwrap();
            let _ = go_rx.recv();
        });
    let task = app.update(Message::Save);
    rx.recv().unwrap();
    let id = app.operations.active.as_ref().unwrap().id;
    let progress = app.update(Message::OperationSignal(
        crate::operations::OperationSignal::PhaseChanged(id),
    ));
    assert_eq!(
        app.operations
            .authority
            .snapshot(Instant::now())
            .live
            .unwrap()
            .deadline,
        before
    );
    go_tx.send(()).unwrap();
    tests::drain_task(&mut app, Task::batch([task, progress]));
    assert_eq!(
        app.operations
            .authority
            .snapshot(Instant::now())
            .live
            .unwrap()
            .deadline,
        before
    );
    assert_eq!(app.last_activity, last_activity);
}

#[test]
fn expired_real_leased_session_cannot_be_revived_by_activity_or_result() {
    use std::sync::mpsc;
    use std::time::{Duration, Instant};
    let (_dir, mut app) = tests::fixture(0);
    let deadline = app
        .operations
        .authority
        .snapshot(Instant::now())
        .live
        .unwrap()
        .deadline;
    let last_activity = app.last_activity;
    let (tx, rx) = mpsc::channel();
    let (go_tx, go_rx) = mpsc::channel();
    app.operations
        .service
        .as_ref()
        .unwrap()
        .before_result_ready_for_test(move || {
            tx.send(()).unwrap();
            let _ = go_rx.recv();
        });
    let task = app.update(Message::Save);
    rx.recv().unwrap();
    let activity = app.update(Message::UserActivity(deadline + Duration::from_secs(1)));
    let masked_before_release = app.operations.authority.snapshot(Instant::now()).masked;
    go_tx.send(()).unwrap();
    tests::drain_task(&mut app, Task::batch([task, activity]));
    assert!(
        masked_before_release,
        "expiry must be evaluated before real input can extend a leased session"
    );
    assert!(app.session.is_none());
    let snapshot = app.operations.authority.snapshot(Instant::now());
    assert!(snapshot.live.is_none() && snapshot.fully_locked);
    assert_eq!(app.last_activity, last_activity);
}

#[test]
fn real_dispose_drain_before_its_ui_signal_does_not_poison_fresh_auth_or_inspection() {
    use std::sync::mpsc;
    use std::time::{Duration, Instant};
    for opening in [false, true] {
        let (_dir, mut app) = tests::fixture(1);
        let (arrived_tx, arrived_rx) = mpsc::channel();
        let (release_tx, release_rx) = mpsc::channel();
        app.operations
            .service
            .as_ref()
            .unwrap()
            .before_result_ready_for_test(move || {
                arrived_tx.send(()).unwrap();
                let _ = release_rx.recv();
            });
        let lock = app.update(Message::Lock);
        arrived_rx
            .recv_timeout(Duration::from_secs(30))
            .expect("real Dispose must reach held worker");
        let disposed = app
            .operations
            .authority
            .snapshot(Instant::now())
            .occupied
            .unwrap();
        assert!(app.session.is_none());
        assert!(
            app.operations.active.is_none(),
            "Dispose has no UI operation result to adopt"
        );
        release_tx.send(()).unwrap();
        app.operations
            .service
            .as_ref()
            .unwrap()
            .wait_for_drain_for_test(disposed);
        assert!(
            app.operations
                .authority
                .snapshot(Instant::now())
                .fully_locked
        );
        // Keep the real Dispose observer alive but deliver no Finished/Drained
        // event. A native/UI input can be scheduled ahead of those notifications.
        if opening {
            app.master_password = "gui-synthetic-master-only".into();
        }
        let (fresh_tx, fresh_rx) = mpsc::channel();
        let (fresh_release_tx, fresh_release_rx) = mpsc::channel();
        app.operations
            .service
            .as_ref()
            .unwrap()
            .before_result_ready_for_test(move || {
                fresh_tx.send(()).unwrap();
                let _ = fresh_release_rx.recv();
            });
        let fresh = app.update(if opening {
            Message::OpenVault
        } else {
            Message::OpenRecovery
        });
        assert!(
            app.operations.failed_input.is_none(),
            "fresh request was admitted by authority then refused by a retained, effect-free Dispose terminal; opening={opening}; {:?}",
            app.operations.authority.snapshot(Instant::now())
        );
        let fresh_id = app.operations.active.as_ref().unwrap().id;
        fresh_rx
            .recv_timeout(Duration::from_secs(30))
            .expect("fresh real request reaches stored-result hold");
        // Its terminal is now stored but unready. Deliver the actual old
        // observer, followed by duplicate/reordered old events, in this window.
        tests::drain_task(&mut app, lock);
        for signal in [
            crate::operations::OperationSignal::Drained(disposed),
            crate::operations::OperationSignal::Finished(disposed),
        ] {
            let old = app.update(Message::OperationSignal(signal));
            tests::drain_task(&mut app, old);
            let active = app.operations.active.as_ref().unwrap();
            assert_eq!(active.id, fresh_id);
            assert!(!active.finished);
            assert_eq!(
                app.operations.authority.snapshot(Instant::now()).occupied,
                Some(fresh_id)
            );
        }
        fresh_release_tx.send(()).unwrap();
        tests::drain_task(&mut app, fresh);
        assert!(!app.operation_busy());
        if opening {
            assert!(app.session.is_some());
        } else {
            assert!(app.recovery.is_some());
        }
        assert!(!app.operations.authority.snapshot(Instant::now()).failed);
    }
}

#[test]
fn failed_dispose_keeps_visible_service_warning_after_late_notification() {
    struct FailingOwner;
    impl Drop for FailingOwner {
        fn drop(&mut self) {
            panic!("synthetic Dispose failure for visible warning");
        }
    }
    let mut app = App::initial();
    app.retire_operation_ui(crate::operations::RetiredUi {
        test_owner: Some(Box::new(FailingOwner)),
        ..crate::operations::RetiredUi::default()
    });
    app.test_drain_pending();
    assert!(app.operations.active.is_none());
    assert!(app.operations.failure_notice.is_some());
    let authority = app.operations.authority.snapshot(std::time::Instant::now());
    assert!(authority.failed && authority.masked);
    assert!(authority.occupied.is_none());
    app.test_update(Message::OpenRecovery);
    assert!(app.operations.active.is_none());
    assert!(app.operations.failure_notice.is_some());
}
