use super::*;
use authority::Coordinator;
use std::time::Duration;

fn prepare(
    c: &Coordinator,
    now: Instant,
    kind: OperationKind,
) -> (authority::Admission, PreparedBinding) {
    let stamp = c.snapshot(now).stamp;
    let a = c
        .try_admit(kind, stamp, now)
        .expect("first admission must succeed");
    let b = PreparedBinding {
        prepared_id: Uuid::new_v4(),
        operation: a.id(),
        session: stamp.session,
    };
    c.mark_ready(a.id(), b).expect("preparation ready");
    (a, b)
}
fn binding() -> SessionBinding {
    SessionBinding {
        instance: Uuid::new_v4(),
        import_epoch: Uuid::new_v4(),
        vault_id: Uuid::new_v4(),
        revision: 1,
        source_hash: [1; 32],
        source_identity: crate::platform::file_transaction::Identity { volume: 1, file: 1 },
    }
}
#[test]
fn one_admission_cancel_keeps_capacity_until_cleanup() {
    let c = Coordinator::new(false);
    let now = Instant::now();
    let (a, _) = prepare(&c, now, OperationKind::Create);
    c.cancel(a.id());
    assert_eq!(c.snapshot(now).occupied, Some(a.id()));
    assert!(
        c.try_admit(OperationKind::Open, c.snapshot(now).stamp, now)
            .is_err()
    );
    c.ack_worker_drained(runner::test_cleanup_witness(OperationId::fresh()));
    assert_eq!(c.snapshot(now).occupied, Some(a.id()));
    c.complete_disk(a.id(), TerminalSummary::Cancelled);
    c.ack_worker_drained(runner::test_cleanup_witness(a.id()));
    assert_eq!(c.snapshot(now).occupied, None);
}
#[test]
fn cancel_before_claim_rejects() {
    let c = Coordinator::new(false);
    let now = Instant::now();
    let (a, b) = prepare(&c, now, OperationKind::Create);
    c.cancel(a.id());
    assert!(c.claim_commit(a.id(), b, now).is_err());
}
#[test]
fn claimed_commit_finishes_before_locked_witness() {
    let c = Coordinator::new(false);
    let now = Instant::now();
    let (a, b) = prepare(&c, now, OperationKind::Create);
    let lease = c.claim_commit(a.id(), b, now).expect("claim");
    c.revoke(RevokeReason::Manual, now);
    let revoked = c.snapshot(now).stamp.epoch;
    c.ack_ui_detached(revoked);
    assert!(lease.authorizes(b));
    assert!(!c.snapshot(now).fully_locked);
    c.ack_worker_drained(runner::test_cleanup_witness(a.id()));
    assert!(!c.snapshot(now).fully_locked);
    c.complete_disk(a.id(), TerminalSummary::Verified);
    c.ack_worker_drained(runner::test_cleanup_witness(a.id()));
    assert!(c.snapshot(now).fully_locked);
}
#[test]
fn observed_close_revokes_before_app_message() {
    let c = Coordinator::new(false);
    let now = Instant::now();
    let (a, b) = prepare(&c, now, OperationKind::Create);
    c.observe_close(now);
    assert!(c.claim_commit(a.id(), b, now).is_err());
    assert!(
        c.try_admit(OperationKind::Open, c.snapshot(now).stamp, now)
            .is_err()
    );
    assert!(c.resume_locked_after_keep_open(now).is_err());
}
#[test]
fn expired_deadline_rejects_without_ui_tick() {
    let c = Coordinator::new(false);
    let now = Instant::now();
    c.activate_session(binding(), now + Duration::from_secs(1));
    let (a, b) = prepare(&c, now, OperationKind::MutateAndSave);
    assert!(
        c.claim_commit(a.id(), b, now + Duration::from_secs(1))
            .is_err()
    );
    assert!(c.snapshot(now + Duration::from_secs(1)).masked);
}
#[test]
fn wrong_prepared_binding_and_second_claim_fail() {
    let c = Coordinator::new(false);
    let now = Instant::now();
    let (a, b) = prepare(&c, now, OperationKind::Create);
    let bad = PreparedBinding {
        prepared_id: Uuid::new_v4(),
        ..b
    };
    assert!(c.claim_commit(a.id(), bad, now).is_err());
    assert!(c.claim_commit(a.id(), b, now).is_ok());
    assert!(c.claim_commit(a.id(), b, now).is_err());
}
#[test]
fn native_revoke_prevents_result_adoption() {
    let c = Coordinator::new(false);
    let now = Instant::now();
    let (a, _) = prepare(&c, now, OperationKind::Open);
    c.complete_disk(a.id(), TerminalSummary::Read);
    c.result_ready(a.id());
    c.revoke(RevokeReason::Native, now);
    assert!(c.claim_adoption(a.id(), a.stamp(), now).is_err());
}
#[test]
fn fresh_form_keeps_original_session_but_not_preview() {
    let c = Coordinator::new(false);
    let now = Instant::now();
    c.activate_session(binding(), now + Duration::from_secs(10));
    let (a, _) = prepare(&c, now, OperationKind::AnalyzeImport);
    c.cancel(a.id());
    c.change_form();
    c.complete_disk(a.id(), TerminalSummary::Cancelled);
    c.result_ready(a.id());
    let lease = c
        .claim_adoption(a.id(), c.snapshot(now).stamp, now)
        .expect("original session return");
    assert!(lease.session);
    assert!(!lease.presentation);
}
#[test]
fn epoch_and_form_ids_are_never_reused() {
    let c = Coordinator::new(false);
    let now = Instant::now();
    let old = c.snapshot(now).stamp;
    c.change_form();
    assert_ne!(old.form, c.snapshot(now).stamp.form);
    c.revoke(RevokeReason::Manual, now);
    assert_ne!(old.epoch, c.snapshot(now).stamp.epoch);
}
#[test]
fn monitor_failure_is_fail_closed_until_fresh_context() {
    let c = Coordinator::new(true);
    let now = Instant::now();
    assert!(
        c.try_admit(OperationKind::Open, c.snapshot(now).stamp, now)
            .is_err()
    );
    c.monitor_ready();
    let (a, b) = prepare(&c, now, OperationKind::Create);
    c.revoke(RevokeReason::MonitorFailed, now);
    c.monitor_ready();
    assert!(c.claim_commit(a.id(), b, now).is_err());
}

fn submit_test(
    service: &runner::OperationService,
    job: impl FnOnce(&WorkControl) -> OperationPayload + Send + 'static,
) -> (OperationId, runner::CompletionObserver) {
    let now = Instant::now();
    let admission = service
        .authority
        .try_admit(
            OperationKind::Open,
            service.authority.snapshot(now).stamp,
            now,
        )
        .expect("admit");
    let id = admission.id();
    let observer = service
        .submit(admission, OperationInput::Test(Box::new(job)))
        .unwrap_or_else(|_| panic!("real worker submission"));
    (id, observer)
}
#[test]
fn real_worker_is_named_and_cancelled_work_keeps_one_lane() {
    use std::sync::{Arc, mpsc};
    let c = Arc::new(Coordinator::new(false));
    let service = runner::OperationService::new(c.clone()).unwrap();
    let (start_tx, start_rx) = mpsc::channel();
    let (release_tx, release_rx) = mpsc::channel();
    let (id, _observer) = submit_test(&service, move |control| {
        start_tx
            .send(std::thread::current().name().map(str::to_owned))
            .unwrap();
        release_rx.recv().unwrap();
        assert!(control.checkpoint().is_err());
        OperationPayload::empty()
    });
    assert_eq!(
        start_rx.recv().unwrap().as_deref(),
        Some("password-manager-vault-worker")
    );
    c.cancel(id);
    assert_eq!(c.snapshot(Instant::now()).occupied, Some(id));
    assert!(
        c.try_admit(
            OperationKind::Create,
            c.snapshot(Instant::now()).stamp,
            Instant::now()
        )
        .is_err()
    );
    service.discard(id);
    release_tx.send(()).unwrap();
}
#[test]
fn rejected_result_owner_is_dropped_on_worker() {
    use std::sync::{Arc, mpsc};
    struct Owner(mpsc::Sender<String>);
    impl Drop for Owner {
        fn drop(&mut self) {
            self.0
                .send(
                    std::thread::current()
                        .name()
                        .unwrap_or("unnamed")
                        .to_owned(),
                )
                .unwrap();
        }
    }
    let c = Arc::new(Coordinator::new(false));
    let service = runner::OperationService::new(c.clone()).unwrap();
    let (tx, rx) = mpsc::channel();
    let (id, observer) = submit_test(&service, move |_| OperationPayload {
        test_owner: Some(Box::new(Owner(tx))),
        ..OperationPayload::empty()
    });
    c.revoke(RevokeReason::Manual, Instant::now());
    drop(observer);
    service.discard(id);
    assert_eq!(rx.recv().unwrap(), "password-manager-vault-worker");
}

#[test]
fn create_job_publishes_on_worker_and_returns_one_owned_session() {
    use iced::futures::{StreamExt, executor::block_on};
    use std::sync::Arc;
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("worker-created.pmvault");
    let c = Arc::new(Coordinator::new(false));
    let service = runner::OperationService::new(c.clone()).unwrap();
    let now = Instant::now();
    let admission = c
        .try_admit(OperationKind::Create, c.snapshot(now).stamp, now)
        .ok()
        .unwrap();
    let id = admission.id();
    let mut observer = service
        .submit(
            admission,
            OperationInput::Create {
                path: path.clone(),
                password: zeroize::Zeroizing::new("synthetic-worker-password".into()),
                confirmation: zeroize::Zeroizing::new("synthetic-worker-password".into()),
            },
        )
        .ok()
        .unwrap();
    block_on(async {
        while let Some(signal) = observer.next().await {
            if signal == OperationSignal::Finished(id) {
                let lease = c
                    .claim_adoption(id, c.snapshot(Instant::now()).stamp, Instant::now())
                    .ok()
                    .unwrap();
                let payload = service.take_result(&lease).unwrap();
                assert!(
                    payload.session.is_some(),
                    "create must return its verified session"
                );
                assert!(path.exists());
                assert!(service.take_result(&lease).is_none());
                drop(payload);
                let _ = service.take_terminal(id);
            }
        }
    });
    assert_eq!(c.snapshot(Instant::now()).occupied, None);
}

#[test]
fn adoption_lease_dropped_before_take_releases_worker_result() {
    use iced::futures::{StreamExt, executor::block_on};
    use std::sync::{Arc, mpsc};
    struct Owner(mpsc::Sender<()>);
    impl Drop for Owner {
        fn drop(&mut self) {
            let _ = self.0.send(());
        }
    }
    let c = Arc::new(Coordinator::new(false));
    let service = runner::OperationService::new(c.clone()).unwrap();
    let (tx, rx) = mpsc::channel();
    let (id, mut observer) = submit_test(&service, move |_| OperationPayload {
        test_owner: Some(Box::new(Owner(tx))),
        ..OperationPayload::empty()
    });
    block_on(async {
        while let Some(signal) = observer.next().await {
            if signal == OperationSignal::Finished(id) {
                break;
            }
        }
    });
    let lease = c
        .claim_adoption(id, c.snapshot(Instant::now()).stamp, Instant::now())
        .ok()
        .unwrap();
    drop(lease);
    service.discard(id);
    // Do not block indefinitely on a bug: the regression oracle is ownership
    // metadata, not a sleep/timeout pretending to prove destructor completion.
    assert!(
        !c.adoption_claimed(id),
        "dropping the one-shot transit lease must release its ownership claim"
    );
    drop(observer);
    drop(service);
    rx.recv().unwrap();
}

#[test]
fn cancelled_restore_candidate_cannot_adopt_as_original_session() {
    let c = Coordinator::new(false);
    let now = Instant::now();
    let original = binding();
    c.activate_session(original, now + Duration::from_secs(30));
    let (a, b) = prepare(&c, now, OperationKind::RestoreCurrent);
    let _winning = c.claim_commit(a.id(), b, now).ok().unwrap();
    c.cancel(a.id());
    c.change_form();
    c.complete_disk(a.id(), TerminalSummary::Verified);
    c.result_ready(a.id());
    let accepted = c.claim_adoption(a.id(), c.snapshot(now).stamp, now).ok();
    assert!(
        accepted.is_none_or(|lease| !lease.session),
        "a replacement session cannot masquerade as the original session after its form is dismissed"
    );
}

#[test]
fn worker_panic_before_claim_retires_authority_and_releases_guarded_owner() {
    use iced::futures::{StreamExt, executor::block_on};
    use std::sync::{Arc, mpsc};
    struct Guard(mpsc::Sender<bool>, zeroize::Zeroizing<Vec<u8>>);
    impl Drop for Guard {
        fn drop(&mut self) {
            use zeroize::Zeroize;
            self.1.as_mut_slice().zeroize();
            let _ = self.0.send(self.1.iter().all(|b| *b == 0));
        }
    }
    let c = Arc::new(Coordinator::new(false));
    let service = runner::OperationService::new(c.clone()).unwrap();
    let (tx, rx) = mpsc::channel();
    let (id, mut observer) = submit_test(&service, move |_| {
        let _guard = Guard(tx, zeroize::Zeroizing::new(vec![42; 1024]));
        panic!("synthetic-private-panic-must-not-log");
    });
    block_on(async {
        while let Some(signal) = observer.next().await {
            if signal == OperationSignal::Finished(id) {
                assert!(matches!(
                    service.take_terminal(id),
                    Some(TerminalOutcome::WorkerFailed { claimed: false, .. })
                ));
            }
        }
    });
    assert!(rx.recv().unwrap());
    assert!(c.snapshot(Instant::now()).masked);
    assert!(
        c.try_admit(
            OperationKind::Open,
            c.snapshot(Instant::now()).stamp,
            Instant::now()
        )
        .is_err()
    );
}
#[test]
fn losing_observer_does_not_auto_commit_prepared_work() {
    use std::sync::{Arc, mpsc};
    let c = Arc::new(Coordinator::new(false));
    let service = runner::OperationService::new(c.clone()).unwrap();
    let (entered_tx, entered_rx) = mpsc::channel();
    let (release_tx, release_rx) = mpsc::channel();
    let (result_tx, result_rx) = mpsc::channel();
    let (_id, observer) = submit_test(&service, move |control| {
        let b = PreparedBinding {
            prepared_id: Uuid::new_v4(),
            operation: control.id,
            session: None,
        };
        control.authority.mark_ready(control.id, b).unwrap();
        entered_tx.send(()).unwrap();
        release_rx.recv().unwrap();
        result_tx
            .send(
                control
                    .authority
                    .claim_commit(control.id, b, Instant::now())
                    .is_err(),
            )
            .unwrap();
        OperationPayload::empty()
    });
    entered_rx.recv().unwrap();
    drop(observer);
    release_tx.send(()).unwrap();
    assert!(result_rx.recv().unwrap());
}
#[test]
fn ui_transit_owner_survives_revoke_until_returned_for_disposal() {
    use iced::futures::{StreamExt, executor::block_on};
    use std::sync::{Arc, mpsc};
    struct Owner(mpsc::Sender<()>);
    impl Drop for Owner {
        fn drop(&mut self) {
            let _ = self.0.send(());
        }
    }
    let c = Arc::new(Coordinator::new(false));
    let service = runner::OperationService::new(c.clone()).unwrap();
    let (tx, rx) = mpsc::channel();
    let (id, mut observer) = submit_test(&service, move |_| OperationPayload {
        test_owner: Some(Box::new(Owner(tx))),
        ..OperationPayload::empty()
    });
    block_on(async {
        while let Some(signal) = observer.next().await {
            if signal == OperationSignal::Finished(id) {
                break;
            }
        }
    });
    let lease = c
        .claim_adoption(id, c.snapshot(Instant::now()).stamp, Instant::now())
        .ok()
        .unwrap();
    c.revoke(RevokeReason::Native, Instant::now());
    service.discard(id);
    let payload = service
        .take_result(&lease)
        .expect("claim owns transit despite later revoke");
    assert!(rx.try_recv().is_err());
    drop(payload);
    assert!(rx.recv().is_ok());
    block_on(async { while observer.next().await.is_some() {} });
}

#[test]
fn poisoned_authority_never_reopens_and_real_cleanup_can_complete_lock() {
    let c = Coordinator::new(false);
    let now = Instant::now();
    let (a, _) = prepare(&c, now, OperationKind::Open);
    c.revoke(RevokeReason::Manual, now);
    let epoch = c.snapshot(now).stamp.epoch;
    c.poison_for_test();
    assert!(
        c.claim_adoption(a.id(), c.snapshot(now).stamp, now)
            .is_err()
    );
    assert!(
        c.try_admit(OperationKind::Open, c.snapshot(now).stamp, now)
            .is_err()
    );
    c.complete_disk(a.id(), TerminalSummary::WorkerFailed);
    c.ack_ui_detached(epoch);
    c.ack_worker_drained(runner::test_cleanup_witness(a.id()));
    assert!(
        c.snapshot(now).fully_locked,
        "actual disposal witnesses can complete cleanup even though poisoned authority stays unavailable"
    );
    assert!(c.resume_locked_after_keep_open(now).is_err());
}

#[test]
fn mailbox_poison_still_disposes_retired_owners_before_worker_exit() {
    use std::sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
        mpsc,
    };
    struct Owner(Arc<AtomicBool>);
    impl Drop for Owner {
        fn drop(&mut self) {
            self.0.store(true, Ordering::Release);
        }
    }
    let c = Arc::new(Coordinator::new(false));
    let service = runner::OperationService::new(c.clone()).unwrap();
    let (entered_tx, entered_rx) = mpsc::channel();
    let (release_tx, release_rx) = mpsc::channel();
    let (id, _observer) = submit_test(&service, move |_| {
        entered_tx.send(()).unwrap();
        release_rx.recv().unwrap();
        OperationPayload::empty()
    });
    entered_rx.recv().unwrap();
    let disposed = Arc::new(AtomicBool::new(false));
    assert!(
        service
            .retire_ui(RetiredUi {
                test_owner: Some(Box::new(Owner(disposed.clone()))),
                ..RetiredUi::default()
            })
            .is_ok()
    );
    service.poison_mailbox_for_test();
    release_tx.send(()).unwrap();
    service.request_shutdown();
    service.wait_for_worker_exit();
    assert!(
        disposed.load(Ordering::Acquire),
        "poisoned mailbox must release actual retired owners on worker before exit"
    );
    assert!(c.snapshot(Instant::now()).masked);
    assert_ne!(c.snapshot(Instant::now()).occupied, Some(id));
}

#[test]
fn disconnected_real_session_owner_cannot_leave_ghost_live_authority() {
    use std::sync::Arc;
    let dir = tempfile::tempdir().unwrap();
    let vault = crate::storage::VaultSession::create(
        dir.path().join("owned.pmvault"),
        "synthetic-worker-only",
    )
    .unwrap();
    let c = Arc::new(Coordinator::new(false));
    let now = Instant::now();
    c.activate_session(vault.operation_binding(), now + Duration::from_secs(300));
    let service = runner::OperationService::new(c.clone()).unwrap();
    let admission = c
        .try_admit(OperationKind::VerifyCurrent, c.snapshot(now).stamp, now)
        .ok()
        .unwrap();
    let id = admission.id();
    let observer = service
        .submit(admission, OperationInput::VerifyCurrent { session: vault })
        .ok()
        .unwrap();
    drop(observer);
    service.wait_for_drain_for_test(id);
    let snapshot = c.snapshot(Instant::now());
    assert!(
        snapshot.live.is_none(),
        "destroying the only real session owner must retire its live authority"
    );
    c.ack_ui_detached(snapshot.stamp.epoch);
    assert!(c.resume_locked_after_keep_open(Instant::now()).is_ok());
    assert!(
        c.try_admit(
            OperationKind::Open,
            c.snapshot(Instant::now()).stamp,
            Instant::now()
        )
        .is_ok()
    );
}

#[test]
fn cancelled_real_session_is_adoptable_without_destroying_live_authority() {
    use iced::futures::{StreamExt, executor::block_on};
    use std::sync::{Arc, mpsc};
    let dir = tempfile::tempdir().unwrap();
    let vault = crate::storage::VaultSession::create(
        dir.path().join("cancel-owned.pmvault"),
        "synthetic-worker-only",
    )
    .unwrap();
    let c = Arc::new(Coordinator::new(false));
    let now = Instant::now();
    c.activate_session(vault.operation_binding(), now + Duration::from_secs(300));
    let service = runner::OperationService::new(c.clone()).unwrap();
    let (tx, rx) = mpsc::channel();
    let (go_tx, go_rx) = mpsc::channel();
    service.before_result_ready_for_test(move || {
        tx.send(()).unwrap();
        go_rx.recv().unwrap();
    });
    let admission = c
        .try_admit(OperationKind::VerifyCurrent, c.snapshot(now).stamp, now)
        .ok()
        .unwrap();
    let id = admission.id();
    let mut observer = service
        .submit(admission, OperationInput::VerifyCurrent { session: vault })
        .ok()
        .unwrap();
    rx.recv().unwrap();
    c.cancel(id);
    go_tx.send(()).unwrap();
    while block_on(observer.next()) != Some(OperationSignal::Finished(id)) {}
    let lease = c
        .claim_adoption(id, c.snapshot(Instant::now()).stamp, Instant::now())
        .unwrap();
    assert!(lease.session);
    assert!(!lease.presentation);
    let mut payload = service.take_result(&lease).unwrap();
    let vault = payload.session.take().unwrap();
    assert!(c.install_session(
        &lease,
        vault.operation_binding(),
        now + Duration::from_secs(300),
        Instant::now()
    ));
    while block_on(observer.next()) != Some(OperationSignal::Drained(id)) {}
    assert!(c.snapshot(Instant::now()).live.is_some());
    assert!(!c.snapshot(Instant::now()).masked);
    assert!(service.take_terminal(id).is_some());
    drop(vault);
}

#[test]
fn failure_owner_container_layout_remains_bounded_inline() {
    let submit_bytes = std::mem::size_of::<runner::SubmitFailure>();
    let retirement_bytes = std::mem::size_of::<RetiredUi>();
    // Heap-backed contents are separately owned; this budget concerns only the
    // fixed shape copied back on failed admission, not total process memory.
    assert!(submit_bytes <= 4096);
    assert!(retirement_bytes <= 2048);
    eprintln!(
        "inline_owner_layout submit_bytes={submit_bytes} retirement_bytes={retirement_bytes}"
    );
}

#[test]
fn failed_dispose_retains_worker_failure_after_actual_cleanup() {
    use iced::futures::{StreamExt, executor::block_on};
    use std::sync::{Arc, mpsc};
    struct FailingOwner(mpsc::Sender<String>);
    impl Drop for FailingOwner {
        fn drop(&mut self) {
            self.0
                .send(std::thread::current().name().unwrap_or_default().to_owned())
                .unwrap();
            panic!("synthetic Dispose owner failure");
        }
    }
    let c = Arc::new(Coordinator::new(false));
    let service = runner::OperationService::new(c.clone()).unwrap();
    let (tx, rx) = mpsc::channel();
    let mut observer = service
        .retire_ui(RetiredUi {
            test_owner: Some(Box::new(FailingOwner(tx))),
            ..RetiredUi::default()
        })
        .ok()
        .flatten()
        .expect("actual Dispose admitted");
    assert_eq!(
        rx.recv_timeout(Duration::from_secs(30)).unwrap(),
        "password-manager-vault-worker"
    );
    let signals = block_on(async {
        let mut signals = Vec::new();
        while let Some(signal) = observer.next().await {
            signals.push(signal);
        }
        signals
    });
    let id = signals
        .iter()
        .find_map(|signal| match signal {
            OperationSignal::Finished(id) => Some(*id),
            _ => None,
        })
        .expect("Dispose failure still publishes Finished");
    assert!(signals.contains(&OperationSignal::Drained(id)));
    assert!(c.snapshot(Instant::now()).occupied.is_none());
    assert!(c.snapshot(Instant::now()).masked);
    assert!(matches!(
        service.take_terminal(id),
        Some(TerminalOutcome::WorkerFailed { claimed: false, .. })
    ));
}

#[test]
fn successful_dispose_keeps_lane_until_actual_retired_owner_drop() {
    use iced::futures::{StreamExt, executor::block_on};
    use std::sync::{Arc, mpsc};
    struct HeldOwner(mpsc::Sender<()>, mpsc::Receiver<()>);
    impl Drop for HeldOwner {
        fn drop(&mut self) {
            self.0.send(()).unwrap();
            let _ = self.1.recv();
        }
    }
    let c = Arc::new(Coordinator::new(false));
    let service = runner::OperationService::new(c.clone()).unwrap();
    let (tx, rx) = mpsc::channel();
    let (go_tx, go_rx) = mpsc::channel();
    let mut observer = service
        .retire_ui(RetiredUi {
            test_owner: Some(Box::new(HeldOwner(tx, go_rx))),
            ..RetiredUi::default()
        })
        .ok()
        .flatten()
        .unwrap();
    rx.recv_timeout(Duration::from_secs(30)).unwrap();
    let id = c.snapshot(Instant::now()).occupied.unwrap();
    let now = Instant::now();
    assert!(
        c.try_admit(OperationKind::InspectRecovery, c.snapshot(now).stamp, now)
            .is_err(),
        "a live destructor must retain the only operation lane"
    );
    go_tx.send(()).unwrap();
    service.wait_for_drain_for_test(id);
    assert!(c.snapshot(Instant::now()).occupied.is_none());
    assert!(service.take_terminal(id).is_none());
    let signals = block_on(async {
        let mut signals = Vec::new();
        while let Some(signal) = observer.next().await {
            signals.push(signal);
        }
        signals
    });
    assert!(signals.contains(&OperationSignal::Finished(id)));
    assert!(signals.contains(&OperationSignal::Drained(id)));
    let now = Instant::now();
    let admission = c
        .try_admit(OperationKind::InspectRecovery, c.snapshot(now).stamp, now)
        .unwrap();
    let next_id = admission.id();
    let directory = tempfile::tempdir().unwrap();
    let mut next = service
        .submit(
            admission,
            OperationInput::InspectRecovery {
                path: directory.path().join("missing-synthetic.pmvault"),
            },
        )
        .ok()
        .unwrap();
    while block_on(next.next()) != Some(OperationSignal::Finished(next_id)) {}
    assert!(
        matches!(
            service.take_terminal(next_id),
            Some(TerminalOutcome::ReadFinished)
        ),
        "ordinary side-effect-free reads must retain their adoption terminal"
    );
    service.discard(next_id);
    while block_on(next.next()).is_some() {}
}
