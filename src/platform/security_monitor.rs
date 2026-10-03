//! Startup-only retry policy shared by the native owner and synthetic tests.
pub(crate) const MAX_STARTUP_ATTEMPTS: u8 = 3;
pub(crate) fn retry_startup(
    attempt: u8,
    reached_ready: bool,
    cleanup_complete: bool,
    connected: bool,
) -> bool {
    attempt < MAX_STARTUP_ATTEMPTS && !reached_ready && cleanup_complete && connected
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn fully_torn_down_startup_failure_has_a_small_retry_budget() {
        assert!(retry_startup(1, false, true, true));
        assert!(retry_startup(2, false, true, true));
        assert!(!retry_startup(MAX_STARTUP_ATTEMPTS, false, true, true));
    }
    #[test]
    fn runtime_failure_requires_thread_exit_not_reinitialization() {
        assert!(!retry_startup(1, true, true, true));
    }
    #[test]
    fn incomplete_cleanup_or_disconnected_consumer_cannot_retry() {
        assert!(!retry_startup(1, false, false, true));
        assert!(!retry_startup(1, false, true, false));
    }
}

pub(crate) fn claim_monitor(started: &std::sync::atomic::AtomicBool) -> bool {
    started
        .compare_exchange(
            false,
            true,
            std::sync::atomic::Ordering::AcqRel,
            std::sync::atomic::Ordering::Acquire,
        )
        .is_ok()
}

#[cfg(test)]
mod ownership_tests {
    #[test]
    fn only_one_native_owner_can_start_in_a_process() {
        let started = std::sync::atomic::AtomicBool::new(false);
        assert!(super::claim_monitor(&started));
        assert!(!super::claim_monitor(&started));
    }
}

/// Every native monitor exit is an authority failure even if no Iced consumer
/// remains to receive its diagnostic event.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum MonitorFailure {
    MissingAuthority,
    DuplicateOwner,
    Spawn,
    Initialization,
    StartupRetry,
    RuntimeExit,
    EventSend,
    ForwardingClosed,
}

impl MonitorFailure {
    pub(super) fn revoke_in(
        self,
        token: &super::operation_authority::MonitorAuthorityToken,
        now: std::time::Instant,
    ) -> bool {
        match self {
            Self::StartupRetry => token.retryable_startup_failure(now),
            _ => token.route(super::SecurityEvent::MonitorFailed, now),
        }
    }
}

/// Covers cancellation of the forwarding future and unwinding of the native
/// owner, where ordinary error branches cannot run.
pub(super) struct MonitorAuthorityGuard<Cleanup: FnOnce()> {
    token: super::operation_authority::MonitorAuthorityToken,
    failure: MonitorFailure,
    after_revocation: Option<Cleanup>,
}

impl<Cleanup: FnOnce()> MonitorAuthorityGuard<Cleanup> {
    pub(super) fn new(
        token: super::operation_authority::MonitorAuthorityToken,
        failure: MonitorFailure,
        after_revocation: Cleanup,
    ) -> Self {
        Self {
            token,
            failure,
            after_revocation: Some(after_revocation),
        }
    }
}

impl<Cleanup: FnOnce()> Drop for MonitorAuthorityGuard<Cleanup> {
    fn drop(&mut self) {
        self.failure
            .revoke_in(&self.token, std::time::Instant::now());
        if let Some(cleanup) = self.after_revocation.take() {
            cleanup();
        }
    }
}

#[cfg(test)]
mod operation_failure_tests {
    use super::*;
    use crate::operations::authority::Coordinator;
    use crate::operations::{OperationKind, PreparedBinding};
    use crate::platform::SecurityEvent;
    use crate::platform::operation_authority::AuthorityRegistry;
    use std::sync::Arc;
    use std::time::Instant;

    #[test]
    fn terminal_failure_before_first_ready_cannot_rearm_after_resume() {
        for failure in [
            MonitorFailure::ForwardingClosed,
            MonitorFailure::DuplicateOwner,
            MonitorFailure::Spawn,
            MonitorFailure::EventSend,
            MonitorFailure::RuntimeExit,
            MonitorFailure::Initialization,
        ] {
            let registry = Arc::new(AuthorityRegistry::default());
            let authority = Arc::new(Coordinator::new(true));
            let _registration = registry.register(Arc::downgrade(&authority)).ok().unwrap();
            let monitor = registry.capture_monitor().unwrap();
            let now = Instant::now();
            let before = authority.snapshot(now).stamp;
            // Model native startup paused before SECURITY_WINDOW publication:
            // the forwarding stop request has no HWND to wake or destroy.
            assert!(failure.revoke_in(&monitor, now));
            assert_ne!(authority.snapshot(now).stamp.epoch, before.epoch);
            authority.ack_ui_detached(authority.snapshot(now).stamp.epoch);
            authority.resume_locked_after_keep_open(now).unwrap();
            assert!(
                !monitor.route(SecurityEvent::MonitorReady, now),
                "{failure:?}"
            );
            assert!(!authority.snapshot(now).monitor_ready, "{failure:?}");
            assert!(
                authority
                    .try_admit(OperationKind::Open, authority.snapshot(now).stamp, now)
                    .is_err(),
                "{failure:?}"
            );
        }
    }

    #[test]
    fn terminal_failure_cannot_be_downgraded_to_startup_retry() {
        let registry = Arc::new(AuthorityRegistry::default());
        let authority = Arc::new(Coordinator::new(true));
        let _registration = registry.register(Arc::downgrade(&authority)).ok().unwrap();
        let monitor = registry.capture_monitor().unwrap();
        let now = Instant::now();
        assert!(MonitorFailure::ForwardingClosed.revoke_in(&monitor, now));
        assert!(retry_startup(1, false, true, true));
        assert!(!MonitorFailure::StartupRetry.revoke_in(&monitor, now));
        assert!(!monitor.route(SecurityEvent::MonitorReady, now));
        assert!(!authority.snapshot(now).monitor_ready);
    }

    #[test]
    fn approved_startup_retry_allows_only_first_ready_with_fresh_context() {
        let registry = Arc::new(AuthorityRegistry::default());
        let authority = Arc::new(Coordinator::new(true));
        let _registration = registry.register(Arc::downgrade(&authority)).ok().unwrap();
        let monitor = registry.capture_monitor().unwrap();
        let now = Instant::now();
        let old = authority.snapshot(now).stamp;
        let inspection = authority
            .try_admit(OperationKind::InspectRecovery, old, now)
            .ok()
            .unwrap();
        assert!(retry_startup(1, false, true, true));
        assert!(MonitorFailure::StartupRetry.revoke_in(&monitor, now));
        assert!(monitor.route(SecurityEvent::MonitorReady, now));
        assert!(!monitor.route(SecurityEvent::MonitorReady, now));
        assert!(authority.checkpoint(inspection.id(), now).is_err());
        assert_ne!(authority.snapshot(now).stamp.epoch, old.epoch);
        authority.complete_disk(
            inspection.id(),
            crate::operations::TerminalSummary::Cancelled,
        );
        authority.ack_worker_drained(crate::operations::runner::test_cleanup_witness(
            inspection.id(),
        ));
        authority.ack_ui_detached(authority.snapshot(now).stamp.epoch);
        authority.resume_locked_after_keep_open(now).unwrap();
        assert!(authority.try_admit(OperationKind::Open, old, now).is_err());
        assert!(
            authority
                .try_admit(OperationKind::Open, authority.snapshot(now).stamp, now)
                .is_ok()
        );
    }

    #[test]
    fn every_monitor_failure_exit_revokes_before_consumer_delivery() {
        for failure in [
            MonitorFailure::MissingAuthority,
            MonitorFailure::DuplicateOwner,
            MonitorFailure::Spawn,
            MonitorFailure::Initialization,
            MonitorFailure::RuntimeExit,
            MonitorFailure::EventSend,
            MonitorFailure::ForwardingClosed,
        ] {
            let registry = Arc::new(AuthorityRegistry::default());
            let authority = Arc::new(Coordinator::new(true));
            let _registration = registry
                .register(Arc::downgrade(&authority))
                .expect("register");
            let monitor = registry.capture_monitor().unwrap();
            let now = Instant::now();
            assert!(monitor.route(SecurityEvent::MonitorReady, now));
            let stamp = authority.snapshot(now).stamp;
            let admission = authority
                .try_admit(OperationKind::Create, stamp, now)
                .expect("admit");
            let binding = PreparedBinding {
                prepared_id: uuid::Uuid::new_v4(),
                operation: admission.id(),
                session: stamp.session,
            };
            authority.mark_ready(admission.id(), binding).unwrap();
            // The production failure router has no delivery dependency. The
            // injected registry avoids shared global state in parallel tests.
            assert!(failure.revoke_in(&monitor, now));
            assert!(
                authority
                    .claim_commit(admission.id(), binding, now)
                    .is_err(),
                "{failure:?}"
            );
            assert!(authority.snapshot(now).masked, "{failure:?}");
        }
    }

    #[test]
    fn forwarding_cancellation_and_native_unwind_guard_revoke_authority() {
        for failure in [
            MonitorFailure::ForwardingClosed,
            MonitorFailure::RuntimeExit,
        ] {
            let registry = Arc::new(AuthorityRegistry::default());
            let authority = Arc::new(Coordinator::new(true));
            let _registration = registry.register(Arc::downgrade(&authority)).ok().unwrap();
            let monitor = registry.capture_monitor().unwrap();
            let now = Instant::now();
            assert!(monitor.route(SecurityEvent::MonitorReady, now));
            let stamp = authority.snapshot(now).stamp;
            let admission = authority
                .try_admit(OperationKind::Open, stamp, now)
                .ok()
                .unwrap();
            let guard = MonitorAuthorityGuard::new(monitor.clone(), failure, || {
                assert!(authority.snapshot(now).masked);
                assert!(registry.capture_monitor().is_some());
            });
            drop(guard);
            assert!(authority.checkpoint(admission.id(), now).is_err());
            assert!(authority.snapshot(now).masked);
        }
    }

    #[test]
    fn startup_retry_ready_does_not_restore_revoked_request() {
        let registry = Arc::new(AuthorityRegistry::default());
        let authority = Arc::new(Coordinator::new(true));
        let _registration = registry.register(Arc::downgrade(&authority)).ok().unwrap();
        let monitor = registry.capture_monitor().unwrap();
        let now = Instant::now();
        let old_stamp = authority.snapshot(now).stamp;
        let admission = authority
            .try_admit(OperationKind::InspectRecovery, old_stamp, now)
            .ok()
            .unwrap();
        assert!(MonitorFailure::StartupRetry.revoke_in(&monitor, now));
        assert!(retry_startup(1, false, true, true));
        assert!(monitor.route(SecurityEvent::MonitorReady, now));
        assert!(authority.checkpoint(admission.id(), now).is_err());
        assert_ne!(authority.snapshot(now).stamp.epoch, old_stamp.epoch);
        assert!(authority.snapshot(now).masked);
    }
}
