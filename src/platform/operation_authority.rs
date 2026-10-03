//! Native/UI entry-point bridge for the metadata-only operation coordinator.
use std::sync::{Arc, Mutex, OnceLock, Weak};
use std::time::Instant;

use uuid::Uuid;

use crate::operations::RevokeReason;
use crate::operations::authority::Coordinator;
use crate::{AppError, Result};

#[cfg(any(windows, test))]
use super::SecurityEvent;

struct RegisteredAuthority {
    id: Uuid,
    authority: Weak<Coordinator>,
    bound: bool,
}

#[derive(Default)]
pub(super) struct AuthorityRegistry {
    active: Mutex<Option<RegisteredAuthority>>,
}

/// Captured by one native monitor owner; it never resolves a later registry slot.
#[derive(Clone)]
pub(super) struct MonitorAuthorityToken {
    id: Uuid,
    authority: Weak<Coordinator>,
}

impl MonitorAuthorityToken {
    #[cfg(any(windows, test))]
    pub(super) fn route(&self, event: SecurityEvent, now: Instant) -> bool {
        let Some(coordinator) = self.authority.upgrade() else {
            return false;
        };
        self.route_captured(&coordinator, event, now)
    }

    #[cfg(any(windows, test))]
    fn route_captured(
        &self,
        coordinator: &Coordinator,
        event: SecurityEvent,
        now: Instant,
    ) -> bool {
        match event {
            SecurityEvent::MonitorReady => coordinator.monitor_ready_for(self.id),
            SecurityEvent::MonitorFailed => coordinator.monitor_failed_for(self.id, now),
            SecurityEvent::SessionLocked
            | SecurityEvent::SessionLoggedOff
            | SecurityEvent::SystemSuspending => coordinator.native_revoke_for(self.id, now),
            SecurityEvent::ClipboardCleanupFailed
            | SecurityEvent::ClipboardCopyCompleted { .. } => true,
        }
    }

    #[cfg(any(windows, test))]
    pub(super) fn retryable_startup_failure(&self, now: Instant) -> bool {
        self.authority
            .upgrade()
            .is_some_and(|coordinator| coordinator.monitor_retryable_failure_for(self.id, now))
    }

    fn detach(&self, now: Instant) {
        if let Some(coordinator) = self.authority.upgrade() {
            coordinator.detach_monitor_registration(self.id, now);
        }
    }
}

/// Keeps a single process registration alive without retaining any vault owner.
pub(crate) struct OperationRegistration {
    registry: Arc<AuthorityRegistry>,
    id: Uuid,
}

impl AuthorityRegistry {
    pub(super) fn register(
        self: &Arc<Self>,
        authority: Weak<Coordinator>,
    ) -> Result<OperationRegistration> {
        let coordinator = authority.upgrade().ok_or_else(|| {
            AppError::Platform("operation authority is no longer available".to_string())
        })?;
        let id = Uuid::new_v4();
        let accepted = match self.active.lock() {
            Ok(mut active) if active.is_none() => {
                *active = Some(RegisteredAuthority {
                    id,
                    authority,
                    bound: false,
                });
                true
            }
            Ok(_) | Err(_) => false,
        };
        // Reserve before binding, but never nest registry/coordinator locks.
        // Pending reservations cannot be captured by native monitor startup.
        if !accepted {
            coordinator.revoke(RevokeReason::MonitorFailed, Instant::now());
            return Err(AppError::Platform(
                "operation authority registration is unavailable or already active".to_string(),
            ));
        }
        if !coordinator.bind_monitor_registration(id) {
            let _ = self.detach_slot(id);
            coordinator.revoke(RevokeReason::MonitorFailed, Instant::now());
            return Err(AppError::Platform(
                "operation authority generation could not be bound".to_string(),
            ));
        }
        let bound = match self.active.lock() {
            Ok(mut active) => active
                .as_mut()
                .filter(|entry| entry.id == id)
                .is_some_and(|entry| {
                    entry.bound = true;
                    true
                }),
            Err(_) => false,
        };
        if !bound {
            if let Some(token) = self.detach_slot(id) {
                token.detach(Instant::now());
            }
            return Err(AppError::Platform(
                "operation authority registry became unavailable".to_string(),
            ));
        }
        Ok(OperationRegistration {
            registry: Arc::clone(self),
            id,
        })
    }

    #[cfg(any(windows, test))]
    pub(super) fn capture_monitor(&self) -> Option<MonitorAuthorityToken> {
        let (captured, healthy) = {
            match self.active.lock() {
                Ok(active) => (
                    active.as_ref().filter(|entry| entry.bound).map(|entry| {
                        MonitorAuthorityToken {
                            id: entry.id,
                            authority: entry.authority.clone(),
                        }
                    }),
                    true,
                ),
                Err(error) => {
                    let active = error.into_inner();
                    (
                        active.as_ref().map(|entry| MonitorAuthorityToken {
                            id: entry.id,
                            authority: entry.authority.clone(),
                        }),
                        false,
                    )
                }
            }
        };
        // Upgrade/routing occurs after the registry guard is gone. Generation
        // validity is checked atomically on every coordinator transition, not
        // as an earlier readiness check that can race with registration Drop.
        if !healthy {
            if let Some(token) = captured {
                token.detach(Instant::now());
            }
            return None;
        }
        captured.filter(|token| token.authority.upgrade().is_some())
    }

    fn detach_slot(&self, id: Uuid) -> Option<MonitorAuthorityToken> {
        let mut active = self
            .active
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        if active.as_ref().is_some_and(|entry| entry.id == id) {
            active.take().map(|entry| MonitorAuthorityToken {
                id: entry.id,
                authority: entry.authority,
            })
        } else {
            None
        }
    }

    fn with_authority(&self, operation: impl FnOnce(&Coordinator)) -> bool {
        let (captured, healthy) = {
            match self.active.lock() {
                Ok(active) => (
                    active.as_ref().map(|entry| MonitorAuthorityToken {
                        id: entry.id,
                        authority: entry.authority.clone(),
                    }),
                    true,
                ),
                Err(error) => {
                    let active = error.into_inner();
                    (
                        active.as_ref().map(|entry| MonitorAuthorityToken {
                            id: entry.id,
                            authority: entry.authority.clone(),
                        }),
                        false,
                    )
                }
            }
        };
        let Some(token) = captured else {
            return false;
        };
        if !healthy {
            token.detach(Instant::now());
            return false;
        }
        let Some(coordinator) = token.authority.upgrade() else {
            return false;
        };
        operation(&coordinator);
        true
    }

    fn observe_close(&self, now: Instant) -> bool {
        self.with_authority(|coordinator| coordinator.observe_close(now))
    }
}

impl Drop for OperationRegistration {
    fn drop(&mut self) {
        if let Some(token) = self.registry.detach_slot(self.id) {
            token.detach(Instant::now());
        }
    }
}

pub(super) fn process_registry() -> &'static Arc<AuthorityRegistry> {
    static REGISTRY: OnceLock<Arc<AuthorityRegistry>> = OnceLock::new();
    REGISTRY.get_or_init(|| Arc::new(AuthorityRegistry::default()))
}

pub(crate) fn register_operation_authority(
    authority: Weak<Coordinator>,
) -> Result<OperationRegistration> {
    process_registry().register(authority)
}

pub(crate) fn observe_operation_close() -> bool {
    process_registry().observe_close(Instant::now())
}

/// Other platforms deliberately do not claim a functioning Windows monitor.
/// The real App still requires successful registration before auth admission.
pub(crate) const fn operation_monitor_required() -> bool {
    cfg!(windows)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::operations::{OperationKind, PreparedBinding, TerminalSummary};
    use std::cell::RefCell;

    fn route(registry: &AuthorityRegistry, event: SecurityEvent, now: Instant) -> bool {
        registry
            .capture_monitor()
            .is_some_and(|token| token.route(event, now))
    }

    fn registry_and_authority() -> (
        Arc<AuthorityRegistry>,
        Arc<Coordinator>,
        OperationRegistration,
    ) {
        let registry = Arc::new(AuthorityRegistry::default());
        let authority = Arc::new(Coordinator::new(true));
        let registration = registry
            .register(Arc::downgrade(&authority))
            .expect("register live authority");
        assert!(route(
            &registry,
            SecurityEvent::MonitorReady,
            Instant::now()
        ));
        (registry, authority, registration)
    }

    fn ready_operation(
        authority: &Coordinator,
        now: Instant,
    ) -> (crate::operations::OperationId, PreparedBinding) {
        let stamp = authority.snapshot(now).stamp;
        let admission = authority
            .try_admit(OperationKind::Create, stamp, now)
            .expect("fresh monitor authorizes auth");
        let binding = PreparedBinding {
            prepared_id: Uuid::new_v4(),
            operation: admission.id(),
            session: stamp.session,
        };
        authority.mark_ready(admission.id(), binding).unwrap();
        (admission.id(), binding)
    }

    #[test]
    fn captured_monitor_ready_after_registration_drop_cannot_reauthorize_auth() {
        let registry = Arc::new(AuthorityRegistry::default());
        let authority = Arc::new(Coordinator::new(true));
        let registration = registry.register(Arc::downgrade(&authority)).ok().unwrap();
        let captured = registry
            .capture_monitor()
            .expect("captured before Weak upgrade pause");
        // Hold the successfully upgraded coordinator, then pause exactly before
        // the generation-checked metadata transition used by production route.
        let upgraded = captured.authority.upgrade().unwrap();
        let now = Instant::now();
        drop(registration);
        assert!(!captured.route_captured(&upgraded, SecurityEvent::MonitorReady, now));
        assert!(!captured.route(SecurityEvent::MonitorReady, now));
        authority.ack_ui_detached(authority.snapshot(now).stamp.epoch);
        authority.resume_locked_after_keep_open(now).unwrap();
        assert!(
            authority
                .try_admit(OperationKind::Open, authority.snapshot(now).stamp, now)
                .is_err()
        );
    }

    #[test]
    fn old_monitor_ready_cannot_authorize_replacement_registration() {
        for reuse_coordinator in [false, true] {
            let registry = Arc::new(AuthorityRegistry::default());
            let first = Arc::new(Coordinator::new(true));
            let first_registration = registry.register(Arc::downgrade(&first)).ok().unwrap();
            let old_monitor = registry.capture_monitor().unwrap();
            drop(first_registration);
            let replacement = if reuse_coordinator {
                Arc::clone(&first)
            } else {
                Arc::new(Coordinator::new(true))
            };
            let _replacement_registration = registry
                .register(Arc::downgrade(&replacement))
                .ok()
                .unwrap();
            let now = Instant::now();
            replacement.ack_ui_detached(replacement.snapshot(now).stamp.epoch);
            replacement.resume_locked_after_keep_open(now).unwrap();
            assert!(!old_monitor.route(SecurityEvent::MonitorReady, now));
            assert!(!replacement.snapshot(now).monitor_ready);
            assert!(
                replacement
                    .try_admit(OperationKind::Open, replacement.snapshot(now).stamp, now)
                    .is_err()
            );
            let current_monitor = registry.capture_monitor().unwrap();
            assert!(current_monitor.route(SecurityEvent::MonitorReady, now));
            let live_stamp = replacement.snapshot(now).stamp;
            for stale_event in [
                SecurityEvent::SessionLocked,
                SecurityEvent::SessionLoggedOff,
                SecurityEvent::SystemSuspending,
                SecurityEvent::MonitorFailed,
            ] {
                assert!(!old_monitor.route(stale_event, now));
                assert_eq!(replacement.snapshot(now).stamp, live_stamp);
                assert!(replacement.snapshot(now).monitor_ready);
            }
        }
    }

    #[test]
    fn native_ready_failure_then_delayed_old_ready_cannot_rearm_monitor() {
        let registry = Arc::new(AuthorityRegistry::default());
        let authority = Arc::new(Coordinator::new(true));
        let _registration = registry.register(Arc::downgrade(&authority)).ok().unwrap();
        let monitor = registry.capture_monitor().unwrap();
        let now = Instant::now();
        assert!(monitor.route(SecurityEvent::MonitorReady, now));
        assert!(monitor.route(SecurityEvent::MonitorFailed, now));
        assert!(!monitor.route(SecurityEvent::MonitorReady, now));
        authority.ack_ui_detached(authority.snapshot(now).stamp.epoch);
        authority.resume_locked_after_keep_open(now).unwrap();
        assert!(!authority.snapshot(now).monitor_ready);
        assert!(
            authority
                .try_admit(OperationKind::Open, authority.snapshot(now).stamp, now)
                .is_err()
        );
    }

    #[test]
    fn old_registration_detach_after_new_bind_does_not_revoke_reused_coordinator() {
        let registry = Arc::new(AuthorityRegistry::default());
        let authority = Arc::new(Coordinator::new(true));
        let old_registration = registry.register(Arc::downgrade(&authority)).ok().unwrap();
        // Retain A's delayed cleanup token after removing/detaching A, then
        // legitimately bind B on the same coordinator before stale cleanup.
        let pending_detach = registry.detach_slot(old_registration.id).unwrap();
        // Registry removal alone cannot authorize B on this same coordinator;
        // A must first complete its generation detach.
        assert!(registry.register(Arc::downgrade(&authority)).is_err());
        assert!(registry.capture_monitor().is_none());
        let now = Instant::now();
        pending_detach.detach(now);
        let _new_registration = registry.register(Arc::downgrade(&authority)).ok().unwrap();
        let new_monitor = registry.capture_monitor().unwrap();
        assert!(new_monitor.route(SecurityEvent::MonitorReady, now));
        authority.ack_ui_detached(authority.snapshot(now).stamp.epoch);
        authority.resume_locked_after_keep_open(now).unwrap();
        let before = authority.snapshot(now).stamp;
        pending_detach.detach(now);
        drop(old_registration);
        assert!(registry.capture_monitor().is_some());
        assert!(authority.snapshot(now).monitor_ready);
        assert_eq!(authority.snapshot(now).stamp, before);
        assert!(
            authority
                .try_admit(OperationKind::Open, before, now)
                .is_ok()
        );
    }

    #[test]
    fn ready_and_registration_detach_are_fail_closed_in_both_orders() {
        for ready_first in [true, false] {
            let registry = Arc::new(AuthorityRegistry::default());
            let authority = Arc::new(Coordinator::new(true));
            let registration = registry.register(Arc::downgrade(&authority)).ok().unwrap();
            let token = registry.capture_monitor().unwrap();
            let now = Instant::now();
            if ready_first {
                assert!(token.route(SecurityEvent::MonitorReady, now));
            }
            drop(registration);
            if !ready_first {
                assert!(!token.route(SecurityEvent::MonitorReady, now));
            }
            assert!(!authority.snapshot(now).monitor_ready);
            assert!(authority.snapshot(now).masked);
        }
    }

    #[test]
    fn native_revocation_wins_while_delivery_and_clipboard_owner_are_held() {
        for event in [
            SecurityEvent::SessionLocked,
            SecurityEvent::SessionLoggedOff,
            SecurityEvent::SystemSuspending,
            SecurityEvent::MonitorFailed,
        ] {
            let (registry, authority, _registration) = registry_and_authority();
            let now = Instant::now();
            let (id, binding) = ready_operation(&authority, now);
            let clipboard_owner = Mutex::new(());
            let held_owner = clipboard_owner.lock().unwrap();
            let deferred = RefCell::new(Vec::new());
            // Model a Win32 callback entering while the outer clipboard owner is
            // borrowed. Deferred Iced delivery is deliberately not polled.
            assert!(route(&registry, event, now));
            {
                assert!(clipboard_owner.try_lock().is_err());
                assert!(registry.active.try_lock().is_ok());
                assert!(authority.claim_commit(id, binding, now).is_err());
                assert!(authority.snapshot(now).masked);
                deferred.borrow_mut().push(event);
            }
            assert_eq!(deferred.borrow().as_slice(), &[event]);
            drop(held_owner);
            assert!(authority.claim_commit(id, binding, now).is_err());
        }
    }

    #[test]
    fn real_clipboard_write_gate_allows_reentrant_native_authority_revocation() {
        use super::super::clipboard::{
            ClipboardBackend, ClipboardEngine, ClipboardQueue, CopyCommand,
        };
        use super::super::{ClipboardKind, ClipboardSession};

        struct ReentrantBackend {
            registry: Arc<AuthorityRegistry>,
            monitor: MonitorAuthorityToken,
            authority: Arc<Coordinator>,
            session: ClipboardSession,
            operation: crate::operations::OperationId,
            binding: PreparedBinding,
            now: Instant,
        }
        impl ClipboardBackend for ReentrantBackend {
            type Prepared = ();
            fn now_ms(&self) -> u64 {
                0
            }
            fn new_marker(&mut self) -> std::result::Result<[u8; 16], ()> {
                Ok([7; 16])
            }
            fn prepare(&mut self, _: &[u16], _: [u8; 16]) -> std::result::Result<(), ()> {
                Ok(())
            }
            fn open(&mut self) -> std::result::Result<(), ()> {
                Ok(())
            }
            fn empty(&mut self) -> std::result::Result<(), ()> {
                Ok(())
            }
            fn set_marker(&mut self, _: &mut ()) -> std::result::Result<(), ()> {
                // ClipboardEngine holds the real session publication permit
                // here. Win32 SetClipboardData may synchronously reenter WndProc.
                assert!(self.monitor.route(SecurityEvent::SessionLocked, self.now));
                self.session.revoke_native();
                assert!(self.registry.active.try_lock().is_ok());
                assert!(
                    self.authority
                        .claim_commit(self.operation, self.binding, self.now)
                        .is_err()
                );
                Ok(())
            }
            fn set_text(&mut self, _: &mut ()) -> std::result::Result<(), ()> {
                panic!("reentrant revocation must prevent subsequent clipboard publication")
            }
            fn close(&mut self) -> std::result::Result<(), ()> {
                Ok(())
            }
            fn matches(&mut self, _: [u8; 16], _: Option<&[u16]>) -> std::result::Result<bool, ()> {
                Ok(false)
            }
            fn sequence(&self) -> u32 {
                1
            }
            fn arm_timer(&mut self, _: u32) -> std::result::Result<(), ()> {
                Ok(())
            }
            fn stop_timer(&mut self) {}
        }

        let (registry, authority, _registration) = registry_and_authority();
        let now = Instant::now();
        let (operation, binding) = ready_operation(&authority, now);
        let mut queue = ClipboardQueue::default();
        let session = queue.begin();
        queue
            .push_copy(
                CopyCommand {
                    session: session.clone(),
                    request: 1,
                    kind: ClipboardKind::Password,
                    text: zeroize::Zeroizing::new("synthetic only".to_string()),
                    timeout_ms: 100,
                },
                || true,
            )
            .unwrap();
        let Some(super::super::clipboard::ClipboardCommand::Copy(command)) = queue.pop() else {
            panic!("queued synthetic copy");
        };
        let backend = ReentrantBackend {
            monitor: registry.capture_monitor().unwrap(),
            registry,
            authority: Arc::clone(&authority),
            session: session.clone(),
            operation,
            binding,
            now,
        };
        let mut engine = ClipboardEngine::new(backend);
        engine.write(command);
        assert!(session.revoked());
        assert!(authority.snapshot(now).masked);
        assert!(authority.claim_commit(operation, binding, now).is_err());
    }

    #[test]
    fn registry_lookup_releases_lock_before_coordinator_or_reentrant_callback() {
        let (registry, authority, _registration) = registry_and_authority();
        assert!(registry.with_authority(|coordinator| {
            assert!(registry.active.try_lock().is_ok());
            coordinator.observe_close(Instant::now());
            assert!(registry.capture_monitor().is_some());
        }));
        assert!(authority.snapshot(Instant::now()).closing);
    }

    #[test]
    fn observed_close_bridge_revokes_before_deferred_app_message() {
        let (registry, authority, _registration) = registry_and_authority();
        let now = Instant::now();
        let (id, binding) = ready_operation(&authority, now);
        assert!(registry.observe_close(now));
        assert!(authority.snapshot(now).closing);
        assert!(authority.claim_commit(id, binding, now).is_err());
        assert!(
            authority
                .try_admit(OperationKind::Open, authority.snapshot(now).stamp, now)
                .is_err()
        );
    }

    #[test]
    fn duplicate_registration_is_rejected_and_cannot_replace_live_authority() {
        let (registry, first, registration) = registry_and_authority();
        let second = Arc::new(Coordinator::new(false));
        assert!(registry.register(Arc::downgrade(&second)).is_err());
        assert!(second.snapshot(Instant::now()).masked);
        assert!(route(
            &registry,
            SecurityEvent::SessionLocked,
            Instant::now()
        ));
        assert!(first.snapshot(Instant::now()).masked);
        assert!(
            second
                .try_admit(
                    OperationKind::Open,
                    second.snapshot(Instant::now()).stamp,
                    Instant::now()
                )
                .is_err()
        );
        drop(registration);
        assert!(registry.register(Arc::downgrade(&second)).is_ok());
    }

    #[test]
    fn missing_or_expired_registration_never_reports_ready() {
        let registry = Arc::new(AuthorityRegistry::default());
        assert!(registry.capture_monitor().is_none());
        assert!(!route(
            &registry,
            SecurityEvent::MonitorReady,
            Instant::now()
        ));
        assert!(!registry.observe_close(Instant::now()));
        let authority = Arc::new(Coordinator::new(true));
        let registration = registry.register(Arc::downgrade(&authority)).ok().unwrap();
        drop(authority);
        assert!(registry.capture_monitor().is_none());
        assert!(!route(
            &registry,
            SecurityEvent::MonitorReady,
            Instant::now()
        ));
        let replacement = Arc::new(Coordinator::new(true));
        assert!(registry.register(Arc::downgrade(&replacement)).is_err());
        drop(registration);
        assert!(registry.register(Arc::downgrade(&replacement)).is_ok());
    }

    #[test]
    fn dropping_registration_revokes_old_authority_and_clears_only_its_slot() {
        let (registry, authority, registration) = registry_and_authority();
        let now = Instant::now();
        let (id, binding) = ready_operation(&authority, now);
        drop(registration);
        assert!(registry.capture_monitor().is_none());
        assert!(authority.claim_commit(id, binding, now).is_err());
        assert!(authority.snapshot(now).masked);
    }

    #[test]
    fn monitor_ready_never_revives_old_epoch_or_old_prepared_request() {
        let (registry, authority, _registration) = registry_and_authority();
        let now = Instant::now();
        let (id, binding) = ready_operation(&authority, now);
        let old = authority.snapshot(now).stamp;
        assert!(route(&registry, SecurityEvent::MonitorFailed, now));
        assert!(!route(&registry, SecurityEvent::MonitorReady, now));
        assert_ne!(authority.snapshot(now).stamp.epoch, old.epoch);
        assert!(authority.claim_commit(id, binding, now).is_err());
        authority.complete_disk(id, TerminalSummary::Cancelled);
        authority.ack_worker_drained(crate::operations::runner::test_cleanup_witness(id));
        authority.ack_ui_detached(authority.snapshot(now).stamp.epoch);
        authority.resume_locked_after_keep_open(now).unwrap();
        assert!(
            authority
                .try_admit(OperationKind::Create, authority.snapshot(now).stamp, now)
                .is_err()
        );
    }

    #[test]
    fn poisoned_registry_is_fail_closed_for_ready() {
        let (registry, authority, _registration) = registry_and_authority();
        let now = Instant::now();
        let (id, binding) = ready_operation(&authority, now);
        let _ = std::panic::catch_unwind(|| {
            let _guard = registry.active.lock().unwrap();
            panic!("synthetic registry poison");
        });
        assert!(registry.capture_monitor().is_none());
        assert!(!route(&registry, SecurityEvent::MonitorReady, now));
        assert!(authority.claim_commit(id, binding, now).is_err());
    }

    #[test]
    fn non_windows_monitor_policy_is_explicit_without_synthetic_ready_event() {
        assert_eq!(operation_monitor_required(), cfg!(windows));
        let authority = Coordinator::new(operation_monitor_required());
        let now = Instant::now();
        let can_auth = authority
            .try_admit(OperationKind::Open, authority.snapshot(now).stamp, now)
            .is_ok();
        assert_eq!(can_auth, !cfg!(windows));
    }
}
