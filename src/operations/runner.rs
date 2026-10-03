//! One named reusable worker and one secret-bearing lane. Metadata observers
//! carry no payloads. Locks only move fixed-shape owners; Drop runs off-lock.
use super::*;
use authority::{Admission, AdoptionLease, Coordinator};
use iced::futures::{Stream, task::AtomicWaker};
use std::pin::Pin;
use std::sync::{
    Arc, Condvar, Mutex, Weak,
    atomic::{AtomicBool, AtomicU8, Ordering},
};
use std::task::{Context, Poll};
use std::time::Duration;

const PHASE: u8 = 1;
const FINISHED: u8 = 2;
const DRAINED: u8 = 4;
pub(super) struct Signals {
    id: OperationId,
    bits: AtomicU8,
    drained: AtomicBool,
    disconnected: AtomicBool,
    waker: AtomicWaker,
}
impl Signals {
    pub(super) fn phase_changed(&self) {
        self.emit(PHASE);
    }
    fn emit(&self, bit: u8) {
        self.bits.fetch_or(bit, Ordering::Release);
        self.waker.wake();
    }
}
#[derive(Default)]
struct Slot {
    id: Option<OperationId>,
    request: Option<(Admission, OperationInput)>,
    result: Option<OperationPayload>,
    terminal: Option<(OperationId, TerminalOutcome)>,
    retired: Option<RetiredUi>,
    signals: Option<Arc<Signals>>,
    taken: bool,
    discard: bool,
    shutdown: bool,
    abandoned: bool,
    #[cfg(test)]
    hooks: Option<TestHooks>,
    #[cfg(test)]
    last_drained: Option<OperationId>,
}
pub(crate) struct Shared {
    authority: Arc<Coordinator>,
    slot: Mutex<Slot>,
    wake: Condvar,
    poison_reported: AtomicBool,
    #[cfg(test)]
    stopped: (Mutex<bool>, Condvar),
    #[cfg(test)]
    probes: Mutex<TestProbes>,
}

impl Shared {
    fn lock_slot(&self) -> std::sync::MutexGuard<'_, Slot> {
        self.slot.lock().unwrap_or_else(|error| error.into_inner())
    }
    pub(super) fn fail_closed_if_poisoned(&self) {
        if self.slot.is_poisoned() && !self.poison_reported.swap(true, Ordering::AcqRel) {
            self.authority
                .revoke(RevokeReason::WorkerFailed, Instant::now());
            self.wake.notify_all();
        }
    }
}

/// Constructed only at the actual worker cleanup boundary, never by the UI or
/// an observer notification. It certifies released/transferred owners and no
/// remaining operation-owned disk work.
pub(crate) struct CleanupWitness {
    id: OperationId,
}
impl CleanupWitness {
    pub(crate) fn id(&self) -> OperationId {
        self.id
    }
}
#[cfg(test)]
pub(crate) fn test_cleanup_witness(id: OperationId) -> CleanupWitness {
    CleanupWitness { id }
}

pub(crate) struct OperationService {
    pub(crate) authority: Arc<Coordinator>,
    shared: Arc<Shared>,
}
pub(crate) struct CompletionObserver {
    signals: Arc<Signals>,
    shared: Weak<Shared>,
    finished: bool,
    ended: bool,
}
pub(crate) struct SubmitFailure {
    pub admission: Admission,
    pub input: OperationInput,
    pub retired: Option<RetiredUi>,
}

impl OperationService {
    pub(crate) fn new(authority: Arc<Coordinator>) -> std::io::Result<Self> {
        install_sanitized_worker_panic_hook();
        let shared = Arc::new(Shared {
            authority: authority.clone(),
            slot: Mutex::new(Slot::default()),
            wake: Condvar::new(),
            poison_reported: AtomicBool::new(false),
            #[cfg(test)]
            stopped: (Mutex::new(false), Condvar::new()),
            #[cfg(test)]
            probes: Mutex::new(TestProbes::default()),
        });
        let worker = shared.clone();
        #[cfg(test)]
        if FAIL_NEXT_SPAWN.with(|flag| flag.replace(false)) {
            return Err(std::io::Error::other("synthetic worker startup failure"));
        }
        // The join handle is deliberately not evidence of completion. Only the
        // worker's final cleanup acknowledgement releases the occupied lane.
        std::thread::Builder::new()
            .name("password-manager-vault-worker".into())
            .spawn(move || {
                #[cfg(test)]
                let _stop = TestStop(worker.clone());
                worker_loop(worker)
            })?;
        Ok(Self { authority, shared })
    }
    #[cfg(test)]
    #[expect(
        clippy::result_large_err,
        reason = "Bounded inline owners return without allocating on transport failure"
    )]
    pub(crate) fn submit(
        &self,
        admission: Admission,
        input: OperationInput,
    ) -> Result<CompletionObserver, SubmitFailure> {
        self.submit_owned(admission, input, None)
    }
    #[expect(
        clippy::result_large_err,
        reason = "Bounded inline owners return without allocating while the mailbox is held"
    )]
    pub(crate) fn submit_owned(
        &self,
        admission: Admission,
        input: OperationInput,
        retired: Option<RetiredUi>,
    ) -> Result<CompletionObserver, SubmitFailure> {
        #[cfg(test)]
        let hooks = TestHooks {
            storage: crate::storage::transaction::take_worker_hook(),
            export: crate::export::tests::take_worker_after_create(),
        };
        let id = admission.id();
        if input.kind().is_some_and(|kind| {
            kind != admission.kind()
                || (kind != OperationKind::Dispose
                    && input.session_binding() != admission.stamp().session)
        }) {
            return Err(SubmitFailure {
                admission,
                input,
                retired,
            });
        }
        let signals = Arc::new(Signals {
            id,
            bits: AtomicU8::new(0),
            drained: AtomicBool::new(false),
            disconnected: AtomicBool::new(false),
            waker: AtomicWaker::new(),
        });
        if self.authority.snapshot(Instant::now()).occupied != Some(id) {
            return Err(SubmitFailure {
                admission,
                input,
                retired,
            });
        }
        self.shared.fail_closed_if_poisoned();
        let mut slot = self.shared.lock_slot();
        if slot.shutdown || slot.id.is_some() || slot.terminal.is_some() {
            return Err(SubmitFailure {
                admission,
                input,
                retired,
            });
        }
        #[cfg(test)]
        {
            slot.hooks = Some(hooks);
        }
        slot.retired = retired;
        slot.id = Some(id);
        slot.request = Some((admission, input));
        slot.signals = Some(signals.clone());
        slot.taken = false;
        slot.discard = false;
        drop(slot);
        self.authority
            .observe_progress(id, Arc::downgrade(&signals));
        self.shared.wake.notify_one();
        Ok(CompletionObserver {
            signals,
            shared: Arc::downgrade(&self.shared),
            finished: false,
            ended: false,
        })
    }
    pub(crate) fn take_result(&self, lease: &AdoptionLease) -> Option<OperationPayload> {
        self.shared.fail_closed_if_poisoned();
        let mut slot = self.shared.lock_slot();
        if self.shared.slot.is_poisoned() || slot.id != Some(lease.id()) || slot.taken {
            return None;
        }
        if slot.result.is_none() || !lease.transferred() {
            return None;
        }
        let p = slot.result.as_mut()?;
        let adopted = OperationPayload {
            session: if lease.session {
                p.session.take()
            } else {
                None
            },
            ui_index: if lease.session {
                p.ui_index.take()
            } else {
                None
            },
            preview: if lease.presentation {
                p.preview.take()
            } else {
                None
            },
            value: if lease.presentation {
                std::mem::replace(&mut p.value, OperationValue::None)
            } else {
                OperationValue::None
            },
            #[cfg(test)]
            test_owner: if lease.presentation {
                p.test_owner.take()
            } else {
                None
            },
        };
        slot.taken = true;
        drop(slot);
        self.shared.wake.notify_one();
        Some(adopted)
    }
    pub(crate) fn take_terminal(&self, id: OperationId) -> Option<TerminalOutcome> {
        self.shared.fail_closed_if_poisoned();
        let mut slot = self.shared.lock_slot();
        if slot
            .terminal
            .as_ref()
            .is_some_and(|(current, _)| *current == id)
        {
            slot.terminal.take().map(|(_, outcome)| outcome)
        } else {
            None
        }
    }
    pub(crate) fn discard(&self, id: OperationId) {
        {
            let mut slot = self.shared.lock_slot();
            if slot.id == Some(id) {
                slot.discard = true;
            }
        }
        self.shared.wake.notify_one();
    }
    #[cfg(test)]
    pub(crate) fn expect_retired_preview_for_test(
        &self,
        id: uuid::Uuid,
        owner: Box<dyn Send>,
    ) -> Arc<AtomicBool> {
        let observed = Arc::new(AtomicBool::new(false));
        self.shared.probes.lock().unwrap().retirement = Some((id, owner, observed.clone()));
        observed
    }
    #[cfg(test)]
    pub(crate) fn before_result_ready_for_test(&self, hook: impl FnOnce() + Send + 'static) {
        self.shared.probes.lock().unwrap().before_ready = Some(Box::new(hook));
    }
    #[cfg(test)]
    pub(crate) fn wait_for_drain_for_test(&self, id: OperationId) {
        let mut slot = self.shared.lock_slot();
        while slot.last_drained != Some(id) {
            slot = self
                .shared
                .wake
                .wait(slot)
                .unwrap_or_else(|error| error.into_inner());
        }
    }
    #[cfg(test)]
    fn attach_preview_probe(&self, mut retired: RetiredUi) -> RetiredUi {
        let probe =
            {
                let mut probes = self.shared.probes.lock().unwrap();
                if probes.retirement.as_ref().is_some_and(|(id, _, _)| {
                    retired.preview.as_ref().is_some_and(|p| p.id() == *id)
                }) {
                    probes.retirement.take()
                } else {
                    None
                }
            };
        if let Some((_, owner, observed)) = probe {
            observed.store(true, Ordering::Release);
            retired.test_owner = Some(owner);
        }
        retired
    }
    #[expect(
        clippy::result_large_err,
        reason = "Return the fixed retirement bundle without allocation on a failed handoff"
    )]
    pub(crate) fn retire_ui(
        &self,
        retired: RetiredUi,
    ) -> Result<Option<CompletionObserver>, RetiredUi> {
        #[cfg(test)]
        let retired = self.attach_preview_probe(retired);
        // If a request already owns the lane, one fixed retired bundle belongs
        // to it. No second request or queue is created.
        self.shared.fail_closed_if_poisoned();
        let mut slot = self.shared.lock_slot();
        if slot.retired.is_some() {
            return Err(retired);
        }
        if slot.id.is_some() {
            slot.retired = Some(retired);
            drop(slot);
            self.shared.wake.notify_one();
            return Ok(None);
        }
        drop(slot);
        let now = Instant::now();
        let admission = match self.authority.try_admit(
            OperationKind::Dispose,
            self.authority.snapshot(now).stamp,
            now,
        ) {
            Ok(a) => a,
            Err(_) => return Err(retired),
        };
        // The UI is the sole submitter. Install bundle before waking the worker.
        let id = admission.id();
        let signals = Arc::new(Signals {
            id,
            bits: AtomicU8::new(0),
            drained: AtomicBool::new(false),
            disconnected: AtomicBool::new(false),
            waker: AtomicWaker::new(),
        });
        let mut slot = self.shared.lock_slot();
        if slot.id.is_some() || slot.shutdown {
            return Err(retired);
        }
        slot.id = Some(id);
        slot.request = Some((admission, OperationInput::Dispose));
        slot.retired = Some(retired);
        slot.signals = Some(signals.clone());
        slot.taken = false;
        slot.discard = true;
        drop(slot);
        self.shared.wake.notify_one();
        Ok(Some(CompletionObserver {
            signals,
            shared: Arc::downgrade(&self.shared),
            finished: false,
            ended: false,
        }))
    }
    pub(crate) fn request_shutdown(&self) {
        self.authority.revoke(RevokeReason::Close, Instant::now());
        {
            let mut slot = self.shared.lock_slot();
            slot.shutdown = true;
            slot.discard = true;
        }
        self.shared.wake.notify_one();
    }
    #[cfg(test)]
    pub(crate) fn poison_mailbox_for_test(&self) {
        let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _guard = self.shared.slot.lock().unwrap();
            panic!("synthetic mailbox poison");
        }));
        self.shared.wake.notify_all();
    }
    #[cfg(test)]
    pub(crate) fn wait_for_worker_exit(&self) {
        let mut stopped = self.shared.stopped.0.lock().unwrap();
        while !*stopped {
            stopped = self.shared.stopped.1.wait(stopped).unwrap();
        }
    }
    pub(crate) fn drain_snapshot(&self) -> authority::Snapshot {
        self.shared.fail_closed_if_poisoned();
        self.authority.snapshot(Instant::now())
    }
}
impl Drop for OperationService {
    fn drop(&mut self) {
        self.shared.lock_slot().abandoned = true;
        self.request_shutdown();
    }
}

impl Stream for CompletionObserver {
    type Item = OperationSignal;
    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let this = self.get_mut();
        if this.ended {
            return Poll::Ready(None);
        }
        this.signals.waker.register(cx.waker());
        let bits = this.signals.bits.load(Ordering::Acquire);
        if !this.finished && bits & FINISHED != 0 {
            this.finished = true;
            this.signals.bits.fetch_and(!FINISHED, Ordering::AcqRel);
            return Poll::Ready(Some(OperationSignal::Finished(this.signals.id)));
        }
        if this.finished && bits & DRAINED != 0 {
            this.ended = true;
            this.signals.bits.fetch_and(!DRAINED, Ordering::AcqRel);
            return Poll::Ready(Some(OperationSignal::Drained(this.signals.id)));
        }
        if bits & PHASE != 0 {
            this.signals.bits.fetch_and(!PHASE, Ordering::AcqRel);
            return Poll::Ready(Some(OperationSignal::PhaseChanged(this.signals.id)));
        }
        Poll::Pending
    }
}
impl Drop for CompletionObserver {
    fn drop(&mut self) {
        if self.signals.drained.load(Ordering::Acquire) {
            return;
        }
        self.signals.disconnected.store(true, Ordering::Release);
        if let Some(shared) = self.shared.upgrade() {
            shared.authority.cancel(self.signals.id);
            shared.wake.notify_one();
        }
    }
}

fn worker_loop(shared: Arc<Shared>) {
    loop {
        let (request, signals, early_retired) = {
            let mut slot = shared.lock_slot();
            while slot.request.is_none() && !slot.shutdown {
                slot = shared
                    .wake
                    .wait(slot)
                    .unwrap_or_else(|error| error.into_inner());
            }
            let Some(request) = slot.request.take() else {
                return;
            };
            let signals = slot
                .signals
                .as_ref()
                .expect("admitted signal owner")
                .clone();
            let retired = slot.retired.take();
            (request, signals, retired)
        };
        shared.fail_closed_if_poisoned();
        let (admission, input) = request;
        let id = admission.id();
        let ownership = admission.ownership();
        #[cfg(test)]
        {
            let hooks = shared.slot.lock().ok().and_then(|mut s| s.hooks.take());
            if let Some(hooks) = hooks {
                crate::storage::transaction::install_worker_hook(hooks.storage);
                crate::export::tests::install_worker_after_create(hooks.export);
            }
        }
        let control = WorkControl {
            authority: shared.authority.clone(),
            id,
            worker: Some(Arc::downgrade(&shared)),
        };
        signals.emit(PHASE);
        let owned_live_session = input.session_binding().is_some();
        let disposal = matches!(&input, OperationInput::Dispose);
        let panic_context = input.panic_context();
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            drop(early_retired);
            jobs::execute(input, &control)
        }));
        let (payload, outcome) = match result {
            Ok(result) => result,
            Err(panic) => {
                // Arbitrary payloads may themselves hold secrets; drop them here,
                // never display, format or include them in a notification.
                drop(panic);
                let claimed =
                    shared.authority.snapshot(Instant::now()).phase == Some(Phase::Committing);
                shared
                    .authority
                    .revoke(RevokeReason::WorkerFailed, Instant::now());
                (
                    OperationPayload::empty(),
                    TerminalOutcome::WorkerFailed {
                        claimed,
                        context: panic_context,
                        snapshot_cleanup: crate::import::take_snapshot_cleanup_failure(),
                    },
                )
            }
        };
        shared.fail_closed_if_poisoned();
        let returned_session = payload
            .session
            .as_ref()
            .map(crate::storage::VaultSession::operation_binding);
        let summary = outcome.summary();
        shared.authority.complete_disk(id, summary);
        // Successful disposal has no UI result or disk-risk notice. Its real
        // cleanup witness and observer signals remain mandatory, but a delayed
        // Dispose notification must not block the next admitted request. Every
        // error/panic and every non-Dispose terminal remains retained.
        let retain_outcome = !(disposal && matches!(&outcome, TerminalOutcome::ReadFinished));
        let mut pending_outcome = Some(outcome);
        {
            let mut slot = shared.lock_slot();
            slot.result = Some(payload);
            // A separately admitted Dispose may race delayed delivery of the
            // previous terminal notice. Never overwrite that retained outcome.
            if retain_outcome && slot.terminal.is_none() {
                slot.terminal = pending_outcome.take().map(|outcome| (id, outcome));
            }
        }
        drop(pending_outcome);
        #[cfg(test)]
        {
            let hook = shared.probes.lock().unwrap().before_ready.take();
            if let Some(hook) = hook {
                hook();
            }
        }
        shared
            .authority
            .result_ready_with_session(id, returned_session);
        signals.emit(FINISHED);
        loop {
            shared.fail_closed_if_poisoned();
            // Ordinary cancellation may still return the original session to
            // its current UI owner. Only security revocation forces disposal.
            let revoked = shared.authority.snapshot(Instant::now()).masked;
            let owners = {
                let mut slot = shared.lock_slot();
                let disconnected = signals.disconnected.load(Ordering::Acquire);
                let requested = slot.discard || disconnected || revoked || slot.shutdown;
                let disposable = if slot.abandoned {
                    true
                } else if requested {
                    ownership
                        .compare_exchange(0, 2, Ordering::AcqRel, Ordering::Acquire)
                        .is_ok()
                        || ownership.load(Ordering::Acquire) == 2
                } else {
                    ownership.load(Ordering::Acquire) == 2
                };
                if slot.taken || disposable {
                    Some((slot.result.take(), slot.retired.take()))
                } else {
                    let waited = shared.wake.wait_timeout(slot, Duration::from_millis(100));
                    drop(waited.unwrap_or_else(|error| error.into_inner()));
                    None
                }
            };
            let Some((payload, retired)) = owners else {
                continue;
            };
            // All potentially large or guarded drops run on this named worker,
            // with neither lock held. No cleanup is scheduled after acknowledgement.
            control.progress(WorkPhase::Cleaning, 0, None);
            if owned_live_session
                && (returned_session.is_none()
                    || payload.as_ref().is_some_and(|p| p.session.is_some()))
            {
                shared.authority.abandon_session_owner(id);
            }
            drop(payload);
            drop(retired);
            let (late_retired, old_signals) = {
                let mut slot = shared.lock_slot();
                let retired = slot.retired.take();
                let signals = if retired.is_none() {
                    slot.id = None;
                    slot.signals.take()
                } else {
                    None
                };
                (retired, signals)
            };
            drop(old_signals);
            if let Some(retired) = late_retired {
                drop(retired);
                continue;
            }
            shared.authority.ack_worker_drained(CleanupWitness { id });
            #[cfg(test)]
            {
                shared.lock_slot().last_drained = Some(id);
                shared.wake.notify_all();
            }
            signals.drained.store(true, Ordering::Release);
            signals.emit(DRAINED);
            break;
        }
    }
}
fn install_sanitized_worker_panic_hook() {
    static ONCE: std::sync::Once = std::sync::Once::new();
    ONCE.call_once(|| {
        let previous = std::panic::take_hook();
        std::panic::set_hook(Box::new(move |info| {
            if std::thread::current().name() != Some("password-manager-vault-worker") {
                previous(info);
            }
        }));
    });
}

#[cfg(test)]
struct TestHooks {
    storage: Option<crate::storage::transaction::WorkerTestHook>,
    export: Option<crate::export::tests::WorkerAfterCreate>,
}

#[cfg(test)]
struct TestStop(Arc<Shared>);
#[cfg(test)]
impl Drop for TestStop {
    fn drop(&mut self) {
        *self.0.stopped.0.lock().unwrap() = true;
        self.0.stopped.1.notify_all();
    }
}

#[cfg(test)]
#[derive(Default)]
struct TestProbes {
    retirement: Option<(uuid::Uuid, Box<dyn Send>, Arc<AtomicBool>)>,
    before_ready: Option<Box<dyn FnOnce() + Send>>,
}

#[cfg(test)]
std::thread_local! {
    static FAIL_NEXT_SPAWN: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
}
#[cfg(test)]
pub(crate) fn fail_next_spawn_for_test() {
    FAIL_NEXT_SPAWN.with(|flag| flag.set(true));
}
