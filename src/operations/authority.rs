//! Process-local metadata arbitration. Never call storage, toolkit or clipboard
//! code under this mutex. Mailbox and coordinator locks must never be nested.
use super::*;
use std::sync::{
    Arc, Mutex, MutexGuard,
    atomic::{AtomicBool, AtomicU8, Ordering},
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Rejected {
    Occupied,
    Stale,
    Revoked,
    Closing,
    NotReady,
    Unavailable,
    Poisoned,
}

pub(crate) struct Admission {
    id: OperationId,
    stamp: ContextStamp,
    kind: OperationKind,
    ownership: Arc<AtomicU8>,
}
impl Admission {
    pub(crate) fn ownership(&self) -> Arc<AtomicU8> {
        self.ownership.clone()
    }
    pub(crate) fn id(&self) -> OperationId {
        self.id
    }
    pub(crate) fn stamp(&self) -> ContextStamp {
        self.stamp
    }
    pub(crate) fn kind(&self) -> OperationKind {
        self.kind
    }
}

/// Private constructor: possession proves this exact immutable prepared owner
/// won its one-shot claim. Revocation never invalidates a *winning* disk lease.
pub(crate) struct CommitLease {
    binding: PreparedBinding,
}
impl CommitLease {
    pub(crate) fn authorizes(&self, binding: PreparedBinding) -> bool {
        self.binding == binding
    }
}

/// The mailbox uses id/epoch to move ownership once; rejected payload fields
/// remain worker-owned. A later revoke still invalidates any UI-transit owner.
pub(crate) struct AdoptionLease {
    id: OperationId,
    epoch: SecurityEpoch,
    ownership: Arc<AtomicU8>,
    installed: AtomicBool,
    pub session: bool,
    pub presentation: bool,
}
impl AdoptionLease {
    pub(crate) fn id(&self) -> OperationId {
        self.id
    }
    pub(crate) fn transferred(&self) -> bool {
        self.ownership
            .compare_exchange(1, 3, Ordering::AcqRel, Ordering::Acquire)
            .is_ok()
    }
}

impl Drop for AdoptionLease {
    fn drop(&mut self) {
        let _ = self
            .ownership
            .compare_exchange(1, 2, Ordering::AcqRel, Ordering::Acquire);
    }
}

#[derive(Debug, Clone, Copy)]
pub(crate) struct Snapshot {
    pub stamp: ContextStamp,
    pub occupied: Option<OperationId>,
    pub phase: Option<Phase>,
    #[cfg(test)]
    pub closing: bool,
    pub monitor_ready: bool,
    pub failed: bool,
    pub masked: bool,
    pub fully_locked: bool,
    pub live: Option<LiveSession>,
    pub progress: Option<Progress>,
}

struct Lane {
    id: OperationId,
    kind: OperationKind,
    stamp: ContextStamp,
    phase: Phase,
    prepared: Option<PreparedBinding>,
    cancelled: bool,
    claimed: bool,
    disk_complete: bool,
    result_ready: bool,
    result_candidate: bool,
    ownership: Arc<AtomicU8>,
    terminal: Option<TerminalSummary>,
    progress: Progress,
    progress_observer: Option<std::sync::Weak<super::runner::Signals>>,
    last_progress: Instant,
}
struct State {
    stamp: ContextStamp,
    live: Option<LiveSession>,
    lane: Option<Lane>,
    monitor_required: bool,
    monitor_ready: bool,
    monitor_registration: Option<Uuid>,
    monitor_seen_ready: bool,
    closing: bool,
    masked: bool,
    ui_detached: bool,
    failed: bool,
}

pub(crate) struct Coordinator {
    state: Mutex<State>,
}
impl Coordinator {
    pub(crate) fn new(monitor_required: bool) -> Self {
        Self {
            state: Mutex::new(State {
                stamp: ContextStamp {
                    epoch: SecurityEpoch::fresh(),
                    form: FormGeneration::fresh(),
                    display: DisplayGeneration::fresh(),
                    session: None,
                },
                live: None,
                lane: None,
                monitor_required,
                monitor_ready: !monitor_required,
                monitor_registration: None,
                monitor_seen_ready: false,
                closing: false,
                masked: false,
                ui_detached: true,
                failed: false,
            }),
        }
    }

    fn state(&self) -> Result<MutexGuard<'_, State>, Rejected> {
        self.state.lock().map_err(|_| Rejected::Poisoned)
    }

    fn expire(state: &mut State, now: Instant, epoch: SecurityEpoch) {
        if state.live.is_some_and(|live| now >= live.deadline) {
            Self::revoke_state(state, RevokeReason::Idle, epoch);
        }
    }

    fn revoke_state(state: &mut State, reason: RevokeReason, epoch: SecurityEpoch) {
        state.stamp.epoch = epoch;
        state.stamp.session = None;
        state.live = None;
        state.masked = true;
        state.ui_detached = false;
        if reason == RevokeReason::Close {
            state.closing = true;
        }
        if reason == RevokeReason::MonitorFailed {
            state.monitor_ready = false;
        }
        if reason == RevokeReason::WorkerFailed {
            state.failed = true;
        }
        if let Some(lane) = state.lane.as_mut() {
            lane.cancelled = true;
        }
    }

    fn usable(state: &State, stamp: ContextStamp) -> Result<(), Rejected> {
        if state.failed {
            return Err(Rejected::Unavailable);
        }
        if state.closing {
            return Err(Rejected::Closing);
        }
        if state.masked || state.stamp.epoch != stamp.epoch {
            return Err(Rejected::Revoked);
        }
        if state.monitor_required && !state.monitor_ready {
            return Err(Rejected::Unavailable);
        }
        if stamp.session != state.stamp.session {
            return Err(Rejected::Stale);
        }
        Ok(())
    }

    pub(crate) fn snapshot(&self, now: Instant) -> Snapshot {
        let epoch = SecurityEpoch::fresh();
        // Poison cannot restore authority. Even its diagnostic snapshot is masked.
        let (mut s, poisoned) = match self.state.lock() {
            Ok(s) => (s, false),
            Err(error) => (error.into_inner(), true),
        };
        Self::expire(&mut s, now, epoch);
        Snapshot {
            stamp: s.stamp,
            occupied: s.lane.as_ref().map(|l| l.id),
            phase: s.lane.as_ref().map(|l| l.phase),
            #[cfg(test)]
            closing: s.closing,
            monitor_ready: s.monitor_ready && !poisoned,
            failed: s.failed || poisoned,
            masked: s.masked || poisoned,
            fully_locked: s.live.is_none() && s.ui_detached && s.lane.is_none(),
            live: if poisoned { None } else { s.live },
            progress: s.lane.as_ref().map(|l| l.progress),
        }
    }

    pub(crate) fn try_admit(
        &self,
        kind: OperationKind,
        stamp: ContextStamp,
        now: Instant,
    ) -> Result<Admission, Rejected> {
        let id = OperationId::fresh();
        let ownership = Arc::new(AtomicU8::new(0));
        let epoch = SecurityEpoch::fresh();
        let mut s = self.state()?;
        Self::expire(&mut s, now, epoch);
        if s.lane.is_some() {
            return Err(Rejected::Occupied);
        }
        if s.live.is_some()
            && matches!(
                kind,
                OperationKind::Open | OperationKind::Create | OperationKind::RestoreNew
            )
        {
            return Err(Rejected::Stale);
        }
        if kind != OperationKind::Dispose {
            if kind == OperationKind::InspectRecovery {
                if s.closing || s.failed || s.masked {
                    return Err(Rejected::Revoked);
                }
            } else {
                Self::usable(&s, stamp)?;
            }
            if stamp != s.stamp {
                return Err(Rejected::Stale);
            }
        }
        s.lane = Some(Lane {
            id,
            kind,
            stamp,
            phase: Phase::Preparing,
            prepared: None,
            cancelled: false,
            claimed: false,
            disk_complete: false,
            result_ready: false,
            result_candidate: false,
            ownership: ownership.clone(),
            terminal: None,
            progress: Progress {
                phase: WorkPhase::Reading,
                completed: 0,
                total: None,
            },
            progress_observer: None,
            last_progress: now,
        });
        Ok(Admission {
            id,
            stamp,
            kind,
            ownership,
        })
    }

    pub(crate) fn checkpoint(&self, id: OperationId, now: Instant) -> Result<(), Rejected> {
        let epoch = SecurityEpoch::fresh();
        let mut s = self.state()?;
        Self::expire(&mut s, now, epoch);
        let l = s
            .lane
            .as_ref()
            .filter(|l| l.id == id)
            .ok_or(Rejected::Stale)?;
        // Once claimed, a writer must finish its storage contract despite revoke.
        if l.claimed {
            return Ok(());
        }
        if l.cancelled {
            return Err(Rejected::Revoked);
        }
        if l.kind != OperationKind::InspectRecovery && l.kind != OperationKind::Dispose {
            Self::usable(&s, l.stamp)?;
        } else if l.kind == OperationKind::InspectRecovery
            && (s.closing || s.stamp.epoch != l.stamp.epoch)
        {
            return Err(Rejected::Revoked);
        }
        Ok(())
    }

    pub(super) fn observe_progress(
        &self,
        id: OperationId,
        observer: std::sync::Weak<super::runner::Signals>,
    ) {
        if let Ok(mut s) = self.state()
            && let Some(l) = s.lane.as_mut().filter(|l| l.id == id)
        {
            l.progress_observer = Some(observer);
        }
    }
    pub(crate) fn record_progress(&self, id: OperationId, progress: Progress, now: Instant) {
        let notify = {
            let Ok(mut s) = self.state() else {
                return;
            };
            let Some(l) = s.lane.as_mut().filter(|l| l.id == id) else {
                return;
            };
            let changed = l.progress.phase != progress.phase;
            l.progress = progress;
            if changed
                || now.saturating_duration_since(l.last_progress)
                    >= std::time::Duration::from_millis(100)
            {
                l.last_progress = now;
                l.progress_observer.clone()
            } else {
                None
            }
        };
        if let Some(observer) = notify.and_then(|weak| weak.upgrade()) {
            observer.phase_changed();
        }
    }
    pub(crate) fn mark_ready(
        &self,
        id: OperationId,
        binding: PreparedBinding,
    ) -> Result<(), Rejected> {
        let mut s = self.state()?;
        let l = s
            .lane
            .as_mut()
            .filter(|l| l.id == id)
            .ok_or(Rejected::Stale)?;
        if l.phase != Phase::Preparing
            || l.cancelled
            || binding.operation != id
            || binding.session != l.stamp.session
        {
            return Err(Rejected::Stale);
        }
        l.prepared = Some(binding);
        l.phase = Phase::Ready;
        Ok(())
    }

    pub(crate) fn claim_commit(
        &self,
        id: OperationId,
        binding: PreparedBinding,
        now: Instant,
    ) -> Result<CommitLease, Rejected> {
        let epoch = SecurityEpoch::fresh();
        let mut s = self.state()?;
        Self::expire(&mut s, now, epoch);
        let l = s
            .lane
            .as_ref()
            .filter(|l| l.id == id)
            .ok_or(Rejected::Stale)?;
        Self::usable(&s, l.stamp)?;
        if !matches!(
            l.kind,
            OperationKind::Create
                | OperationKind::MutateAndSave
                | OperationKind::ApplyImport
                | OperationKind::Backup
                | OperationKind::RestoreCurrent
                | OperationKind::RestoreNew
                | OperationKind::ExportCsv
        ) {
            return Err(Rejected::NotReady);
        }
        if l.cancelled || l.phase != Phase::Ready || l.claimed || l.prepared != Some(binding) {
            return Err(Rejected::NotReady);
        }
        let l = s.lane.as_mut().ok_or(Rejected::Stale)?;
        l.claimed = true;
        l.phase = Phase::Committing;
        Ok(CommitLease { binding })
    }

    pub(crate) fn cancel(&self, id: OperationId) {
        if let Ok(mut s) = self.state()
            && let Some(l) = s.lane.as_mut().filter(|l| l.id == id)
        {
            l.cancelled = true;
        }
    }
    pub(crate) fn revoke(&self, reason: RevokeReason, _now: Instant) {
        let epoch = SecurityEpoch::fresh();
        if let Ok(mut s) = self.state() {
            Self::revoke_state(&mut s, reason, epoch);
        }
    }
    pub(crate) fn observe_close(&self, now: Instant) {
        self.revoke(RevokeReason::Close, now);
    }
    #[cfg(test)]
    pub(crate) fn monitor_ready(&self) {
        if let Ok(mut s) = self.state() {
            s.monitor_ready = true;
        }
    }
    pub(crate) fn bind_monitor_registration(&self, id: Uuid) -> bool {
        let Ok(mut s) = self.state() else {
            return false;
        };
        if s.monitor_registration.is_some() {
            return false;
        }
        s.monitor_registration = Some(id);
        s.monitor_seen_ready = false;
        s.monitor_ready = !s.monitor_required;
        true
    }
    #[cfg(any(windows, test))]
    pub(crate) fn monitor_ready_for(&self, id: Uuid) -> bool {
        let Ok(mut s) = self.state() else {
            return false;
        };
        if s.monitor_registration != Some(id) || s.monitor_seen_ready {
            return false;
        }
        s.monitor_seen_ready = true;
        s.monitor_ready = true;
        true
    }
    #[cfg(any(windows, test))]
    pub(crate) fn monitor_failed_for(&self, id: Uuid, _now: Instant) -> bool {
        let epoch = SecurityEpoch::fresh();
        let Ok(mut s) = self.state() else {
            return false;
        };
        if s.monitor_registration != Some(id) {
            return false;
        }
        // A terminal monitor exit cannot be revived by its delayed first Ready.
        s.monitor_seen_ready = true;
        Self::revoke_state(&mut s, RevokeReason::MonitorFailed, epoch);
        true
    }
    #[cfg(any(windows, test))]
    pub(crate) fn monitor_retryable_failure_for(&self, id: Uuid, _now: Instant) -> bool {
        let epoch = SecurityEpoch::fresh();
        let Ok(mut s) = self.state() else {
            return false;
        };
        if s.monitor_registration != Some(id) || s.monitor_seen_ready {
            return false;
        }
        Self::revoke_state(&mut s, RevokeReason::MonitorFailed, epoch);
        true
    }
    #[cfg(any(windows, test))]
    pub(crate) fn native_revoke_for(&self, id: Uuid, _now: Instant) -> bool {
        let epoch = SecurityEpoch::fresh();
        let Ok(mut s) = self.state() else {
            return false;
        };
        if s.monitor_registration != Some(id) {
            return false;
        }
        Self::revoke_state(&mut s, RevokeReason::Native, epoch);
        true
    }
    pub(crate) fn detach_monitor_registration(&self, id: Uuid, _now: Instant) {
        let epoch = SecurityEpoch::fresh();
        let Ok(mut s) = self.state() else {
            return;
        };
        if s.monitor_registration == Some(id) {
            s.monitor_registration = None;
            Self::revoke_state(&mut s, RevokeReason::MonitorFailed, epoch);
        }
    }
    pub(crate) fn complete_disk(&self, id: OperationId, summary: TerminalSummary) {
        // Poison never permits new work. A real owner's terminal/cleanup
        // acknowledgements may still retire its fixed-size metadata safely.
        let mut s = match self.state.lock() {
            Ok(s) => s,
            Err(error) => {
                let mut s = error.into_inner();
                s.failed = true;
                s.masked = true;
                s
            }
        };
        if let Some(l) = s.lane.as_mut().filter(|l| l.id == id) {
            l.disk_complete = true;
            l.terminal = Some(summary);
            // Finished is published only after the actual result slot exists.
        }
    }
    #[cfg(test)]
    pub(crate) fn result_ready(&self, id: OperationId) {
        if let Ok(mut s) = self.state()
            && let Some(l) = s.lane.as_mut().filter(|l| l.id == id && l.disk_complete)
        {
            l.result_ready = true;
            l.phase = Phase::Finished;
            l.result_candidate = matches!(
                l.kind,
                OperationKind::Open | OperationKind::Create | OperationKind::RestoreCurrent
            );
        }
    }
    pub(crate) fn result_ready_with_session(
        &self,
        id: OperationId,
        session: Option<SessionBinding>,
    ) {
        if let Ok(mut s) = self.state()
            && let Some(l) = s.lane.as_mut().filter(|l| l.id == id && l.disk_complete)
        {
            l.result_ready = true;
            l.phase = Phase::Finished;
            l.result_candidate = session.is_some_and(|returned| {
                l.stamp
                    .session
                    .is_none_or(|original| original.instance != returned.instance)
            });
        }
    }
    pub(crate) fn claim_adoption(
        &self,
        id: OperationId,
        current: ContextStamp,
        now: Instant,
    ) -> Result<AdoptionLease, Rejected> {
        let epoch = SecurityEpoch::fresh();
        let mut s = self.state()?;
        Self::expire(&mut s, now, epoch);
        let l = s
            .lane
            .as_ref()
            .filter(|l| l.id == id)
            .ok_or(Rejected::Stale)?;
        if current != s.stamp || current.epoch != l.stamp.epoch || s.masked || s.closing || s.failed
        {
            return Err(Rejected::Revoked);
        }
        if !l.result_ready || l.ownership.load(Ordering::Acquire) != 0 {
            return Err(Rejected::NotReady);
        }
        let presentation = !l.cancelled && current.form == l.stamp.form;
        if l.result_candidate && l.stamp.session.is_some() && !presentation {
            Self::revoke_state(&mut s, RevokeReason::Manual, epoch);
            return Err(Rejected::Revoked);
        }
        let session = if l.result_candidate {
            presentation
        } else {
            l.stamp
                .session
                .is_some_and(|original| Some(original) == s.stamp.session)
        };
        if !session && !presentation {
            return Err(Rejected::Stale);
        }
        let l = s.lane.as_mut().ok_or(Rejected::Stale)?;
        l.ownership
            .compare_exchange(0, 1, Ordering::AcqRel, Ordering::Acquire)
            .map_err(|_| Rejected::NotReady)?;
        l.phase = Phase::Draining;
        Ok(AdoptionLease {
            id,
            epoch: current.epoch,
            ownership: l.ownership.clone(),
            installed: AtomicBool::new(false),
            session,
            presentation,
        })
    }
    #[cfg(test)]
    pub(crate) fn adoption_claimed(&self, id: OperationId) -> bool {
        self.state().is_ok_and(|s| {
            s.lane
                .as_ref()
                .is_some_and(|l| l.id == id && l.ownership.load(Ordering::Acquire) == 1)
        })
    }
    /// The worker is disposing the sole returned session owner. A dropped
    /// observer or an abandoned adoption must not leave authority for that
    /// destroyed owner alive. Successful transfers have no session left here.
    pub(crate) fn abandon_session_owner(&self, id: OperationId) {
        let epoch = SecurityEpoch::fresh();
        let Ok(mut s) = self.state() else {
            return;
        };
        let original = s
            .lane
            .as_ref()
            .filter(|l| l.id == id)
            .and_then(|l| l.stamp.session);
        if original.is_some_and(|binding| s.live.is_some_and(|live| live.binding == binding)) {
            Self::revoke_state(&mut s, RevokeReason::Manual, epoch);
        }
    }
    pub(crate) fn ack_ui_detached(&self, epoch: SecurityEpoch) {
        let mut s = match self.state.lock() {
            Ok(s) => s,
            Err(error) => error.into_inner(),
        };
        if s.stamp.epoch == epoch {
            s.ui_detached = true;
        }
    }
    /// Only an opaque witness from the actual owning worker can release the
    /// lane. Poison leaves admission permanently unavailable, but cannot hide
    /// the fact that guarded owners really were released.
    pub(crate) fn ack_worker_drained(&self, witness: super::runner::CleanupWitness) {
        let id = witness.id();
        let (mut s, poisoned) = match self.state.lock() {
            Ok(s) => (s, false),
            Err(error) => (error.into_inner(), true),
        };
        let retired = if s
            .lane
            .as_ref()
            .is_some_and(|l| l.id == id && l.disk_complete)
        {
            s.lane.take()
        } else {
            None
        };
        if poisoned && retired.is_some() {
            s.live = None;
            s.stamp.session = None;
            s.failed = true;
            s.masked = true;
        }
        drop(s);
        drop(retired);
    }
    pub(crate) fn resume_locked_after_keep_open(&self, now: Instant) -> Result<(), Rejected> {
        let epoch = SecurityEpoch::fresh();
        let form = FormGeneration::fresh();
        let display = DisplayGeneration::fresh();
        let mut s = self.state()?;
        Self::expire(&mut s, now, epoch);
        if s.failed || s.lane.is_some() || !s.ui_detached || s.live.is_some() {
            return Err(Rejected::NotReady);
        }
        s.closing = false;
        s.masked = false;
        s.stamp = ContextStamp {
            epoch,
            form,
            display,
            session: None,
        };
        Ok(())
    }
    pub(crate) fn install_session(
        &self,
        lease: &AdoptionLease,
        binding: SessionBinding,
        deadline: Instant,
        now: Instant,
    ) -> bool {
        let epoch = SecurityEpoch::fresh();
        let Ok(mut s) = self.state() else {
            return false;
        };
        Self::expire(&mut s, now, epoch);
        if !lease.session
            || s.masked
            || s.closing
            || s.failed
            || s.stamp.epoch != lease.epoch
            || now >= deadline
        {
            return false;
        }
        if lease.installed.swap(true, Ordering::AcqRel) {
            return false;
        }
        s.live = Some(LiveSession { binding, deadline });
        s.stamp.session = Some(binding);
        s.ui_detached = false;
        true
    }
    #[cfg(test)]
    pub(crate) fn activate_session(&self, binding: SessionBinding, deadline: Instant) {
        let mut s = self.state().unwrap();
        s.live = Some(LiveSession { binding, deadline });
        s.stamp.session = Some(binding);
        s.ui_detached = false;
    }
    pub(crate) fn change_form(&self) {
        let form = FormGeneration::fresh();
        if let Ok(mut s) = self.state() {
            s.stamp.form = form;
            if let Some(l) = &mut s.lane {
                l.cancelled = true;
            }
        }
    }
    pub(crate) fn change_display(&self) {
        let display = DisplayGeneration::fresh();
        if let Ok(mut s) = self.state() {
            s.stamp.display = display;
        }
    }
    pub(crate) fn activity(&self, now: Instant, idle: std::time::Duration) {
        let epoch = SecurityEpoch::fresh();
        let mut s = match self.state() {
            Ok(s) => s,
            Err(_) => return,
        };
        Self::expire(&mut s, now, epoch);
        if let Some(live) = s.live.as_mut() {
            live.deadline = now + idle;
        }
    }
    #[cfg(test)]
    pub(crate) fn poison_for_test(&self) {
        let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _guard = self.state.lock().unwrap();
            panic!("synthetic metadata poison");
        }));
    }
}
