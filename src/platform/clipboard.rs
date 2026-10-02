//! Clipboard requests carry no plaintext in their completion events or Debug output.
use std::fmt;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ClipboardKind {
    Password,
    Username,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ClipboardCopyOutcome {
    Copied,
    Cancelled,
    Failed,
}

#[derive(Clone)]
pub struct ClipboardSession {
    id: u64,
    permit: Arc<Mutex<Permit>>,
    revoked: Arc<AtomicBool>,
}
#[derive(Debug)]
struct Permit {
    valid: bool,
    #[cfg(any(windows, test))]
    latest_request: Option<u64>,
}
static NEXT_SESSION: AtomicU64 = AtomicU64::new(1);
impl ClipboardSession {
    pub fn id(&self) -> u64 {
        self.id
    }
    pub(super) fn new() -> Self {
        Self {
            id: NEXT_SESSION.fetch_add(1, Ordering::Relaxed),
            revoked: Arc::new(AtomicBool::new(false)),
            permit: Arc::new(Mutex::new(Permit {
                valid: true,
                #[cfg(any(windows, test))]
                latest_request: None,
            })),
        }
    }
    #[cfg(any(windows, test))]
    pub(super) fn revoked(&self) -> bool {
        self.revoked.load(Ordering::Acquire)
    }
    pub(super) fn revoke_native(&self) {
        self.revoked.store(true, Ordering::Release);
    }
    pub(super) fn revoke(&self) {
        self.revoke_native();
        self.permit.lock().unwrap_or_else(|e| e.into_inner()).valid = false;
    }
}
impl fmt::Debug for ClipboardSession {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ClipboardSession")
            .field("id", &self.id)
            .finish_non_exhaustive()
    }
}

#[cfg(any(windows, test))]
mod owner {
    use super::*;
    use crate::platform::SecurityEvent;
    use zeroize::Zeroizing;
    pub(crate) struct CopyCommand {
        pub session: ClipboardSession,
        pub request: u64,
        pub kind: ClipboardKind,
        pub text: Zeroizing<String>,
        pub timeout_ms: u32,
    }
    impl fmt::Debug for CopyCommand {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            f.debug_struct("CopyCommand")
                .field("session", &self.session)
                .field("request", &self.request)
                .field("kind", &self.kind)
                .finish_non_exhaustive()
        }
    }
    pub(crate) trait ClipboardBackend {
        type Prepared;
        fn now_ms(&self) -> u64;
        fn new_marker(&mut self) -> Result<[u8; 16], ()>;
        fn prepare(&mut self, text: &[u16], marker: [u8; 16]) -> Result<Self::Prepared, ()>;
        fn open(&mut self) -> Result<(), ()>;
        fn empty(&mut self) -> Result<(), ()>;
        fn set_marker(&mut self, prepared: &mut Self::Prepared) -> Result<(), ()>;
        fn set_text(&mut self, prepared: &mut Self::Prepared) -> Result<(), ()>;
        fn close(&mut self) -> Result<(), ()>;
        fn matches(&mut self, marker: [u8; 16], expected: Option<&[u16]>) -> Result<bool, ()>;
        fn sequence(&self) -> u32;
        fn arm_timer(&mut self, delay_ms: u32) -> Result<(), ()>;
        fn stop_timer(&mut self);
    }
    use std::collections::VecDeque;
    use std::sync::mpsc::SyncSender;

    pub(crate) enum ClipboardCommand {
        Copy(CopyCommand),
        ClearRevoked,
        Stop {
            done: SyncSender<bool>,
        },
        Shutdown {
            session: u64,
            done: SyncSender<bool>,
        },
    }
    #[derive(Default)]
    pub(crate) struct ClipboardQueue {
        active: Option<ClipboardSession>,
        commands: VecDeque<ClipboardCommand>,
    }
    impl ClipboardQueue {
        pub(crate) fn begin(&mut self) -> ClipboardSession {
            self.revoke_active();
            let session = ClipboardSession::new();
            self.active = Some(session.clone());
            session
        }
        pub(crate) fn revoke_active(&mut self) {
            if let Some(session) = self.active.take() {
                session.revoke();
            }
            self.commands
                .retain(|command| !matches!(command, ClipboardCommand::Copy(_)));
        }
        pub(crate) fn revoke_active_native(&mut self) {
            if let Some(session) = self.active.take() {
                session.revoke_native();
            }
            self.commands
                .retain(|command| !matches!(command, ClipboardCommand::Copy(_)));
        }
        pub(crate) fn has_work(&self) -> bool {
            !self.commands.is_empty()
        }
        pub(crate) fn push_copy(
            &mut self,
            command: CopyCommand,
            post: impl FnOnce() -> bool,
        ) -> Result<(), ()> {
            if self.active.as_ref().map(ClipboardSession::id) != Some(command.session.id) {
                return Err(());
            }
            {
                let permit = command
                    .session
                    .permit
                    .lock()
                    .unwrap_or_else(|e| e.into_inner());
                if !permit.valid
                    || command.session.revoked()
                    || permit
                        .latest_request
                        .is_some_and(|latest| command.request <= latest)
                {
                    return Err(());
                }
            }
            let session = command.session.clone();
            let request = command.request;
            let index = self.commands.iter().position(
                |old| matches!(old,ClipboardCommand::Copy(copy) if copy.session.id==session.id),
            );
            let old = index.and_then(|index| self.commands.remove(index));
            if self.commands.len() >= 16 {
                if let (Some(index), Some(old)) = (index, old) {
                    self.commands.insert(index, old);
                }
                return Err(());
            }
            self.commands.push_back(ClipboardCommand::Copy(command));
            if post() {
                // The queue mutex still excludes the consumer. Only a successful
                // post commits the new request ID, so a failed enqueue cannot
                // transiently cancel an already-popped, accepted older request.
                session
                    .permit
                    .lock()
                    .unwrap_or_else(|e| e.into_inner())
                    .latest_request = Some(request);
                return Ok(());
            }
            self.commands.pop_back();
            if let (Some(index), Some(old)) = (index, old) {
                self.commands.insert(index, old);
            }
            Err(())
        }
        pub(crate) fn push_clear(&mut self, post: impl FnOnce() -> bool) -> Result<(), ()> {
            self.commands.retain(
                |command| !matches!(command,ClipboardCommand::Copy(copy) if copy.session.revoked()),
            );
            if self
                .commands
                .iter()
                .any(|command| matches!(command, ClipboardCommand::ClearRevoked))
            {
                return Ok(());
            }
            if self.commands.len() >= 16 {
                return Err(());
            }
            self.commands.push_back(ClipboardCommand::ClearRevoked);
            if post() {
                Ok(())
            } else {
                self.commands.pop_back();
                Err(())
            }
        }
        pub(crate) fn push_stop(
            &mut self,
            done: SyncSender<bool>,
            post: impl FnOnce() -> bool,
        ) -> Result<(), ()> {
            self.revoke_active_native();
            if self.commands.len() >= 16 {
                return Err(());
            }
            self.commands.push_back(ClipboardCommand::Stop { done });
            if post() {
                Ok(())
            } else {
                self.commands.pop_back();
                Err(())
            }
        }
        pub(crate) fn push_shutdown(
            &mut self,
            session: u64,
            done: SyncSender<bool>,
            post: impl FnOnce() -> bool,
        ) -> Result<(), ()> {
            self.commands.retain(
                |command| !matches!(command,ClipboardCommand::Copy(copy) if copy.session.revoked()),
            );
            if self.commands.len() >= 16 {
                return Err(());
            }
            self.commands
                .push_back(ClipboardCommand::Shutdown { session, done });
            if post() {
                Ok(())
            } else {
                self.commands.pop_back();
                Err(())
            }
        }
        pub(crate) fn pop(&mut self) -> Option<ClipboardCommand> {
            self.commands.pop_front()
        }
    }
    const RETRY_MS: u64 = 250;
    const MAX_RETRIES: u8 = 4;

    #[derive(Clone, Copy, PartialEq, Eq)]
    enum ReceiptMatch {
        Same,
        Foreign,
        Changed,
    }
    enum Binding {
        Confirm(Zeroizing<Vec<u16>>),
        Bound(u32),
    }
    struct Receipt {
        session: ClipboardSession,
        request: u64,
        kind: ClipboardKind,
        marker: [u8; 16],
        binding: Binding,
        deadline: u64,
        due: u64,
        retries: u8,
        completion_pending: bool,
    }
    pub(crate) struct ClipboardEngine<B: ClipboardBackend> {
        pub(super) backend: B,
        pending: Option<Receipt>,
        events: Vec<SecurityEvent>,
        failed: bool,
    }
    impl<B: ClipboardBackend> ClipboardEngine<B> {
        pub(crate) fn new(backend: B) -> Self {
            Self {
                backend,
                pending: None,
                events: Vec::new(),
                failed: false,
            }
        }
        fn close(&mut self) -> Result<(), ()> {
            if self.backend.close().is_ok() {
                return Ok(());
            }
            // Preserve the original error even when the immediate close-only
            // retry succeeds. If neither call succeeds, stop native ownership;
            // exiting its thread releases any remaining clipboard lock.
            if self.backend.close().is_err() && !self.failed {
                self.failed = true;
                self.events.push(SecurityEvent::MonitorFailed);
            }
            Err(())
        }
        fn report(
            &mut self,
            session: u64,
            request: u64,
            kind: ClipboardKind,
            outcome: ClipboardCopyOutcome,
        ) {
            self.events.push(SecurityEvent::ClipboardCopyCompleted {
                session,
                request,
                kind,
                outcome,
            });
        }
        fn complete(&mut self, receipt: &mut Receipt, outcome: ClipboardCopyOutcome) {
            if receipt.completion_pending {
                receipt.completion_pending = false;
                self.report(receipt.session.id, receipt.request, receipt.kind, outcome);
            }
        }
        pub(crate) fn write(&mut self, command: CopyCommand) {
            let failure = |this: &mut Self, outcome| {
                this.report(command.session.id, command.request, command.kind, outcome)
            };
            if self.failed || command.text.contains('\0') {
                failure(self, ClipboardCopyOutcome::Failed);
                return;
            }
            let expected =
                Zeroizing::new(command.text.encode_utf16().chain([0]).collect::<Vec<_>>());
            let prepared = self.backend.new_marker().and_then(|marker| {
                self.backend
                    .prepare(&expected, marker)
                    .map(|buffer| (marker, buffer))
            });
            let Ok((marker, mut prepared)) = prepared else {
                failure(self, ClipboardCopyOutcome::Failed);
                return;
            };
            let now = self.backend.now_ms();
            let deadline = now.saturating_add(u64::from(command.timeout_ms.max(1)));
            let first_due = self
                .pending
                .as_ref()
                .map_or(deadline, |old| old.due.min(deadline));
            // Establish a native timer BEFORE publishing any password. A failed
            // new request must not cancel the previous copy's cleanup timer.
            if self.backend.arm_timer(delay(now, first_due)).is_err() {
                failure(self, ClipboardCopyOutcome::Failed);
                self.restore_timer();
                return;
            }
            if self.backend.open().is_err() {
                failure(self, ClipboardCopyOutcome::Failed);
                self.restore_timer();
                return;
            }
            // Precheck without retaining the gate across EmptyClipboard: that
            // call notifies the previous owner and may wait on another process.
            let permit = command
                .session
                .permit
                .lock()
                .unwrap_or_else(|e| e.into_inner());
            if !permit.valid
                || command.session.revoked()
                || permit.latest_request != Some(command.request)
            {
                drop(permit);
                if self.close().is_err() {
                    self.events.push(SecurityEvent::ClipboardCleanupFailed);
                }
                failure(self, ClipboardCopyOutcome::Cancelled);
                self.restore_timer();
                return;
            }
            drop(permit);
            if self.backend.empty().is_err() {
                if self.close().is_err() {
                    self.events.push(SecurityEvent::ClipboardCleanupFailed);
                }
                failure(self, ClipboardCopyOutcome::Failed);
                self.restore_timer();
                return;
            }
            if let Some(mut old) = self.pending.take() {
                self.complete(&mut old, ClipboardCopyOutcome::Cancelled);
            }
            // Only the final request check, SetClipboardData and provisional
            // receipt assignment share the gate. Revocation during a stalled
            // EmptyClipboard can return immediately and prevents publication.
            let permit = command
                .session
                .permit
                .lock()
                .unwrap_or_else(|e| e.into_inner());
            if !permit.valid
                || command.session.revoked()
                || permit.latest_request != Some(command.request)
            {
                drop(permit);
                if self.close().is_err() {
                    self.events.push(SecurityEvent::ClipboardCleanupFailed);
                }
                failure(self, ClipboardCopyOutcome::Cancelled);
                self.backend.stop_timer();
                return;
            }
            // Marker first: if either SetClipboardData fails, no untracked
            // password has been transferred to Windows.
            if command.session.revoked()
                || self.backend.set_marker(&mut prepared).is_err()
                || command.session.revoked()
                || self.backend.set_text(&mut prepared).is_err()
            {
                drop(permit);
                let rollback = self.backend.empty();
                let close = self.close();
                if rollback.is_err() || close.is_err() {
                    self.events.push(SecurityEvent::ClipboardCleanupFailed);
                }
                failure(self, ClipboardCopyOutcome::Failed);
                self.backend.stop_timer();
                return;
            }
            self.pending = Some(Receipt {
                session: command.session.clone(),
                request: command.request,
                kind: command.kind,
                marker,
                binding: Binding::Confirm(expected),
                deadline,
                due: now,
                retries: 0,
                completion_pending: true,
            });
            drop(permit);
            // CloseClipboard can synthesize formats and change the sequence.
            // Confirm the exact owner, random marker AND expected Unicode text
            // after reopening, rather than adopting the sequence seen now.
            if self.close().is_err() {
                if let Some(mut receipt) = self.pending.take() {
                    self.complete(&mut receipt, ClipboardCopyOutcome::Failed);
                    self.abort_cleanup(receipt);
                }
                return;
            }
            self.process(false);
        }
        pub(crate) fn tick(&mut self) {
            self.process(false);
        }
        pub(crate) fn stop(&mut self) -> bool {
            if let Some(receipt) = self.pending.as_ref() {
                receipt.session.revoke();
                let session = receipt.session.id;
                self.shutdown(session)
            } else {
                true
            }
        }
        pub(crate) fn shutdown(&mut self, session: u64) -> bool {
            if !self
                .pending
                .as_ref()
                .is_some_and(|receipt| receipt.session.id == session && receipt.session.revoked())
            {
                return true;
            }
            let mut receipt = self.pending.take().expect("matching receipt");
            self.complete(&mut receipt, ClipboardCopyOutcome::Cancelled);
            let success = self.rollback_once(&receipt);
            if !success {
                self.events.push(SecurityEvent::ClipboardCleanupFailed);
            }
            self.backend.stop_timer();
            success
        }
        pub(crate) fn clear_revoked(&mut self) {
            if self
                .pending
                .as_ref()
                .is_some_and(|receipt| receipt.session.revoked())
            {
                self.process(true);
            }
        }
        fn process(&mut self, force: bool) {
            let Some(mut receipt) = self.pending.take() else {
                self.backend.stop_timer();
                return;
            };
            let now = self.backend.now_ms();
            let force = force || receipt.session.revoked();
            if !force && now < receipt.due {
                self.retain(receipt);
                return;
            }
            if force || matches!(receipt.binding, Binding::Bound(_)) {
                self.clear(receipt);
                return;
            }
            if self.backend.open().is_err() {
                self.retry(receipt);
                return;
            }
            let Binding::Confirm(expected) = &receipt.binding else {
                unreachable!()
            };
            let matches = self.backend.matches(receipt.marker, Some(expected));
            let sequence = self.backend.sequence();
            let close = self.close();
            if matches == Ok(false) {
                self.complete(&mut receipt, ClipboardCopyOutcome::Failed);
                if close.is_err() {
                    self.events.push(SecurityEvent::ClipboardCleanupFailed);
                }
                self.backend.stop_timer();
                return;
            }
            if matches.is_err()
                || close.is_err()
                || sequence == 0
                || sequence != self.backend.sequence()
            {
                self.retry(receipt);
                return;
            }
            receipt.binding = Binding::Bound(sequence); // Drops/zeroizes expected text.
            receipt.retries = 0;
            if receipt.session.revoked() || self.backend.now_ms() >= receipt.deadline {
                self.complete(&mut receipt, ClipboardCopyOutcome::Cancelled);
                self.clear(receipt);
                return;
            }
            if receipt.kind == ClipboardKind::Username {
                self.complete(&mut receipt, ClipboardCopyOutcome::Copied);
                self.backend.stop_timer();
                return;
            }
            receipt.due = receipt.deadline;
            if self
                .backend
                .arm_timer(delay(self.backend.now_ms(), receipt.due))
                .is_err()
            {
                self.complete(&mut receipt, ClipboardCopyOutcome::Failed);
                self.abort_cleanup(receipt);
                return;
            }
            self.complete(&mut receipt, ClipboardCopyOutcome::Copied);
            self.pending = Some(receipt);
        }
        fn clear(&mut self, mut receipt: Receipt) {
            if self.backend.open().is_err() {
                self.retry(receipt);
                return;
            }
            let matching = self.match_receipt(&receipt);
            if matches!(matching, Ok(ReceiptMatch::Foreign | ReceiptMatch::Changed)) {
                let changed = matching == Ok(ReceiptMatch::Changed);
                self.complete(
                    &mut receipt,
                    if changed {
                        ClipboardCopyOutcome::Failed
                    } else {
                        ClipboardCopyOutcome::Cancelled
                    },
                );
                let closed = self.close();
                if changed || closed.is_err() {
                    self.events.push(SecurityEvent::ClipboardCleanupFailed);
                }
                self.backend.stop_timer();
                return;
            }
            if matching.is_err() {
                let _ = self.close();
                self.retry(receipt);
                return;
            }
            let emptied = self.backend.empty();
            let close = self.close();
            if emptied.is_err() {
                self.retry(receipt);
                return;
            }
            self.complete(&mut receipt, ClipboardCopyOutcome::Cancelled);
            if close.is_err() {
                self.events.push(SecurityEvent::ClipboardCleanupFailed);
            }
            self.backend.stop_timer();
        }
        fn retry(&mut self, mut receipt: Receipt) {
            if receipt.retries >= MAX_RETRIES {
                self.complete(&mut receipt, ClipboardCopyOutcome::Failed);
                self.abort_cleanup(receipt);
                return;
            }
            receipt.retries += 1;
            receipt.due = self.backend.now_ms().saturating_add(RETRY_MS);
            self.retain(receipt);
        }
        fn retain(&mut self, mut receipt: Receipt) {
            if self
                .backend
                .arm_timer(delay(self.backend.now_ms(), receipt.due))
                .is_err()
            {
                self.complete(&mut receipt, ClipboardCopyOutcome::Failed);
                self.abort_cleanup(receipt);
                return;
            }
            self.pending = Some(receipt);
        }
        fn restore_timer(&mut self) {
            if let Some(receipt) = self.pending.take() {
                self.retain(receipt);
            } else {
                self.backend.stop_timer();
            }
        }
        // Last bounded, identity-checked rollback. Never retain expected text
        // indefinitely after timer/confirmation/retry exhaustion failures.
        fn abort_cleanup(&mut self, receipt: Receipt) {
            self.events.push(SecurityEvent::ClipboardCleanupFailed);
            self.rollback_once(&receipt);
            self.backend.stop_timer();
        }
        fn rollback_once(&mut self, receipt: &Receipt) -> bool {
            if self.backend.open().is_err() {
                return false;
            }
            let cleared = match self.match_receipt(receipt) {
                Ok(ReceiptMatch::Same) => self.backend.empty().is_ok(),
                Ok(ReceiptMatch::Foreign) => true,
                Ok(ReceiptMatch::Changed) | Err(()) => false,
            };
            let closed = self.close().is_ok();
            cleared && closed
        }
        fn match_receipt(&mut self, receipt: &Receipt) -> Result<ReceiptMatch, ()> {
            let map = |matches| {
                if matches {
                    ReceiptMatch::Same
                } else {
                    ReceiptMatch::Foreign
                }
            };
            match &receipt.binding {
                Binding::Confirm(expected) => self
                    .backend
                    .matches(receipt.marker, Some(expected))
                    .map(map),
                Binding::Bound(sequence) => {
                    let current = self.backend.sequence();
                    // Zero denotes unavailable sequence information, not proof
                    // of a foreign replacement. Never claim cleanup succeeded.
                    if current == 0 || *sequence == 0 {
                        return Err(());
                    }
                    let ours = self.backend.matches(receipt.marker, None)?;
                    if !ours {
                        Ok(ReceiptMatch::Foreign)
                    } else if current == *sequence {
                        Ok(ReceiptMatch::Same)
                    } else {
                        // Do not adopt another sequence even when our marker
                        // remains. Surface unusual owned-content changes so the
                        // caller can warn instead of silently abandoning text.
                        Ok(ReceiptMatch::Changed)
                    }
                }
            }
        }
        pub(crate) fn events(&mut self) -> Vec<SecurityEvent> {
            std::mem::take(&mut self.events)
        }
    }
    fn delay(now: u64, due: u64) -> u32 {
        due.saturating_sub(now).clamp(1, u64::from(u32::MAX)) as u32
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        #[derive(Default)]
        struct Fake {
            now: u64,
            seq: u32,
            text: Vec<u16>,
            marker: Option<[u8; 16]>,
            owned: bool,
            opened: bool,
            clears: usize,
            fail: Option<&'static str>,
            timer: Option<u32>,
            next_marker: u8,
            synthesize: bool,
            replace_on_open: bool,
            repeat_fail: bool,
            zero_sequence: bool,
            arm_count: usize,
            fail_arm_number: Option<usize>,
            close_count: usize,
            replace_after_close: Option<usize>,
            advance_on_match: u64,
            revoke_on_empty: Option<ClipboardSession>,
            block_empty: Option<(
                std::sync::mpsc::SyncSender<()>,
                std::sync::mpsc::Receiver<()>,
            )>,
        }
        impl Fake {
            fn operation(&mut self, name: &'static str) -> Result<(), ()> {
                if self.fail == Some(name) {
                    if !self.repeat_fail {
                        self.fail = None;
                    }
                    Err(())
                } else {
                    Ok(())
                }
            }
            fn foreign(&mut self, text: &str) {
                self.seq += 1;
                self.text = text.encode_utf16().chain([0]).collect();
                self.owned = false;
                self.marker = None;
            }
        }
        impl ClipboardBackend for Fake {
            type Prepared = (Vec<u16>, [u8; 16]);
            fn now_ms(&self) -> u64 {
                self.now
            }
            fn new_marker(&mut self) -> Result<[u8; 16], ()> {
                self.operation("marker")?;
                self.next_marker += 1;
                Ok([self.next_marker; 16])
            }
            fn prepare(&mut self, text: &[u16], marker: [u8; 16]) -> Result<Self::Prepared, ()> {
                self.operation("allocate")?;
                Ok((text.to_vec(), marker))
            }
            fn open(&mut self) -> Result<(), ()> {
                if self.opened {
                    self.close()?;
                }
                self.operation("open")?;
                if self.replace_on_open {
                    self.replace_on_open = false;
                    self.foreign("foreign");
                }
                self.opened = true;
                Ok(())
            }
            fn empty(&mut self) -> Result<(), ()> {
                self.operation("empty")?;
                if let Some((entered, resume)) = self.block_empty.take() {
                    entered.send(()).unwrap();
                    resume.recv().unwrap();
                }
                if let Some(session) = self.revoke_on_empty.take() {
                    session.revoke_native();
                }
                assert!(self.opened);
                self.seq += 1;
                self.text.clear();
                self.marker = None;
                self.owned = true;
                self.clears += 1;
                Ok(())
            }
            fn set_marker(&mut self, p: &mut Self::Prepared) -> Result<(), ()> {
                self.operation("set_marker")?;
                assert!(self.opened);
                self.marker = Some(p.1);
                self.seq += 1;
                Ok(())
            }
            fn set_text(&mut self, p: &mut Self::Prepared) -> Result<(), ()> {
                self.operation("set_text")?;
                assert!(self.opened);
                self.text = p.0.clone();
                self.seq += 1;
                Ok(())
            }
            fn close(&mut self) -> Result<(), ()> {
                self.operation("close")?;
                self.opened = false;
                self.close_count += 1;
                if self.replace_after_close == Some(self.close_count) {
                    self.foreign("foreign");
                }
                if self.synthesize {
                    self.synthesize = false;
                    self.seq += 2;
                }
                Ok(())
            }
            fn matches(&mut self, marker: [u8; 16], expected: Option<&[u16]>) -> Result<bool, ()> {
                self.operation("bind")?;
                self.now = self.now.saturating_add(self.advance_on_match);
                self.advance_on_match = 0;
                assert!(self.opened);
                Ok(self.owned
                    && self.marker == Some(marker)
                    && expected.is_none_or(|e| self.text == e))
            }
            fn sequence(&self) -> u32 {
                if self.zero_sequence { 0 } else { self.seq }
            }
            fn arm_timer(&mut self, ms: u32) -> Result<(), ()> {
                self.arm_count += 1;
                if self.fail_arm_number == Some(self.arm_count) {
                    return Err(());
                }
                self.operation("timer")?;
                self.timer = Some(ms);
                Ok(())
            }
            fn stop_timer(&mut self) {
                self.timer = None;
            }
        }
        fn request(
            session: &ClipboardSession,
            request: u64,
            text: &str,
            kind: ClipboardKind,
        ) -> CopyCommand {
            session.permit.lock().unwrap().latest_request = Some(request);
            CopyCommand {
                session: session.clone(),
                request,
                kind,
                text: Zeroizing::new(text.to_owned()),
                timeout_ms: 30_000,
            }
        }
        #[test]
        fn writes_unicode_before_reporting_success() {
            let session = ClipboardSession::new();
            let mut engine = ClipboardEngine::new(Fake::default());
            engine.write(request(&session, 1, "测试🦀", ClipboardKind::Password));
            assert_eq!(
                engine.backend.text,
                "测试🦀".encode_utf16().chain([0]).collect::<Vec<_>>()
            );
        }
        #[test]
        fn stale_timer_cannot_clear_newer_password_early() {
            let session = ClipboardSession::new();
            let mut engine = ClipboardEngine::new(Fake::default());
            engine.write(request(&session, 1, "A", ClipboardKind::Password));
            engine.backend.now = 20_000;
            engine.write(request(&session, 2, "B", ClipboardKind::Password));
            engine.backend.now = 30_000;
            engine.tick();
            assert_eq!(engine.backend.text, vec![66, 0]);
            assert_eq!(engine.backend.timer, Some(20_000));
            engine.backend.now = 50_000;
            engine.tick();
            assert!(engine.backend.text.is_empty());
        }

        fn copied(engine: &mut ClipboardEngine<Fake>) -> bool {
            engine.events().iter().any(|e| {
                matches!(
                    e,
                    SecurityEvent::ClipboardCopyCompleted {
                        outcome: ClipboardCopyOutcome::Copied,
                        ..
                    }
                )
            })
        }
        fn failed(engine: &mut ClipboardEngine<Fake>) -> bool {
            engine.events().iter().any(|e| {
                matches!(
                    e,
                    SecurityEvent::ClipboardCopyCompleted {
                        outcome: ClipboardCopyOutcome::Failed,
                        ..
                    }
                )
            })
        }
        #[test]
        fn failed_write_never_arms_unrelated_clipboard() {
            for operation in ["marker", "allocate", "open", "timer"] {
                let session = ClipboardSession::new();
                let mut fake = Fake::default();
                fake.foreign("unrelated");
                fake.fail = Some(operation);
                let mut engine = ClipboardEngine::new(fake);
                engine.write(request(&session, 1, "secret", ClipboardKind::Password));
                assert!(failed(&mut engine), "{operation}");
                engine.backend.now = 100_000;
                engine.tick();
                assert_eq!(
                    engine.backend.text,
                    "unrelated".encode_utf16().chain([0]).collect::<Vec<_>>(),
                    "{operation}"
                );
            }
        }
        #[test]
        fn pre_mutation_failure_preserves_previous_receipt() {
            for operation in ["marker", "allocate", "open", "timer", "empty"] {
                let session = ClipboardSession::new();
                let mut engine = ClipboardEngine::new(Fake::default());
                engine.write(request(&session, 1, "A", ClipboardKind::Password));
                assert!(copied(&mut engine));
                engine.backend.now = 1_000;
                engine.backend.fail = Some(operation);
                engine.write(request(&session, 2, "B", ClipboardKind::Password));
                assert!(failed(&mut engine));
                engine.backend.now = 30_000;
                engine.tick();
                assert!(engine.backend.text.is_empty(), "{operation}");
            }
        }
        #[test]
        fn synthesized_formats_are_included_in_bound_sequence() {
            let session = ClipboardSession::new();
            let mut engine = ClipboardEngine::new(Fake {
                synthesize: true,
                ..Fake::default()
            });
            engine.write(request(&session, 1, "secret", ClipboardKind::Password));
            assert!(copied(&mut engine));
            engine.backend.now = 30_000;
            engine.tick();
            assert!(engine.backend.text.is_empty());
        }
        #[test]
        fn foreign_replacement_before_cleanup_open_is_preserved() {
            let session = ClipboardSession::new();
            let mut engine = ClipboardEngine::new(Fake::default());
            engine.write(request(&session, 1, "secret", ClipboardKind::Password));
            engine.backend.replace_on_open = true;
            engine.backend.now = 30_000;
            engine.tick();
            assert_eq!(
                engine.backend.text,
                "foreign".encode_utf16().chain([0]).collect::<Vec<_>>()
            );
        }
        #[test]
        fn same_text_copied_by_someone_else_is_preserved() {
            let session = ClipboardSession::new();
            let mut engine = ClipboardEngine::new(Fake::default());
            engine.write(request(&session, 1, "secret", ClipboardKind::Password));
            engine.backend.foreign("secret");
            engine.backend.now = 30_000;
            engine.tick();
            assert_eq!(
                engine.backend.text,
                "secret".encode_utf16().chain([0]).collect::<Vec<_>>()
            );
        }
        #[test]
        fn username_replaces_password_and_cancels_password_timer() {
            let session = ClipboardSession::new();
            let mut engine = ClipboardEngine::new(Fake::default());
            engine.write(request(&session, 1, "secret", ClipboardKind::Password));
            engine.write(request(&session, 2, "username", ClipboardKind::Username));
            engine.backend.now = 100_000;
            engine.tick();
            assert_eq!(
                engine.backend.text,
                "username".encode_utf16().chain([0]).collect::<Vec<_>>()
            );
            assert_eq!(engine.backend.timer, None);
        }
        #[test]
        fn revoked_and_superseded_requests_cannot_write() {
            for revoke in [true, false] {
                let session = ClipboardSession::new();
                let mut engine = ClipboardEngine::new(Fake::default());
                let command = request(&session, 1, "secret", ClipboardKind::Password);
                if revoke {
                    session.revoke();
                } else {
                    let _ = request(&session, 2, "new", ClipboardKind::Username);
                }
                engine.write(command);
                assert!(engine.backend.text.is_empty());
                assert!(engine.events().iter().any(|e| matches!(
                    e,
                    SecurityEvent::ClipboardCopyCompleted {
                        outcome: ClipboardCopyOutcome::Cancelled,
                        ..
                    }
                )));
            }
        }
        #[test]
        fn revoke_clears_current_session_without_waiting_for_app_callback() {
            let session = ClipboardSession::new();
            let mut engine = ClipboardEngine::new(Fake::default());
            engine.write(request(&session, 1, "secret", ClipboardKind::Password));
            session.revoke();
            engine.clear_revoked();
            assert!(engine.backend.text.is_empty());
        }
        #[test]
        fn delayed_old_session_clear_cannot_clear_new_unlock_copy() {
            let old = ClipboardSession::new();
            let new = ClipboardSession::new();
            let mut engine = ClipboardEngine::new(Fake::default());
            engine.write(request(&old, 1, "old", ClipboardKind::Password));
            old.revoke();
            engine.write(request(&new, 1, "new", ClipboardKind::Password));
            engine.clear_revoked();
            assert_eq!(engine.backend.text, vec![110, 101, 119, 0]);
        }
        #[test]
        fn empty_text_is_valid_but_interior_nul_is_rejected() {
            let session = ClipboardSession::new();
            let mut engine = ClipboardEngine::new(Fake::default());
            engine.write(request(&session, 1, "", ClipboardKind::Password));
            assert!(copied(&mut engine));
            assert_eq!(engine.backend.text, vec![0]);
            engine.write(request(
                &session,
                2,
                "hidden\0tail",
                ClipboardKind::Password,
            ));
            assert!(failed(&mut engine));
            assert_eq!(engine.backend.text, vec![0]);
        }
        #[test]
        fn mutation_failures_report_failure_and_never_expose_secret() {
            for operation in ["empty", "set_marker", "set_text"] {
                let session = ClipboardSession::new();
                let mut fake = Fake::default();
                fake.foreign("foreign");
                fake.fail = Some(operation);
                let mut engine = ClipboardEngine::new(fake);
                engine.write(request(&session, 1, "secret", ClipboardKind::Password));
                assert!(failed(&mut engine));
                assert_ne!(
                    engine.backend.text,
                    "secret".encode_utf16().chain([0]).collect::<Vec<_>>()
                );
            }
        }
        #[test]
        fn binding_failure_retries_before_reporting_success() {
            let session = ClipboardSession::new();
            let mut engine = ClipboardEngine::new(Fake {
                fail: Some("bind"),
                ..Fake::default()
            });
            engine.write(request(&session, 1, "secret", ClipboardKind::Password));
            assert!(!copied(&mut engine));
            engine.backend.now = 250;
            engine.tick();
            assert!(copied(&mut engine));
        }
        #[test]
        fn foreign_replacement_during_binding_retry_is_not_adopted() {
            let session = ClipboardSession::new();
            let mut engine = ClipboardEngine::new(Fake {
                fail: Some("bind"),
                ..Fake::default()
            });
            engine.write(request(&session, 1, "secret", ClipboardKind::Password));
            engine.backend.foreign("secret");
            engine.backend.now = 250;
            engine.tick();
            assert!(failed(&mut engine));
            engine.backend.now = 30_000;
            engine.tick();
            assert_eq!(
                engine.backend.text,
                "secret".encode_utf16().chain([0]).collect::<Vec<_>>()
            );
        }
        #[test]
        fn cleanup_open_failure_retries_and_preserves_foreign_replacement() {
            let session = ClipboardSession::new();
            let mut engine = ClipboardEngine::new(Fake::default());
            engine.write(request(&session, 1, "secret", ClipboardKind::Password));
            engine.backend.now = 30_000;
            engine.backend.fail = Some("open");
            engine.tick();
            engine.backend.foreign("new");
            engine.backend.now = 30_250;
            engine.tick();
            assert_eq!(engine.backend.text, vec![110, 101, 119, 0]);
        }
        #[test]
        fn cleanup_empty_failure_is_retried_not_silently_discarded() {
            let session = ClipboardSession::new();
            let mut engine = ClipboardEngine::new(Fake::default());
            engine.write(request(&session, 1, "secret", ClipboardKind::Password));
            engine.backend.now = 30_000;
            engine.backend.fail = Some("empty");
            engine.tick();
            assert!(!engine.backend.text.is_empty());
            engine.backend.now = 30_250;
            engine.tick();
            assert!(engine.backend.text.is_empty());
        }
        #[test]
        fn debug_output_redacts_secret_payload() {
            let session = ClipboardSession::new();
            let command = request(
                &session,
                1,
                "super secret test payload",
                ClipboardKind::Password,
            );
            assert!(!format!("{command:?}").contains("super secret"));
            assert!(!format!("{session:?}").contains("super secret"));
        }

        #[test]
        fn queue_coalesces_password_and_username_in_call_order() {
            let mut queue = ClipboardQueue::default();
            let session = queue.begin();
            let mut first = request(&session, 1, "secret", ClipboardKind::Password);
            session.permit.lock().unwrap().latest_request = None;
            assert!(queue.push_copy(first, || true).is_ok());
            first = request(&session, 2, "user", ClipboardKind::Username);
            session.permit.lock().unwrap().latest_request = Some(1);
            assert!(queue.push_copy(first, || true).is_ok());
            let Some(ClipboardCommand::Copy(command)) = queue.pop() else {
                panic!("copy missing")
            };
            assert_eq!(command.kind, ClipboardKind::Username);
            assert_eq!(command.request, 2);
            assert!(queue.pop().is_none());
        }
        #[test]
        fn failed_post_withdraws_secret_and_restores_accepted_request() {
            let mut queue = ClipboardQueue::default();
            let session = queue.begin();
            let one = request(&session, 1, "first", ClipboardKind::Password);
            session.permit.lock().unwrap().latest_request = None;
            assert!(queue.push_copy(one, || true).is_ok());
            let two = request(&session, 2, "second", ClipboardKind::Password);
            session.permit.lock().unwrap().latest_request = Some(1);
            assert!(queue.push_copy(two, || false).is_err());
            let Some(ClipboardCommand::Copy(command)) = queue.pop() else {
                panic!("copy missing")
            };
            assert_eq!(&**command.text, "first");
            assert_eq!(session.permit.lock().unwrap().latest_request, Some(1));
            assert!(queue.pop().is_none());
        }
        #[test]
        fn native_revocation_wipes_queued_copy_before_notification() {
            let mut queue = ClipboardQueue::default();
            let session = queue.begin();
            let command = request(&session, 1, "secret", ClipboardKind::Password);
            session.permit.lock().unwrap().latest_request = None;
            assert!(queue.push_copy(command, || true).is_ok());
            queue.revoke_active();
            assert!(session.revoked());
            assert!(queue.pop().is_none());
        }
        #[test]
        fn cleanup_queue_coalesces_but_never_revokes_new_session() {
            let mut queue = ClipboardQueue::default();
            let old = queue.begin();
            old.revoke();
            assert!(queue.push_clear(|| true).is_ok());
            for _ in 0..100 {
                assert!(queue.push_clear(|| true).is_ok());
            }
            let new = queue.begin();
            assert!(!new.revoked());
            assert!(matches!(queue.pop(), Some(ClipboardCommand::ClearRevoked)));
            assert!(queue.pop().is_none());
        }

        #[test]
        fn failed_post_without_previous_command_leaves_no_queued_plaintext() {
            let mut queue = ClipboardQueue::default();
            let session = queue.begin();
            let command = request(&session, 1, "secret", ClipboardKind::Password);
            session.permit.lock().unwrap().latest_request = None;
            assert!(queue.push_copy(command, || false).is_err());
            assert!(queue.pop().is_none());
            assert_eq!(session.permit.lock().unwrap().latest_request, None);
        }
        #[test]
        fn foreign_replacement_after_write_close_is_never_bound() {
            let session = ClipboardSession::new();
            let mut engine = ClipboardEngine::new(Fake {
                replace_after_close: Some(1),
                ..Fake::default()
            });
            engine.write(request(&session, 1, "secret", ClipboardKind::Password));
            assert!(failed(&mut engine));
            engine.backend.now = 30_000;
            engine.tick();
            assert_eq!(
                engine.backend.text,
                "foreign".encode_utf16().chain([0]).collect::<Vec<_>>()
            );
        }
        #[test]
        fn binding_retry_exhaustion_drops_expected_secret_and_warns() {
            let session = ClipboardSession::new();
            let mut engine = ClipboardEngine::new(Fake {
                fail: Some("bind"),
                repeat_fail: true,
                ..Fake::default()
            });
            engine.write(request(&session, 1, "secret", ClipboardKind::Password));
            for step in 1..=4 {
                engine.backend.now = step * 250;
                engine.tick();
            }
            let events = engine.events();
            assert!(
                events
                    .iter()
                    .any(|event| matches!(event, SecurityEvent::ClipboardCleanupFailed))
            );
            assert!(events.iter().any(|event| matches!(
                event,
                SecurityEvent::ClipboardCopyCompleted {
                    outcome: ClipboardCopyOutcome::Failed,
                    ..
                }
            )));
            assert!(engine.pending.is_none());
            assert_eq!(engine.backend.timer, None);
        }
        #[test]
        fn zero_sequence_is_never_bound_and_failed_confirmation_rolls_back() {
            let session = ClipboardSession::new();
            let mut engine = ClipboardEngine::new(Fake {
                zero_sequence: true,
                ..Fake::default()
            });
            engine.write(request(&session, 1, "secret", ClipboardKind::Password));
            for step in 1..=4 {
                engine.backend.now = step * 250;
                engine.tick();
            }
            assert!(failed(&mut engine));
            assert!(engine.pending.is_none());
            assert!(engine.backend.text.is_empty());
        }
        #[test]
        fn timer_rearm_failure_rolls_back_and_does_not_report_copied() {
            let session = ClipboardSession::new();
            let mut engine = ClipboardEngine::new(Fake {
                fail_arm_number: Some(2),
                ..Fake::default()
            });
            engine.write(request(&session, 1, "secret", ClipboardKind::Password));
            let events = engine.events();
            assert!(!events.iter().any(|event| matches!(
                event,
                SecurityEvent::ClipboardCopyCompleted {
                    outcome: ClipboardCopyOutcome::Copied,
                    ..
                }
            )));
            assert!(events.iter().any(|event| matches!(
                event,
                SecurityEvent::ClipboardCopyCompleted {
                    outcome: ClipboardCopyOutcome::Failed,
                    ..
                }
            )));
            assert!(engine.backend.text.is_empty());
        }
        #[test]
        fn close_failure_reports_failure_and_conditionally_rolls_back() {
            let session = ClipboardSession::new();
            let mut engine = ClipboardEngine::new(Fake {
                fail: Some("close"),
                ..Fake::default()
            });
            engine.write(request(&session, 1, "secret", ClipboardKind::Password));
            assert!(failed(&mut engine));
            assert!(engine.backend.text.is_empty());
        }
        #[test]
        fn cleanup_retry_exhaustion_warns_and_stops() {
            let session = ClipboardSession::new();
            let mut engine = ClipboardEngine::new(Fake::default());
            engine.write(request(&session, 1, "secret", ClipboardKind::Password));
            engine.events();
            engine.backend.fail = Some("open");
            engine.backend.repeat_fail = true;
            for step in 0..=4 {
                engine.backend.now = 30_000 + step * 250;
                engine.tick();
            }
            assert!(
                engine
                    .events()
                    .contains(&SecurityEvent::ClipboardCleanupFailed)
            );
            assert!(engine.pending.is_none());
            assert_eq!(engine.backend.timer, None);
        }
        #[test]
        fn newer_copy_resets_old_cleanup_retry_budget() {
            let session = ClipboardSession::new();
            let mut engine = ClipboardEngine::new(Fake::default());
            engine.write(request(&session, 1, "A", ClipboardKind::Password));
            engine.backend.now = 30_000;
            engine.backend.fail = Some("open");
            engine.tick();
            engine.write(request(&session, 2, "B", ClipboardKind::Password));
            engine.backend.now = 60_000;
            engine.backend.fail = Some("open");
            engine.tick();
            assert_eq!(engine.backend.timer, Some(250));
            engine.backend.now = 60_250;
            engine.tick();
            assert!(engine.backend.text.is_empty());
        }
        #[test]
        fn shutdown_clears_exact_receipt_without_waiting_for_timer() {
            let session = ClipboardSession::new();
            let mut engine = ClipboardEngine::new(Fake::default());
            engine.write(request(&session, 1, "secret", ClipboardKind::Password));
            session.revoke();
            assert!(engine.shutdown(session.id()));
            assert!(engine.backend.text.is_empty());
        }
        #[test]
        fn shutdown_does_not_clear_foreign_or_new_session() {
            let old = ClipboardSession::new();
            let new = ClipboardSession::new();
            let mut engine = ClipboardEngine::new(Fake::default());
            engine.write(request(&old, 1, "old", ClipboardKind::Password));
            old.revoke();
            engine.write(request(&new, 1, "new", ClipboardKind::Password));
            assert!(engine.shutdown(old.id()));
            assert_eq!(engine.backend.text, vec![110, 101, 119, 0]);
            engine.backend.foreign("foreign");
            new.revoke();
            assert!(engine.shutdown(new.id()));
            assert_eq!(
                engine.backend.text,
                "foreign".encode_utf16().chain([0]).collect::<Vec<_>>()
            );
        }
        #[test]
        fn shutdown_failure_is_bounded_and_explicit() {
            let session = ClipboardSession::new();
            let mut engine = ClipboardEngine::new(Fake::default());
            engine.write(request(&session, 1, "secret", ClipboardKind::Password));
            session.revoke();
            engine.backend.fail = Some("open");
            engine.backend.repeat_fail = true;
            assert!(!engine.shutdown(session.id()));
            assert!(engine.pending.is_none());
            assert!(
                engine
                    .events()
                    .contains(&SecurityEvent::ClipboardCleanupFailed)
            );
        }
        #[test]
        fn shutdown_queue_is_bounded_and_post_failure_is_withdrawn() {
            let mut queue = ClipboardQueue::default();
            let (sender, _receiver) = std::sync::mpsc::sync_channel(1);
            assert!(queue.push_shutdown(1, sender.clone(), || false).is_err());
            assert!(queue.pop().is_none());
            for index in 0..16 {
                assert!(queue.push_shutdown(index, sender.clone(), || true).is_ok());
            }
            assert!(queue.push_shutdown(99, sender, || true).is_err());
            assert_eq!(queue.commands.len(), 16);
        }

        #[test]
        fn failed_new_post_cannot_cancel_already_popped_accepted_copy() {
            let mut queue = ClipboardQueue::default();
            let session = queue.begin();
            let one = request(&session, 1, "first", ClipboardKind::Password);
            session.permit.lock().unwrap().latest_request = None;
            queue.push_copy(one, || true).unwrap();
            let Some(ClipboardCommand::Copy(one)) = queue.pop() else {
                panic!("copy missing")
            };
            let two = request(&session, 2, "second", ClipboardKind::Password);
            session.permit.lock().unwrap().latest_request = Some(1);
            let mut engine = ClipboardEngine::new(Fake::default());
            assert!(
                queue
                    .push_copy(two, || {
                        engine.write(one);
                        false
                    })
                    .is_err()
            );
            assert!(copied(&mut engine));
            assert_eq!(
                engine.backend.text,
                "first".encode_utf16().chain([0]).collect::<Vec<_>>()
            );
        }
        #[test]
        fn slow_confirmation_past_deadline_cleans_instead_of_reporting_copied() {
            let session = ClipboardSession::new();
            let mut engine = ClipboardEngine::new(Fake {
                advance_on_match: 31_000,
                ..Fake::default()
            });
            engine.write(request(&session, 1, "secret", ClipboardKind::Password));
            assert!(!copied(&mut engine));
            assert!(engine.backend.text.is_empty());
        }
        #[test]
        fn terminal_cleanup_close_failure_is_settled_immediately() {
            let session = ClipboardSession::new();
            let mut engine = ClipboardEngine::new(Fake::default());
            engine.write(request(&session, 1, "secret", ClipboardKind::Password));
            engine.backend.now = 30_000;
            engine.backend.fail = Some("close");
            engine.tick();
            assert!(!engine.backend.opened);
            assert!(engine.backend.text.is_empty());
            assert!(
                engine
                    .events()
                    .contains(&SecurityEvent::ClipboardCleanupFailed)
            );
        }
        #[test]
        fn persistent_close_failure_fails_monitor_closed() {
            let session = ClipboardSession::new();
            let mut engine = ClipboardEngine::new(Fake::default());
            engine.write(request(&session, 1, "secret", ClipboardKind::Password));
            engine.events();
            engine.backend.now = 30_000;
            engine.backend.fail = Some("close");
            engine.backend.repeat_fail = true;
            engine.tick();
            assert!(engine.events().contains(&SecurityEvent::MonitorFailed));
            engine.backend.fail = None;
            engine.write(request(&session, 2, "new", ClipboardKind::Password));
            assert!(engine.backend.text.is_empty());
            assert!(failed(&mut engine));
        }
        #[test]
        fn native_reentrant_revocation_does_not_lock_the_write_gate() {
            let session = ClipboardSession::new();
            let gate = session.permit.lock().unwrap();
            session.revoke_native();
            drop(gate);
            assert!(session.revoked());
        }
        #[test]
        fn reentrant_native_lock_during_empty_cancels_password_transfer() {
            let session = ClipboardSession::new();
            let mut engine = ClipboardEngine::new(Fake {
                revoke_on_empty: Some(session.clone()),
                ..Fake::default()
            });
            engine.write(request(&session, 1, "secret", ClipboardKind::Password));
            assert!(engine.backend.text.is_empty());
            assert!(!copied(&mut engine));
        }
        #[test]
        fn stop_revokes_and_cleans_owned_receipt() {
            let session = ClipboardSession::new();
            let mut engine = ClipboardEngine::new(Fake::default());
            engine.write(request(&session, 1, "secret", ClipboardKind::Password));
            engine.stop();
            assert!(session.revoked());
            assert!(engine.backend.text.is_empty());
        }

        #[test]
        fn global_shutdown_covers_old_receipt_after_multiple_empty_unlocks() {
            let mut queue = ClipboardQueue::default();
            let old = queue.begin();
            let mut engine = ClipboardEngine::new(Fake::default());
            engine.write(request(&old, 1, "secret", ClipboardKind::Password));
            old.revoke();
            let middle = queue.begin();
            middle.revoke();
            let current = queue.begin();
            queue.revoke_active();
            assert!(current.revoked());
            let (sender, receiver) = std::sync::mpsc::sync_channel(1);
            queue.push_stop(sender, || true).unwrap();
            assert!(queue.has_work());
            let Some(ClipboardCommand::Stop { done }) = queue.pop() else {
                panic!("stop missing")
            };
            engine.stop();
            done.try_send(engine.pending.is_none()).unwrap();
            assert!(receiver.try_recv().unwrap());
            assert!(engine.backend.text.is_empty());
        }
        #[test]
        fn native_revocation_purges_queue_without_waiting_on_gate() {
            let mut queue = ClipboardQueue::default();
            let session = queue.begin();
            let command = request(&session, 1, "secret", ClipboardKind::Password);
            session.permit.lock().unwrap().latest_request = None;
            queue.push_copy(command, || true).unwrap();
            let gate = session.permit.lock().unwrap();
            queue.revoke_active_native();
            drop(gate);
            assert!(session.revoked());
            assert!(!queue.has_work());
        }
        #[test]
        fn shutdown_barrier_reports_only_requested_session() {
            let mut queue = ClipboardQueue::default();
            let (sender, receiver) = std::sync::mpsc::sync_channel(1);
            queue.push_shutdown(42, sender, || true).unwrap();
            let Some(ClipboardCommand::Shutdown { session, done }) = queue.pop() else {
                panic!("shutdown missing")
            };
            assert_eq!(session, 42);
            done.try_send(true).unwrap();
            assert!(receiver.try_recv().unwrap());
        }

        #[test]
        fn global_shutdown_enqueue_never_waits_on_native_write_gate() {
            let mut queue = ClipboardQueue::default();
            let session = queue.begin();
            let gate = session.permit.lock().unwrap();
            let (started_sender, started) = std::sync::mpsc::sync_channel(1);
            let (finished_sender, finished) = std::sync::mpsc::sync_channel(1);
            let worker = std::thread::spawn(move || {
                let (done, _) = std::sync::mpsc::sync_channel(1);
                started_sender.send(()).unwrap();
                let result = queue.push_stop(done, || true);
                finished_sender.send(result).unwrap();
            });
            started.recv().unwrap();
            let result = finished.recv_timeout(std::time::Duration::from_secs(1));
            drop(gate);
            worker.join().unwrap();
            assert_eq!(result, Ok(Ok(())));
            assert!(session.revoked());
        }

        #[test]
        fn ui_revocation_does_not_wait_for_blocked_foreign_owner_notification() {
            let session = ClipboardSession::new();
            let command = request(&session, 1, "secret", ClipboardKind::Password);
            let (entered_sender, entered) = std::sync::mpsc::sync_channel(1);
            let (resume_sender, resume) = std::sync::mpsc::sync_channel(1);
            let worker = std::thread::spawn(move || {
                let mut engine = ClipboardEngine::new(Fake {
                    block_empty: Some((entered_sender, resume)),
                    ..Fake::default()
                });
                engine.write(command);
                engine
            });
            entered.recv().unwrap();
            let (revoked_sender, revoked) = std::sync::mpsc::sync_channel(1);
            let token = session.clone();
            let revoker = std::thread::spawn(move || {
                token.revoke();
                revoked_sender.send(()).unwrap();
            });
            let prompt = revoked.recv_timeout(std::time::Duration::from_secs(1));
            resume_sender.send(()).unwrap();
            let engine = worker.join().unwrap();
            revoker.join().unwrap();
            assert_eq!(prompt, Ok(()));
            assert!(engine.backend.text.is_empty());
        }

        #[test]
        fn changed_sequence_with_our_marker_warns_without_adopting_or_clearing() {
            let session = ClipboardSession::new();
            let mut engine = ClipboardEngine::new(Fake::default());
            engine.write(request(&session, 1, "secret", ClipboardKind::Password));
            engine.events();
            engine.backend.seq += 1;
            engine.backend.now = 30_000;
            engine.tick();
            assert!(!engine.backend.text.is_empty());
            assert!(
                engine
                    .events()
                    .contains(&SecurityEvent::ClipboardCleanupFailed)
            );
            assert!(engine.pending.is_none());
        }
        #[test]
        fn unavailable_sequence_during_cleanup_retries_then_warns() {
            let session = ClipboardSession::new();
            let mut engine = ClipboardEngine::new(Fake::default());
            engine.write(request(&session, 1, "secret", ClipboardKind::Password));
            engine.events();
            engine.backend.zero_sequence = true;
            engine.backend.now = 30_000;
            engine.tick();
            assert_eq!(engine.backend.timer, Some(250));
            for step in 1..=4 {
                engine.backend.now = 30_000 + step * 250;
                engine.tick();
            }
            assert!(
                engine
                    .events()
                    .contains(&SecurityEvent::ClipboardCleanupFailed)
            );
            assert!(!engine.backend.text.is_empty());
            assert!(engine.pending.is_none());
        }
        #[test]
        fn unavailable_sequence_makes_shutdown_report_failure() {
            let session = ClipboardSession::new();
            let mut engine = ClipboardEngine::new(Fake::default());
            engine.write(request(&session, 1, "secret", ClipboardKind::Password));
            engine.backend.zero_sequence = true;
            session.revoke();
            assert!(!engine.shutdown(session.id()));
            assert!(!engine.backend.text.is_empty());
            assert!(
                engine
                    .events()
                    .contains(&SecurityEvent::ClipboardCleanupFailed)
            );
        }
    }
}
#[cfg(windows)]
pub(super) use owner::*;
