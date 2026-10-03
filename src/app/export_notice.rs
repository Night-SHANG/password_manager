//! Residual plaintext risk lives outside session, Settings and ordinary status.
use super::*;
use crate::export::{ExportFailure, OutputDisposition};

pub(super) struct ExportNotice {
    pub generation: u64,
    pub failure: ExportFailure,
}
#[derive(Clone, Copy)]
pub(super) struct ExportClosePrompt {
    pub window: iced::window::Id,
    pub notice_generation: u64,
    pub request: u64,
}
impl App {
    pub(super) fn finish_plaintext_export(&mut self, result: Result<usize>) {
        self.status = match result {
            Ok(count) => format!("已导出 {count} 条到明文 CSV，请妥善保护导出文件"),
            Err(AppError::Export(failure))
                if matches!(failure.output, OutputDisposition::MayRemain { .. }) =>
            {
                self.export_notice_generation = self.export_notice_generation.wrapping_add(1);
                self.export_notice = Some(ExportNotice {
                    generation: self.export_notice_generation,
                    failure: *failure,
                });
                "导出未确认成功；请查看可能残留的明文文件提示".into()
            }
            Err(error) => format!("导出失败：{error}"),
        };
    }
    pub(super) fn acknowledge_export(&mut self, generation: u64) {
        if self.export_close_prompt.is_none()
            && self
                .export_notice
                .as_ref()
                .is_some_and(|notice| notice.generation == generation)
        {
            self.export_notice = None;
            self.status = "已确认可能残留的明文风险；软件未验证文件已删除".into();
        }
    }
    pub(super) fn request_close(&mut self, window: iced::window::Id) -> Task<Message> {
        if self.closing {
            return Task::none();
        }
        self.operations
            .authority
            .observe_close(std::time::Instant::now());
        self.operations.close_window = Some(window);
        self.operations.close_notice_seen = (self.operations.failure_notice.is_some()
            || self.recovery_notice.is_some())
        .then_some(self.operations.encrypted_notice_generation);
        self.mask_for_operation_lock("正在退出", false);
        self.advance_close();
        self.operations.task.take().unwrap_or_else(Task::none)
    }
    pub(super) fn advance_close(&mut self) {
        let Some(window) = self.operations.close_window else {
            return;
        };
        if self.closing || self.operations.shutdown_started {
            return;
        }
        if !self.close_ready(window) {
            return;
        }
        self.operations.shutdown_started = true;
        let (sender, receiver) = iced::futures::channel::oneshot::channel();
        let spawned = std::thread::Builder::new()
            .name("password-manager-clipboard-shutdown".into())
            .spawn(move || {
                let result = platform::shutdown_clipboard().is_ok();
                let _ = sender.send(result);
            });
        if spawned.is_err() {
            self.operations.shutdown_started = false;
            self.operations
                .note_failure("无法启动退出清理；窗口保持打开".into());
            return;
        }
        self.operations.task = Some(Task::perform(
            async move { (window, receiver.await.unwrap_or(false)) },
            |(window, ok)| Message::ClipboardShutdownFinished(window, ok),
        ));
    }
    fn close_ready(&mut self, window: iced::window::Id) -> bool {
        if !self
            .operations
            .authority
            .snapshot(std::time::Instant::now())
            .fully_locked
            // Cleanup alone is insufficient: the retained terminal may still
            // carry a late plaintext or encrypted-file risk notification.
            || self.operations.active.is_some()
            || self.picker_pending.is_some()
            || self.operations.launch_retired.is_some()
            || self.operations.failed_input.is_some()
        {
            return false;
        }
        if (self.operations.failure_notice.is_some() || self.recovery_notice.is_some())
            && self.operations.close_notice_seen
                != Some(self.operations.encrypted_notice_generation)
        {
            self.operations.close_window = None;
            self.status = "后台操作留下未确认结果，请检查恢复提示后再退出".into();
            let _ = self
                .operations
                .authority
                .resume_locked_after_keep_open(std::time::Instant::now());
            return false;
        }
        if let Some(notice) = &self.export_notice
            && self.operations.close_confirmed != Some(notice.generation)
        {
            if self.export_close_prompt.is_none_or(|prompt| {
                prompt.notice_generation != notice.generation || prompt.window != window
            }) {
                self.export_close_sequence = self.export_close_sequence.wrapping_add(1);
                self.export_close_prompt = Some(ExportClosePrompt {
                    window,
                    notice_generation: notice.generation,
                    request: self.export_close_sequence,
                });
            }
            return false;
        }
        true
    }
    pub(super) fn finish_clipboard_shutdown(
        &mut self,
        window: iced::window::Id,
        ok: bool,
    ) -> Task<Message> {
        if !self.operations.shutdown_started || self.operations.close_window != Some(window) {
            return Task::none();
        }
        self.operations.shutdown_started = false;
        if !ok {
            self.clipboard_cleanup_failed = true;
        }
        // Recheck the exact current notices at the final irreversible action,
        // not just when asynchronous clipboard cleanup was started.
        if !self.close_ready(window) {
            return Task::none();
        }
        self.closing = true;
        iced::window::close(window)
    }
    pub(super) fn keep_open(&mut self, request: u64) {
        if self
            .export_close_prompt
            .is_some_and(|prompt| prompt.request == request)
        {
            self.export_close_prompt = None;
            self.operations.close_window = None;
            self.operations.close_confirmed = None;
            let _ = self
                .operations
                .authority
                .resume_locked_after_keep_open(std::time::Instant::now());
        }
    }
    pub(super) fn confirm_export_exit(&mut self, request: u64, generation: u64) -> Task<Message> {
        let Some(prompt) = self.export_close_prompt else {
            return Task::none();
        };
        if self.operations.close_window != Some(prompt.window)
            || prompt.request != request
            || prompt.notice_generation != generation
            || !self
                .export_notice
                .as_ref()
                .is_some_and(|notice| notice.generation == generation)
        {
            return Task::none();
        }
        self.operations.close_confirmed = Some(generation);
        self.export_close_prompt = None;
        self.advance_close();
        self.operations.task.take().unwrap_or_else(Task::none)
    }
}

#[cfg(test)]
mod tests {
    use super::super::tests::fixture;
    use super::*;
    use crate::export::{Cause, Observation, ObservedTarget, Stage};

    fn failed_app() -> (tempfile::TempDir, App, std::path::PathBuf) {
        let (dir, mut app) = fixture(2);
        let target = dir.path().join("残留-明文.csv");
        let before = std::fs::read(app.session.as_ref().unwrap().path()).unwrap();
        app.session.as_mut().unwrap().body_mut().entries[1]
            .secret
            .ciphertext
            .clear();
        let body = serde_json::to_vec(app.session.as_ref().unwrap().body()).unwrap();
        let _ = app.test_update(Message::OpenSettings);
        let _ = app.test_update(Message::CsvPathChanged(target.display().to_string()));
        let _ = app.test_update(Message::ConfirmPlaintextChanged(true));
        let _ = app.test_update(Message::ExportPlaintextCsv);
        let notice = app
            .export_notice
            .as_ref()
            .expect("handler must install risk notice");
        assert_eq!(notice.failure.target, target);
        assert_eq!(notice.failure.stage, Stage::RevealEntry);
        assert_eq!(
            before,
            std::fs::read(app.session.as_ref().unwrap().path()).unwrap()
        );
        assert_eq!(
            body,
            serde_json::to_vec(app.session.as_ref().unwrap().body()).unwrap()
        );
        assert!(target.exists());
        (dir, app, target)
    }
    fn synthetic_notice(app: &mut App, target: std::path::PathBuf) {
        app.finish_plaintext_export(Err(AppError::Export(Box::new(ExportFailure {
            target,
            stage: Stage::IdentifyOutput,
            cause: Cause::Io {
                kind: std::io::ErrorKind::PermissionDenied,
                code: None,
            },
            output: OutputDisposition::MayRemain {
                observation: Observation {
                    target: ObservedTarget::Unobserved,
                    error: None,
                },
            },
        }))));
    }
    #[test]
    fn clipboard_shutdown_completion_rechecks_current_notice_before_exit() {
        let mut app = App::initial();
        let window = iced::window::Id::unique();
        let shutdown = app.update(Message::CloseRequested(window));
        assert!(app.operations.shutdown_started);
        synthetic_notice(&mut app, std::path::PathBuf::from("synthetic-late.csv"));
        let effects = super::super::tests::drain_task(&mut app, shutdown);
        assert!(
            !effects.closes(window),
            "a newly installed warning must be checked at final close completion"
        );
        assert!(app.export_close_prompt.is_some());
    }
    #[test]
    fn export_notice_survives_navigation_path_changes_picker_and_status() {
        let (dir, mut app, target) = failed_app();
        let generation = app.export_notice.as_ref().unwrap().generation;
        for message in [
            Message::CancelPanel,
            Message::OpenSettings,
            Message::CsvPathChanged(dir.path().join("other.csv").display().to_string()),
            Message::ConfirmPlaintextChanged(true),
        ] {
            let _ = app.test_update(message);
            assert_eq!(app.export_notice.as_ref().unwrap().generation, generation);
        }
        let _ = app.test_update(Message::PickPath(picker::Purpose::Csv));
        let _ = app.test_update(Message::PathPicked(app.picker_sequence, Ok(None)));
        app.status = "unrelated ordinary status".into();
        app.note_clipboard_cleanup_failure();
        let _ = app.test_update(Message::ExportPlaintextCsv);
        assert!(!dir.path().join("other.csv").exists());
        assert_eq!(app.export_notice.as_ref().unwrap().failure.target, target);
        let _ = app.test_update(Message::Lock);
        let after_lock = app.operations.authority.snapshot(std::time::Instant::now());
        let _ = app.test_update(Message::OpenRecovery);
        assert!(
            app.recovery.is_some(),
            "inspection did not return; after_lock={after_lock:?}; after_inspection={:?}; active={:?}; retired_pending={}",
            app.operations.authority.snapshot(std::time::Instant::now()),
            app.operations.active.as_ref().map(|a| (a.id, a.finished)),
            app.operations.launch_retired.is_some()
        );
        let recovery_generation = app.recovery.as_ref().unwrap().generation;
        let _ = app.test_update(Message::CloseRecovery(recovery_generation));
        app.session = Some(
            VaultSession::create(dir.path().join("another.pmvault"), "synthetic-master").unwrap(),
        );
        app.reset_unlocked_state();
        assert_eq!(app.export_notice.as_ref().unwrap().generation, generation);
    }
    #[test]
    fn export_notice_survives_manual_idle_and_native_security_locks() {
        let (_dir, mut app, _) = failed_app();
        let generation = app.export_notice.as_ref().unwrap().generation;
        let vault_path = app.session.as_ref().unwrap().path().to_path_buf();
        let _ = app.test_update(Message::SecurityTick(
            std::time::Instant::now() + std::time::Duration::from_secs(3600),
        ));
        assert!(app.session.is_none());
        for message in [
            Message::Lock,
            Message::PlatformSecurity(SecurityEvent::SessionLocked),
            Message::PlatformSecurity(SecurityEvent::SessionLoggedOff),
            Message::PlatformSecurity(SecurityEvent::SystemSuspending),
            Message::PlatformSecurity(SecurityEvent::MonitorFailed),
        ] {
            app.session =
                Some(VaultSession::open(&vault_path, "gui-synthetic-master-only").unwrap());
            app.reset_unlocked_state();
            let _ = app.test_update(message);
            assert!(app.session.is_none());
            assert_eq!(app.export_notice.as_ref().unwrap().generation, generation);
        }
    }
    #[test]
    fn export_notice_acknowledgment_is_current_generation_only() {
        let (dir, mut app, _) = failed_app();
        let old = app.export_notice.as_ref().unwrap().generation;
        let _ = app.test_update(Message::AcknowledgeExportNotice(old + 1));
        assert!(app.export_notice.is_some());
        let _ = app.test_update(Message::AcknowledgeExportNotice(old));
        assert!(app.export_notice.is_none());
        synthetic_notice(&mut app, dir.path().join("empty-output.csv"));
        let new = app.export_notice.as_ref().unwrap().generation;
        assert_ne!(old, new);
        let _ = app.test_update(Message::AcknowledgeExportNotice(old));
        assert!(app.export_notice.is_some());
        let _ = app.test_update(Message::AcknowledgeExportNotice(new));
        assert!(app.export_notice.is_none());
    }
    #[test]
    fn export_close_guard_masks_and_binds_exit_to_prompt_and_notice() {
        let (dir, mut app, _) = failed_app();
        let window = iced::window::Id::unique();
        assert_eq!(app.test_update(Message::CloseRequested(window)).units(), 0);
        assert!(app.session.is_none());
        let prompt = app.export_close_prompt.unwrap();
        let _ = app.test_update(Message::AcknowledgeExportNotice(prompt.notice_generation));
        assert!(app.export_notice.is_some());
        let _ = app.test_update(Message::OpenVault);
        assert!(app.session.is_none());
        assert_eq!(
            app.test_update(Message::ConfirmExportExit(
                prompt.request + 1,
                prompt.notice_generation
            ))
            .units(),
            0
        );
        let _ = app.test_update(Message::KeepOpen(prompt.request));
        assert!(app.export_close_prompt.is_none());
        assert!(app.export_notice.is_some());
        assert_eq!(
            app.test_update(Message::ConfirmExportExit(
                prompt.request,
                prompt.notice_generation
            ))
            .units(),
            0
        );
        let _ = app.test_update(Message::CloseRequested(window));
        let current = app.export_close_prompt.unwrap();
        assert_eq!(
            app.test_update(Message::ConfirmExportExit(
                prompt.request,
                prompt.notice_generation
            ))
            .units(),
            0
        );
        // A later outcome would make an already displayed close confirmation stale.
        synthetic_notice(&mut app, dir.path().join("later.csv"));
        assert_eq!(
            app.test_update(Message::ConfirmExportExit(
                current.request,
                current.notice_generation
            ))
            .units(),
            0
        );
        let _ = app.test_update(Message::CloseRequested(window));
        let latest = app.export_close_prompt.unwrap();
        assert!(
            app.test_update(Message::ConfirmExportExit(
                latest.request,
                latest.notice_generation
            ))
            .closes(window),
            "only the current warning may issue the deferred close action"
        );
        assert_eq!(
            app.test_update(Message::ConfirmExportExit(
                latest.request,
                latest.notice_generation
            ))
            .units(),
            0
        );
        assert!(app.export_notice.is_some());
    }
    #[test]
    fn export_close_prompt_drains_invalidated_picker_and_security_completion() {
        let (_dir, mut app, _) = failed_app();
        let _ = app.test_update(Message::PickPath(picker::Purpose::Csv));
        let picker_id = app.picker_pending.unwrap().id;
        app.screen_capture_protection_active = true;
        let _ = app.test_update(Message::CloseRequested(iced::window::Id::unique()));
        assert!(app.picker_pending.is_some());
        let notice_generation = app.export_notice.as_ref().unwrap().generation;
        let _ = app.test_update(Message::PathPicked(
            picker_id,
            Ok(Some("must-not-adopt.csv".into())),
        ));
        assert!(
            app.picker_pending.is_none(),
            "close warning must drain invalidated picker completion"
        );
        let _ = app.test_update(Message::ScreenCaptureProtectionApplied(Ok(false)));
        assert!(
            !app.screen_capture_protection_active,
            "completed OS setting must not leave stale protection status"
        );
        assert!(app.session.is_none());
        assert_eq!(
            app.export_notice.as_ref().unwrap().generation,
            notice_generation
        );
        let prompt = app.export_close_prompt.unwrap();
        let _ = app.test_update(Message::KeepOpen(prompt.request));
        let _ = app.test_update(Message::ToggleAuthOptions);
        let _ = app.test_update(Message::PickPath(picker::Purpose::OpenVault));
        assert!(
            app.picker_pending.is_some(),
            "picker can be used again after Keep open"
        );
    }

    #[test]
    fn export_close_prompt_accepts_security_setting_completion_without_unlocking() {
        let (_dir, mut app, _) = failed_app();
        app.screen_capture_protection_active = true;
        app.screen_capture_protection_requested = false;
        let _ = app.test_update(Message::CloseRequested(iced::window::Id::unique()));
        let _ = app.test_update(Message::ScreenCaptureProtectionApplied(Ok(false)));
        assert!(!app.screen_capture_protection_active);
        assert!(!app.screen_capture_protection_requested);
        assert!(app.session.is_none());
        assert!(app.export_notice.is_some());
        assert!(app.export_close_prompt.is_some());
    }

    #[test]
    fn export_close_prompt_accepts_only_current_clipboard_acknowledgment() {
        let (_dir, mut app, _) = failed_app();
        app.note_clipboard_cleanup_failure();
        let _ = app.test_update(Message::CloseRequested(iced::window::Id::unique()));
        // Close revokes the native clipboard permit. That can itself produce a
        // newer cleanup warning (for example without a Windows monitor in CI).
        // Use the token the close view actually renders, not a pre-close token.
        let clipboard_generation = app.clipboard_warning_generation;
        let _ = app.test_update(Message::AcknowledgeClipboardCleanup(
            clipboard_generation.wrapping_sub(1),
        ));
        assert!(app.clipboard_cleanup_failed);
        let _ = app.test_update(Message::AcknowledgeClipboardCleanup(clipboard_generation));
        assert!(
            !app.clipboard_cleanup_failed,
            "rendered clipboard acknowledgment must work during close warning"
        );
        assert!(app.export_notice.is_some());
        assert!(app.export_close_prompt.is_some());
        assert!(app.session.is_none());
    }

    #[test]
    fn export_close_prompt_rejects_clipboard_ack_after_a_new_native_failure() {
        let (_dir, mut app, _) = failed_app();
        app.note_clipboard_cleanup_failure();
        let _ = app.test_update(Message::CloseRequested(iced::window::Id::unique()));
        let rendered_generation = app.clipboard_warning_generation;
        let notice_generation = app.export_notice.as_ref().unwrap().generation;
        // Deterministic delivery of a later native failure on every platform.
        let _ = app.test_update(Message::PlatformSecurity(
            SecurityEvent::ClipboardCleanupFailed,
        ));
        let current_generation = app.clipboard_warning_generation;
        assert_ne!(current_generation, rendered_generation);
        let _ = app.test_update(Message::AcknowledgeClipboardCleanup(rendered_generation));
        assert!(
            app.clipboard_cleanup_failed,
            "old rendered acknowledgment cannot dismiss a new warning"
        );
        let _ = app.test_update(Message::AcknowledgeClipboardCleanup(current_generation));
        assert!(!app.clipboard_cleanup_failed);
        assert_eq!(
            app.export_notice.as_ref().unwrap().generation,
            notice_generation
        );
        assert!(app.export_close_prompt.is_some());
        assert!(app.session.is_none());
    }

    #[test]
    fn export_close_without_notice_revokes_same_batch_export_admission() {
        let (dir, mut app) = fixture(2);
        app.session.as_mut().unwrap().body_mut().entries[1]
            .secret
            .ciphertext
            .clear();
        let target = dir.path().join("must-not-export-after-close.csv");
        let _ = app.test_update(Message::OpenSettings);
        let _ = app.test_update(Message::CsvPathChanged(target.display().to_string()));
        let _ = app.test_update(Message::ConfirmPlaintextChanged(true));
        assert!(
            app.test_update(Message::CloseRequested(iced::window::Id::unique()))
                .units()
                > 0
        );
        let _ = app.test_update(Message::ExportPlaintextCsv);
        assert!(
            !target.exists(),
            "queued export after close intent must not begin"
        );
        assert!(
            app.session.is_none(),
            "normal close must revoke the session before issuing close action"
        );
        assert!(app.export_notice.is_none());
    }

    #[test]
    fn export_both_final_close_paths_block_queued_unlock_and_duplicate_close() {
        for notice in [false, true] {
            let (dir, mut app) = fixture(0);
            app.security_monitor_ready = true;
            if notice {
                synthetic_notice(&mut app, dir.path().join("residual.csv"));
            }
            let window = iced::window::Id::unique();
            let first_close = app.test_update(Message::CloseRequested(window));
            if notice {
                assert_eq!(first_close.units(), 0);
                let prompt = app.export_close_prompt.unwrap();
                assert!(
                    app.test_update(Message::ConfirmExportExit(
                        prompt.request,
                        prompt.notice_generation
                    ))
                    .closes(window)
                );
            } else {
                assert!(first_close.closes(window));
            }
            let _ = app.test_update(Message::AuthMode(false));
            let _ = app.test_update(Message::MasterPasswordChanged(
                "gui-synthetic-master-only".into(),
            ));
            let _ = app.test_update(Message::OpenVault);
            assert!(
                app.session.is_none(),
                "final closing must not permit a new unlock"
            );
            assert!(app.master_password.is_empty());
            assert_eq!(
                app.test_update(Message::CloseRequested(window)).units(),
                0,
                "only one final close action"
            );
        }
    }

    #[test]
    fn export_normal_close_and_success_do_not_install_false_failure_notice() {
        let (dir, mut app) = fixture(0);
        let target = dir.path().join("empty.csv");
        let _ = app.test_update(Message::OpenSettings);
        let _ = app.test_update(Message::CsvPathChanged(target.display().to_string()));
        let _ = app.test_update(Message::ConfirmPlaintextChanged(true));
        let _ = app.test_update(Message::ExportPlaintextCsv);
        assert!(app.export_notice.is_none());
        assert!(app.status.contains("已导出 0 条"));
        assert_eq!(
            std::fs::read(target).unwrap(),
            b"name,url,username,password,category,notes\n"
        );
        assert!(
            app.test_update(Message::CloseRequested(iced::window::Id::unique()))
                .units()
                > 0
        );
    }
    #[test]
    fn export_admission_requires_settings_live_session_checkbox_and_no_picker() {
        let (dir, mut app) = fixture(0);
        let target = dir.path().join("blocked.csv");
        let _ = app.test_update(Message::ExportPlaintextCsv);
        assert!(!target.exists());
        let _ = app.test_update(Message::OpenSettings);
        let _ = app.test_update(Message::CsvPathChanged(target.display().to_string()));
        let _ = app.test_update(Message::ExportPlaintextCsv);
        assert!(!target.exists());
        let _ = app.test_update(Message::ConfirmPlaintextChanged(true));
        let _ = app.test_update(Message::PickPath(picker::Purpose::Csv));
        let _ = app.test_update(Message::ExportPlaintextCsv);
        assert!(!target.exists());
        let _ = app.test_update(Message::PathPicked(
            app.picker_sequence,
            Ok(Some(target.clone())),
        ));
        assert!(matches!(&app.panel,Panel::Settings(s) if !s.confirm_plaintext));
        let _ = app.test_update(Message::ConfirmPlaintextChanged(true));
        let _ = app.test_update(Message::CsvPathChanged(target.display().to_string()));
        assert!(matches!(&app.panel,Panel::Settings(s) if !s.confirm_plaintext));
        let _ = app.test_update(Message::ConfirmPlaintextChanged(true));
        let _ = app.test_update(Message::CancelPanel);
        let _ = app.test_update(Message::ExportPlaintextCsv);
        assert!(!target.exists());
        let _ = app.test_update(Message::OpenSettings);
        let _ = app.test_update(Message::CsvPathChanged(target.display().to_string()));
        let _ = app.test_update(Message::ConfirmPlaintextChanged(true));
        let _ = app.test_update(Message::Lock);
        let _ = app.test_update(Message::ExportPlaintextCsv);
        assert!(!target.exists());
    }
}

#[cfg(test)]
mod asynchronous_tests {
    use super::*;

    #[test]
    fn asynchronous_export_processes_lock_before_io_finishes() {
        use super::super::tests::{drain_task, fixture};
        use std::sync::mpsc;

        let (dir, mut app) = fixture(0);
        let target = dir.path().join("blocked.csv");
        app.test_update(Message::OpenSettings);
        app.test_update(Message::CsvPathChanged(target.display().to_string()));
        app.test_update(Message::ConfirmPlaintextChanged(true));
        let (entered_send, entered_recv) = mpsc::channel();
        let (release_send, release_recv) = mpsc::channel();
        crate::export::tests::set_worker_after_create(move || {
            entered_send.send(()).unwrap();
            release_recv.recv().unwrap();
        });
        // The observer remains alive while the real named worker is held after
        // output creation. The update handler has already returned to the UI.
        let export_task = app.update(Message::ExportPlaintextCsv);
        assert!(export_task.units() > 0);
        assert!(app.session.is_none(), "worker leases the live session");
        entered_recv.recv().unwrap();
        assert!(target.exists(), "real export reached its create boundary");
        let lock_task = app.update(Message::Lock);
        assert!(
            app.session.is_none(),
            "queued lock is processed during worker I/O"
        );
        assert!(matches!(app.panel, Panel::Vault));
        let masked = app.operations.authority.snapshot(std::time::Instant::now());
        assert!(masked.masked);
        assert!(
            masked.occupied.is_some(),
            "cleanup has not been acknowledged"
        );
        let premature_locked_claim = app.status.contains("保险库已锁定");
        assert!(!app.status.contains("已导出"));
        release_send.send(()).unwrap();
        let effects = drain_task(&mut app, Task::batch([export_task, lock_task]));
        assert!(
            !premature_locked_claim,
            "masked finishing text must not claim full lock before worker cleanup"
        );
        assert_eq!(effects.units(), 0, "lock does not close the window");
        assert!(
            app.session.is_none(),
            "late completion cannot resurrect a locked session"
        );
        assert!(
            app.operations
                .authority
                .snapshot(std::time::Instant::now())
                .occupied
                .is_none()
        );
        assert!(matches!(
            app.operations.session,
            operations::SessionUi::Locked
        ));
        assert_eq!(
            std::fs::read(target).unwrap(),
            b"name,url,username,password,category,notes\n"
        );
    }
}
