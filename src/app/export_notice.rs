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
        let Some(notice) = &self.export_notice else {
            return self.begin_final_close(window);
        };
        let generation = notice.generation;
        self.lock_with_status("已锁定；退出前请确认可能残留的明文文件风险");
        self.export_close_sequence = self.export_close_sequence.wrapping_add(1);
        self.export_close_prompt = Some(ExportClosePrompt {
            window,
            notice_generation: generation,
            request: self.export_close_sequence,
        });
        Task::none()
    }
    pub(super) fn keep_open(&mut self, request: u64) {
        if self
            .export_close_prompt
            .is_some_and(|prompt| prompt.request == request)
        {
            self.export_close_prompt = None;
        }
    }
    pub(super) fn confirm_export_exit(&mut self, request: u64, generation: u64) -> Task<Message> {
        let Some(prompt) = self.export_close_prompt else {
            return Task::none();
        };
        if prompt.request != request
            || prompt.notice_generation != generation
            || !self
                .export_notice
                .as_ref()
                .is_some_and(|notice| notice.generation == generation)
        {
            return Task::none();
        }
        self.export_close_prompt = None;
        // Keep the notice. This confirms awareness, never file removal. The
        // window's normal final close still runs App Drop/clipboard shutdown.
        self.begin_final_close(prompt.window)
    }
    fn begin_final_close(&mut self, window: iced::window::Id) -> Task<Message> {
        self.closing = true;
        self.lock_with_status("正在退出，保险库已锁定");
        iced::window::close(window)
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
        let _ = app.update(Message::OpenSettings);
        let _ = app.update(Message::CsvPathChanged(target.display().to_string()));
        let _ = app.update(Message::ConfirmPlaintextChanged(true));
        let _ = app.update(Message::ExportPlaintextCsv);
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
    fn export_notice_survives_navigation_path_changes_picker_and_status() {
        let (dir, mut app, target) = failed_app();
        let generation = app.export_notice.as_ref().unwrap().generation;
        for message in [
            Message::CancelPanel,
            Message::OpenSettings,
            Message::CsvPathChanged(dir.path().join("other.csv").display().to_string()),
            Message::ConfirmPlaintextChanged(true),
        ] {
            let _ = app.update(message);
            assert_eq!(app.export_notice.as_ref().unwrap().generation, generation);
        }
        let _ = app.update(Message::PickPath(picker::Purpose::Csv));
        let _ = app.update(Message::PathPicked(app.picker_sequence, Ok(None)));
        app.status = "unrelated ordinary status".into();
        app.note_clipboard_cleanup_failure();
        let _ = app.update(Message::ExportPlaintextCsv);
        assert!(!dir.path().join("other.csv").exists());
        assert_eq!(app.export_notice.as_ref().unwrap().failure.target, target);
        let _ = app.update(Message::Lock);
        let _ = app.update(Message::OpenRecovery);
        let recovery_generation = app.recovery.as_ref().unwrap().generation;
        let _ = app.update(Message::CloseRecovery(recovery_generation));
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
        let _ = app.update(Message::SecurityTick(
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
            let _ = app.update(message);
            assert!(app.session.is_none());
            assert_eq!(app.export_notice.as_ref().unwrap().generation, generation);
        }
    }
    #[test]
    fn export_notice_acknowledgment_is_current_generation_only() {
        let (dir, mut app, _) = failed_app();
        let old = app.export_notice.as_ref().unwrap().generation;
        let _ = app.update(Message::AcknowledgeExportNotice(old + 1));
        assert!(app.export_notice.is_some());
        let _ = app.update(Message::AcknowledgeExportNotice(old));
        assert!(app.export_notice.is_none());
        synthetic_notice(&mut app, dir.path().join("empty-output.csv"));
        let new = app.export_notice.as_ref().unwrap().generation;
        assert_ne!(old, new);
        let _ = app.update(Message::AcknowledgeExportNotice(old));
        assert!(app.export_notice.is_some());
        let _ = app.update(Message::AcknowledgeExportNotice(new));
        assert!(app.export_notice.is_none());
    }
    #[test]
    fn export_close_guard_masks_and_binds_exit_to_prompt_and_notice() {
        let (dir, mut app, _) = failed_app();
        let window = iced::window::Id::unique();
        assert_eq!(app.update(Message::CloseRequested(window)).units(), 0);
        assert!(app.session.is_none());
        let prompt = app.export_close_prompt.unwrap();
        let _ = app.update(Message::AcknowledgeExportNotice(prompt.notice_generation));
        assert!(app.export_notice.is_some());
        let _ = app.update(Message::OpenVault);
        assert!(app.session.is_none());
        assert_eq!(
            app.update(Message::ConfirmExportExit(
                prompt.request + 1,
                prompt.notice_generation
            ))
            .units(),
            0
        );
        let _ = app.update(Message::KeepOpen(prompt.request));
        assert!(app.export_close_prompt.is_none());
        assert!(app.export_notice.is_some());
        assert_eq!(
            app.update(Message::ConfirmExportExit(
                prompt.request,
                prompt.notice_generation
            ))
            .units(),
            0
        );
        let _ = app.update(Message::CloseRequested(window));
        let current = app.export_close_prompt.unwrap();
        assert_eq!(
            app.update(Message::ConfirmExportExit(
                prompt.request,
                prompt.notice_generation
            ))
            .units(),
            0
        );
        // A later outcome would make an already displayed close confirmation stale.
        synthetic_notice(&mut app, dir.path().join("later.csv"));
        assert_eq!(
            app.update(Message::ConfirmExportExit(
                current.request,
                current.notice_generation
            ))
            .units(),
            0
        );
        let _ = app.update(Message::CloseRequested(window));
        let latest = app.export_close_prompt.unwrap();
        assert!(
            app.update(Message::ConfirmExportExit(
                latest.request,
                latest.notice_generation
            ))
            .units()
                > 0
        );
        assert_eq!(
            app.update(Message::ConfirmExportExit(
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
        let _ = app.update(Message::PickPath(picker::Purpose::Csv));
        let picker_id = app.picker_pending.unwrap().id;
        app.screen_capture_protection_active = true;
        let _ = app.update(Message::CloseRequested(iced::window::Id::unique()));
        assert!(app.picker_pending.is_some());
        let notice_generation = app.export_notice.as_ref().unwrap().generation;
        let _ = app.update(Message::PathPicked(
            picker_id,
            Ok(Some("must-not-adopt.csv".into())),
        ));
        assert!(
            app.picker_pending.is_none(),
            "close warning must drain invalidated picker completion"
        );
        let _ = app.update(Message::ScreenCaptureProtectionApplied(Ok(false)));
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
        let _ = app.update(Message::KeepOpen(prompt.request));
        let _ = app.update(Message::ToggleAuthOptions);
        let _ = app.update(Message::PickPath(picker::Purpose::OpenVault));
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
        let _ = app.update(Message::CloseRequested(iced::window::Id::unique()));
        let _ = app.update(Message::ScreenCaptureProtectionApplied(Ok(false)));
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
        let clipboard_generation = app.clipboard_warning_generation;
        let _ = app.update(Message::CloseRequested(iced::window::Id::unique()));
        let _ = app.update(Message::AcknowledgeClipboardCleanup(
            clipboard_generation.wrapping_sub(1),
        ));
        assert!(app.clipboard_cleanup_failed);
        let _ = app.update(Message::AcknowledgeClipboardCleanup(clipboard_generation));
        assert!(
            !app.clipboard_cleanup_failed,
            "rendered clipboard acknowledgment must work during close warning"
        );
        assert!(app.export_notice.is_some());
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
        let _ = app.update(Message::OpenSettings);
        let _ = app.update(Message::CsvPathChanged(target.display().to_string()));
        let _ = app.update(Message::ConfirmPlaintextChanged(true));
        assert!(
            app.update(Message::CloseRequested(iced::window::Id::unique()))
                .units()
                > 0
        );
        let _ = app.update(Message::ExportPlaintextCsv);
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
            let first_close = app.update(Message::CloseRequested(window));
            if notice {
                assert_eq!(first_close.units(), 0);
                let prompt = app.export_close_prompt.unwrap();
                assert!(
                    app.update(Message::ConfirmExportExit(
                        prompt.request,
                        prompt.notice_generation
                    ))
                    .units()
                        > 0
                );
            } else {
                assert!(first_close.units() > 0);
            }
            let _ = app.update(Message::AuthMode(false));
            let _ = app.update(Message::MasterPasswordChanged(
                "gui-synthetic-master-only".into(),
            ));
            let _ = app.update(Message::OpenVault);
            assert!(
                app.session.is_none(),
                "final closing must not permit a new unlock"
            );
            assert!(app.master_password.is_empty());
            assert_eq!(
                app.update(Message::CloseRequested(window)).units(),
                0,
                "only one final close action"
            );
        }
    }

    #[test]
    fn export_normal_close_and_success_do_not_install_false_failure_notice() {
        let (dir, mut app) = fixture(0);
        let target = dir.path().join("empty.csv");
        let _ = app.update(Message::OpenSettings);
        let _ = app.update(Message::CsvPathChanged(target.display().to_string()));
        let _ = app.update(Message::ConfirmPlaintextChanged(true));
        let _ = app.update(Message::ExportPlaintextCsv);
        assert!(app.export_notice.is_none());
        assert!(app.status.contains("已导出 0 条"));
        assert_eq!(
            std::fs::read(target).unwrap(),
            b"name,url,username,password,category,notes\n"
        );
        assert!(
            app.update(Message::CloseRequested(iced::window::Id::unique()))
                .units()
                > 0
        );
    }
    #[test]
    fn export_admission_requires_settings_live_session_checkbox_and_no_picker() {
        let (dir, mut app) = fixture(0);
        let target = dir.path().join("blocked.csv");
        let _ = app.update(Message::ExportPlaintextCsv);
        assert!(!target.exists());
        let _ = app.update(Message::OpenSettings);
        let _ = app.update(Message::CsvPathChanged(target.display().to_string()));
        let _ = app.update(Message::ExportPlaintextCsv);
        assert!(!target.exists());
        let _ = app.update(Message::ConfirmPlaintextChanged(true));
        let _ = app.update(Message::PickPath(picker::Purpose::Csv));
        let _ = app.update(Message::ExportPlaintextCsv);
        assert!(!target.exists());
        let _ = app.update(Message::PathPicked(
            app.picker_sequence,
            Ok(Some(target.clone())),
        ));
        assert!(matches!(&app.panel,Panel::Settings(s) if !s.confirm_plaintext));
        let _ = app.update(Message::ConfirmPlaintextChanged(true));
        let _ = app.update(Message::CsvPathChanged(target.display().to_string()));
        assert!(matches!(&app.panel,Panel::Settings(s) if !s.confirm_plaintext));
        let _ = app.update(Message::ConfirmPlaintextChanged(true));
        let _ = app.update(Message::CancelPanel);
        let _ = app.update(Message::ExportPlaintextCsv);
        assert!(!target.exists());
        let _ = app.update(Message::OpenSettings);
        let _ = app.update(Message::CsvPathChanged(target.display().to_string()));
        let _ = app.update(Message::ConfirmPlaintextChanged(true));
        let _ = app.update(Message::Lock);
        let _ = app.update(Message::ExportPlaintextCsv);
        assert!(!target.exists());
    }
}

#[cfg(test)]
mod synchronous_tests {
    use super::*;
    #[test]
    fn synchronous_export_processes_queued_lock_only_after_return() {
        use std::sync::mpsc;
        let (entered_send, entered_recv) = mpsc::channel();
        let (release_send, release_recv) = mpsc::channel();
        let (events_send, events_recv) = mpsc::channel();
        let (result_send, result_recv) = mpsc::channel();
        let worker = std::thread::spawn(move || {
            let (dir, mut app) = super::super::tests::fixture(0);
            let _ = app.update(Message::OpenSettings);
            let _ = app.update(Message::CsvPathChanged(
                dir.path().join("blocked.csv").display().to_string(),
            ));
            let _ = app.update(Message::ConfirmPlaintextChanged(true));
            crate::export::tests::set_after_create(move || {
                entered_send.send(()).unwrap();
                release_recv.recv().unwrap();
            });
            let _ = app.update(Message::ExportPlaintextCsv);
            assert!(
                app.session.is_some(),
                "the queued lock has not run during synchronous I/O"
            );
            assert!(app.status.contains("已导出"));
            let _ = app.update(events_recv.recv().unwrap());
            assert!(app.session.is_none());
            result_send.send(()).unwrap();
        });
        entered_recv.recv().unwrap();
        events_send.send(Message::Lock).unwrap();
        assert!(matches!(
            result_recv.try_recv(),
            Err(mpsc::TryRecvError::Empty)
        ));
        release_send.send(()).unwrap();
        result_recv.recv().unwrap();
        worker.join().unwrap();
    }
}
