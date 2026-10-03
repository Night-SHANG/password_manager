//! UI-local idle and plaintext-display lifecycle.
use super::*;
use std::time::{Duration, Instant};

pub(super) const IDLE_MINUTES: [u16; 5] = [1, 5, 10, 15, 30];
pub(super) const CLIPBOARD_SECONDS: [u16; 3] = [15, 30, 60];

impl App {
    pub(super) fn finish_editor_cut(
        &mut self,
        request: u64,
        outcome: platform::ClipboardCopyOutcome,
    ) {
        let Some(mut pending) = self.pending_editor_cut.take() else {
            return;
        };
        if outcome == platform::ClipboardCopyOutcome::Copied
            && pending.request == request
            && pending.generation == self.context_generation
            && let Panel::Editor(editor) = &mut self.panel
            && editor.password == *pending.change.original
        {
            replace_secret(
                &mut editor.password,
                std::mem::take(&mut *pending.change.replacement),
            );
        }
    }

    pub(super) fn ensure_monitor_ready(&mut self, required: bool) -> bool {
        if !required || self.security_monitor_ready {
            return true;
        }
        self.status = if self.security_monitor_failed {
            "Windows 会话监控初始化失败或已中断，请重启软件后重试"
        } else {
            "正在等待 Windows 会话监控就绪，请稍后重试"
        }
        .into();
        false
    }

    pub(super) fn change_security_preferences(&mut self, idle: u16, clipboard: u16) {
        if self.session.is_none() || !matches!(self.panel, Panel::Settings(_)) {
            return;
        }
        let Some(path) = &self.preferences_path else {
            self.status = "设置目录不可用，继续沿用当前安全设置".into();
            return;
        };
        let preferences = crate::preferences::Preferences {
            auto_lock_minutes: idle,
            clipboard_seconds: clipboard,
        };
        match crate::preferences::save(path, &preferences) {
            Ok(()) => {
                self.idle_minutes = idle;
                self.clipboard_seconds = clipboard;
                self.last_activity = Instant::now();
                self.operations.authority.activity(
                    self.last_activity,
                    Duration::from_secs(u64::from(self.idle_minutes) * 60),
                );
                self.status = "安全设置已保存；剪贴板时限从下一次复制开始生效".into();
            }
            Err(error) => self.status = error,
        }
    }

    pub(super) fn security_tick(&mut self, now: Instant) {
        if let Some(service) = &self.operations.service {
            let _ = service.drain_snapshot();
        }
        let snapshot = self.operations.authority.snapshot(now);
        if snapshot.masked
            && !matches!(
                self.operations.session,
                operations::SessionUi::Locking | operations::SessionUi::Locked
            )
        {
            self.mask_for_operation_lock("安全权限已撤销", false);
        }
        // Durable polling also recovers lost/coalesced UI transport notifications.
        if let Some(id) = self.operations.active.as_ref().map(|a| a.id) {
            if snapshot.phase == Some(crate::operations::Phase::Finished) {
                self.finish_operation_signal(crate::operations::OperationSignal::Finished(id));
            }
            if snapshot.occupied.is_none() {
                self.finish_operation_signal(crate::operations::OperationSignal::Finished(id));
                self.finish_operation_signal(crate::operations::OperationSignal::Drained(id));
            }
        }
    }
    pub(super) fn user_activity(&mut self, now: Instant) {
        self.security_tick(now);
        if self.window_focused
            && now >= self.last_activity
            && self.operations.authority.snapshot(now).live.is_some()
        {
            self.last_activity = now;
            self.operations
                .authority
                .activity(now, Duration::from_secs(u64::from(self.idle_minutes) * 60));
        }
    }

    pub(super) fn window_focus_changed(&mut self, focused: bool) {
        self.window_focused = focused;
        self.operations.authority.change_display();
        if !focused {
            self.pending_editor_cut = None;
            // Releasing the zeroizing payload is stronger than merely hiding it.
            self.revealed = None;
            self.context_generation = self.context_generation.wrapping_add(1);
            if let Panel::Editor(editor) = &mut self.panel {
                editor.password_visible = false;
            }
        }
    }
}

pub(super) fn runtime_event(
    event: iced::Event,
    _status: iced::event::Status,
    window: iced::window::Id,
) -> Option<Message> {
    // Captured input is still user activity. Redraws, timers, pointer movement,
    // background completions and focus changes must not extend the deadline.
    match event {
        iced::Event::Window(iced::window::Event::CloseRequested) => {
            platform::observe_operation_close();
            Some(Message::CloseRequested(window))
        }
        iced::Event::Window(iced::window::Event::Focused) => {
            Some(Message::WindowFocusChanged(true))
        }
        iced::Event::Window(iced::window::Event::Unfocused) => {
            Some(Message::WindowFocusChanged(false))
        }
        iced::Event::Keyboard(keyboard::Event::KeyPressed { .. })
        | iced::Event::Mouse(iced::mouse::Event::ButtonPressed(_))
        | iced::Event::Mouse(iced::mouse::Event::WheelScrolled { .. })
        | iced::Event::Touch(iced::touch::Event::FingerPressed { .. })
        | iced::Event::Touch(iced::touch::Event::FingerMoved { .. })
        | iced::Event::InputMethod(iced::advanced::input_method::Event::Preedit(..))
        | iced::Event::InputMethod(iced::advanced::input_method::Event::Commit(_)) => {
            Some(Message::UserActivity(Instant::now()))
        }
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn unlocked() -> (tempfile::TempDir, App, Uuid) {
        let (dir, app) = super::super::tests::fixture(1);
        let id = app.session.as_ref().unwrap().entries()[0].id;
        (dir, app, id)
    }

    #[test]
    fn safety_idle_timeout_locks_and_invalidates_pending_file_selection() {
        let (_dir, mut app, _) = unlocked();
        let now = Instant::now();
        app.test_set_fixture_clock(now);
        let _ = app.test_update(Message::OpenSettings);
        let _ = app.test_update(Message::PickPath(picker::Purpose::Restore));
        let request = app.picker_sequence;
        app.security_tick(now + Duration::from_secs(299));
        assert!(app.session.is_some());
        app.security_tick(now + Duration::from_secs(300));
        app.test_drain_pending();
        assert!(app.session.is_none(), "idle vault stayed unlocked");
        let _ = app.test_update(Message::PathPicked(
            request,
            Ok(Some("stale.pmvault".into())),
        ));
        assert!(matches!(app.panel, Panel::Vault));
        assert!(app.picker_pending.is_none());
    }

    #[test]
    fn safety_activity_resets_timer_but_late_activity_cannot_bypass_lock() {
        let (_dir, mut app, _) = unlocked();
        let now = Instant::now();
        app.test_set_fixture_clock(now);
        app.user_activity(now + Duration::from_secs(250));
        app.security_tick(now + Duration::from_secs(300));
        app.test_drain_pending();
        assert!(app.session.is_some());
        app.user_activity(now + Duration::from_secs(550));
        app.test_drain_pending();
        assert!(
            app.session.is_none(),
            "late input extended an expired vault"
        );
    }

    #[test]
    fn safety_focus_loss_destroys_reveal_without_locking_or_canceling_picker() {
        let (_dir, mut app, id) = unlocked();
        let _ = app.test_update(Message::ContextEntry(id));
        let _ = app.test_update(Message::ToggleReveal);
        assert!(app.revealed.is_some());
        app.window_focus_changed(false);
        assert!(
            app.revealed.is_none(),
            "focus loss retained decrypted payload"
        );
        assert!(app.context_open);
        assert!(app.session.is_some());
        let _ = app.test_update(Message::ToggleReveal);
        assert!(
            app.revealed.is_none(),
            "queued reveal unmasked an unfocused window"
        );
        app.window_focus_changed(true);
        let _ = app.test_update(Message::OpenSettings);
        let _ = app.test_update(Message::PickPath(picker::Purpose::Restore));
        app.window_focus_changed(false);
        let _ = app.test_update(Message::PathPicked(
            app.picker_sequence,
            Ok(Some("synthetic-backup.pmvault".into())),
        ));
        assert!(
            matches!(&app.panel, Panel::Settings(s) if s.restore_path == "synthetic-backup.pmvault")
        );
    }
    #[test]
    fn safety_captured_input_counts_but_passive_events_do_not() {
        let id = iced::window::Id::unique();
        assert!(matches!(
            runtime_event(
                iced::Event::Mouse(iced::mouse::Event::ButtonPressed(iced::mouse::Button::Left)),
                iced::event::Status::Captured,
                id
            ),
            Some(Message::UserActivity(_))
        ));
        assert!(matches!(
            runtime_event(
                iced::Event::InputMethod(iced::advanced::input_method::Event::Preedit(
                    "输入".into(),
                    None
                )),
                iced::event::Status::Captured,
                id
            ),
            Some(Message::UserActivity(_))
        ));
        for event in [
            iced::Event::Window(iced::window::Event::RedrawRequested(Instant::now())),
            iced::Event::Mouse(iced::mouse::Event::CursorMoved {
                position: iced::Point::new(10.0, 10.0),
            }),
            iced::Event::Window(iced::window::Event::Resized(iced::Size::new(960.0, 640.0))),
        ] {
            assert!(runtime_event(event, iced::event::Status::Ignored, id).is_none());
        }
    }

    #[test]
    fn safety_expired_session_rejects_next_action_before_timer_message() {
        let (_dir, mut app, id) = unlocked();
        app.test_set_fixture_clock(Instant::now() - Duration::from_secs(301));
        let _ = app.test_update(Message::ContextEntry(id));
        assert!(app.session.is_none());
        assert!(!app.context_open);
        assert!(app.selected.is_none());
    }

    #[test]
    fn safety_unlock_resets_clock_and_unfocused_activity_cannot_extend_it() {
        let (_dir, mut app, _) = unlocked();
        app.test_set_fixture_clock(Instant::now() - Duration::from_secs(900));
        app.reset_unlocked_state();
        let started = app.last_activity;
        assert!(Instant::now().duration_since(started) < Duration::from_secs(1));
        app.window_focus_changed(false);
        app.user_activity(started + Duration::from_secs(200));
        assert_eq!(app.last_activity, started);
        app.window_focus_changed(true);
        assert_eq!(app.last_activity, started);
        app.security_tick(started + Duration::from_secs(300));
        app.test_drain_pending();
        assert!(app.session.is_none());
    }

    #[test]
    fn safety_focus_loss_masks_editor_without_discarding_draft() {
        let (_dir, mut app, _) = unlocked();
        let _ = app.test_update(Message::NewEntry);
        if let Panel::Editor(editor) = &mut app.panel {
            editor.password = "synthetic-draft".into();
            editor.password_visible = true;
        } else {
            panic!("editor did not open");
        }
        app.window_focus_changed(false);
        let _ = app.test_update(Message::ToggleEditorPasswordVisible(app.context_generation));
        assert!(
            matches!(&app.panel, Panel::Editor(editor) if !editor.password_visible && editor.password == "synthetic-draft")
        );
        assert!(app.session.is_some());
    }

    #[test]
    fn safety_preferences_commit_only_after_success_and_reject_locked_messages() {
        let (dir, mut app, _) = unlocked();
        app.preferences_path = Some(dir.path().join("settings.json"));
        let _ = app.test_update(Message::OpenSettings);
        let _ = app.test_update(Message::IdleTimeoutChanged(1));
        let _ = app.test_update(Message::ClipboardTimeoutChanged(15));
        assert_eq!(app.idle_minutes, 1);
        assert_eq!(app.clipboard_seconds, 15);
        let (stored, warning) = crate::preferences::load(app.preferences_path.as_ref().unwrap());
        assert_eq!(stored.auto_lock_minutes, 1);
        assert_eq!(stored.clipboard_seconds, 15);
        assert!(warning.is_none());
        let _ = app.test_update(Message::IdleTimeoutChanged(0));
        assert_eq!(app.idle_minutes, 1);
        let blocked = dir.path().join("directory-instead-of-file");
        std::fs::create_dir(&blocked).unwrap();
        app.preferences_path = Some(blocked);
        let _ = app.test_update(Message::IdleTimeoutChanged(30));
        assert_eq!(
            app.idle_minutes, 1,
            "failed persistence relaxed the timeout"
        );
        assert!(app.status.contains("无法"));
        let _ = app.test_update(Message::Lock);
        let _ = app.test_update(Message::IdleTimeoutChanged(30));
        assert_eq!(app.idle_minutes, 1);
    }

    #[test]
    fn safety_preferences_shortened_deadline_expires_without_subsequent_input() {
        let (dir, mut app, _) = unlocked();
        app.preferences_path = Some(dir.path().join("settings.json"));
        let _ = app.test_update(Message::OpenSettings);
        app.test_set_fixture_clock(Instant::now() - Duration::from_secs(200));
        let _ = app.test_update(Message::IdleTimeoutChanged(1));
        let saved = app.last_activity;
        app.security_tick(saved + Duration::from_secs(59));
        assert!(app.session.is_some());
        app.security_tick(saved + Duration::from_secs(60));
        app.test_drain_pending();
        assert!(
            app.session.is_none(),
            "saved one-minute preference left the old worker deadline in force"
        );
        assert!(
            app.operations
                .authority
                .snapshot(saved + Duration::from_secs(60))
                .fully_locked
        );
    }

    #[test]
    fn safety_preferences_extended_deadline_does_not_lock_at_previous_deadline() {
        let (dir, mut app, _) = unlocked();
        app.preferences_path = Some(dir.path().join("settings.json"));
        let _ = app.test_update(Message::OpenSettings);
        app.test_set_fixture_clock(Instant::now() - Duration::from_secs(240));
        let _ = app.test_update(Message::IdleTimeoutChanged(30));
        let saved = app.last_activity;
        app.security_tick(saved + Duration::from_secs(120));
        app.test_drain_pending();
        assert!(
            app.session.is_some(),
            "saved longer interval kept the old early worker deadline"
        );
        app.security_tick(saved + Duration::from_secs(1799));
        assert!(app.session.is_some());
        app.security_tick(saved + Duration::from_secs(1800));
        app.test_drain_pending();
        assert!(app.session.is_none());
    }

    #[test]
    fn safety_preferences_clipboard_change_restarts_current_idle_deadline() {
        let (dir, mut app, _) = unlocked();
        app.preferences_path = Some(dir.path().join("settings.json"));
        let _ = app.test_update(Message::OpenSettings);
        app.test_set_fixture_clock(Instant::now() - Duration::from_secs(200));
        let _ = app.test_update(Message::ClipboardTimeoutChanged(15));
        let saved = app.last_activity;
        app.security_tick(saved + Duration::from_secs(120));
        app.test_drain_pending();
        assert!(
            app.session.is_some(),
            "successful clipboard preference save did not restart the existing idle interval"
        );
        assert_eq!(app.clipboard_seconds, 15);
        assert_eq!(
            app.operations
                .authority
                .snapshot(saved)
                .live
                .unwrap()
                .deadline,
            saved + Duration::from_secs(300)
        );
    }

    #[test]
    fn safety_preferences_failed_save_preserves_fields_activity_and_authority_deadline() {
        let (dir, mut app, _) = unlocked();
        let blocked = dir.path().join("settings-directory");
        std::fs::create_dir(&blocked).unwrap();
        app.preferences_path = Some(blocked);
        let _ = app.test_update(Message::OpenSettings);
        let started = Instant::now() - Duration::from_secs(100);
        app.test_set_fixture_clock(started);
        let before = app.operations.authority.snapshot(Instant::now());
        for (idle, clipboard) in [(1, 15), (30, 60)] {
            app.change_security_preferences(idle, clipboard);
            let after = app.operations.authority.snapshot(Instant::now());
            assert_eq!(app.idle_minutes, 5);
            assert_eq!(app.clipboard_seconds, 30);
            assert_eq!(app.last_activity, started);
            assert_eq!(after.live.unwrap().deadline, before.live.unwrap().deadline);
            assert_eq!(after.stamp, before.stamp);
            assert_eq!(after.masked, before.masked);
            assert_eq!(after.occupied, before.occupied);
            assert!(app.status.contains("无法"));
        }
        app.security_tick(started + Duration::from_secs(299));
        assert!(app.session.is_some());
        app.security_tick(started + Duration::from_secs(300));
        app.test_drain_pending();
        assert!(app.session.is_none());
    }

    #[test]
    fn safety_clipboard_status_cannot_cross_requests_or_sessions() {
        let (_dir, mut app, _) = unlocked();
        let first = app.clipboard_session.as_ref().unwrap().id();
        app.clipboard_request = 12;
        app.status = "current status".into();
        let completion = |session, request| {
            Message::PlatformSecurity(SecurityEvent::ClipboardCopyCompleted {
                session,
                request,
                kind: platform::ClipboardKind::Password,
                outcome: platform::ClipboardCopyOutcome::Copied,
            })
        };
        let _ = app.test_update(completion(first, 11));
        assert_eq!(app.status, "current status");
        let _ = app.test_update(completion(first, 12));
        assert!(app.status.contains("密码已复制"));
        let _ = app.test_update(Message::Lock);
        let status = app.status.clone();
        let _ = app.test_update(completion(first, 12));
        assert_eq!(app.status, status);
        assert!(app.clipboard_session.is_none());
        // A new unlock gets a distinct permit even if a request counter repeats.
        let (_other_dir, mut other, _) = unlocked();
        other.clipboard_request = 12;
        other.status = "new session".into();
        let _ = other.test_update(completion(first, 12));
        assert_eq!(other.status, "new session");
    }

    #[test]
    fn safety_monitor_failure_locks_an_unprotected_session() {
        let (_dir, mut app, id) = unlocked();
        let _ = app.test_update(Message::ContextEntry(id));
        let _ = app.test_update(Message::ToggleReveal);
        assert!(app.revealed.is_some());
        let _ = app.test_update(Message::PlatformSecurity(SecurityEvent::MonitorFailed));
        assert!(
            app.session.is_none(),
            "monitor failure left the vault unlocked"
        );
        assert!(app.revealed.is_none());
        assert!(app.clipboard_session.is_none());
        assert!(!app.security_monitor_ready);
    }

    #[test]
    fn safety_monitor_startup_and_recovery_require_a_fresh_unlock() {
        let mut app = App::initial();
        assert!(!app.ensure_monitor_ready(true));
        assert!(app.status.contains("等待"));
        let first_registration = Uuid::new_v4();
        assert!(
            app.operations
                .authority
                .bind_monitor_registration(first_registration)
        );
        assert!(
            app.operations
                .authority
                .monitor_ready_for(first_registration)
        );
        let _ = app.test_update(Message::PlatformSecurity(SecurityEvent::MonitorReady));
        assert!(app.ensure_monitor_ready(true));
        assert!(!app.security_monitor_failed);
        assert!(
            app.operations
                .authority
                .monitor_failed_for(first_registration, Instant::now())
        );
        let _ = app.test_update(Message::PlatformSecurity(SecurityEvent::MonitorFailed));
        assert!(!app.ensure_monitor_ready(true));
        assert!(app.status.contains("重启"));
        // A fresh native owner establishes readiness before its UI notification;
        // merely replaying a displayed Ready from the failed owner cannot do so.
        app.operations
            .authority
            .detach_monitor_registration(first_registration, Instant::now());
        let fresh_registration = Uuid::new_v4();
        assert!(
            app.operations
                .authority
                .bind_monitor_registration(fresh_registration)
        );
        assert!(
            app.operations
                .authority
                .monitor_ready_for(fresh_registration)
        );
        let _ = app.test_update(Message::PlatformSecurity(SecurityEvent::MonitorReady));
        assert!(app.ensure_monitor_ready(true));
        assert!(
            app.session.is_none(),
            "monitor recovery must not unlock a vault"
        );
        assert!(!app.security_monitor_failed);
    }

    #[test]
    fn safety_old_editor_reveal_cannot_unmask_after_refocus() {
        let (_dir, mut app, _) = unlocked();
        let _ = app.test_update(Message::NewEntry);
        let old = app.context_generation;
        app.window_focus_changed(false);
        app.window_focus_changed(true);
        let _ = app.test_update(Message::ToggleEditorPasswordVisible(old));
        assert!(matches!(&app.panel, Panel::Editor(editor) if !editor.password_visible));
    }
    #[test]
    fn safety_cleanup_warning_survives_lifecycle_and_old_acknowledgement() {
        let (_dir, mut app, _) = unlocked();
        let _ = app.test_update(Message::PlatformSecurity(
            SecurityEvent::ClipboardCleanupFailed,
        ));
        let old = app.clipboard_warning_generation;
        let _ = app.test_update(Message::PlatformSecurity(SecurityEvent::SystemSuspending));
        assert!(
            app.clipboard_cleanup_failed,
            "suspend hid a cleanup failure"
        );
        let _ = app.test_update(Message::AuthMode(false));
        assert!(
            app.clipboard_cleanup_failed,
            "auth navigation hid cleanup failure"
        );
        let _ = app.test_update(Message::PlatformSecurity(
            SecurityEvent::ClipboardCleanupFailed,
        ));
        let _ = app.test_update(Message::AcknowledgeClipboardCleanup(old));
        assert!(
            app.clipboard_cleanup_failed,
            "old acknowledgement hid a new failure"
        );
        let _ = app.test_update(Message::AcknowledgeClipboardCleanup(
            app.clipboard_warning_generation,
        ));
        assert!(!app.clipboard_cleanup_failed);
    }

    #[test]
    fn safety_cut_commits_only_after_matching_success_with_unchanged_draft() {
        for scenario in 0..5 {
            let (_dir, mut app, _) = unlocked();
            let _ = app.test_update(Message::NewEntry);
            let _ = app.test_update(Message::EditorPasswordChanged("synthetic-original".into()));
            let session = app.clipboard_session.as_ref().unwrap().id();
            app.clipboard_request = 7;
            app.pending_editor_cut = Some(PendingEditorCut {
                generation: app.context_generation,
                request: 7,
                change: EditorCut {
                    original: zeroize::Zeroizing::new("synthetic-original".into()),
                    replacement: zeroize::Zeroizing::new("synthetic-remaining".into()),
                },
            });
            match scenario {
                2 => {
                    let _ = app.test_update(Message::EditorPasswordChanged("newer draft".into()));
                }
                3 => app.window_focus_changed(false),
                4 => {
                    let _ = app.test_update(Message::CancelPanel);
                    let _ = app.test_update(Message::NewEntry);
                }
                _ => {}
            }
            let _ = app.test_update(Message::PlatformSecurity(
                SecurityEvent::ClipboardCopyCompleted {
                    session,
                    request: 7,
                    kind: platform::ClipboardKind::Password,
                    outcome: if scenario == 1 {
                        platform::ClipboardCopyOutcome::Failed
                    } else {
                        platform::ClipboardCopyOutcome::Copied
                    },
                },
            ));
            let expected = match scenario {
                0 => "synthetic-remaining",
                2 => "newer draft",
                4 => "",
                _ => "synthetic-original",
            };
            assert!(matches!(&app.panel, Panel::Editor(editor) if editor.password == expected));
            assert!(app.pending_editor_cut.is_none());
        }
    }
    #[test]
    fn safety_successful_editor_save_drops_pending_cut_buffers() {
        let (_dir, mut app, _) = unlocked();
        let _ = app.test_update(Message::NewEntry);
        let _ = app.test_update(Message::EditorNameChanged("synthetic new entry".into()));
        let _ = app.test_update(Message::EditorPasswordChanged("synthetic-original".into()));
        app.pending_editor_cut = Some(PendingEditorCut {
            generation: app.context_generation,
            request: app.clipboard_request,
            change: EditorCut {
                original: zeroize::Zeroizing::new("synthetic-original".into()),
                replacement: zeroize::Zeroizing::new(String::new()),
            },
        });
        let _ = app.test_update(Message::SaveEditor);
        assert!(matches!(app.panel, Panel::Vault));
        assert!(app.pending_editor_cut.is_none());
    }
}
