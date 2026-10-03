//! Native dialogs choose paths only. Vault I/O stays behind existing actions.
use super::*;
use std::path::PathBuf;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Purpose {
    OpenVault,
    CreateVault,
    Import,
    Backup,
    Restore,
    Csv,
    RecoverySource,
    RecoveryDestination,
}

#[derive(Clone, Copy)]
pub(super) struct Pending {
    pub(super) id: u64,
    purpose: Purpose,
    valid: bool,
}

impl App {
    pub(super) fn picker_allowed(&self, purpose: Purpose) -> bool {
        if self.operation_busy()
            || self
                .operations
                .authority
                .snapshot(std::time::Instant::now())
                .masked
        {
            return false;
        }
        match purpose {
            Purpose::RecoverySource | Purpose::RecoveryDestination => {
                self.session.is_none() && self.recovery.is_some()
            }
            Purpose::OpenVault => {
                self.session.is_none() && !self.creating && self.auth_options_open
            }
            Purpose::CreateVault => self.session.is_none() && self.creating,
            Purpose::Import => self.session.is_some() && matches!(self.panel, Panel::Import(_)),
            Purpose::Backup | Purpose::Restore | Purpose::Csv => {
                self.session.is_some() && matches!(self.panel, Panel::Settings(_))
            }
        }
    }

    pub(super) fn invalidate_picker(&mut self) {
        if let Some(pending) = &mut self.picker_pending {
            pending.valid = false;
        }
    }

    pub(super) fn begin_picker(&mut self, purpose: Purpose) -> Task<Message> {
        if self.picker_pending.is_some() || !self.picker_allowed(purpose) {
            return Task::none();
        }
        self.picker_sequence = self.picker_sequence.wrapping_add(1);
        let id = self.picker_sequence;
        self.picker_pending = Some(Pending {
            id,
            purpose,
            valid: true,
        });
        let path = match purpose {
            Purpose::RecoverySource | Purpose::RecoveryDestination => {
                let state = self.recovery.as_ref().unwrap();
                if purpose == Purpose::RecoverySource {
                    state.source.clone()
                } else {
                    state.destination.clone()
                }
            }
            Purpose::OpenVault | Purpose::CreateVault => self.vault_path.clone(),
            Purpose::Import => match &self.panel {
                Panel::Import(s) => s.path.clone(),
                _ => unreachable!(),
            },
            Purpose::Backup | Purpose::Restore | Purpose::Csv => match &self.panel {
                Panel::Settings(s) => match purpose {
                    Purpose::Backup => s.backup_path.clone(),
                    Purpose::Restore => s.restore_path.clone(),
                    _ => s.csv_path.clone(),
                },
                _ => unreachable!(),
            },
        };
        iced::window::oldest().then(move |window| match window {
            Some(window) => {
                let path = path.clone();
                iced::window::run(window, move |parent| {
                    let dialog = configured_dialog(purpose, &path).set_parent(&parent);
                    async move {
                        let chosen = if purpose.is_save() {
                            dialog.save_file().await
                        } else {
                            dialog.pick_file().await
                        };
                        Ok(chosen.map(|file| file.path().to_path_buf()))
                    }
                })
                .then(Task::future)
                .map(move |result| Message::PathPicked(id, result))
            }
            None => Task::done(Message::PathPicked(
                id,
                Err("无法找到主窗口，请手动输入路径".into()),
            )),
        })
    }

    pub(super) fn finish_picker(
        &mut self,
        id: u64,
        result: std::result::Result<Option<PathBuf>, String>,
    ) {
        let Some(pending) = self.picker_pending else {
            return;
        };
        if pending.id != id {
            return;
        }
        self.picker_pending = None;
        if self.operations.inspect_after_picker {
            self.operations.inspect_after_picker = false;
            self.start_inspection(true);
            return;
        }
        if !pending.valid || !self.picker_allowed(pending.purpose) {
            return;
        }
        let path = match result {
            Ok(Some(path)) => path,
            Ok(None) => {
                self.status = "未选择文件，或系统文件窗口不可用；可重试或手动输入路径".into();
                return;
            }
            Err(error) => {
                self.status = error;
                return;
            }
        };
        let Some(path) = path
            .to_str()
            .filter(|path| !path.is_empty() && !path.contains('\0'))
        else {
            self.status = "路径包含不支持的字符，请重新选择".into();
            return;
        };
        let message = match pending.purpose {
            Purpose::RecoverySource => Message::RecoverySourceChanged(
                self.recovery.as_ref().unwrap().generation,
                path.into(),
            ),
            Purpose::RecoveryDestination => Message::RecoveryDestinationChanged(
                self.recovery.as_ref().unwrap().generation,
                path.into(),
            ),
            Purpose::OpenVault | Purpose::CreateVault => Message::VaultPathChanged(path.into()),
            Purpose::Import => Message::ImportPathChanged(path.into()),
            Purpose::Backup => Message::BackupPathChanged(path.into()),
            Purpose::Restore => Message::RestorePathChanged(path.into()),
            Purpose::Csv => Message::CsvPathChanged(path.into()),
        };
        let _ = self.update(message);
        if pending.purpose == Purpose::OpenVault && self.check_startup_recovery() {
            return;
        }
        self.status = "已选择路径；请检查后再执行操作".into();
    }
}

impl Purpose {
    fn is_save(self) -> bool {
        matches!(
            self,
            Self::CreateVault | Self::Backup | Self::Csv | Self::RecoveryDestination
        )
    }
}

fn configured_dialog(purpose: Purpose, path: &str) -> rfd::AsyncFileDialog {
    let (title, label, extensions): (&str, &str, &[&str]) = match purpose {
        Purpose::RecoverySource => ("选择恢复副本", "加密保险库", &["pmvault", "bak"]),
        Purpose::RecoveryDestination => ("选择新文件位置", "加密保险库", &["pmvault"]),
        Purpose::OpenVault => ("选择保险库文件", "加密保险库", &["pmvault"]),
        Purpose::CreateVault => ("选择新建位置", "加密保险库", &["pmvault"]),
        Purpose::Import => ("选择导入文件", "支持的导入文件", &["csv", "enc", "db"]),
        Purpose::Backup => ("选择备份位置", "加密保险库", &["pmvault"]),
        Purpose::Restore => ("选择恢复文件", "加密保险库", &["pmvault"]),
        Purpose::Csv => ("选择 CSV 导出位置", "CSV 文件", &["csv"]),
    };
    let mut dialog = rfd::AsyncFileDialog::new()
        .set_title(title)
        .add_filter(label, extensions)
        .add_filter("所有文件", &["*"]);
    let path = Path::new(path);
    if let Some(parent) = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
    {
        dialog = dialog.set_directory(parent);
    }
    if purpose.is_save()
        && let Some(name) = path.file_name().and_then(|name| name.to_str())
    {
        dialog = dialog.set_file_name(name);
    }
    dialog
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn picker_cancellation_and_repeated_clicks_are_safe() {
        let mut app = App::initial();
        app.auth_options_open = true;
        let original = app.vault_path.clone();
        let task = app.begin_picker(Purpose::OpenVault);
        assert!(task.units() > 0, "native picker task missing");
        let first = app.picker_pending.unwrap();
        assert_eq!(app.begin_picker(Purpose::OpenVault).units(), 0);
        assert_eq!(app.picker_pending.unwrap().id, first.id);
        app.finish_picker(first.id, Ok(None));
        assert!(app.picker_pending.is_none());
        assert_eq!(app.vault_path, original);
    }

    #[test]
    fn picker_returns_only_to_the_original_context() {
        for transition in [
            Message::AuthMode(true),
            Message::ToggleAuthOptions,
            Message::Lock,
            Message::VaultPathChanged("manual.pmvault".into()),
        ] {
            let mut app = App::initial();
            app.auth_options_open = true;
            let _ = app.begin_picker(Purpose::OpenVault);
            let first = app.picker_pending.unwrap();
            let _ = app.test_update(transition);
            let expected = app.vault_path.clone();
            let _ = app.test_update(Message::AuthMode(false));
            app.auth_options_open = true;
            app.finish_picker(first.id, Ok(Some(PathBuf::from("stale.pmvault"))));
            assert_eq!(app.vault_path, expected);
            assert!(app.picker_pending.is_none());
        }
    }
    fn workspace() -> (tempfile::TempDir, App) {
        let dir = tempfile::tempdir().unwrap();
        let mut app = App::initial();
        app.session = Some(
            VaultSession::create(dir.path().join("synthetic.pmvault"), "synthetic-only").unwrap(),
        );
        app.reset_unlocked_state();
        (dir, app)
    }

    #[test]
    fn picker_six_routes_only_fill_paths_and_clear_bound_confirmations() {
        for purpose in [
            Purpose::OpenVault,
            Purpose::CreateVault,
            Purpose::Import,
            Purpose::Backup,
            Purpose::Restore,
            Purpose::Csv,
        ] {
            let (_dir, mut app) = workspace();
            match purpose {
                Purpose::OpenVault | Purpose::CreateVault => {
                    app.session = None;
                    app.creating = purpose == Purpose::CreateVault;
                    app.auth_options_open = true;
                }
                Purpose::Import => {
                    let _ = app.test_update(Message::OpenImport);
                }
                _ => {
                    let _ = app.test_update(Message::OpenSettings);
                }
            }
            if let Panel::Settings(s) = &mut app.panel {
                s.confirm_restore = true;
                s.confirm_plaintext = true;
                s.restore_password = "old-synthetic-password".into();
            }
            if let Panel::Import(s) = &mut app.panel {
                s.legacy_password = "old-synthetic-password".into();
                s.resolutions.insert(0, ConflictResolution::KeepLocal);
            }
            let _ = app.begin_picker(purpose);
            let id = app.picker_pending.unwrap().id;
            let selected = _dir.path().join("中文 😀 selected.csv");
            app.finish_picker(id, Ok(Some(selected.clone())));
            assert!(!selected.exists(), "choosing a path performed I/O");
            let expected = selected.to_str().unwrap();
            match purpose {
                Purpose::OpenVault | Purpose::CreateVault => assert_eq!(app.vault_path, expected),
                Purpose::Import => match &app.panel {
                    Panel::Import(s) => {
                        assert_eq!(s.path, expected);
                        assert!(s.preview.is_none());
                        assert!(s.resolutions.is_empty());
                        assert!(s.legacy_password.is_empty());
                    }
                    _ => panic!("wrong panel"),
                },
                _ => match &app.panel {
                    Panel::Settings(s) => match purpose {
                        Purpose::Backup => assert_eq!(s.backup_path, expected),
                        Purpose::Restore => {
                            assert_eq!(s.restore_path, expected);
                            assert!(!s.confirm_restore);
                            assert!(s.restore_password.is_empty());
                        }
                        Purpose::Csv => {
                            assert_eq!(s.csv_path, expected);
                            assert!(!s.confirm_plaintext);
                        }
                        _ => unreachable!(),
                    },
                    _ => panic!("wrong panel"),
                },
            }
            assert!(app.picker_pending.is_none());
        }
    }

    #[test]
    fn picker_old_callbacks_cannot_clear_new_request_or_reopened_panel() {
        let (_dir, mut app) = workspace();
        let _ = app.test_update(Message::OpenImport);
        let _ = app.begin_picker(Purpose::Import);
        let first = app.picker_pending.unwrap().id;
        let _ = app.test_update(Message::CancelPanel);
        let _ = app.test_update(Message::OpenImport);
        assert_eq!(
            app.begin_picker(Purpose::Import).units(),
            0,
            "old dialog still owns the slot"
        );
        app.finish_picker(first, Ok(Some(PathBuf::from("stale.csv"))));
        assert!(matches!(&app.panel, Panel::Import(s) if s.path.is_empty()));
        let _ = app.begin_picker(Purpose::Import);
        let second = app.picker_pending.unwrap().id;
        app.finish_picker(first, Ok(Some(PathBuf::from("duplicate.csv"))));
        assert_eq!(app.picker_pending.unwrap().id, second);
        let _ = app.test_update(Message::PlatformSecurity(SecurityEvent::SessionLocked));
        app.finish_picker(second, Ok(Some(PathBuf::from("locked.csv"))));
        assert!(app.session.is_none());
        assert!(app.picker_pending.is_none());
    }

    #[test]
    fn picker_invalid_targets_errors_and_paths_are_safe() {
        let mut app = App::initial();
        for purpose in [
            Purpose::OpenVault,
            Purpose::CreateVault,
            Purpose::Import,
            Purpose::Backup,
            Purpose::Restore,
            Purpose::Csv,
        ] {
            assert_eq!(app.begin_picker(purpose).units(), 0);
        }
        app.auth_options_open = true;
        let original = app.vault_path.clone();
        for result in [
            Err("native dialog unavailable".into()),
            Ok(Some(PathBuf::new())),
            Ok(Some(PathBuf::from("bad\0path"))),
        ] {
            let _ = app.begin_picker(Purpose::OpenVault);
            let id = app.picker_pending.unwrap().id;
            app.finish_picker(id, result);
            assert_eq!(app.vault_path, original);
            assert!(!app.status.is_empty());
            assert!(app.picker_pending.is_none());
        }
    }

    #[test]
    fn picker_blocks_file_actions_until_dialog_returns() {
        let dir = tempfile::tempdir().unwrap();
        let mut app = App::initial();
        app.creating = true;
        app.vault_path = dir.path().join("not-yet.pmvault").display().to_string();
        app.master_password = "synthetic-only".into();
        app.confirm_password = app.master_password.clone();
        let _ = app.begin_picker(Purpose::CreateVault);
        let _ = app.test_update(Message::CreateVault);
        assert!(
            app.session.is_none(),
            "pending dialog must not create a vault"
        );
        assert!(!Path::new(&app.vault_path).exists());
    }
    #[test]
    fn picker_directory_hint_does_not_require_filesystem_access() {
        let dir = tempfile::tempdir().unwrap();
        let unavailable_parent = dir.path().join("not-created-yet");
        let hint = unavailable_parent.join("new.pmvault");
        let dialog = configured_dialog(Purpose::CreateVault, hint.to_str().unwrap());
        // rfd owns this hint and the native backend resolves it off the UI thread.
        // A nonexistent parent is still retained; building a dialog must not stat it.
        assert!(format!("{dialog:?}").contains("not-created-yet"));
        assert!(!unavailable_parent.exists());
    }
}

#[cfg(test)]
mod recovery_tests {
    use super::*;
    #[test]
    fn recovery_dialog_results_cannot_cross_close_reopen_or_lock() {
        for lock in [false, true] {
            let (_dir, mut app) = crate::app::tests::fixture(0);
            app.test_lock_with_status("synthetic");
            app.test_open_recovery();
            let _ = app.begin_picker(Purpose::RecoverySource);
            let pending = app.picker_pending.unwrap();
            if lock {
                app.test_lock_with_status("synthetic");
            } else {
                app.dismiss_recovery();
            }
            app.test_open_recovery();
            app.finish_picker(pending.id, Ok(Some(PathBuf::from("stale.pmvault"))));
            app.test_drain_pending();
            assert!(app.recovery.as_ref().unwrap().source.is_empty());
            assert!(app.picker_pending.is_none());
            let _ = app.begin_picker(Purpose::RecoveryDestination);
            let pending = app.picker_pending.unwrap();
            app.finish_picker(pending.id, Ok(Some(PathBuf::from("fresh.pmvault"))));
            assert_eq!(app.recovery.as_ref().unwrap().destination, "fresh.pmvault");
        }
    }
}
