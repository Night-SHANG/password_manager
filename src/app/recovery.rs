//! Locked, read-only evidence selection and explicit authenticated copy-to-new.
use super::*;
use crate::storage::recovery::{
    self as evidence, CurrentObservation, RecoveryInfo, RecoveryListing,
};

pub(super) struct RecoveryState {
    pub generation: u64,
    pub listing: RecoveryListing,
    pub source: String,
    pub destination: String,
    pub password: zeroize::Zeroizing<String>,
}
impl App {
    pub(super) fn dismiss_recovery(&mut self) {
        self.invalidate_picker();
        self.recovery_generation = self.recovery_generation.wrapping_add(1);
        self.recovery = None;
    }
    pub(super) fn open_recovery(&mut self) {
        if self.session.is_some() {
            return;
        }
        self.clear_password_fields();
        self.dismiss_recovery();
        let listing = match evidence::inspect(Path::new(&self.vault_path)) {
            Ok(listing) => listing,
            Err(error) => RecoveryListing {
                maintenance_required: true,
                detail: format!(
                    "无法完整检查目录：{error}。可手动选择加密副本，原目录不会被修改。"
                ),
                ..RecoveryListing::default()
            },
        };
        self.recovery = Some(RecoveryState {
            generation: self.recovery_generation,
            listing,
            source: String::new(),
            destination: String::new(),
            password: zeroize::Zeroizing::new(String::new()),
        });
    }
    pub(super) fn handle_persist_error(&mut self, error: &AppError) {
        if !error.invalidates_session() {
            return;
        }
        let info = if let AppError::Persist(failure) = error {
            failure.recovery.clone()
        } else {
            RecoveryInfo {
                destination: Path::new(&self.vault_path).to_path_buf(),
                stage: "source check".into(),
                current: CurrentObservation::Other,
                artifacts: Vec::new(),
                detail: "磁盘文件与会话不一致；请重新检查当前文件或恢复选定副本到新位置。".into(),
            }
        };
        self.lock_with_status("存储状态已变化，保险库已锁定；请检查恢复材料");
        self.vault_path = info.destination.display().to_string();
        self.recovery_notice = Some(info);
        self.open_recovery();
    }
    pub(super) fn restore_recovery_copy(&mut self, generation: u64) {
        if !self.ensure_monitor_ready(cfg!(windows)) {
            if let Some(state) = &mut self.recovery {
                state.password.zeroize();
            }
            return;
        }
        if self.session.is_some() || self.picker_pending.is_some() {
            return;
        }
        let Some(state) = &mut self.recovery else {
            return;
        };
        if state.generation != generation {
            return;
        }
        if state.source.is_empty() || state.destination.is_empty() || state.password.is_empty() {
            self.status = "请选择源副本、新文件位置并输入该副本的主密码".into();
            return;
        }
        let destination = state.destination.clone();
        let result = VaultSession::restore_encrypted_backup(
            Path::new(&state.source),
            Path::new(&destination),
            &state.password,
            false,
        );
        state.password.zeroize();
        match result {
            Ok(()) => {
                self.dismiss_recovery();
                self.recovery_notice = None;
                self.vault_path = destination;
                self.auth_options_open = true;
                self.status = "选定副本已验证并恢复到新文件。原文件与恢复材料均已保留；请输入主密码解锁新文件。".into();
            }
            Err(error) => {
                self.status =
                    format!("恢复未完成：{error}。源副本保持只读；请检查密码和新文件位置。")
            }
        }
    }
    pub(super) fn check_startup_recovery(&mut self) -> bool {
        match evidence::inspect(Path::new(&self.vault_path)) {
            Ok(listing) if listing.maintenance_required => {
                self.open_recovery();
                self.status = "发现未解决的存储材料；请先检查并恢复到新位置".into();
                true
            }
            Err(error) => {
                let path = Path::new(&self.vault_path);
                let parent = path
                    .parent()
                    .filter(|p| !p.as_os_str().is_empty())
                    .unwrap_or(Path::new("."));
                if matches!(std::fs::symlink_metadata(parent), Err(e) if e.kind() == std::io::ErrorKind::NotFound)
                {
                    return false;
                }
                self.open_recovery();
                self.status =
                    format!("恢复材料检查不完整：{error}。请检查目录权限或选择副本恢复到新文件。");
                true
            }
            _ => false,
        }
    }
}
