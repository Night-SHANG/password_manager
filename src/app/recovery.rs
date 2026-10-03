//! Locked, read-only evidence selection and explicit authenticated copy-to-new.
use super::*;
use crate::storage::recovery::{CurrentObservation, RecoveryInfo, RecoveryListing};

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
        if let Some(state) = self.recovery.take() {
            self.operations.recovery_cache = Some(state.listing);
        }
    }
    pub(super) fn open_recovery(&mut self) {
        if self.session.is_some() || self.operation_busy() {
            return;
        }
        self.dismiss_recovery();
        if self.picker_pending.is_some() {
            let mut listing = self.operations.recovery_cache.take().unwrap_or_default();
            listing
                .detail
                .push_str(" 等待原文件选择窗口返回后重新检查目录；当前列表可能已变化。");
            self.recovery = Some(RecoveryState {
                generation: self.recovery_generation,
                listing,
                source: String::new(),
                destination: String::new(),
                password: zeroize::Zeroizing::new(String::new()),
            });
            self.operations.inspect_after_picker = true;
            return;
        }
        self.start_inspection(true);
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
        self.lock_with_status("存储状态已变化，正在锁定；请检查恢复材料");
        self.vault_path = info.destination.display().to_string();
        self.recovery_notice = Some(info);
        self.operations.encrypted_notice_generation =
            self.operations.encrypted_notice_generation.wrapping_add(1);
        self.operations.inspect_after_drain = true;
    }
    pub(super) fn restore_recovery_copy(&mut self, generation: u64) {
        self.start_restore_new(generation);
    }
    pub(super) fn check_startup_recovery(&mut self) -> bool {
        self.start_inspection(false);
        self.operation_busy()
    }
}
