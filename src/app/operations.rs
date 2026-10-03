//! UI admission and owned handoff. No vault I/O, KDF, parsing or save here.
use super::*;
use crate::operations as work;
use std::sync::Arc;
use std::time::{Duration, Instant};
use work::{
    OperationId, OperationInput, OperationKind, OperationPayload, OperationSignal, OperationValue,
    RetiredUi, RevokeReason, TerminalOutcome, VaultMutation,
};

pub(super) enum SessionUi {
    Locked,
    Present,
    Leased(OperationId),
    Locking,
}
pub(super) struct Active {
    pub id: OperationId,
    kind: OperationKind,
    pub(super) finished: bool,
    success: &'static str,
}
pub(super) struct UiOperations {
    pub authority: Arc<work::authority::Coordinator>,
    pub service: Option<work::runner::OperationService>,
    pub registration: Option<platform::OperationRegistration>,
    pub session: SessionUi,
    pub active: Option<Active>,
    pub task: Option<Task<Message>>,
    pub close_window: Option<iced::window::Id>,
    pub close_notice_seen: Option<u64>,
    pub encrypted_notice_generation: u64,
    pub close_confirmed: Option<u64>,
    pub failure_notice: Option<String>,
    pub commit_notice: Option<String>,
    pub edit_stamp: Option<work::ContextStamp>,
    pub shutdown_started: bool,
    pub failed_input: Option<OperationInput>,
    pub launch_retired: Option<RetiredUi>,
    explicit_inspection: bool,
    pub inspect_after_picker: bool,
    pub inspect_after_drain: bool,
    pub recovery_cache: Option<crate::storage::recovery::RecoveryListing>,
}
impl UiOperations {
    pub(super) fn note_failure(&mut self, warning: String) {
        self.encrypted_notice_generation = self.encrypted_notice_generation.wrapping_add(1);
        self.failure_notice = Some(warning);
    }
    pub fn new() -> Self {
        let authority = Arc::new(work::authority::Coordinator::new(
            platform::operation_monitor_required() && !cfg!(test),
        ));
        let service = work::runner::OperationService::new(authority.clone()).ok();
        if service.is_none() {
            authority.revoke(RevokeReason::WorkerFailed, Instant::now());
        }
        Self {
            authority,
            service,
            registration: None,
            session: SessionUi::Locked,
            active: None,
            task: None,
            close_window: None,
            close_notice_seen: None,
            encrypted_notice_generation: 0,
            close_confirmed: None,
            failure_notice: None,
            commit_notice: None,
            edit_stamp: None,
            shutdown_started: false,
            failed_input: None,
            launch_retired: None,
            explicit_inspection: false,
            inspect_after_picker: false,
            inspect_after_drain: false,
            recovery_cache: None,
        }
    }
}
impl App {
    pub(super) fn operation_busy(&self) -> bool {
        self.operations.active.is_some()
            || self
                .operations
                .authority
                .snapshot(Instant::now())
                .occupied
                .is_some()
    }
    fn admit_operation(
        &mut self,
        kind: OperationKind,
        success: &'static str,
    ) -> Option<work::authority::Admission> {
        if self.picker_pending.is_some()
            || self.operations.active.is_some()
            || self.operations.service.is_none()
        {
            return None;
        }
        let now = Instant::now();
        let snapshot = self.operations.authority.snapshot(now);
        let admission = match self
            .operations
            .authority
            .try_admit(kind, snapshot.stamp, now)
        {
            Ok(a) => a,
            Err(_) => return None,
        };
        let id = admission.id();
        self.operations.active = Some(Active {
            id,
            kind,
            finished: false,
            success,
        });
        if self.session.is_some() {
            self.operations.session = SessionUi::Leased(id);
            self.operations.launch_retired = Some(RetiredUi {
                ui_index: self.view_index.take(),
                filtered_entries: self.filtered_entries.take(),
                ..RetiredUi::default()
            });
        }
        self.revealed = None;
        self.pending_editor_cut = None;
        self.context_open = false;
        self.status = "正在后台处理；可取消或锁定，已开始的写入会完成验证".into();
        Some(admission)
    }
    fn submit_operation(&mut self, admission: work::authority::Admission, input: OperationInput) {
        let id = admission.id();
        let retired = self.operations.launch_retired.take();
        let result = self
            .operations
            .service
            .as_ref()
            .expect("admission requires worker")
            .submit_owned(admission, input, retired);
        match result {
            Ok(observer) => {
                self.operations.task = Some(Task::run(observer, Message::OperationSignal))
            }
            Err(failure) => {
                // This path is an unavailable transport, never permission to run
                // a publishing operation synchronously. Return owners to the
                // same service's disposal lane before reporting a full lock.
                let _ = failure.admission;
                self.operations
                    .authority
                    .revoke(RevokeReason::WorkerFailed, Instant::now());
                self.operations.session = SessionUi::Locking;
                self.status = "后台处理无法提交；保持遮蔽，请重新启动软件".into();
                // The service failure API retains ownership. This is only reached
                // for poisoned/shutdown transport and cannot certify cleanup.
                self.operations.failed_input = Some(failure.input);
                self.operations.launch_retired = failure.retired;
                self.operations
                    .authority
                    .complete_disk(id, work::TerminalSummary::WorkerFailed);
            }
        }
        self.attach_launch_retired();
    }
    pub(super) fn start_auth(&mut self, create: bool) {
        if !self.ensure_monitor_ready(cfg!(windows)) {
            return;
        }
        let kind = if create {
            OperationKind::Create
        } else {
            OperationKind::Open
        };
        let Some(admission) = self.admit_operation(
            kind,
            if create {
                "新保险库已创建并加密"
            } else {
                "保险库已解锁"
            },
        ) else {
            return;
        };
        let path = std::path::PathBuf::from(&self.vault_path);
        let password = zeroize::Zeroizing::new(std::mem::take(&mut self.master_password));
        let confirmation = zeroize::Zeroizing::new(std::mem::take(&mut self.confirm_password));
        let input = if create {
            OperationInput::Create {
                path,
                password,
                confirmation,
            }
        } else {
            let retired = RetiredUi {
                passwords: [Some(confirmation), None, None, None],
                ..RetiredUi::default()
            };
            // Attach only after submission below, avoiding a competing Dispose job.
            self.operations.launch_retired = Some(retired);
            OperationInput::Open { path, password }
        };
        self.submit_operation(admission, input);
        self.attach_launch_retired();
    }
    fn attach_launch_retired(&mut self) {
        if let Some(retired) = self.operations.launch_retired.take() {
            self.retire_operation_ui(retired);
            if self.operations.launch_retired.is_none() && self.operations.failed_input.is_none() {
                let epoch = self
                    .operations
                    .authority
                    .snapshot(Instant::now())
                    .stamp
                    .epoch;
                self.operations.authority.ack_ui_detached(epoch);
            }
        }
    }
    pub(super) fn start_inspection(&mut self, explicit: bool) {
        let Some(admission) = self.admit_operation(OperationKind::InspectRecovery, "") else {
            return;
        };
        self.operations.explicit_inspection = explicit;
        self.submit_operation(
            admission,
            OperationInput::InspectRecovery {
                path: Path::new(&self.vault_path).to_path_buf(),
            },
        );
    }
    pub(super) fn start_verify(&mut self) {
        if self.session.is_none() || !matches!(self.panel, Panel::Vault) {
            return;
        }
        let Some(admission) = self.admit_operation(
            OperationKind::VerifyCurrent,
            "保险库已保存，磁盘文件校验通过",
        ) else {
            return;
        };
        let session = self.session.take().expect("live session admitted");
        self.submit_operation(admission, OperationInput::VerifyCurrent { session });
    }
    pub(super) fn start_mutation(&mut self, mutation: VaultMutation, success: &'static str) {
        if self.session.is_none() {
            return;
        }
        let Some(admission) = self.admit_operation(OperationKind::MutateAndSave, success) else {
            return;
        };
        let session = self.session.take().expect("live session admitted");
        self.submit_operation(
            admission,
            OperationInput::MutateAndSave { session, mutation },
        );
    }
    pub(super) fn finish_operation_signal(&mut self, signal: OperationSignal) {
        let id = match signal {
            OperationSignal::PhaseChanged(id)
            | OperationSignal::Finished(id)
            | OperationSignal::Drained(id) => id,
        };
        if !self.operations.active.as_ref().is_some_and(|a| a.id == id) {
            // A disposal job may be independent of a visible operation. Its
            // terminal metadata is still consumed before another admission.
            if let Some(service) = &self.operations.service {
                let _ = service.take_terminal(id);
            }
            self.refresh_operation_drain();
            self.advance_close();
            return;
        }
        if matches!(signal, OperationSignal::Finished(_)) {
            self.install_operation_result(id);
        }
        if matches!(signal, OperationSignal::Drained(_)) {
            // Durable drain may be observed before a delayed Finished message.
            // Install retained risk metadata before releasing the UI barrier.
            self.install_operation_result(id);
            if !self.operations.active.as_ref().is_some_and(|a| a.finished) {
                return;
            }
            self.operations.active = None;
            if self.session.is_none()
                && matches!(self.operations.session,SessionUi::Leased(leased) if leased==id)
            {
                self.operations.session = SessionUi::Locked;
            }
            self.refresh_operation_drain();
            self.advance_close();
            if self.operations.inspect_after_drain && self.operations.close_window.is_none() {
                self.operations.inspect_after_drain = false;
                self.start_inspection(true);
            }
        }
    }
    fn install_operation_result(&mut self, id: OperationId) {
        if self.operations.active.as_ref().is_some_and(|a| a.finished) {
            return;
        }
        let snapshot = self.operations.authority.snapshot(Instant::now());
        if snapshot.occupied == Some(id)
            && !matches!(
                snapshot.phase,
                Some(work::Phase::Finished | work::Phase::Draining)
            )
        {
            // Slot storage precedes authoritative result readiness. An early
            // poll must not consume the terminal or dispose the sole result.
            return;
        }
        let Some(service) = self.operations.service.as_ref() else {
            return;
        };
        let terminal = service.take_terminal(id);
        if terminal.is_none() {
            return;
        }
        if let Some(active) = &mut self.operations.active {
            active.finished = true;
        }
        let now = Instant::now();
        let current_authority = self.operations.authority.snapshot(now);
        let current = current_authority.stamp;
        // Captured user activity can advance the shared deadline while this
        // session is leased. Completion preserves that deadline; it never
        // restores the older admission value or counts as new activity.
        let deadline = current_authority.live.map(|live| live.deadline);
        let lease = self
            .operations
            .authority
            .claim_adoption(id, current, now)
            .ok();
        let mut payload = lease.as_ref().and_then(|lease| service.take_result(lease));
        if lease.is_none() {
            service.discard(id);
        }
        let (kind, success) = self
            .operations
            .active
            .as_ref()
            .map(|a| (a.kind, a.success))
            .expect("matching active");
        let presentation = lease.as_ref().is_some_and(|lease| lease.presentation);
        if let Some(payload) = payload.as_mut() {
            if let Some(session) = payload.session.take() {
                let replacing_session = current.session.is_some_and(|original| {
                    original.instance != session.operation_binding().instance
                });
                let until = deadline
                    .unwrap_or(now + Duration::from_secs(u64::from(self.idle_minutes) * 60));
                if lease.as_ref().is_some_and(|lease| {
                    self.operations.authority.install_session(
                        lease,
                        session.operation_binding(),
                        until,
                        now,
                    )
                }) {
                    self.session = Some(session);
                    self.operations.session = SessionUi::Present;
                    self.view_index = payload.ui_index.take();

                    if matches!(kind, OperationKind::Open | OperationKind::Create)
                        || (kind == OperationKind::RestoreCurrent && replacing_session)
                    {
                        if matches!(kind, OperationKind::Open | OperationKind::Create) {
                            self.last_activity = now;
                        }
                        self.revoke_clipboard_session();
                        self.clipboard_session = Some(platform::begin_clipboard_session());
                        self.panel = Panel::Vault;
                        self.nav = NavFilter::All;
                        self.category_page = 0;
                        self.card_page = 0;
                        self.selected = None;
                        self.search.clear();
                        self.dismiss_recovery();
                    }
                } else {
                    payload.session = Some(session);
                }
            }
            if presentation {
                if let Some(preview) = payload.preview.take() {
                    if let Panel::Import(state) = &mut self.panel {
                        state.preview = Some(preview);
                        if kind == OperationKind::AnalyzeImport {
                            state.resolutions.clear();
                            state.candidate_pages.clear();
                            state.candidate_focus = None;
                            self.import_page = 0;
                            state.apply_updates = true;
                        }
                    } else {
                        payload.preview = Some(preview);
                    }
                }
                match std::mem::replace(&mut payload.value, OperationValue::None) {
                    OperationValue::Entry(id) => {
                        self.selected = Some(id);
                        self.panel = Panel::Vault;
                    }
                    OperationValue::Mutation(effect) => {
                        use crate::operations::MutationEffect;
                        if matches!(
                            effect,
                            MutationEffect::Recycle
                                | MutationEffect::Restore
                                | MutationEffect::DeleteEntry
                        ) {
                            self.selected = None;
                        }
                        if matches!(
                            effect,
                            MutationEffect::DeleteEntry | MutationEffect::DeleteCategory
                        ) {
                            self.panel = Panel::Vault;
                        }
                        if matches!(effect, MutationEffect::DeleteCategory) {
                            self.nav = NavFilter::All;
                        }
                    }
                    OperationValue::ImportRetry(options) => {
                        if let Panel::Import(state) = &mut self.panel {
                            state.resolutions = options.conflict_resolutions;
                            state.apply_updates = options.apply_update_candidates;
                        }
                    }
                    OperationValue::ImportReport(report) => {
                        self.status = format!(
                            "已导入：新增 {}，更新 {}，跳过 {}，无效 {}，延后更新 {}。再次操作请重新分析源文件。",
                            report.added,
                            report.updated,
                            report.skipped,
                            report.invalid,
                            report.updates_deferred
                        );
                    }
                    OperationValue::ExportCount(count) => self.finish_plaintext_export(Ok(count)),
                    OperationValue::Recovery(listing) => {
                        if listing.maintenance_required || self.operations.explicit_inspection {
                            self.recovery = Some(recovery::RecoveryState {
                                generation: self.recovery_generation,
                                listing,
                                source: String::new(),
                                destination: String::new(),
                                password: zeroize::Zeroizing::new(String::new()),
                            });
                            self.status = "请检查恢复材料；未自动选择或修改任何文件".into();
                        } else {
                            self.status = "文件检查完成，可解锁或创建保险库".into();
                        }
                    }
                    OperationValue::OutputPath(path) if kind == OperationKind::RestoreNew => {
                        self.dismiss_recovery();
                        self.vault_path = path.display().to_string();
                        self.auth_options_open = true;
                    }
                    _ => {}
                }
            }
        }
        if self.session.is_some() {
            self.filtered_entries = self
                .view_index
                .as_ref()
                .filter(|_| !self.search.is_empty())
                .map(|i| i.filter(&self.nav, &self.search));
        }
        self.clamp_view_pages();
        if let Some(payload) = payload {
            self.retire_operation_payload(payload);
        }
        if let Some(terminal) = terminal {
            match terminal {
                TerminalOutcome::ReadFinished => {
                    if presentation
                        && !matches!(
                            kind,
                            OperationKind::ExportCsv
                                | OperationKind::ApplyImport
                                | OperationKind::InspectRecovery
                        )
                        && !(kind == OperationKind::Open && self.session.is_none())
                    {
                        self.status = success.into();
                    }
                }
                TerminalOutcome::CsvFinished { count } => {
                    self.operations.commit_notice = Some(format!(
                        "明文 CSV 导出已验证完成：{count} 条。请妥善保管导出文件。"
                    ));
                    if presentation {
                        self.finish_plaintext_export(Ok(count));
                    }
                }
                TerminalOutcome::VerifiedCommit { maintenance: None } => {
                    self.operations.commit_notice = Some("已开始的加密写入已完成磁盘验证。".into());
                    if presentation && kind != OperationKind::ApplyImport {
                        self.status = success.into();
                    }
                }
                TerminalOutcome::VerifiedCommit {
                    maintenance: Some(warning),
                } => {
                    self.operations.commit_notice =
                        Some("加密内容已验证保存，但维护步骤仍需检查。".into());
                    self.operations.note_failure(warning.clone());
                    self.status = warning;
                }
                TerminalOutcome::CancelledBeforeClaim => {
                    if presentation {
                        self.status = "操作已取消，未开始目标写入".into();
                    }
                }
                TerminalOutcome::Rejected(error) => {
                    let persistent = error.invalidates_session()
                        || matches!(error, AppError::Export(_) | AppError::ImportCleanup(_));
                    if error.invalidates_session() {
                        self.handle_persist_error(&error);
                    }
                    match error {
                        AppError::Export(failure) => {
                            self.finish_plaintext_export(Err(AppError::Export(failure)))
                        }
                        AppError::ImportCleanup(failure) => {
                            let warning = failure.to_string();
                            self.operations.note_failure(warning.clone());
                            self.status = warning;
                        }
                        error if persistent || presentation => {
                            self.status = format!("操作未完成：{error}")
                        }
                        _ => {}
                    }
                }
                TerminalOutcome::WorkerFailed {
                    claimed,
                    context,
                    snapshot_cleanup,
                } => {
                    if claimed && let Some(target) = context.csv_target {
                        self.finish_plaintext_export(Err(AppError::Export(Box::new(
                            crate::export::ExportFailure {
                                target,
                                stage: crate::export::Stage::Interrupted,
                                cause: crate::export::Cause::Interrupted,
                                output: crate::export::OutputDisposition::MayRemain {
                                    observation: crate::export::Observation {
                                        target: crate::export::ObservedTarget::Unobserved,
                                        error: None,
                                    },
                                },
                            },
                        ))));
                    }
                    if claimed && let Some(target) = context.encrypted_target {
                        self.recovery_notice=Some(crate::storage::recovery::RecoveryInfo{destination:target,stage:"后台写入中断".into(),current:crate::storage::recovery::CurrentObservation::Unreadable,artifacts:Vec::new(),detail:"目标写入已取得授权但未获得终态，不能断言未修改。请保留现有文件和恢复材料。".into()});
                    }
                    let mut warning = if claimed {
                        "后台写入中断，目标状态未确认；请保留目标并检查恢复材料"
                    } else {
                        "后台处理发生错误，未开始目标写入；请重新启动软件"
                    }
                    .to_string();
                    if let Some(cleanup) = snapshot_cleanup {
                        warning.push('；');
                        warning.push_str(&cleanup.to_string());
                    }
                    self.operations.note_failure(warning);
                    self.mask_for_operation_lock("后台处理已停止；正在释放所持材料", false);
                }
            }
        }
    }
    fn retire_operation_payload(&mut self, mut payload: OperationPayload) {
        if payload.session.is_none() && payload.preview.is_none() && payload.ui_index.is_none() {
            return;
        }
        self.retire_operation_ui(RetiredUi {
            session: payload.session.take(),
            preview: payload.preview.take(),
            ui_index: payload.ui_index.take(),
            ..RetiredUi::default()
        });
    }
    pub(super) fn retire_operation_ui(&mut self, retired: RetiredUi) {
        if retired.is_empty() {
            return;
        }
        let Some(service) = &self.operations.service else {
            self.operations.launch_retired = Some(retired);
            return;
        };
        match service.retire_ui(retired) {
            Ok(Some(observer)) => {
                self.operations.task = Some(Task::run(observer, Message::OperationSignal))
            }
            Ok(None) => {}
            Err(retired) => {
                self.operations.launch_retired = Some(retired);
                self.operations.session = SessionUi::Locking;
            }
        }
    }
    pub(super) fn mask_for_operation_lock(&mut self, status: &str, revoke: bool) {
        if revoke {
            self.operations
                .authority
                .revoke(RevokeReason::Manual, Instant::now());
        }
        self.operations.session = SessionUi::Locking;
        let cut_secrets = self
            .pending_editor_cut
            .take()
            .map(|pending| (pending.change.original, pending.change.replacement));
        self.invalidate_picker();
        self.revoke_clipboard_session();
        self.context_open = false;
        let mut retired = RetiredUi {
            cut_secrets,
            session: self.session.take(),
            ui_index: self.view_index.take(),
            filtered_entries: self.filtered_entries.take(),
            passwords: [
                Some(zeroize::Zeroizing::new(std::mem::take(
                    &mut self.master_password,
                ))),
                Some(zeroize::Zeroizing::new(std::mem::take(
                    &mut self.confirm_password,
                ))),
                None,
                None,
            ],
            ..RetiredUi::default()
        };
        if let Some(mut revealed) = self.revealed.take() {
            retired.passwords[2] =
                Some(zeroize::Zeroizing::new(std::mem::take(&mut revealed.value)));
        }
        let panel = std::mem::replace(&mut self.panel, Panel::Vault);
        match panel {
            Panel::Import(mut state) => {
                retired.preview = state.preview.take();
                retired.passwords[3] = Some(zeroize::Zeroizing::new(std::mem::take(
                    &mut state.legacy_password,
                )));
            }
            Panel::Settings(mut state) => {
                retired.passwords[3] = Some(zeroize::Zeroizing::new(std::mem::take(
                    &mut state.restore_password,
                )))
            }
            Panel::Editor(mut state) => {
                retired.editor_secrets = Some((
                    zeroize::Zeroizing::new(std::mem::take(&mut state.password)),
                    zeroize::Zeroizing::new(std::mem::take(&mut state.notes)),
                ));
            }
            _ => {}
        }
        if let Some(mut recovery) = self.recovery.take() {
            retired.recovery_password = Some(std::mem::take(&mut recovery.password));
        }
        self.creating = false;
        self.selected = None;
        self.status = format!("{status}；已遮蔽，正在等待处理与清理完成");
        self.retire_operation_ui(retired);
        let epoch = self
            .operations
            .authority
            .snapshot(Instant::now())
            .stamp
            .epoch;
        if self.operations.launch_retired.is_none() && self.operations.failed_input.is_none() {
            self.operations.authority.ack_ui_detached(epoch);
        }
        if let Some(active) = &self.operations.active {
            self.operations.authority.cancel(active.id);
            if let Some(service) = &self.operations.service {
                service.discard(active.id);
            }
        }
        self.refresh_operation_drain();
    }
    pub(super) fn refresh_operation_drain(&mut self) {
        if let Some(retired) = self.operations.launch_retired.take() {
            self.retire_operation_ui(retired);
            if self.operations.launch_retired.is_none() && self.operations.failed_input.is_none() {
                let epoch = self
                    .operations
                    .authority
                    .snapshot(Instant::now())
                    .stamp
                    .epoch;
                self.operations.authority.ack_ui_detached(epoch);
            }
        }
        let snapshot = self.operations.authority.snapshot(Instant::now());
        if snapshot.failed && self.operations.failure_notice.is_none() {
            self.operations
                .note_failure("后台服务无法继续接受工作；材料释放完成后请重新启动软件。".into());
        }
        if snapshot.masked
            && !matches!(
                self.operations.session,
                SessionUi::Locking | SessionUi::Locked
            )
        {
            self.mask_for_operation_lock("安全权限已撤销", false);
            return;
        }
        if snapshot.fully_locked && self.operations.launch_retired.is_none() {
            if matches!(self.operations.session, SessionUi::Locking) {
                self.operations.session = SessionUi::Locked;
                self.status = if let Some(notice) = &self.operations.commit_notice {
                    format!("保险库已锁定，后台材料已释放。{notice}")
                } else {
                    "保险库已锁定，后台材料已释放".into()
                };
            }
            if self.operations.close_window.is_none() && snapshot.masked {
                let _ = self
                    .operations
                    .authority
                    .resume_locked_after_keep_open(Instant::now());
            }
        }
    }
}

impl App {
    pub(super) fn start_import_analysis(&mut self) {
        if self.session.is_none() || !matches!(self.panel, Panel::Import(_)) {
            return;
        }
        let Some(admission) = self.admit_operation(
            OperationKind::AnalyzeImport,
            "分析完成；尚未写入保险库，请先检查预览",
        ) else {
            return;
        };
        let Panel::Import(state) = &mut self.panel else {
            unreachable!()
        };
        let path = Path::new(&state.path).to_path_buf();
        let password = zeroize::Zeroizing::new(std::mem::take(&mut state.legacy_password));
        let old_preview = state.preview.take();
        state.resolutions.clear();
        let session = self.session.take().expect("admitted live import session");
        self.submit_operation(
            admission,
            OperationInput::AnalyzeImport {
                session,
                path,
                password,
                old_preview,
            },
        );
    }
    pub(super) fn start_import_application(&mut self, id: Uuid) {
        if self.session.is_none() {
            return;
        }
        let Panel::Import(state) = &self.panel else {
            return;
        };
        let Some(preview) = state.preview.as_ref().filter(|p| p.id() == id) else {
            return;
        };
        let summary = preview.summary();
        if state.resolutions.len() < summary.conflicts + summary.locally_deleted {
            self.status = "请先为全部冲突和本地删除条目选择处理方式".into();
            return;
        }
        let Some(admission) = self.admit_operation(OperationKind::ApplyImport, "导入决定已处理")
        else {
            return;
        };
        let Panel::Import(state) = &mut self.panel else {
            unreachable!()
        };
        let preview = state.preview.take().expect("admitted preview");
        let options = ImportApplyOptions {
            preview_id: id,
            apply_update_candidates: state.apply_updates,
            conflict_resolutions: std::mem::take(&mut state.resolutions),
        };
        let session = self.session.take().expect("admitted live session");
        self.submit_operation(
            admission,
            OperationInput::ApplyImport {
                session,
                preview,
                options,
            },
        );
    }
    pub(super) fn start_backup(&mut self) {
        if self.session.is_none() || !matches!(self.panel, Panel::Settings(_)) {
            return;
        }
        let Some(admission) = self.admit_operation(OperationKind::Backup, "加密备份已创建")
        else {
            return;
        };
        let Panel::Settings(state) = &self.panel else {
            unreachable!()
        };
        let destination = Path::new(&state.backup_path).to_path_buf();
        let session = self.session.take().expect("admitted live session");
        self.submit_operation(
            admission,
            OperationInput::Backup {
                session,
                destination,
            },
        );
    }
    pub(super) fn start_restore_current(&mut self) {
        if self.session.is_none() {
            return;
        }
        let Panel::Settings(state) = &self.panel else {
            return;
        };
        if !state.confirm_restore {
            self.status = "请先确认替换当前保险库".into();
            return;
        }
        let Some(admission) = self.admit_operation(OperationKind::RestoreCurrent, "加密备份已恢复")
        else {
            return;
        };
        let Panel::Settings(state) = &mut self.panel else {
            unreachable!()
        };
        let source = Path::new(&state.restore_path).to_path_buf();
        let password = zeroize::Zeroizing::new(std::mem::take(&mut state.restore_password));
        state.confirm_restore = false;
        let session = self.session.take().expect("admitted live session");
        self.submit_operation(
            admission,
            OperationInput::RestoreCurrent {
                session,
                source,
                password,
            },
        );
    }
    pub(super) fn start_export(&mut self) {
        if self.export_notice.is_some() || self.session.is_none() {
            return;
        }
        let Panel::Settings(state) = &self.panel else {
            return;
        };
        if !state.confirm_plaintext {
            self.status = "请先确认明文 CSV 的风险".into();
            return;
        }
        let Some(admission) = self.admit_operation(OperationKind::ExportCsv, "明文导出已完成")
        else {
            return;
        };
        let Panel::Settings(state) = &mut self.panel else {
            unreachable!()
        };
        let destination = Path::new(&state.csv_path).to_path_buf();
        state.confirm_plaintext = false;
        let session = self.session.take().expect("admitted live session");
        self.submit_operation(
            admission,
            OperationInput::ExportCsv {
                session,
                destination,
                acknowledgement: PlaintextExportAcknowledgement::user_confirmed_risk(),
            },
        );
    }
    pub(super) fn start_restore_new(&mut self, generation: u64) {
        if !self.ensure_monitor_ready(cfg!(windows)) || self.session.is_some() {
            return;
        }
        let Some(state) = self
            .recovery
            .as_ref()
            .filter(|s| s.generation == generation)
        else {
            return;
        };
        if state.source.is_empty() || state.destination.is_empty() || state.password.is_empty() {
            self.status = "请选择源副本、新文件位置并输入该副本的主密码".into();
            return;
        }
        let Some(admission) = self.admit_operation(
            OperationKind::RestoreNew,
            "选定副本已验证并恢复到新文件。原文件与恢复材料均已保留；请输入主密码解锁新文件。",
        ) else {
            return;
        };
        let state = self.recovery.as_mut().expect("admitted recovery form");
        let source = Path::new(&state.source).to_path_buf();
        let destination = Path::new(&state.destination).to_path_buf();
        let password = std::mem::take(&mut state.password);
        self.submit_operation(
            admission,
            OperationInput::RestoreNew {
                source,
                destination,
                password,
            },
        );
    }
    pub(super) fn cancel_operation(&mut self) {
        let snapshot = self.operations.authority.snapshot(Instant::now());
        if let Some(id) = snapshot.occupied {
            self.operations.authority.cancel(id);
        }
        self.operations.authority.change_form();
        self.status = if snapshot.phase == Some(work::Phase::Committing) {
            "已开始的写入仍在完成验证；关闭页面不会撤销已发布内容"
        } else {
            "正在取消；处理与材料清理完成前不能开始另一项操作"
        }
        .into();
    }
}

pub(super) fn form_edit(message: &Message) -> bool {
    matches!(
        message,
        Message::RecoverySourceChanged(_, _)
            | Message::RecoveryDestinationChanged(_, _)
            | Message::RecoveryPasswordChanged(_, _)
            | Message::VaultPathChanged(_)
            | Message::MasterPasswordChanged(_)
            | Message::ConfirmPasswordChanged(_)
            | Message::ImportPathChanged(_)
            | Message::ImportLegacyPasswordChanged(_)
            | Message::ImportApplyUpdatesChanged(_, _)
            | Message::SetImportResolution(_, _, _)
            | Message::BackupPathChanged(_)
            | Message::RestorePathChanged(_)
            | Message::RestorePasswordChanged(_)
            | Message::ConfirmRestoreChanged(_)
            | Message::CsvPathChanged(_)
            | Message::ConfirmPlaintextChanged(_)
            | Message::EditorNameChanged(_)
            | Message::EditorWebsiteChanged(_)
            | Message::EditorUsernameChanged(_)
            | Message::EditorPasswordChanged(_)
            | Message::EditorNotesAction(_)
            | Message::EditorCategoryChanged(_)
            | Message::EditorFavoriteChanged(_)
    )
}

impl App {
    pub(super) fn retire_current_panel(&mut self) {
        let panel = std::mem::replace(&mut self.panel, Panel::Vault);
        let mut retired = RetiredUi::default();
        match panel {
            Panel::Import(mut state) => {
                retired.preview = state.preview.take();
                retired.passwords[3] = Some(zeroize::Zeroizing::new(std::mem::take(
                    &mut state.legacy_password,
                )));
            }
            Panel::Settings(mut state) => {
                retired.passwords[3] = Some(zeroize::Zeroizing::new(std::mem::take(
                    &mut state.restore_password,
                )))
            }
            Panel::Editor(mut state) => {
                retired.editor_secrets = Some((
                    zeroize::Zeroizing::new(std::mem::take(&mut state.password)),
                    zeroize::Zeroizing::new(std::mem::take(&mut state.notes)),
                ))
            }
            _ => {}
        }
        self.retire_operation_ui(retired);
    }
}
