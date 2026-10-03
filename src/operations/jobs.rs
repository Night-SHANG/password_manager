//! Existing v1 operations. All preparation and cleanup here run on the one
//! worker. Public synchronous APIs remain separate library entry points.
use super::*;
use crate::{
    AppError,
    import::plan,
    storage::{VaultSession, prepared},
};
use std::path::Path;

pub(crate) fn execute(
    input: OperationInput,
    control: &WorkControl,
) -> (OperationPayload, TerminalOutcome) {
    control.progress(WorkPhase::Reading, 0, None);
    let (mut payload, outcome) = execute_inner(input, control);
    payload.ui_index = payload
        .session
        .as_ref()
        .map(crate::app::view_index::ViewIndex::build);
    (payload, outcome)
}
fn execute_inner(
    input: OperationInput,
    control: &WorkControl,
) -> (OperationPayload, TerminalOutcome) {
    match input {
        OperationInput::Dispose => (OperationPayload::empty(), TerminalOutcome::ReadFinished),
        OperationInput::InspectRecovery { path } => plain(control, || {
            Ok(OperationPayload {
                value: OperationValue::Recovery(inspect(&path)?),
                ..OperationPayload::empty()
            })
        }),
        OperationInput::Open { path, password } => plain(control, || {
            let listing = inspect(&path)?;
            if listing.maintenance_required {
                return Ok(OperationPayload {
                    value: OperationValue::Recovery(listing),
                    ..OperationPayload::empty()
                });
            }
            control.checkpoint()?;
            let session = VaultSession::open(path, &password)?;
            control.checkpoint()?;
            Ok(OperationPayload {
                session: Some(session),
                ..OperationPayload::empty()
            })
        }),
        OperationInput::Create {
            path,
            password,
            confirmation,
        } => {
            let result = (|| {
                control.checkpoint()?;
                if *password != *confirmation {
                    return Err(WorkError::Failure(AppError::Input(
                        "两次输入的主密码不一致".into(),
                    )));
                }
                drop(confirmation);
                control.progress(WorkPhase::Deriving, 0, None);
                let mut candidate = prepared::prepare_create(path, &password)?;
                control.checkpoint()?;
                let binding = candidate.associate_operation(control.id);
                let lease = claim(control, binding)?;
                let session = candidate.commit(&lease)?;
                Ok(OperationPayload {
                    session: Some(session),
                    ..OperationPayload::empty()
                })
            })();
            finish(result, true)
        }
        OperationInput::VerifyCurrent { session } => {
            with_session(session, control, false, |session| {
                session.verify_current_file()?;
                Ok(OperationPayload::empty())
            })
        }
        OperationInput::MutateAndSave {
            mut session,
            mutation,
        } => {
            let original = session.snapshot_body();
            let result = (|| {
                control.checkpoint()?;
                control.progress(WorkPhase::PreparingSave, 0, None);
                let value = mutate(&mut session, mutation)?;
                control.checkpoint()?;
                let mut candidate = session.prepare_save()?;
                let binding = candidate.associate_operation(control.id);
                let lease = claim(control, binding)?;
                candidate.commit(&lease, &mut session)?;
                Ok(OperationPayload {
                    value,
                    ..OperationPayload::empty()
                })
            })();
            if result.is_err() {
                session.restore_body(original);
            } else {
                drop(original);
            }
            finish_session(session, result, true)
        }
        OperationInput::AnalyzeImport {
            session,
            path,
            password,
            old_preview,
        } => {
            drop(old_preview);
            with_session(session, control, false, |session| {
                let batch = crate::import::stage_path_controlled(
                    &path,
                    (!password.is_empty()).then_some(password.as_str()),
                    control,
                )?;
                let preview = plan::build_preview_controlled(session, batch, control)?;
                control.checkpoint()?;
                Ok(OperationPayload {
                    preview: Some(preview),
                    ..OperationPayload::empty()
                })
            })
        }
        OperationInput::ApplyImport {
            mut session,
            preview,
            options,
        } => {
            let mut wrote = false;
            let result = (|| {
                control.checkpoint()?;
                let application =
                    plan::prepare_application(&mut session, &preview, &options, control)?;
                let result = if application.changed {
                    (|| {
                        let mut candidate = session.prepare_save()?;
                        let binding = candidate.associate_operation(control.id);
                        let lease = claim(control, binding)?;
                        candidate.commit(&lease, &mut session)?;
                        wrote = true;
                        Ok(())
                    })()
                } else {
                    control.checkpoint()
                };
                match result {
                    Ok(()) => Ok(OperationPayload {
                        value: OperationValue::ImportReport(
                            application.finish_success(&mut session)?,
                        ),
                        ..OperationPayload::empty()
                    }),
                    Err(error) => {
                        application.restore_original(&mut session)?;
                        Err(error)
                    }
                }
            })();
            // A safe unchanged failure keeps the same owned captured preview
            // and choices retryable, but only under their original full context.
            // Cancel/revoke or an invalidated/changed session never restores it.
            let retry = matches!(&result, Err(WorkError::Failure(error)) if !error.invalidates_session())
                && options.preview_id == preview.id()
                && preview.matches_session_context(&session);
            let (mut payload, outcome) = finish_session(session, result, wrote);
            if retry {
                payload.preview = Some(preview);
                payload.value = OperationValue::ImportRetry(options);
            }
            (payload, outcome)
        }
        OperationInput::Backup {
            session,
            destination,
        } => with_session(session, control, true, |session| {
            let mut candidate = prepared::prepare_backup(session, &destination)?;
            let binding = candidate.associate_operation(control.id);
            let lease = claim(control, binding)?;
            candidate.commit(&lease, session)?;
            Ok(OperationPayload {
                value: OperationValue::OutputPath(destination),
                ..OperationPayload::empty()
            })
        }),
        OperationInput::RestoreCurrent {
            mut session,
            source,
            password,
        } => {
            let result = (|| {
                control.checkpoint()?;
                control.progress(WorkPhase::Deriving, 0, None);
                let mut candidate =
                    prepared::prepare_restore_current(&session, &source, &password)?;
                let binding = candidate.associate_operation(control.id);
                let lease = claim(control, binding)?;
                let replacement = candidate.commit(&lease, &mut session)?;
                Ok(OperationPayload {
                    session: Some(replacement),
                    ..OperationPayload::empty()
                })
            })();
            finish_session(session, result, true)
        }
        OperationInput::RestoreNew {
            source,
            destination,
            password,
        } => {
            let result = (|| {
                control.checkpoint()?;
                control.progress(WorkPhase::Deriving, 0, None);
                let mut candidate =
                    prepared::prepare_restore_new(&source, &destination, &password)?;
                let binding = candidate.associate_operation(control.id);
                let lease = claim(control, binding)?;
                candidate.commit(&lease)?;
                Ok(OperationPayload {
                    value: OperationValue::OutputPath(destination),
                    ..OperationPayload::empty()
                })
            })();
            finish(result, true)
        }
        OperationInput::ExportCsv {
            session,
            destination,
            acknowledgement,
        } => with_session(session, control, false, |session| {
            let candidate =
                crate::export::PreparedCsv::new(session, destination, acknowledgement, control.id);
            let lease = claim(control, candidate.binding())?;
            let count = candidate.commit(session, &lease)?;
            Ok(OperationPayload {
                value: OperationValue::ExportCount(count),
                ..OperationPayload::empty()
            })
        }),
        #[cfg(test)]
        OperationInput::Test(job) => (job(control), TerminalOutcome::ReadFinished),
    }
}
fn claim(control: &WorkControl, binding: PreparedBinding) -> WorkResult<authority::CommitLease> {
    control.checkpoint()?;
    control
        .authority
        .mark_ready(control.id, binding)
        .map_err(|_| WorkError::Cancelled)?;
    let lease = control
        .authority
        .claim_commit(control.id, binding, Instant::now())
        .map_err(|_| WorkError::Cancelled)?;
    control.progress(WorkPhase::Publishing, 0, None);
    Ok(lease)
}
fn plain(
    control: &WorkControl,
    f: impl FnOnce() -> WorkResult<OperationPayload>,
) -> (OperationPayload, TerminalOutcome) {
    finish(control.checkpoint().and_then(|()| f()), false)
}
fn with_session(
    mut session: VaultSession,
    control: &WorkControl,
    writes: bool,
    f: impl FnOnce(&mut VaultSession) -> WorkResult<OperationPayload>,
) -> (OperationPayload, TerminalOutcome) {
    let result = control.checkpoint().and_then(|()| f(&mut session));
    finish_session(session, result, writes)
}
fn finish_session(
    session: VaultSession,
    result: WorkResult<OperationPayload>,
    writes: bool,
) -> (OperationPayload, TerminalOutcome) {
    let invalid = matches!(&result,Err(WorkError::Failure(error)) if error.invalidates_session());
    let maintenance = session.maintenance_warning().map(str::to_owned);
    let (mut payload, mut outcome) = finish(result, writes);
    if let TerminalOutcome::VerifiedCommit {
        maintenance: warning,
    } = &mut outcome
        && warning.is_none()
    {
        *warning = maintenance;
    }
    if !invalid && payload.session.is_none() {
        payload.session = Some(session);
    }
    (payload, outcome)
}
fn finish(
    result: WorkResult<OperationPayload>,
    writes: bool,
) -> (OperationPayload, TerminalOutcome) {
    match result {
        Ok(payload) => {
            let outcome = if let OperationValue::ExportCount(count) = &payload.value {
                TerminalOutcome::CsvFinished { count: *count }
            } else if writes {
                TerminalOutcome::VerifiedCommit {
                    maintenance: payload
                        .session
                        .as_ref()
                        .and_then(VaultSession::maintenance_warning)
                        .map(str::to_owned),
                }
            } else {
                TerminalOutcome::ReadFinished
            };
            (payload, outcome)
        }
        Err(WorkError::Cancelled) => (
            OperationPayload::empty(),
            TerminalOutcome::CancelledBeforeClaim,
        ),
        Err(WorkError::Failure(error)) => {
            (OperationPayload::empty(), TerminalOutcome::Rejected(error))
        }
    }
}
fn inspect(path: &Path) -> crate::Result<crate::storage::recovery::RecoveryListing> {
    match crate::storage::recovery::inspect(path) {
        Ok(listing) => Ok(listing),
        Err(error) => {
            let parent = path
                .parent()
                .filter(|p| !p.as_os_str().is_empty())
                .unwrap_or(Path::new("."));
            if matches!(std::fs::symlink_metadata(parent),Err(e) if e.kind()==std::io::ErrorKind::NotFound)
            {
                return Ok(Default::default());
            }
            Ok(crate::storage::recovery::RecoveryListing {
                maintenance_required: true,
                detail: format!(
                    "恢复材料检查不完整：{error}。可手动选择加密副本，原目录不会被修改。"
                ),
                ..Default::default()
            })
        }
    }
}
fn mutate(session: &mut VaultSession, mutation: VaultMutation) -> crate::Result<OperationValue> {
    let effect = match &mutation {
        VaultMutation::Upsert { .. } | VaultMutation::Favorite(..) => MutationEffect::Favorite,
        VaultMutation::Recycle(_) => MutationEffect::Recycle,
        VaultMutation::RestoreEntry(_) => MutationEffect::Restore,
        VaultMutation::DeleteEntry(_) => MutationEffect::DeleteEntry,
        VaultMutation::AddCategory(_) => MutationEffect::AddCategory,
        VaultMutation::MoveCategory(..) => MutationEffect::MoveCategory,
        VaultMutation::DeleteCategory(_) => MutationEffect::DeleteCategory,
    };
    match mutation {
        VaultMutation::Upsert { id, draft } => {
            crate::services::validate_entry_draft(&draft)?;
            let id = if let Some(id) = id {
                session.update_entry(id, *draft)?;
                id
            } else {
                session.add_entry(*draft)?
            };
            return Ok(OperationValue::Entry(id));
        }
        VaultMutation::Favorite(id, value) => session.set_favorite(id, value)?,
        VaultMutation::Recycle(id) => session.move_to_recycle_bin(id)?,
        VaultMutation::RestoreEntry(id) => session.restore_from_recycle_bin(id)?,
        VaultMutation::DeleteEntry(id) => session.permanently_delete(id)?,
        VaultMutation::AddCategory(name) => {
            let name = name.trim();
            if name.is_empty() || ["全部", "收藏", "回收站"].contains(&name) {
                return Err(AppError::Input(
                    "请输入有效且不与系统分组重复的分类名称".into(),
                ));
            }
            if session.categories().iter().any(|c| c == name) {
                return Err(AppError::Input("分类已存在".into()));
            }
            session.body_mut().categories.push(name.into());
        }
        VaultMutation::MoveCategory(name, up) => {
            let categories = &mut session.body_mut().categories;
            let index = categories
                .iter()
                .position(|c| *c == name)
                .ok_or_else(|| AppError::Input("分类不存在".into()))?;
            let target = if up {
                index.saturating_sub(1)
            } else {
                (index + 1).min(categories.len() - 1)
            };
            categories.swap(index, target);
        }
        VaultMutation::DeleteCategory(name) => {
            if name == "其他" {
                return Err(AppError::Input("默认分类不能删除".into()));
            }
            let body = session.body_mut();
            if !body.categories.iter().any(|c| c == "其他") {
                body.categories.push("其他".into());
            }
            for entry in &mut body.entries {
                if entry.category == name {
                    entry.category = "其他".into();
                    entry.updated_at_unix = std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .unwrap_or_default()
                        .as_secs();
                }
            }
            body.categories.retain(|c| *c != name);
        }
    }
    Ok(OperationValue::Mutation(effect))
}
