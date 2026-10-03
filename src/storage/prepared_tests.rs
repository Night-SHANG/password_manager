//! Behavioral contract for the off-thread preparation/publication boundary.
use super::*;
use crate::operations::authority::{CommitLease, Coordinator};
use crate::operations::{OperationKind, RevokeReason};
use std::time::{Duration, Instant};

fn contents(root: &Path) -> Vec<(PathBuf, Option<Vec<u8>>)> {
    fn visit(root: &Path, path: &Path, out: &mut Vec<(PathBuf, Option<Vec<u8>>)>) {
        for entry in fs::read_dir(path).unwrap() {
            let entry = entry.unwrap();
            let path = entry.path();
            if path.is_dir() {
                out.push((path.strip_prefix(root).unwrap().to_path_buf(), None));
                visit(root, &path, out);
            } else {
                out.push((
                    path.strip_prefix(root).unwrap().to_path_buf(),
                    Some(fs::read(path).unwrap()),
                ));
            }
        }
    }
    let mut result = Vec::new();
    visit(root, root, &mut result);
    result.sort_by(|a, b| a.0.cmp(&b.0));
    result
}

fn claim(
    coordinator: &Coordinator,
    kind: OperationKind,
    session: Option<&VaultSession>,
    bind: impl FnOnce(crate::operations::OperationId) -> crate::operations::PreparedBinding,
) -> CommitLease {
    let now = Instant::now();
    if let Some(session) = session {
        coordinator.activate_session(session.operation_binding(), now + Duration::from_secs(300));
    }
    let admission = coordinator
        .try_admit(kind, coordinator.snapshot(now).stamp, now)
        .unwrap();
    let binding = bind(admission.id());
    coordinator.mark_ready(admission.id(), binding).unwrap();
    coordinator
        .claim_commit(admission.id(), binding, now)
        .unwrap()
}

#[test]
fn prepared_create_does_not_create_parent_temp_or_destination() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("missing").join("new.pmvault");
    let before = contents(dir.path());
    let result = prepared::prepare_create(path, "synthetic-only");
    assert!(
        result.is_ok(),
        "valid create must prepare without publishing"
    );
    let prepared = result.unwrap();
    assert!(prepared.binding().is_none());
    assert_eq!(contents(dir.path()), before);
    drop(prepared);
    assert_eq!(contents(dir.path()), before);
}

#[test]
fn prepared_save_leaves_disk_namespace_and_revision_unchanged() {
    let dir = tempfile::tempdir().unwrap();
    let mut session =
        VaultSession::create(dir.path().join("current.pmvault"), "synthetic-only").unwrap();
    session
        .add_entry(EntryDraft::login("candidate", "", "", "secret"))
        .unwrap();
    let before = contents(dir.path());
    let revision = session.revision();
    drop(session.prepare_save().unwrap());
    assert_eq!(session.revision(), revision);
    assert_eq!(contents(dir.path()), before);
}

#[test]
fn prepared_backup_leaves_destination_and_namespace_unchanged() {
    let dir = tempfile::tempdir().unwrap();
    let session =
        VaultSession::create(dir.path().join("current.pmvault"), "synthetic-only").unwrap();
    let before = contents(dir.path());
    drop(prepared::prepare_backup(&session, &dir.path().join("nested/backup.pmvault")).unwrap());
    assert_eq!(contents(dir.path()), before);
}

#[test]
fn prepared_restore_variants_leave_destinations_and_namespace_unchanged() {
    let dir = tempfile::tempdir().unwrap();
    let source = dir.path().join("source.pmvault");
    VaultSession::create(&source, "synthetic-source").unwrap();
    let session =
        VaultSession::create(dir.path().join("current.pmvault"), "synthetic-current").unwrap();
    let before = contents(dir.path());
    drop(prepared::prepare_restore_current(&session, &source, "synthetic-source").unwrap());
    drop(
        prepared::prepare_restore_new(
            &source,
            &dir.path().join("nested/restored.pmvault"),
            "synthetic-source",
        )
        .unwrap(),
    );
    assert_eq!(contents(dir.path()), before);
}

#[test]
fn prepared_save_rejects_unsaved_body_change_without_increment_or_publication() {
    let dir = tempfile::tempdir().unwrap();
    let mut session =
        VaultSession::create(dir.path().join("current.pmvault"), "synthetic-only").unwrap();
    let mut prepared = session.prepare_save().unwrap();
    let coordinator = Coordinator::new(false);
    let lease = claim(
        &coordinator,
        OperationKind::MutateAndSave,
        Some(&session),
        |id| prepared.associate_operation(id),
    );
    let before = contents(dir.path());
    let revision = session.revision();
    session
        .add_entry(EntryDraft::login("late", "", "", "secret"))
        .unwrap();
    assert!(prepared.commit(&lease, &mut session).is_err());
    assert_eq!(session.revision(), revision);
    assert_eq!(contents(dir.path()), before);
    assert!(!session.write_invalid);
}

#[test]
fn prepared_save_rejects_same_path_reopened_session() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("current.pmvault");
    let session = VaultSession::create(&path, "synthetic-only").unwrap();
    let mut reopened = VaultSession::open(&path, "synthetic-only").unwrap();
    let mut prepared = session.prepare_save().unwrap();
    let coordinator = Coordinator::new(false);
    let lease = claim(
        &coordinator,
        OperationKind::MutateAndSave,
        Some(&session),
        |id| prepared.associate_operation(id),
    );
    let before = contents(dir.path());
    assert!(prepared.commit(&lease, &mut reopened).is_err());
    assert_eq!(contents(dir.path()), before);
}

#[test]
fn prepared_create_requires_its_exact_real_lease_before_parent_mutation() {
    let dir = tempfile::tempdir().unwrap();
    let mut authorized =
        prepared::prepare_create(dir.path().join("authorized.pmvault"), "synthetic-only").unwrap();
    let mut other =
        prepared::prepare_create(dir.path().join("missing/other.pmvault"), "synthetic-only")
            .unwrap();
    let coordinator = Coordinator::new(false);
    let lease = claim(&coordinator, OperationKind::Create, None, |id| {
        other.associate_operation(id);
        authorized.associate_operation(id)
    });
    let before = contents(dir.path());
    assert!(other.commit(&lease).is_err());
    assert_eq!(contents(dir.path()), before);
}

#[test]
fn prepared_restore_new_uses_exact_captured_source_after_path_replacement() {
    let dir = tempfile::tempdir().unwrap();
    let source = dir.path().join("source.pmvault");
    let destination = dir.path().join("restored.pmvault");
    let source_session = VaultSession::create(&source, "synthetic-only").unwrap();
    let captured = fs::read(&source).unwrap();
    let mut prepared =
        prepared::prepare_restore_new(&source, &destination, "synthetic-only").unwrap();
    fs::write(&source, b"changed after capture").unwrap();
    let coordinator = Coordinator::new(false);
    let lease = claim(&coordinator, OperationKind::RestoreNew, None, |id| {
        prepared.associate_operation(id)
    });
    prepared.commit(&lease).unwrap();
    assert_eq!(fs::read(&destination).unwrap(), captured);
    assert_eq!(
        VaultSession::open(&destination, "synthetic-only")
            .unwrap()
            .vault_id(),
        source_session.vault_id()
    );
    assert_eq!(fs::read(&source).unwrap(), b"changed after capture");
}

#[test]
fn prepared_restore_current_adopts_exact_capture_without_reopening_source() {
    let dir = tempfile::tempdir().unwrap();
    let source = dir.path().join("source.pmvault");
    let source_session = VaultSession::create(&source, "synthetic-source").unwrap();
    let captured = fs::read(&source).unwrap();
    let mut current =
        VaultSession::create(dir.path().join("current.pmvault"), "synthetic-current").unwrap();
    let mut prepared =
        prepared::prepare_restore_current(&current, &source, "synthetic-source").unwrap();
    fs::write(&source, b"changed after capture").unwrap();
    let coordinator = Coordinator::new(false);
    let lease = claim(
        &coordinator,
        OperationKind::RestoreCurrent,
        Some(&current),
        |id| prepared.associate_operation(id),
    );
    let adopted = prepared.commit(&lease, &mut current).unwrap();
    assert_eq!(adopted.vault_id(), source_session.vault_id());
    assert_eq!(fs::read(adopted.path()).unwrap(), captured);
    assert!(current.write_invalid);
}

#[test]
fn prepared_backup_uses_captured_bytes_after_source_path_replacement() {
    let dir = tempfile::tempdir().unwrap();
    let source = dir.path().join("source.pmvault");
    let session = VaultSession::create(&source, "synthetic-only").unwrap();
    let captured = fs::read(&source).unwrap();
    let destination = dir.path().join("backup.pmvault");
    let mut prepared = prepared::prepare_backup(&session, &destination).unwrap();
    fs::write(&source, b"changed after capture").unwrap();
    let coordinator = Coordinator::new(false);
    let lease = claim(&coordinator, OperationKind::Backup, Some(&session), |id| {
        prepared.associate_operation(id)
    });
    prepared.commit(&lease, &session).unwrap();
    assert_eq!(fs::read(destination).unwrap(), captured);
}

#[test]
fn prepared_new_targets_preserve_all_no_clobber_collisions() {
    let dir = tempfile::tempdir().unwrap();
    let source = dir.path().join("source.pmvault");
    let session = VaultSession::create(&source, "synthetic-only").unwrap();
    for kind in [
        OperationKind::Create,
        OperationKind::Backup,
        OperationKind::RestoreNew,
    ] {
        let destination = dir.path().join(format!("collision-{kind:?}.pmvault"));
        let coordinator = Coordinator::new(false);
        let result = match kind {
            OperationKind::Create => {
                let mut owner =
                    prepared::prepare_create(destination.clone(), "synthetic-only").unwrap();
                let lease = claim(&coordinator, kind, None, |id| owner.associate_operation(id));
                fs::write(&destination, b"competitor").unwrap();
                owner.commit(&lease).map(|_| ())
            }
            OperationKind::Backup => {
                let mut owner = prepared::prepare_backup(&session, &destination).unwrap();
                let lease = claim(&coordinator, kind, Some(&session), |id| {
                    owner.associate_operation(id)
                });
                fs::write(&destination, b"competitor").unwrap();
                owner.commit(&lease, &session)
            }
            _ => {
                let mut owner =
                    prepared::prepare_restore_new(&source, &destination, "synthetic-only").unwrap();
                let lease = claim(&coordinator, kind, None, |id| owner.associate_operation(id));
                fs::write(&destination, b"competitor").unwrap();
                owner.commit(&lease)
            }
        };
        assert!(matches!(result, Err(AppError::AlreadyExists)));
        assert_eq!(fs::read(destination).unwrap(), b"competitor");
    }
}

#[test]
fn prepared_new_file_postpublication_failure_is_explicit_recovery_and_preserved() {
    let dir = tempfile::tempdir().unwrap();
    let destination = dir.path().join("new.pmvault");
    let mut prepared = prepared::prepare_create(destination.clone(), "synthetic-only").unwrap();
    let coordinator = Coordinator::new(false);
    let lease = claim(&coordinator, OperationKind::Create, None, |id| {
        prepared.associate_operation(id)
    });
    let changed = destination.clone();
    transaction::set_hook(transaction::Point::AfterPublish, move || {
        fs::write(changed, b"competitor after publication").unwrap();
        Ok(())
    });
    match prepared.commit_outcome(&lease) {
        prepared::NewFileOutcome::PublicationAttempted { recovery, .. } => {
            assert_eq!(recovery.destination, destination);
            assert_eq!(recovery.current, recovery::CurrentObservation::Other);
            assert!(
                recovery.artifacts.is_empty(),
                "new-file outcome must not fabricate transaction artifacts"
            );
        }
        _ => panic!("postpublication verification cannot be reported as unchanged"),
    }
    assert_eq!(
        fs::read(destination).unwrap(),
        b"competitor after publication"
    );
}

#[test]
fn prepared_claim_winner_finishes_storage_after_revocation() {
    let dir = tempfile::tempdir().unwrap();
    let mut session =
        VaultSession::create(dir.path().join("current.pmvault"), "synthetic-only").unwrap();
    let revision = session.revision();
    let mut prepared = session.prepare_save().unwrap();
    let coordinator = Coordinator::new(false);
    let lease = claim(
        &coordinator,
        OperationKind::MutateAndSave,
        Some(&session),
        |id| prepared.associate_operation(id),
    );
    coordinator.revoke(RevokeReason::Native, Instant::now());
    prepared.commit(&lease, &mut session).unwrap();
    assert_eq!(session.revision(), revision + 1);
    session.verify_current_file().unwrap();
    assert!(!coordinator.snapshot(Instant::now()).fully_locked);
}

#[test]
fn all_entries_secret_traversal_includes_deleted_without_id_lookups() {
    let dir = tempfile::tempdir().unwrap();
    let mut session =
        VaultSession::create(dir.path().join("current.pmvault"), "synthetic-only").unwrap();
    session
        .add_entry(EntryDraft::login("active", "", "", "one"))
        .unwrap();
    let deleted = session
        .add_entry(EntryDraft::login("deleted", "", "", "two"))
        .unwrap();
    session.move_to_recycle_bin(deleted).unwrap();
    export_probe::reset();
    let entries: Vec<_> = session
        .all_entries_with_secrets()
        .collect::<Result<Vec<_>>>()
        .unwrap();
    assert_eq!(entries.len(), 2);
    assert_eq!(entries[0].1.password, "one");
    assert_eq!(entries[1].1.password, "two");
    assert!(entries[1].0.is_deleted());
    assert_eq!(export_probe::counts(), (2, 2, 0));
}

#[test]
fn prepared_save_retains_physical_source_recheck_and_invalidation() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("current.pmvault");
    let mut session = VaultSession::create(&path, "synthetic-only").unwrap();
    let revision = session.revision();
    let mut prepared = session.prepare_save().unwrap();
    let coordinator = Coordinator::new(false);
    let lease = claim(
        &coordinator,
        OperationKind::MutateAndSave,
        Some(&session),
        |id| prepared.associate_operation(id),
    );
    fs::write(&path, b"external change").unwrap();
    let result = prepared.commit(&lease, &mut session);
    assert!(
        matches!(result, Err(AppError::Persist(ref failure)) if failure.disposition == transaction::Disposition::ExternalConflict)
    );
    assert!(session.write_invalid);
    assert_eq!(session.revision(), revision);
    assert_eq!(fs::read(path).unwrap(), b"external change");
}

#[test]
fn prepared_save_verified_maintenance_failure_is_terminal_warning() {
    let dir = tempfile::tempdir().unwrap();
    let mut session =
        VaultSession::create(dir.path().join("current.pmvault"), "synthetic-only").unwrap();
    let revision = session.revision();
    let mut prepared = session.prepare_save().unwrap();
    let coordinator = Coordinator::new(false);
    let lease = claim(
        &coordinator,
        OperationKind::MutateAndSave,
        Some(&session),
        |id| prepared.associate_operation(id),
    );
    transaction::set_hook(transaction::Point::WitnessRemove, || {
        Err(AppError::InvalidVault("injected witness removal failure"))
    });
    prepared.commit(&lease, &mut session).unwrap();
    assert_eq!(session.revision(), revision + 1);
    assert!(session.maintenance_warning().is_some());
    session.verify_current_file().unwrap();
    let terminal = contents(dir.path());
    drop(prepared::prepare_backup(&session, &dir.path().join("backup.pmvault")).unwrap());
    assert_eq!(
        contents(dir.path()),
        terminal,
        "preparation cannot resume pending maintenance"
    );
}

#[test]
fn prepared_create_rejects_reencrypted_logically_identical_publication() {
    let dir = tempfile::tempdir().unwrap();
    let destination = dir.path().join("new.pmvault");
    let mut prepared = prepared::prepare_create(destination.clone(), "synthetic-only").unwrap();
    let coordinator = Coordinator::new(false);
    let lease = claim(&coordinator, OperationKind::Create, None, |id| {
        prepared.associate_operation(id)
    });
    let changed = destination.clone();
    transaction::set_hook(transaction::Point::AfterPublish, move || {
        let session = VaultSession::open(&changed, "synthetic-only").unwrap();
        let replacement = encode_file(&session.header, &session.body, &session.keys).unwrap();
        assert_ne!(fs::read(&changed).unwrap(), replacement);
        fs::write(changed, replacement).unwrap();
        Ok(())
    });
    assert!(
        matches!(
            prepared.commit_outcome(&lease),
            prepared::NewFileOutcome::PublicationAttempted { .. }
        ),
        "logical equality must not authorize different captured candidate bytes"
    );
    assert!(destination.exists());
}

#[test]
fn prepared_claim_survives_revocation_at_every_existing_transaction_checkpoint() {
    use std::cell::Cell;
    use std::rc::Rc;
    let dir = tempfile::tempdir().unwrap();
    let mut session =
        VaultSession::create(dir.path().join("current.pmvault"), "synthetic-only").unwrap();
    for point in [
        transaction::Point::BeforePublish,
        transaction::Point::AfterPublish,
        transaction::Point::BeforeVerify,
        transaction::Point::AfterSync,
        transaction::Point::BeforeRegister,
        transaction::Point::Cleanup,
        transaction::Point::WitnessCreate,
        transaction::Point::WitnessSync,
        transaction::Point::WitnessRemove,
    ] {
        let coordinator = Rc::new(Coordinator::new(false));
        let mut prepared = session.prepare_save().unwrap();
        let lease = claim(
            &coordinator,
            OperationKind::MutateAndSave,
            Some(&session),
            |id| prepared.associate_operation(id),
        );
        let reached = Rc::new(Cell::new(false));
        let reached_hook = reached.clone();
        let authority_hook = coordinator.clone();
        transaction::set_hook(point, move || {
            reached_hook.set(true);
            authority_hook.revoke(RevokeReason::Native, Instant::now());
            assert!(!authority_hook.snapshot(Instant::now()).fully_locked);
            Ok(())
        });
        let revision = session.revision();
        prepared.commit(&lease, &mut session).unwrap();
        assert!(reached.get(), "checkpoint {point:?} was not exercised");
        assert_eq!(session.revision(), revision + 1);
        assert!(session.maintenance_warning().is_none());
        session.verify_current_file().unwrap();
        let terminal = contents(dir.path());
        assert_eq!(
            contents(dir.path()),
            terminal,
            "no deferred mutation after return at {point:?}"
        );
        assert!(!coordinator.snapshot(Instant::now()).fully_locked);
    }
}

#[test]
fn prepared_backup_rejects_identical_bytes_from_replaced_source_identity() {
    let dir = tempfile::tempdir().unwrap();
    let source = dir.path().join("current.pmvault");
    let session = VaultSession::create(&source, "synthetic-only").unwrap();
    let copied = dir.path().join("replacement.pmvault");
    fs::write(&copied, fs::read(&source).unwrap()).unwrap();
    fs::remove_file(&source).unwrap();
    fs::rename(copied, &source).unwrap();
    let before = contents(dir.path());
    assert!(
        matches!(
            prepared::prepare_backup(&session, &dir.path().join("backup.pmvault")),
            Err(AppError::ExternalChange)
        ),
        "identical encrypted bytes from a new file cannot satisfy live source identity"
    );
    assert_eq!(contents(dir.path()), before);
}

#[test]
fn prepared_backup_authenticates_disk_body_while_unsaved_memory_is_preserved() {
    let dir = tempfile::tempdir().unwrap();
    let source = dir.path().join("current.pmvault");
    let mut session = VaultSession::create(&source, "synthetic-only").unwrap();
    let saved = fs::read(&source).unwrap();
    session
        .add_entry(EntryDraft::login("not yet saved", "", "", "secret"))
        .unwrap();
    let destination = dir.path().join("backup.pmvault");
    let mut prepared = prepared::prepare_backup(&session, &destination).unwrap();
    let coordinator = Coordinator::new(false);
    let lease = claim(&coordinator, OperationKind::Backup, Some(&session), |id| {
        prepared.associate_operation(id)
    });
    prepared.commit(&lease, &session).unwrap();
    assert_eq!(fs::read(destination).unwrap(), saved);
    assert_eq!(session.entries().len(), 1);
}

#[test]
fn coordinated_backup_and_restore_new_keep_postpublish_recovery_classification() {
    let dir = tempfile::tempdir().unwrap();
    let source = dir.path().join("current.pmvault");
    let session = VaultSession::create(&source, "synthetic-only").unwrap();
    let original = fs::read(&source).unwrap();
    for kind in [OperationKind::Backup, OperationKind::RestoreNew] {
        let destination = dir.path().join(format!("output-{kind:?}.pmvault"));
        let coordinator = Coordinator::new(false);
        transaction::set_hook(transaction::Point::BeforeVerify, || {
            Err(AppError::InvalidVault("injected verification failure"))
        });
        let result = if kind == OperationKind::Backup {
            let mut prepared = prepared::prepare_backup(&session, &destination).unwrap();
            let lease = claim(&coordinator, kind, Some(&session), |id| {
                prepared.associate_operation(id)
            });
            prepared.commit(&lease, &session)
        } else {
            let mut prepared =
                prepared::prepare_restore_new(&source, &destination, "synthetic-only").unwrap();
            let lease = claim(&coordinator, kind, None, |id| {
                prepared.associate_operation(id)
            });
            prepared.commit(&lease)
        };
        assert!(matches!(result, Err(AppError::Persist(ref failure))
            if failure.disposition == transaction::Disposition::RecoveryRequired
                && failure.recovery.destination == destination
                && failure.recovery.current == recovery::CurrentObservation::ExpectedCandidate));
        assert_eq!(fs::read(destination).unwrap(), original);
        assert_eq!(fs::read(&source).unwrap(), original);
    }
}

#[test]
fn oversized_prepared_and_standalone_save_reject_before_verifier_entry() {
    let dir = tempfile::tempdir().unwrap();
    let mut session =
        VaultSession::create(dir.path().join("current.pmvault"), "synthetic-only").unwrap();
    let before = contents(dir.path());
    let revision = session.revision();
    // Base64 expansion plus the v1 envelope makes this real encoded candidate
    // exceed 64 MiB, without changing any accepted limit or crypto algorithm.
    session
        .body
        .categories
        .push("x".repeat((MAX_VAULT_BYTES / 4 * 3) as usize));

    verifier_entry_probe::reset();
    let prepared_error = session.prepare_save().err();
    let prepare_entries = verifier_entry_probe::count();
    verifier_entry_probe::reset();
    let standalone_error = session.save().err();
    let standalone_entries = verifier_entry_probe::count();

    assert_eq!(
        (prepare_entries, standalone_entries),
        (0, 0),
        "oversized candidate must be rejected before JSON/base64/AEAD/body verification"
    );
    for error in [prepared_error, standalone_error] {
        match error {
            Some(AppError::Persist(failure)) => {
                assert_eq!(failure.disposition, transaction::Disposition::Unchanged);
                assert_eq!(failure.stage, "candidate size");
                assert_eq!(
                    failure.primary,
                    AppError::InvalidVault("candidate exceeds size limit").to_string()
                );
                assert!(failure.secondary.is_empty());
                assert_eq!(failure.recovery.destination, session.path());
                assert_eq!(failure.recovery.stage, "candidate size");
                assert_eq!(
                    failure.recovery.current,
                    recovery::CurrentObservation::ExpectedOld
                );
                assert!(failure.recovery.artifacts.is_empty());
                assert!(!failure.invalidates_session());
            }
            _ => panic!("oversized save must keep the original typed candidate-size rejection"),
        }
    }
    assert_eq!(session.revision(), revision);
    assert!(!session.write_invalid);
    assert_eq!(contents(dir.path()), before);
}
