use super::recovery::Namespace;
use super::transaction::{Disposition, Point, set_hook};
use super::*;
use crate::platform::file_transaction as native;

fn fixture() -> (tempfile::TempDir, VaultSession) {
    let dir = tempfile::tempdir().unwrap();
    let vault =
        VaultSession::create(dir.path().join("synthetic.pmvault"), "synthetic-only").unwrap();
    (dir, vault)
}
fn kind(error: AppError) -> Disposition {
    match error {
        AppError::Persist(failure) => failure.disposition,
        other => panic!("missing disposition: {other}"),
    }
}
fn fault(point: Point) {
    set_hook(point, || {
        Err(AppError::Platform("synthetic deterministic fault".into()))
    });
}
fn replace(path: &Path, bytes: &[u8]) {
    let staged = path.with_file_name("synthetic-competing.tmp");
    fs::write(&staged, bytes).unwrap();
    fs::remove_file(path).unwrap();
    fs::rename(staged, path).unwrap();
}
fn retained_bytes(vault: &VaultSession, bytes: &[u8]) -> bool {
    recovery::inspect(vault.path())
        .unwrap()
        .artifacts
        .iter()
        .any(|a| fs::read(&a.path).is_ok_and(|value| value == bytes))
}
#[test]
fn transaction_rejected_before_publish_keeps_session_and_stable_lock() {
    let (_dir, mut vault) = fixture();
    let before = fs::read(vault.path()).unwrap();
    fault(Point::BeforePublish);
    assert_eq!(kind(vault.save().unwrap_err()), Disposition::Unchanged);
    assert_eq!(fs::read(vault.path()).unwrap(), before);
    assert!(
        Namespace::new(vault.path())
            .unwrap()
            .transaction_paths()
            .unwrap()
            .is_empty()
    );
    let lock_path = Namespace::new(vault.path()).unwrap().lock();
    let id = native::identity(&native::open_regular(&lock_path, false).unwrap(), true).unwrap();
    vault.save().unwrap();
    assert_eq!(
        id,
        native::identity(&native::open_regular(&lock_path, false).unwrap(), true).unwrap()
    );
}
#[test]
fn transaction_cooperative_lock_is_nonblocking_and_never_unlinked() {
    let (_dir, mut vault) = fixture();
    let ns = Namespace::new(vault.path()).unwrap();
    let held = native::Lock::acquire(&ns.lock()).unwrap();
    assert_eq!(kind(vault.save().unwrap_err()), Disposition::Busy);
    assert!(ns.lock().exists());
    drop(held);
    vault.save().unwrap();
    assert!(ns.lock().exists());
}
#[test]
fn transaction_actual_displaced_competitor_is_retained_and_session_invalidated() {
    let (_dir, mut vault) = fixture();
    let before = fs::read(vault.path()).unwrap();
    let path = vault.path().to_path_buf();
    set_hook(Point::BeforePublish, move || {
        replace(&path, b"late external encrypted placeholder");
        Ok(())
    });
    assert_eq!(
        kind(vault.save().unwrap_err()),
        Disposition::RecoveryRequired
    );
    assert!(retained_bytes(&vault, &before));
    assert!(retained_bytes(
        &vault,
        b"late external encrypted placeholder"
    ));
    assert!(vault.save().is_err());
}
#[test]
fn transaction_missing_target_never_falls_back_to_create() {
    let (_dir, mut vault) = fixture();
    let before = fs::read(vault.path()).unwrap();
    let path = vault.path().to_path_buf();
    set_hook(Point::BeforePublish, move || {
        fs::remove_file(path).unwrap();
        Ok(())
    });
    assert_eq!(
        kind(vault.save().unwrap_err()),
        Disposition::RecoveryRequired
    );
    assert!(!vault.path().exists());
    assert!(retained_bytes(&vault, &before));
}
#[test]
fn transaction_postpublication_failure_preserves_all_evidence() {
    for point in [Point::AfterPublish, Point::BeforeVerify, Point::Sync] {
        let (_dir, mut vault) = fixture();
        let before = fs::read(vault.path()).unwrap();
        fault(point);
        assert_eq!(
            kind(vault.save().unwrap_err()),
            Disposition::RecoveryRequired
        );
        assert!(retained_bytes(&vault, &before));
        let reopened = VaultSession::open(vault.path(), "synthetic-only").unwrap();
        assert_eq!(reopened.revision(), 2);
        assert_eq!(vault.revision(), 1);
        assert!(
            recovery::inspect(vault.path())
                .unwrap()
                .maintenance_required
        );
    }
}
#[test]
fn transaction_success_retention_is_bounded_and_preserves_foreign_bak() {
    let (dir, mut vault) = fixture();
    let foreign = dir.path().join("synthetic.pmvault.bak");
    fs::write(&foreign, b"unknown backup").unwrap();
    for _ in 0..5 {
        let before = fs::read(vault.path()).unwrap();
        vault.save().unwrap();
        assert!(vault.maintenance_warning().is_none());
        let listing = recovery::inspect(vault.path()).unwrap();
        assert!(!listing.maintenance_required);
        assert_eq!(
            Namespace::new(vault.path())
                .unwrap()
                .transaction_paths()
                .unwrap()
                .len(),
            1
        );
        assert!(retained_bytes(&vault, &before));
    }
    assert_eq!(fs::read(foreign).unwrap(), b"unknown backup");
}
#[test]
fn transaction_descriptor_and_cleanup_faults_are_success_with_bounded_block() {
    for point in [
        Point::BeforeRegister,
        Point::AfterRegister,
        Point::Cleanup,
        Point::AfterRetire,
    ] {
        let (_dir, mut vault) = fixture();
        vault.save().unwrap();
        let before = fs::read(vault.path()).unwrap();
        let revision = vault.revision();
        fault(point);
        vault.save().unwrap();
        assert_eq!(vault.revision(), revision + 1);
        assert!(vault.maintenance_warning().is_some(), "{point:?}");
        assert!(retained_bytes(&vault, &before));
        let count = Namespace::new(vault.path())
            .unwrap()
            .transaction_paths()
            .unwrap()
            .len();
        assert!(count <= 2);
        assert_eq!(
            kind(vault.save().unwrap_err()),
            Disposition::MaintenanceRequired
        );
        let mut restarted = VaultSession::open(vault.path(), "synthetic-only").unwrap();
        assert_eq!(
            kind(restarted.save().unwrap_err()),
            Disposition::MaintenanceRequired
        );
        assert_eq!(
            Namespace::new(vault.path())
                .unwrap()
                .transaction_paths()
                .unwrap()
                .len(),
            count
        );
    }
}
#[test]
fn transaction_unknown_children_modified_backup_and_symlinks_disable_deletion() {
    for mode in ["unknown", "changed", "malformed"] {
        let (_dir, mut vault) = fixture();
        vault.save().unwrap();
        let ns = Namespace::new(vault.path()).unwrap();
        let directory = ns.transaction_paths().unwrap().pop().unwrap();
        let current = fs::read(vault.path()).unwrap();
        match mode {
            "unknown" => {
                fs::write(directory.join("manual-export.pmvault"), b"do not delete").unwrap()
            }
            "changed" => fs::write(directory.join("previous.pmvault"), b"do not delete").unwrap(),
            _ => fs::write(directory.join("receipt.json"), b"broken descriptor").unwrap(),
        }
        assert_eq!(
            kind(vault.save().unwrap_err()),
            Disposition::MaintenanceRequired
        );
        assert_eq!(fs::read(vault.path()).unwrap(), current);
        assert!(directory.exists());
    }
}
#[cfg(unix)]
#[test]
fn transaction_final_symlink_and_hardlink_targets_fail_closed() {
    use std::os::unix::fs::symlink;
    let (dir, mut vault) = fixture();
    let original = fs::read(vault.path()).unwrap();
    let alias = dir.path().join("alias.pmvault");
    fs::hard_link(vault.path(), &alias).unwrap();
    assert_eq!(
        kind(vault.save().unwrap_err()),
        Disposition::ExternalConflict
    );
    assert_eq!(fs::read(alias).unwrap(), original);
    let link = dir.path().join("symlink.pmvault");
    symlink(vault.path(), &link).unwrap();
    assert!(VaultSession::open(link, "synthetic-only").is_err());
}
#[test]
fn transaction_overwrite_restore_authenticates_captured_source_and_destination() {
    let (dir, mut target) = fixture();
    let source = dir.path().join("source.pmvault");
    let source_vault = VaultSession::create(&source, "source-only").unwrap();
    let expected = fs::read(&source).unwrap();
    let old = fs::read(target.path()).unwrap();
    let source_path = source.clone();
    set_hook(Point::BeforePublish, move || {
        replace(&source_path, b"source replaced after capture");
        Ok(())
    });
    let adopted = target.restore_over_current(&source, "source-only").unwrap();
    assert_eq!(adopted.vault_id(), source_vault.vault_id());
    assert_eq!(fs::read(adopted.path()).unwrap(), expected);
    assert!(retained_bytes(&adopted, &old));
    assert!(target.save().is_err());
    assert_eq!(fs::read(source).unwrap(), b"source replaced after capture");
}
#[test]
fn transaction_revision_overflow_preserves_all_paths() {
    let (_dir, mut vault) = fixture();
    let before = fs::read(vault.path()).unwrap();
    vault.header.revision = u64::MAX;
    assert!(vault.save().is_err());
    assert_eq!(fs::read(vault.path()).unwrap(), before);
    assert!(
        Namespace::new(vault.path())
            .unwrap()
            .transaction_paths()
            .unwrap()
            .is_empty()
    );
}

/// The child blocks on stdin only after announcing the exact injected boundary.
/// Killing it proves process termination behavior, not power-loss durability.
#[test]
fn transaction_process_kill_child() {
    let Ok(path) = std::env::var("PM_SYNTHETIC_KILL_PATH") else {
        return;
    };
    let point = match std::env::var("PM_SYNTHETIC_KILL_STAGE").unwrap().as_str() {
        "prepublish" => Point::BeforePublish,
        "afterpublish" => Point::AfterPublish,
        _ => Point::BeforeVerify,
    };
    let mut vault = VaultSession::open(path, "synthetic-only").unwrap();
    set_hook(point, || {
        use std::io::Write;
        println!("SYNTHETIC_TRANSACTION_BOUNDARY");
        std::io::stdout().flush().unwrap();
        let mut input = String::new();
        std::io::stdin().read_line(&mut input).unwrap();
        panic!("parent should kill this process");
    });
    let _ = vault.save();
    panic!("boundary not reached");
}
#[test]
fn transaction_process_kill_restart_lists_preimage_and_candidate_without_replay() {
    use std::io::{BufRead, BufReader};
    use std::process::{Command, Stdio};
    for stage in ["prepublish", "afterpublish", "beforeverify"] {
        let (_dir, vault) = fixture();
        let before = fs::read(vault.path()).unwrap();
        let mut child = Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "storage::transaction_tests::transaction_process_kill_child",
                "--nocapture",
            ])
            .env("PM_SYNTHETIC_KILL_PATH", vault.path())
            .env("PM_SYNTHETIC_KILL_STAGE", stage)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        let mut reader = BufReader::new(child.stdout.take().unwrap());
        let mut reached = false;
        loop {
            let mut line = String::new();
            if reader.read_line(&mut line).unwrap() == 0 {
                break;
            }
            if line.contains("SYNTHETIC_TRANSACTION_BOUNDARY") {
                reached = true;
                break;
            }
        }
        assert!(reached, "child exited before {stage}");
        child.kill().unwrap();
        assert!(!child.wait().unwrap().success());
        let live = fs::read(vault.path()).unwrap();
        let listing = recovery::inspect(vault.path()).unwrap();
        assert!(listing.maintenance_required);
        assert!(listing.artifacts.len() >= 3);
        assert!(retained_bytes(&vault, &before));
        assert_eq!(
            fs::read(vault.path()).unwrap(),
            live,
            "listing must not replay"
        );
        if stage == "prepublish" {
            assert_eq!(live, before);
        } else {
            assert_ne!(live, before);
        }
    }
}

#[test]
fn transaction_windows_partial_failure_namespace_models_require_observations() {
    // MODELS only: these file moves represent documented outcomes; they do not
    // reproduce Win32/NTFS internals or replace native sharing tests on Windows.
    for (code, changed, unchanged) in [
        (1175, false, true),
        (1176, false, true),
        (1177, false, false),
        (9999, false, false),
        (1175, true, false),
    ] {
        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("target");
        let transaction = dir.path().join("transaction");
        fs::create_dir(&transaction).unwrap();
        fs::write(&target, b"old").unwrap();
        fs::write(transaction.join("publish.pmvault"), b"candidate").unwrap();
        let old = recovery::FileRecord::capture(&target).unwrap();
        let publish = recovery::FileRecord::capture(&transaction.join("publish.pmvault")).unwrap();
        let record = recovery::Record {
            version: 1,
            transaction: Uuid::new_v4(),
            destination_key: "model".into(),
            directory_identity: native::identity(
                &native::open_directory(&transaction).unwrap(),
                false,
            )
            .unwrap(),
            old: old.clone(),
            previous: old,
            candidate: publish.clone(),
            publish,
        };
        if code == 1177 {
            fs::rename(&target, transaction.join("displaced.pmvault")).unwrap();
        }
        if changed {
            replace(&target, b"foreign");
        }
        let error = native::windows_publish_error(code);
        assert_eq!(
            transaction::unchanged_after_failure(&error, &record, &target, &transaction, true),
            unchanged,
            "Win32 model {code}, changed={changed}"
        );
        assert!(transaction.join("publish.pmvault").exists());
        if code == 1177 {
            assert!(!target.exists());
            assert_eq!(
                fs::read(transaction.join("displaced.pmvault")).unwrap(),
                b"old"
            );
        }
    }
}

#[test]
fn transaction_owned_backup_symlink_is_never_followed_or_deleted() {
    #[cfg(unix)]
    {
        use std::os::unix::fs::symlink;
        let (dir, mut vault) = fixture();
        vault.save().unwrap();
        let directory = Namespace::new(vault.path())
            .unwrap()
            .transaction_paths()
            .unwrap()
            .pop()
            .unwrap();
        let previous = directory.join("previous.pmvault");
        let foreign = dir.path().join("manual-export.pmvault");
        fs::write(&foreign, b"foreign bytes").unwrap();
        fs::remove_file(&previous).unwrap();
        symlink(&foreign, &previous).unwrap();
        assert_eq!(
            kind(vault.save().unwrap_err()),
            Disposition::MaintenanceRequired
        );
        assert_eq!(fs::read(foreign).unwrap(), b"foreign bytes");
        assert!(
            fs::symlink_metadata(previous)
                .unwrap()
                .file_type()
                .is_symlink()
        );
    }
}
#[test]
fn transaction_cleanup_prevalidation_never_deletes_unknown_children_or_only_preimage() {
    let (_dir, mut vault) = fixture();
    let old = fs::read(vault.path()).unwrap();
    let path = vault.path().to_path_buf();
    set_hook(Point::AfterRegister, move || {
        let directory = Namespace::new(&path)
            .unwrap()
            .transaction_paths()
            .unwrap()
            .pop()
            .unwrap();
        fs::write(directory.join("unknown.pmvault"), b"manual bytes").unwrap();
        Ok(())
    });
    vault.save().unwrap();
    assert!(vault.maintenance_warning().is_some());
    assert!(retained_bytes(&vault, &old));
    let directory = Namespace::new(vault.path())
        .unwrap()
        .transaction_paths()
        .unwrap()
        .pop()
        .unwrap();
    assert_eq!(
        fs::read(directory.join("unknown.pmvault")).unwrap(),
        b"manual bytes"
    );
    assert!(directory.join("candidate.pmvault").exists());
}
#[test]
fn transaction_old_registered_backup_survives_new_preimage_verification_failure() {
    let (_dir, mut vault) = fixture();
    vault.save().unwrap();
    let old_descriptor = Namespace::new(vault.path())
        .unwrap()
        .read_descriptor()
        .unwrap()
        .unwrap();
    let previous = Namespace::new(vault.path())
        .unwrap()
        .directory(old_descriptor.current.transaction)
        .join("previous.pmvault");
    let prior = fs::read(&previous).unwrap();
    let path = vault.path().to_path_buf();
    set_hook(Point::BeforeVerify, move || {
        let ns = Namespace::new(&path).unwrap();
        let current = ns.read_descriptor().unwrap().unwrap();
        let fresh = ns
            .transaction_paths()
            .unwrap()
            .into_iter()
            .find(|p| *p != ns.directory(current.current.transaction))
            .unwrap();
        fs::write(fresh.join("previous.pmvault"), b"staged-copy-corruption").unwrap();
        Ok(())
    });
    assert_eq!(
        kind(vault.save().unwrap_err()),
        Disposition::RecoveryRequired
    );
    assert_eq!(fs::read(previous).unwrap(), prior);
}

#[test]
fn transaction_primary_error_is_preserved_with_secondary_observation_failure() {
    let (_dir, mut vault) = fixture();
    let path = vault.path().to_path_buf();
    set_hook(Point::AfterPublish, move || {
        fs::remove_file(path).unwrap();
        Err(AppError::Platform("primary synthetic sync fault".into()))
    });
    let error = vault.save().unwrap_err();
    let AppError::Persist(failure) = error else {
        panic!()
    };
    assert!(failure.primary.contains("primary synthetic sync fault"));
    assert!(
        !failure.secondary.is_empty(),
        "failed current-file observation must not erase its secondary error"
    );
    assert_eq!(
        failure.recovery.current,
        recovery::CurrentObservation::Missing
    );
}
#[test]
fn transaction_late_sync_conflict_is_not_a_verified_success() {
    let (_dir, mut vault) = fixture();
    let path = vault.path().to_path_buf();
    set_hook(Point::AfterSync, move || {
        replace(&path, b"late during required sync");
        Ok(())
    });
    assert_eq!(
        kind(vault.save().unwrap_err()),
        Disposition::RecoveryRequired
    );
    assert_eq!(
        fs::read(vault.path()).unwrap(),
        b"late during required sync"
    );
}
#[test]
fn transaction_changed_descriptor_during_commit_is_preserved_with_warning() {
    let (_dir, mut vault) = fixture();
    vault.save().unwrap();
    let ns = Namespace::new(vault.path()).unwrap();
    let descriptor = ns.parent.join(format!("{}.success.json", ns.prefix()));
    let path = descriptor.clone();
    set_hook(Point::BeforeRegister, move || {
        fs::write(path, b"unexpected descriptor replacement").unwrap();
        Ok(())
    });
    vault.save().unwrap();
    assert!(vault.maintenance_warning().is_some());
    assert_eq!(
        fs::read(descriptor).unwrap(),
        b"unexpected descriptor replacement"
    );
    assert_eq!(
        Namespace::new(vault.path())
            .unwrap()
            .transaction_paths()
            .unwrap()
            .len(),
        2
    );
}

#[test]
fn review_b1_terminal_retention_sync_failure_blocks_next_save_and_restart() {
    for (prior_saves, point) in [
        (0, Point::FinalDirectorySync),
        (0, Point::FinalParentSync),
        (1, Point::CleanDescriptorSync),
        (1, Point::FinalDirectorySync),
        (1, Point::FinalParentSync),
    ] {
        let (_dir, mut vault) = fixture();
        for _ in 0..prior_saves {
            vault.save().unwrap();
        }
        let revision = vault.revision();
        fault(point);
        vault.save().unwrap();
        assert_eq!(vault.revision(), revision + 1);
        assert!(vault.maintenance_warning().is_some());
        let ns = Namespace::new(vault.path()).unwrap();
        let count = ns.transaction_paths().unwrap().len();
        assert_eq!(
            kind(vault.save().unwrap_err()),
            Disposition::MaintenanceRequired,
            "{point:?}"
        );
        let mut restarted = VaultSession::open(vault.path(), "synthetic-only").unwrap();
        assert_eq!(
            kind(restarted.save().unwrap_err()),
            Disposition::MaintenanceRequired,
            "restart {point:?}"
        );
        assert_eq!(ns.transaction_paths().unwrap().len(), count);
    }
}
#[test]
fn review_b3_overlimit_candidate_rejected_before_namespace_mutation() {
    let (dir, mut vault) = fixture();
    let old = fs::read(vault.path()).unwrap();
    let count = fs::read_dir(dir.path()).unwrap().count();
    let oversized = vec![0; MAX_VAULT_BYTES as usize + 1];
    let result = transaction::commit(
        transaction::SourceExpectation {
            target: vault.path(),
            hash: vault.source_hash,
            identity: vault.source_identity,
        },
        &oversized,
        |_| Ok(()),
        |_| Ok(()),
    );
    assert!(result.is_err());
    assert_eq!(
        fs::read_dir(dir.path()).unwrap().count(),
        count,
        "predictable size rejection created transaction/lock material"
    );
    assert_eq!(fs::read(vault.path()).unwrap(), old);
    vault.save().unwrap();
    assert!(vault.maintenance_warning().is_none());
}
#[test]
fn review_b3_maximum_candidate_reaches_authentication_without_exceeding_limit() {
    let (_dir, vault) = fixture();
    let maximum = vec![0; MAX_VAULT_BYTES as usize];
    let called = std::cell::Cell::new(false);
    let result = transaction::commit(
        transaction::SourceExpectation {
            target: vault.path(),
            hash: vault.source_hash,
            identity: vault.source_identity,
        },
        &maximum,
        |_| Ok(()),
        |_| {
            called.set(true);
            Err(AppError::InvalidVault(
                "synthetic candidate authentication rejection",
            ))
        },
    );
    assert!(called.get());
    assert!(result.is_err());
    assert!(
        Namespace::new(vault.path())
            .unwrap()
            .transaction_paths()
            .unwrap()
            .is_empty()
    );
}

#[test]
fn review_b2_missing_destination_still_lists_retained_evidence() {
    let (_dir, mut vault) = fixture();
    fault(Point::AfterPublish);
    assert!(vault.save().is_err());
    let expected = recovery::inspect(vault.path()).unwrap();
    fs::remove_file(vault.path()).unwrap();
    let actual = recovery::inspect(vault.path()).unwrap();
    assert!(actual.maintenance_required);
    let mut a: Vec<_> = expected.artifacts.into_iter().map(|x| x.path).collect();
    let mut b: Vec<_> = actual.artifacts.into_iter().map(|x| x.path).collect();
    a.sort();
    b.sort();
    assert_eq!(a, b);
}
#[test]
fn review_b2_distinct_case_sensitive_files_keep_separate_namespaces() {
    let dir = tempfile::tempdir().unwrap();
    let mixed = dir.path().join("MixedCase.pmvault");
    let upper = dir.path().join("MIXEDCASE.PMVAULT");
    let mut first = VaultSession::create(&mixed, "synthetic-only").unwrap();
    if upper.exists() {
        eprintln!("case-sensitive file test not applicable: this directory folds case");
        return;
    }
    let second = VaultSession::create(&upper, "synthetic-only").unwrap();
    fault(Point::AfterPublish);
    assert!(first.save().is_err());
    assert!(
        recovery::inspect(first.path())
            .unwrap()
            .maintenance_required
    );
    let other = recovery::inspect(second.path()).unwrap();
    assert!(!other.maintenance_required);
    assert!(other.artifacts.is_empty());
}
#[cfg(windows)]
#[test]
fn review_b2_windows_existing_alias_finds_same_retained_copies() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("MixedCase Long Filename.pmvault");
    let mut vault = VaultSession::create(&path, "synthetic-only").unwrap();
    fault(Point::AfterPublish);
    assert!(vault.save().is_err());
    let expected = recovery::inspect(vault.path()).unwrap();
    assert!(expected.maintenance_required);
    let mut expected_paths: Vec<_> = expected.artifacts.into_iter().map(|x| x.path).collect();
    expected_paths.sort();
    let uppercase = path.with_file_name("MIXEDCASE LONG FILENAME.PMVAULT");
    if uppercase.exists() {
        let actual = recovery::inspect(&uppercase).unwrap();
        assert!(actual.maintenance_required);
        let mut paths: Vec<_> = actual.artifacts.into_iter().map(|x| x.path).collect();
        paths.sort();
        assert_eq!(paths, expected_paths);
    } else {
        eprintln!("case-folded alias unavailable in this case-sensitive directory");
    }
    if let Ok(short) = native::short_path_for_test(&path) {
        let actual = recovery::inspect(&short).unwrap();
        assert!(actual.maintenance_required);
        let mut paths: Vec<_> = actual.artifacts.into_iter().map(|x| x.path).collect();
        paths.sort();
        assert_eq!(paths, expected_paths);
    } else {
        eprintln!("8.3 alias unavailable; no alias was guessed");
    }
}

#[test]
fn review_b1_witness_creation_sync_and_removal_faults_stay_bounded() {
    for prior in [false, true] {
        for point in [
            Point::WitnessCreate,
            Point::WitnessSync,
            Point::WitnessRemove,
        ] {
            let (_dir, mut vault) = fixture();
            if prior {
                vault.save().unwrap();
            }
            let revision = vault.revision();
            fault(point);
            vault.save().unwrap();
            assert_eq!(vault.revision(), revision + 1);
            assert!(vault.maintenance_warning().is_some());
            let ns = Namespace::new(vault.path()).unwrap();
            let count = ns.transaction_paths().unwrap().len();
            assert!(count <= 2);
            assert_eq!(
                kind(vault.save().unwrap_err()),
                Disposition::MaintenanceRequired
            );
            let mut fresh = VaultSession::open(vault.path(), "synthetic-only").unwrap();
            assert_eq!(
                kind(fresh.save().unwrap_err()),
                Disposition::MaintenanceRequired
            );
            assert_eq!(ns.transaction_paths().unwrap().len(), count);
        }
    }
}
