use super::*;
use crate::domain::EntryDraft;
thread_local! { static AFTER_CREATE: std::cell::RefCell<Option<Box<dyn FnOnce()>>> = std::cell::RefCell::new(None); }
pub(super) fn run_after_create() {
    if let Some(f) = AFTER_CREATE.with(|slot| slot.borrow_mut().take()) {
        f();
    }
}
#[cfg(target_os = "linux")]
#[test]
fn replacement_after_create_is_never_deleted_or_reported_success() {
    for corrupt in [false, true] {
        let dir = tempfile::tempdir().unwrap();
        let vault_path = dir.path().join("synthetic.pmvault");
        let target = dir.path().join("out.csv");
        let moved = dir.path().join("moved.csv");
        let mut vault = VaultSession::create(&vault_path, "synthetic-master").unwrap();
        vault
            .add_entry(EntryDraft::login("first", "", "", "synthetic"))
            .unwrap();
        if corrupt {
            vault.body_mut().entries[0].secret.ciphertext.clear();
        }
        let before = std::fs::read(&vault_path).unwrap();
        let body = serde_json::to_vec(vault.body()).unwrap();
        let t = target.clone();
        let m = moved.clone();
        AFTER_CREATE.with(|slot| {
            *slot.borrow_mut() = Some(Box::new(move || {
                std::fs::rename(&t, &m).unwrap();
                std::fs::write(&t, b"competitor sentinel").unwrap();
            }))
        });
        let result = export_plaintext_csv(
            &vault,
            &target,
            PlaintextExportAcknowledgement::user_confirmed_risk(),
        );
        assert!(
            result.is_err(),
            "a replaced target cannot be reported as successful export"
        );
        assert_eq!(
            std::fs::read(&target).unwrap(),
            b"competitor sentinel",
            "never remove the competitor"
        );
        assert!(moved.exists());
        assert_eq!(before, std::fs::read(&vault_path).unwrap());
        assert_eq!(body, serde_json::to_vec(vault.body()).unwrap());
    }
}

#[test]
fn failed_secret_reveal_retains_created_plaintext_and_vault() {
    let dir = tempfile::tempdir().unwrap();
    let vault_path = dir.path().join("synthetic.pmvault");
    let target = dir.path().join("partial.csv");
    let mut vault = VaultSession::create(&vault_path, "synthetic-master").unwrap();
    vault
        .add_entry(EntryDraft::login("first", "", "", "synthetic"))
        .unwrap();
    vault
        .add_entry(EntryDraft::login("second", "", "", "synthetic"))
        .unwrap();
    vault.body_mut().entries[1].secret.ciphertext = b"invalid synthetic ciphertext".to_vec();
    let before = std::fs::read(&vault_path).unwrap();
    let body = serde_json::to_vec(vault.body()).unwrap();
    assert!(
        export_plaintext_csv(
            &vault,
            &target,
            PlaintextExportAcknowledgement::user_confirmed_risk()
        )
        .is_err()
    );
    assert!(
        target.exists(),
        "post-create failure must retain output rather than deleting a pathname"
    );
    assert_eq!(before, std::fs::read(vault_path).unwrap());
    assert_eq!(body, serde_json::to_vec(vault.body()).unwrap());
}

pub(super) fn observe_wiped_buffer(bytes: &[u8]) {
    assert!(bytes.iter().all(|byte| *byte == 0));
    WIPES.with(|value| value.borrow_mut().push(bytes.len()));
}

use std::cell::{Cell, RefCell};
use std::collections::BTreeMap;
use std::io::Write;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum Op {
    Parents,
    Create,
    Identity,
    Write,
    Flush,
    Sync,
    Open,
    Read,
    Length,
}
type Hook = Box<dyn FnMut(Op, usize) -> io::Result<()>>;
struct ProbeIo {
    hook: RefCell<Hook>,
    counts: RefCell<BTreeMap<Op, usize>>,
    calls: RefCell<Vec<Op>>,
    partial: Cell<Option<(usize, bool)>>,
}
impl ProbeIo {
    fn new(hook: impl FnMut(Op, usize) -> io::Result<()> + 'static) -> Self {
        Self {
            hook: RefCell::new(Box::new(hook)),
            counts: RefCell::new(BTreeMap::new()),
            calls: RefCell::new(Vec::new()),
            partial: Cell::new(None),
        }
    }
    fn step(&self, op: Op) -> io::Result<()> {
        self.calls.borrow_mut().push(op);
        let count = {
            let mut counts = self.counts.borrow_mut();
            let count = counts.entry(op).or_default();
            *count += 1;
            *count
        };
        (self.hook.borrow_mut())(op, count)
    }
}
impl ExportIo for ProbeIo {
    fn parents(&self, target: &Path) -> io::Result<()> {
        self.step(Op::Parents)?;
        SystemIo.parents(target)
    }
    fn create(&self, target: &Path) -> io::Result<File> {
        self.step(Op::Create)?;
        // Namespace fault model intentionally permits renames on Windows. Actual
        // production sharing is tested separately, not inferred from this seam.
        std::fs::OpenOptions::new()
            .create_new(true)
            .read(true)
            .write(true)
            .open(target)
    }
    fn identity(&self, file: &File) -> io::Result<files::Identity> {
        self.step(Op::Identity)?;
        SystemIo.identity(file)
    }
    fn write(&self, file: &mut File, bytes: &[u8]) -> io::Result<usize> {
        self.step(Op::Write)?;
        if let Some((prefix, panic)) = self.partial.take() {
            file.write_all(&bytes[..prefix.min(bytes.len())])?;
            if panic {
                panic!("synthetic sink panic after accepting a prefix");
            }
            return Err(io::Error::from(io::ErrorKind::WriteZero));
        }
        SystemIo.write(file, bytes)
    }
    fn flush(&self, file: &mut File) -> io::Result<()> {
        self.step(Op::Flush)?;
        SystemIo.flush(file)
    }
    fn sync(&self, file: &File) -> io::Result<()> {
        self.step(Op::Sync)?;
        SystemIo.sync(file)
    }
    fn open(&self, target: &Path) -> io::Result<File> {
        self.step(Op::Open)?;
        SystemIo.open(target)
    }
    fn read(&self, file: &mut File, bytes: &mut [u8]) -> io::Result<usize> {
        self.step(Op::Read)?;
        SystemIo.read(file, bytes)
    }
    fn length(&self, file: &File) -> io::Result<u64> {
        self.step(Op::Length)?;
        SystemIo.length(file)
    }
}

fn synthetic() -> (tempfile::TempDir, VaultSession) {
    let dir = tempfile::tempdir().unwrap();
    let mut vault =
        VaultSession::create(dir.path().join("synthetic.pmvault"), "synthetic-master").unwrap();
    for index in 0..3 {
        vault
            .add_entry(EntryDraft::login(
                format!("name-{index}"),
                "https://example.test",
                " synthetic user ",
                " synthetic 密码 \" ,\n",
            ))
            .unwrap();
    }
    vault.save().unwrap();
    (dir, vault)
}
fn unchanged(vault: &VaultSession, body: &[u8], disk: &[u8]) {
    assert_eq!(body, serde_json::to_vec(vault.body()).unwrap());
    assert_eq!(disk, std::fs::read(vault.path()).unwrap());
}
fn retained(failure: &ExportFailure) -> Observation {
    let OutputDisposition::MayRemain { observation } = failure.output else {
        panic!("must report MayRemain: {failure:?}");
    };
    observation
}

#[test]
fn fault_matrix_retains_primary_output_and_vault_without_destructor_io() {
    let (dir, vault) = synthetic();
    let body = serde_json::to_vec(vault.body()).unwrap();
    let disk = std::fs::read(vault.path()).unwrap();
    for (op, occurrence, stage) in [
        (Op::Identity, 1, Stage::IdentifyOutput),
        (Op::Write, 1, Stage::WriteHeader),
        (Op::Write, 3, Stage::WriteRow),
        (Op::Flush, 1, Stage::Flush),
        (Op::Sync, 1, Stage::Sync),
        (Op::Open, 1, Stage::VerifyOutput),
        (Op::Read, 1, Stage::VerifyOutput),
        (Op::Length, 1, Stage::VerifyOutput),
        (Op::Identity, 3, Stage::VerifyOutput),
        (Op::Open, 2, Stage::VerifyPath),
        (Op::Length, 3, Stage::VerifyPath),
        (Op::Identity, 4, Stage::VerifyPath),
    ] {
        for replacement in [false, true] {
            let target = dir
                .path()
                .join(format!("{op:?}-{occurrence}-{replacement}.csv"));
            let moved = target.with_extension("moved");
            let t = target.clone();
            let m = moved.clone();
            let io = ProbeIo::new(move |point, index| {
                if point == op && index == occurrence {
                    if replacement {
                        std::fs::rename(&t, &m)?;
                        std::fs::write(&t, b"competitor sentinel")?;
                    }
                    return Err(io::Error::from(io::ErrorKind::PermissionDenied));
                }
                Ok(())
            });
            let failure = export_with(&vault, &target, &io).unwrap_err();
            assert_eq!(failure.stage, stage);
            assert_eq!(
                failure.cause,
                Cause::Io {
                    kind: io::ErrorKind::PermissionDenied,
                    code: None
                }
            );
            let observation = retained(&failure);
            if replacement && stage != Stage::IdentifyOutput {
                assert_eq!(observation.target, ObservedTarget::TargetDifferent);
            }
            assert!(target.exists());
            if replacement {
                assert_eq!(std::fs::read(&target).unwrap(), b"competitor sentinel");
                assert!(moved.exists());
            }
            let calls = io.calls.borrow().clone();
            let terminal = calls
                .iter()
                .enumerate()
                .filter(|(_, p)| **p == op)
                .nth(occurrence - 1)
                .unwrap()
                .0;
            assert!(
                !calls[terminal + 1..]
                    .iter()
                    .any(|p| matches!(p, Op::Write | Op::Flush | Op::Sync)),
                "no terminal-error or destructor retry: {calls:?}"
            );
            let call_count = calls.len();
            drop(failure);
            assert_eq!(io.calls.borrow().len(), call_count);
            unchanged(&vault, &body, &disk);
        }
    }
}

#[test]
fn diagnostic_failure_does_not_hide_write_reveal_or_sync_failure() {
    let (dir, mut vault) = synthetic();
    for (index, op, stage) in [
        (0, Op::Write, Stage::WriteHeader),
        (1, Op::Sync, Stage::Sync),
        (2, Op::Identity, Stage::RevealEntry),
    ] {
        if index == 2 {
            vault.body_mut().entries[1].secret.ciphertext.clear();
        }
        let body = serde_json::to_vec(vault.body()).unwrap();
        let disk = std::fs::read(vault.path()).unwrap();
        let io = ProbeIo::new(move |point, _| {
            if point == Op::Open {
                return Err(io::Error::from(io::ErrorKind::PermissionDenied));
            }
            if index != 2 && point == op {
                return Err(io::Error::from(io::ErrorKind::WriteZero));
            }
            Ok(())
        });
        let failure = export_with(
            &vault,
            &dir.path().join(format!("diagnostic-{index}.csv")),
            &io,
        )
        .unwrap_err();
        assert_eq!(failure.stage, stage);
        assert_eq!(
            failure.cause,
            if index == 2 {
                Cause::SecretUnavailable
            } else {
                Cause::Io {
                    kind: io::ErrorKind::WriteZero,
                    code: None,
                }
            }
        );
        let observation = retained(&failure);
        assert_eq!(observation.target, ObservedTarget::Unobserved);
        assert!(observation.error.is_some());
        unchanged(&vault, &body, &disk);
    }
}

#[test]
fn partial_write_error_and_unwind_never_flush_or_retry_and_wipe_live_buffers() {
    let (dir, vault) = synthetic();
    let body = serde_json::to_vec(vault.body()).unwrap();
    let disk = std::fs::read(vault.path()).unwrap();
    for panic in [false, true] {
        let target = dir.path().join(format!("prefix-{panic}.csv"));
        let io = ProbeIo::new(|_, _| Ok(()));
        io.partial.set(Some((7, panic)));
        WIPES.with(|value| value.borrow_mut().clear());
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            export_with(&vault, &target, &io)
        }));
        if panic {
            assert!(result.is_err());
        } else {
            assert_eq!(result.unwrap().unwrap_err().stage, Stage::WriteHeader);
        }
        assert_eq!(std::fs::read(target).unwrap(), b"name,ur");
        assert_eq!(
            io.calls
                .borrow()
                .iter()
                .filter(|p| **p == Op::Write)
                .count(),
            1
        );
        assert!(
            !io.calls
                .borrow()
                .iter()
                .any(|p| matches!(p, Op::Flush | Op::Sync))
        );
        assert!(WIPES.with(|value| value.borrow().contains(&8192)));
        unchanged(&vault, &body, &disk);
    }
}

#[test]
fn interrupted_io_retries_but_zero_write_is_terminal() {
    let (dir, vault) = synthetic();
    let io = ProbeIo::new(|op, occurrence| {
        if matches!(op, Op::Write | Op::Read) && occurrence == 1 {
            return Err(io::Error::from(io::ErrorKind::Interrupted));
        }
        Ok(())
    });
    assert_eq!(
        export_with(&vault, &dir.path().join("interrupted.csv"), &io).unwrap(),
        3
    );
    struct Zero;
    impl ExportIo for Zero {
        fn write(&self, _file: &mut File, _bytes: &[u8]) -> io::Result<usize> {
            Ok(0)
        }
    }
    let failure = export_with(&vault, &dir.path().join("zero.csv"), &Zero).unwrap_err();
    assert_eq!(
        failure.cause,
        Cause::Io {
            kind: io::ErrorKind::WriteZero,
            code: None
        }
    );
    retained(&failure);
}

#[test]
fn poisoned_owner_and_encoder_refuse_later_writes_preserving_first_failure() {
    let (dir, vault) = synthetic();
    let target = dir.path().join("poison.csv");
    let io = ProbeIo::new(|_, _| Ok(()));
    io.partial.set(Some((2, false)));
    let mut owner = OwnedCsvOutput {
        file: io.create(&target).unwrap(),
        target,
        io: &io,
        identity: None,
        length: 0,
        hash: Sha256::new(),
        failure: None,
    };
    let first = owner.write_vault(&vault).unwrap_err();
    let count = io.calls.borrow().len();
    assert_eq!(owner.emit(b"must not write", Stage::WriteRow), Err(first));
    assert_eq!(owner.write_vault(&vault), Err(first));
    assert_eq!(owner.verify(), Err(first));
    drop(owner);
    assert_eq!(io.calls.borrow().len(), count);
    let mut encoder = Encoder::<2>::new().unwrap();
    assert_eq!(encoder.record(["a"; 6], |_| Err(first)), Err(first));
    assert_eq!(
        encoder.record(["b"; 6], |_| panic!("poisoned encoder wrote")),
        Err(first)
    );
    assert_eq!(
        encoder.finish(|_| panic!("poisoned encoder flushed")),
        Err(first)
    );
}

#[test]
fn namespace_changes_and_same_inode_corruption_prevent_success() {
    let (dir, vault) = synthetic();
    let body = serde_json::to_vec(vault.body()).unwrap();
    let disk = std::fs::read(vault.path()).unwrap();
    for schedule in [
        "replace",
        "same-data",
        "missing",
        "directory",
        "during-read",
        "corrupt",
        "truncate",
        "append",
        "during-append",
        "during-truncate",
    ] {
        let parent = dir.path().join(schedule);
        std::fs::create_dir(&parent).unwrap();
        let target = parent.join("out.csv");
        let t = target.clone();
        let applied = std::rc::Rc::new(Cell::new(false));
        let applied_hook = applied.clone();
        let io = namespace_probe(schedule, move |op, occurrence| {
            let trigger = if ["during-read", "during-append", "during-truncate"].contains(&schedule)
            {
                op == Op::Read && occurrence == 1
            } else {
                op == Op::Open && occurrence == 1
            };
            if trigger {
                match schedule {
                    "replace" | "same-data" | "during-read" => {
                        let bytes = if schedule == "same-data" {
                            std::fs::read(&t)?
                        } else {
                            b"competitor sentinel".to_vec()
                        };
                        std::fs::rename(&t, t.with_extension("moved"))?;
                        std::fs::write(&t, bytes)?;
                    }
                    "missing" => std::fs::remove_file(&t)?,
                    "directory" => {
                        std::fs::rename(&t, t.with_extension("moved"))?;
                        std::fs::create_dir(&t)?;
                    }
                    "corrupt" => {
                        let mut bytes = std::fs::read(&t)?;
                        bytes[0] ^= 1;
                        std::fs::write(&t, bytes)?;
                    }
                    "truncate" | "during-truncate" => {
                        std::fs::OpenOptions::new()
                            .write(true)
                            .open(&t)?
                            .set_len(2)?;
                    }
                    "append" | "during-append" => {
                        std::fs::OpenOptions::new()
                            .append(true)
                            .open(&t)?
                            .write_all(b"extra")?;
                    }
                    _ => unreachable!(),
                }
                applied_hook.set(true);
            }
            Ok(())
        });
        let failure = export_with(&vault, &target, &io).expect_err(schedule);
        assert!(
            applied.get(),
            "namespace schedule did not complete: {schedule}"
        );
        let observation = retained(&failure);
        assert_eq!(
            failure.stage,
            if schedule == "during-read" {
                Stage::VerifyPath
            } else {
                Stage::VerifyOutput
            },
            "wrong detection stage for completed schedule {schedule}: {failure:?}"
        );
        if schedule == "corrupt" {
            assert_eq!(failure.cause, Cause::DigestChanged, "{schedule}");
        }
        if ["replace", "same-data", "during-read"].contains(&schedule) {
            assert_eq!(failure.cause, Cause::IdentityChanged, "{schedule}");
            assert_eq!(
                observation.target,
                ObservedTarget::TargetDifferent,
                "{schedule}"
            );
            let moved = target.with_extension("moved");
            assert!(moved.is_file(), "owned output must remain: {schedule}");
            if schedule == "same-data" {
                assert_eq!(
                    std::fs::read(&target).unwrap(),
                    std::fs::read(moved).unwrap(),
                    "{schedule}"
                );
            } else {
                assert_eq!(
                    std::fs::read(&target).unwrap(),
                    b"competitor sentinel",
                    "{schedule}"
                );
            }
        }
        if schedule == "missing" {
            assert_eq!(
                observation.target,
                ObservedTarget::TargetMissing,
                "{schedule}"
            );
            assert!(!target.exists(), "{schedule}");
        }
        unchanged(&vault, &body, &disk);
    }
}

#[cfg(target_os = "linux")]
#[test]
fn symlink_and_hardlink_replacements_are_not_followed_or_removed() {
    let (dir, vault) = synthetic();
    for link in ["symlink", "hardlink"] {
        let target = dir.path().join(format!("{link}.csv"));
        let t = target.clone();
        let alias = target.with_extension("alias");
        let a = alias.clone();
        let io = ProbeIo::new(move |op, occurrence| {
            if op == Op::Open && occurrence == 1 {
                if link == "symlink" {
                    std::fs::rename(&t, &a)?;
                    std::os::unix::fs::symlink(&a, &t)?;
                } else {
                    std::fs::hard_link(&t, &a)?;
                }
            }
            Ok(())
        });
        retained(&export_with(&vault, &target, &io).unwrap_err());
        assert!(alias.exists());
        assert!(std::fs::symlink_metadata(target).is_ok());
    }
}

#[test]
fn admission_failures_are_not_created_and_preserve_competitors() {
    let (dir, vault) = synthetic();
    let target = dir.path().join("collision.csv");
    let t = target.clone();
    let io = ProbeIo::new(move |op, _| {
        if op == Op::Create {
            std::fs::write(&t, b"competitor sentinel")?;
        }
        Ok(())
    });
    let failure = export_with(&vault, &target, &io).unwrap_err();
    assert_eq!(failure.output, OutputDisposition::NotCreated);
    assert_eq!(std::fs::read(target).unwrap(), b"competitor sentinel");
    assert!(!io.calls.borrow().contains(&Op::Write));
    for op in [Op::Parents, Op::Create] {
        let io = ProbeIo::new(move |point, _| {
            if point == op {
                Err(io::Error::from(io::ErrorKind::PermissionDenied))
            } else {
                Ok(())
            }
        });
        let failure =
            export_with(&vault, &dir.path().join(format!("{op:?}.csv")), &io).unwrap_err();
        assert_eq!(failure.output, OutputDisposition::NotCreated);
        assert!(!io.calls.borrow().contains(&Op::Write));
    }
    for bad in [
        PathBuf::new(),
        PathBuf::from("bad\0.csv"),
        vault.path().join("child.csv"),
        dir.path().to_path_buf(),
    ] {
        let failure = export_with(&vault, &bad, &SystemIo).unwrap_err();
        assert_eq!(failure.output, OutputDisposition::NotCreated);
        assert!(failure.target.is_absolute());
    }
}

fn encode<const N: usize>(rows: &[[&str; 6]]) -> Vec<u8> {
    let mut bytes = Vec::new();
    let mut encoder = Encoder::<N>::new().unwrap();
    for row in rows {
        encoder
            .record(*row, |chunk| {
                bytes.extend_from_slice(chunk);
                Ok(())
            })
            .unwrap();
    }
    encoder
        .finish(|chunk| {
            bytes.extend_from_slice(chunk);
            Ok(())
        })
        .unwrap();
    bytes
}
#[test]
fn serializer_matches_pinned_dialect_at_tiny_and_large_chunk_boundaries() {
    let long = format!("{}\"\r\n中", "a".repeat(32769));
    let corpus = [
        "",
        " leading and trailing ",
        "\t",
        "a,b",
        "\"",
        "\r",
        "\n",
        "\r\n",
        "中文 🦀",
        "=SUM(A1)",
        "+formula",
        "-formula",
        "@formula",
        &long,
    ];
    let mut rows = vec![
        ["name", "url", "username", "password", "category", "notes"],
        [""; 6],
    ];
    for field in corpus {
        rows.push([field, "", field, field, "", field]);
    }
    let mut reference = csv::WriterBuilder::new().from_writer(Vec::new());
    for row in &rows {
        reference.write_record(row).unwrap();
    }
    let expected = reference.into_inner().unwrap();
    assert_eq!(encode::<2>(&rows), expected);
    assert_eq!(encode::<3>(&rows), expected);
    assert_eq!(encode::<7>(&rows), expected);
    assert_eq!(encode::<8192>(&rows), expected);
    assert_eq!(encode::<2>(&[[""; 6]]), b",,,,,\n");
    assert_eq!(
        encode::<3>(&[["a,b", "\"", "\n", "中", "=x", ""]]),
        "\"a,b\",\"\"\"\",\"\n\",中,=x,\n".as_bytes()
    );
    assert!(Encoder::<0>::new().is_err());
    assert!(Encoder::<1>::new().is_err());
    let parsed: Vec<_> = csv::ReaderBuilder::new()
        .has_headers(false)
        .from_reader(expected.as_slice())
        .records()
        .collect::<std::result::Result<_, _>>()
        .unwrap();
    for (actual, expected) in parsed.iter().zip(rows) {
        assert_eq!(actual.iter().collect::<Vec<_>>(), expected);
    }
}

thread_local! { static WIPES: RefCell<Vec<usize>> = const { RefCell::new(Vec::new()) }; }
#[test]
fn hashing_feature_and_named_buffer_owners_are_zeroized_on_all_returns() {
    fn assert_zeroize<T: zeroize::ZeroizeOnDrop>() {}
    assert_zeroize::<Sha256>();
    let (dir, vault) = synthetic();
    for fault in [
        None,
        Some(Op::Write),
        Some(Op::Flush),
        Some(Op::Sync),
        Some(Op::Read),
        Some(Op::Length),
    ] {
        WIPES.with(|value| value.borrow_mut().clear());
        let io = ProbeIo::new(move |op, _| {
            if fault == Some(op) {
                Err(io::Error::from(io::ErrorKind::PermissionDenied))
            } else {
                Ok(())
            }
        });
        let result = export_with(&vault, &dir.path().join(format!("wipe-{fault:?}.csv")), &io);
        let sizes = WIPES.with(|value| value.borrow().clone());
        assert!(sizes.contains(&8192));
        if fault.is_none() {
            assert!(result.is_ok());
            assert_eq!(sizes.iter().filter(|size| **size == 32).count(), 2);
        } else {
            retained(&result.unwrap_err());
        }
    }
}

#[test]
fn production_export_has_no_destructive_path_or_buffered_writer_calls() {
    // The exporter file-I/O interface has no delete/rename/truncate method. A
    // source guard also catches bypasses of that interface. Test fixtures above
    // deliberately mutate namespaces; they are not part of production modules.
    for source in [
        include_str!("../export.rs"),
        include_str!("io.rs"),
        include_str!("encoder.rs"),
    ] {
        for forbidden in [
            "remove_file(",
            "remove_dir",
            "rename(",
            ".truncate(true)",
            "set_len(",
            "NamedTempFile",
            "BufWriter",
            "csv::Writer",
        ] {
            assert!(
                !source.contains(forbidden),
                "destructive/private buffering API: {forbidden}"
            );
        }
    }
    assert!(!include_str!("../export.rs").contains(".reveal_secret("));
}

#[test]
fn active_entry_traversal_is_linear_and_never_scans_by_id() {
    let (dir, mut vault) = synthetic();
    for n in [20, 40] {
        vault.body_mut().entries.clear();
        for index in 0..n {
            let id = vault
                .add_entry(EntryDraft::login(
                    format!("entry-{index}"),
                    "",
                    "",
                    "synthetic",
                ))
                .unwrap();
            if index % 2 == 1 {
                vault.move_to_recycle_bin(id).unwrap();
            }
        }
        crate::storage::export_probe::reset();
        assert_eq!(
            export_with(
                &vault,
                &dir.path().join(format!("linear-{n}.csv")),
                &SystemIo
            )
            .unwrap(),
            n / 2
        );
        assert_eq!(crate::storage::export_probe::counts(), (n, n / 2, 0));
    }
    vault.body_mut().entries[2].secret.ciphertext.clear();
    crate::storage::export_probe::reset();
    let failure =
        export_with(&vault, &dir.path().join("linear-failure.csv"), &SystemIo).unwrap_err();
    assert_eq!(failure.stage, Stage::RevealEntry);
    assert_eq!(crate::storage::export_probe::counts(), (3, 2, 0));
}

#[test]
fn relative_path_is_captured_once_without_lexically_erasing_parent_semantics() {
    let (dir, vault) = synthetic();
    let cwd = std::env::current_dir().unwrap();
    // A relative path under the existing writable working directory. Avoid a
    // process-global chdir because other tests can be running concurrently.
    let relative =
        PathBuf::from("target").join(format!("synthetic-export-{}.csv", uuid::Uuid::new_v4()));
    let io = ProbeIo::new(|op, _| {
        if op == Op::Write {
            Err(io::Error::from(io::ErrorKind::WriteZero))
        } else {
            Ok(())
        }
    });
    let failure = export_with(&vault, &relative, &io).unwrap_err();
    assert_eq!(failure.target, cwd.join(&relative));
    retained(&failure);
    // Test-harness cleanup only; production never removes the output.
    std::fs::remove_file(&relative).unwrap();
    let target = dir.path().join("new/../literal.csv");
    let failure = export_with(&vault, &target, &io).unwrap_err();
    assert_eq!(failure.target, target);
}

#[cfg(target_os = "linux")]
#[test]
fn final_symlink_and_dangling_symlink_are_refused_before_writing() {
    let (dir, vault) = synthetic();
    let sentinel = dir.path().join("sentinel");
    std::fs::write(&sentinel, b"sentinel").unwrap();
    for existing in [true, false] {
        let target = dir.path().join(format!("link-{existing}.csv"));
        std::os::unix::fs::symlink(
            if existing {
                sentinel.clone()
            } else {
                dir.path().join("absent")
            },
            &target,
        )
        .unwrap();
        let failure = export_with(&vault, &target, &SystemIo).unwrap_err();
        assert_eq!(failure.output, OutputDisposition::NotCreated);
        assert!(
            std::fs::symlink_metadata(target)
                .unwrap()
                .file_type()
                .is_symlink()
        );
        assert_eq!(std::fs::read(&sentinel).unwrap(), b"sentinel");
    }
}

#[test]
fn partial_quoted_multibyte_row_has_exact_prefix_and_no_retry() {
    let (dir, mut vault) = synthetic();
    vault.body_mut().entries.clear();
    let mut entry = EntryDraft::login("中\"文", "", "", "synthetic");
    entry.secret.notes = "结尾\"".into();
    vault.add_entry(entry).unwrap();
    let complete = dir.path().join("complete.csv");
    export_with(&vault, &complete, &SystemIo).unwrap();
    let bytes = std::fs::read(complete).unwrap();
    let header = b"name,url,username,password,category,notes\n".len();
    for prefix in [1, 2, 3, 4, 5, 6, 7] {
        struct Partial {
            writes: Cell<usize>,
            prefix: usize,
        }
        impl ExportIo for Partial {
            fn write(&self, file: &mut File, bytes: &[u8]) -> io::Result<usize> {
                self.writes.set(self.writes.get() + 1);
                if self.writes.get() == 2 {
                    file.write_all(&bytes[..self.prefix])?;
                    return Err(io::Error::from(io::ErrorKind::WriteZero));
                }
                assert_eq!(self.writes.get(), 1, "no retry after partial error");
                file.write(bytes)
            }
        }
        let target = dir.path().join(format!("partial-{prefix}.csv"));
        let io = Partial {
            writes: Cell::new(0),
            prefix,
        };
        let failure = export_with(&vault, &target, &io).unwrap_err();
        assert_eq!(failure.stage, Stage::WriteRow);
        retained(&failure);
        assert_eq!(std::fs::read(target).unwrap(), bytes[..header + prefix]);
        assert_eq!(io.writes.get(), 2);
    }
}

#[cfg(windows)]
#[test]
fn windows_production_sharing_allows_readback_but_blocks_writers_and_delete() {
    let (dir, vault) = synthetic();
    let target = dir.path().join("sharing.csv");
    let t = target.clone();
    AFTER_CREATE.with(|slot| {
        *slot.borrow_mut() = Some(Box::new(move || {
            assert!(std::fs::OpenOptions::new().write(true).open(&t).is_err());
            assert!(std::fs::rename(&t, t.with_extension("moved")).is_err());
            assert!(std::fs::remove_file(&t).is_err());
            assert!(files::open_regular(&t, false).is_ok());
        }))
    });
    assert_eq!(export_with(&vault, &target, &SystemIo).unwrap(), 3);
}
#[cfg(windows)]
#[test]
fn windows_device_and_alternate_stream_names_are_rejected_before_creation() {
    let (dir, vault) = synthetic();
    for name in [
        "out.csv:stream",
        "CON",
        "CON.txt",
        "NUL",
        "AUX.txt",
        "PRN",
        "COM1",
        "LPT9.txt",
        "COM¹",
    ] {
        let target = dir.path().join(name);
        let io = ProbeIo::new(|_, _| Ok(()));
        let failure = export_with(&vault, &target, &io).unwrap_err();
        assert_eq!(failure.stage, Stage::Resolve);
        assert_eq!(failure.output, OutputDisposition::NotCreated);
        assert!(io.calls.borrow().is_empty());
    }
    for path in [
        r"\\.\NUL",
        r"\\server\share\out.csv",
        r"\\?\GLOBALROOT\Device\HarddiskVolume1\out.csv",
    ] {
        assert!(file_io::validate_destination(Path::new(path)).is_err());
    }
}

#[test]
fn forced_exit_after_prefix_can_leave_plaintext_and_never_cleans_competitor() {
    const CHILD_ENV: &str = "PM_SYNTHETIC_EXPORT_EXIT_FIXTURE";
    if let Some(path) = std::env::var_os(CHILD_ENV) {
        let root = PathBuf::from(path);
        let vault = VaultSession::create(root.join("child.pmvault"), "synthetic-master").unwrap();
        struct ExitIo(PathBuf);
        impl ExportIo for ExitIo {
            fn create(&self, target: &Path) -> io::Result<File> {
                std::fs::OpenOptions::new()
                    .create_new(true)
                    .read(true)
                    .write(true)
                    .open(target)
            }
            fn write(&self, file: &mut File, bytes: &[u8]) -> io::Result<usize> {
                file.write_all(&bytes[..7]).unwrap();
                file.sync_all().unwrap();
                std::fs::rename(&self.0, self.0.with_extension("moved")).unwrap();
                std::fs::write(&self.0, b"competitor sentinel").unwrap();
                std::process::exit(77);
            }
        }
        let target = root.join("forced.csv");
        let _ = export_with(&vault, &target, &ExitIo(target.clone()));
        panic!("child must exit during write");
    }
    let dir = tempfile::tempdir().unwrap();
    let output=std::process::Command::new(std::env::current_exe().unwrap())
        .args(["--exact","export::tests::forced_exit_after_prefix_can_leave_plaintext_and_never_cleans_competitor","--nocapture"])
        .env(CHILD_ENV,dir.path()).output().unwrap();
    assert_eq!(
        output.status.code(),
        Some(77),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(
        std::fs::read(dir.path().join("forced.moved")).unwrap(),
        b"name,ur"
    );
    assert_eq!(
        std::fs::read(dir.path().join("forced.csv")).unwrap(),
        b"competitor sentinel"
    );
    // A new synthetic export doesn't scan/remove unrelated prior CSV outputs.
    let reopened =
        VaultSession::open(dir.path().join("child.pmvault"), "synthetic-master").unwrap();
    export_with(&reopened, &dir.path().join("after-restart.csv"), &SystemIo).unwrap();
    assert_eq!(
        std::fs::read(dir.path().join("forced.csv")).unwrap(),
        b"competitor sentinel"
    );
    assert!(dir.path().join("forced.moved").exists());
}

pub(crate) fn set_after_create(hook: impl FnOnce() + 'static) {
    AFTER_CREATE.with(|slot| *slot.borrow_mut() = Some(Box::new(hook)));
}

#[cfg(target_os = "linux")]
#[test]
fn restrictive_creation_survives_permissive_umask_in_child_process() {
    const CHILD: &str = "PM_SYNTHETIC_EXPORT_UMASK";
    if std::env::var_os(CHILD).is_some() {
        use std::os::unix::fs::PermissionsExt;
        let (dir, vault) = synthetic();
        let target = dir.path().join("mode.csv");
        export_with(&vault, &target, &SystemIo).unwrap();
        assert_eq!(
            std::fs::metadata(target).unwrap().permissions().mode() & 0o777,
            0o600
        );
        return;
    }
    // Set umask only in the synthetic child, never in the concurrent test runner.
    let output=std::process::Command::new("sh")
        .args(["-c","umask 000; exec \"$1\" --exact export::tests::restrictive_creation_survives_permissive_umask_in_child_process", "synthetic-umask"])
        .arg(std::env::current_exe().unwrap()).env(CHILD,"1").output().unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn late_secret_write_and_populated_read_unwinds_wipe_named_owners_without_retry() {
    use std::io::Read;
    let (dir, mut vault) = synthetic();
    vault.body_mut().entries.clear();
    const SECRET: &str = "unique-late-secret-buffer-probe";
    vault
        .add_entry(EntryDraft::login("public-name", "", "", SECRET))
        .unwrap();
    let body = serde_json::to_vec(vault.body()).unwrap();
    let disk = std::fs::read(vault.path()).unwrap();
    for fault in [
        "write-panic",
        "read-error",
        "read-panic",
        "hash-panic",
        "digest-panic",
    ] {
        struct LateIo {
            fault: &'static str,
            writes: Cell<usize>,
            reads: Cell<usize>,
            identities: Cell<usize>,
        }
        impl ExportIo for LateIo {
            fn write(&self, file: &mut File, bytes: &[u8]) -> io::Result<usize> {
                self.writes.set(self.writes.get() + 1);
                if self.fault == "write-panic" && self.writes.get() == 2 {
                    assert!(
                        bytes
                            .windows(SECRET.len())
                            .any(|window| window == SECRET.as_bytes())
                    );
                    file.write_all(bytes)?;
                    panic!("synthetic late secret write panic");
                }
                file.write(bytes)
            }
            fn read(&self, file: &mut File, bytes: &mut [u8]) -> io::Result<usize> {
                self.reads.set(self.reads.get() + 1);
                if self.fault == "hash-panic" && self.reads.get() == 2 {
                    panic!("synthetic panic after readback hasher accepted secret bytes");
                }
                let count = file.read(bytes)?;
                if self.reads.get() == 1 && ["read-error", "read-panic"].contains(&self.fault) {
                    assert!(
                        bytes[..count]
                            .windows(SECRET.len())
                            .any(|window| window == SECRET.as_bytes())
                    );
                    if self.fault == "read-panic" {
                        panic!("synthetic populated read-buffer panic");
                    }
                    return Err(io::Error::from(io::ErrorKind::PermissionDenied));
                }
                Ok(count)
            }
            fn identity(&self, file: &File) -> io::Result<files::Identity> {
                self.identities.set(self.identities.get() + 1);
                if self.fault == "digest-panic" && self.identities.get() == 3 {
                    panic!("synthetic panic while expected and actual digest owners are live");
                }
                files::identity(file, true)
            }
        }
        let io = LateIo {
            fault,
            writes: Cell::new(0),
            reads: Cell::new(0),
            identities: Cell::new(0),
        };
        let target = dir.path().join(format!("{fault}.csv"));
        WIPES.with(|value| value.borrow_mut().clear());
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            export_with(&vault, &target, &io)
        }));
        if fault == "read-error" {
            retained(&result.unwrap().unwrap_err());
        } else {
            assert!(result.is_err());
        }
        let wipes = WIPES.with(|value| value.borrow().clone());
        assert!(wipes.contains(&8192));
        if fault == "digest-panic" {
            assert_eq!(wipes.iter().filter(|n| **n == 32).count(), 2);
        }
        assert_eq!(
            io.writes.get(),
            2,
            "no write or flush retry after terminal error/unwind"
        );
        let output = std::fs::read(target).unwrap();
        assert!(
            output
                .windows(SECRET.len())
                .any(|window| window == SECRET.as_bytes())
        );
        unchanged(&vault, &body, &disk);
    }
}

// Namespace mutations belong to the test actor, not the exporter's I/O result.
// Fail setup loudly; never count a failed mutation as successful fault coverage.
fn namespace_probe(
    schedule: &'static str,
    mut hook: impl FnMut(Op, usize) -> io::Result<()> + 'static,
) -> ProbeIo {
    ProbeIo::new(move |op, occurrence| {
        hook(op, occurrence).unwrap_or_else(|error| {
            panic!("namespace fixture {schedule} failed at {op:?}#{occurrence}: {error}")
        });
        Ok(())
    })
}

#[test]
fn namespace_injection_failure_must_not_masquerade_as_product_rejection() {
    let (dir, vault) = synthetic();
    let io = namespace_probe("denied synthetic rename", |op, occurrence| {
        if op == Op::Open && occurrence == 1 {
            return Err(io::Error::from(io::ErrorKind::PermissionDenied));
        }
        Ok(())
    });
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        export_with(&vault, &dir.path().join("fixture-error.csv"), &io)
    }));
    assert!(
        result.is_err(),
        "a failed namespace mutation must fail the test harness, not become an expected ExportFailure"
    );
}

#[test]
fn parent_redirection_model_requires_original_full_path_and_rejects_equal_bytes() {
    let (dir, vault) = synthetic();
    let body = serde_json::to_vec(vault.body()).unwrap();
    let disk = std::fs::read(vault.path()).unwrap();
    let reference = dir.path().join("reference.csv");
    export_with(&vault, &reference, &SystemIo).unwrap();
    let expected = std::fs::read(reference).unwrap();
    for redirect_on in [1, 2] {
        let parent = dir.path().join(format!("logical-{redirect_on}"));
        let other_parent = dir.path().join(format!("redirected-{redirect_on}"));
        std::fs::create_dir(&other_parent).unwrap();
        let target = parent.join("out.csv");
        let competitor = other_parent.join("out.csv");
        std::fs::write(&competitor, &expected).unwrap();
        struct RedirectParent {
            full_target: PathBuf,
            competitor: PathBuf,
            redirect_on: usize,
            opens: Cell<usize>,
            applied: Cell<bool>,
        }
        impl ExportIo for RedirectParent {
            fn open(&self, target: &Path) -> io::Result<File> {
                // This is an explicit namespace-resolution model, not a claim
                // that Windows permits renaming an ancestor with open children.
                assert_eq!(
                    target, self.full_target,
                    "must re-open the captured full target"
                );
                let index = self.opens.get() + 1;
                self.opens.set(index);
                if index >= self.redirect_on {
                    self.applied.set(true);
                    SystemIo.open(&self.competitor)
                } else {
                    SystemIo.open(target)
                }
            }
        }
        let io = RedirectParent {
            full_target: target.clone(),
            competitor: competitor.clone(),
            redirect_on,
            opens: Cell::new(0),
            applied: Cell::new(false),
        };
        let failure = export_with(&vault, &target, &io).unwrap_err();
        assert!(
            io.applied.get(),
            "redirection {redirect_on} was not exercised"
        );
        assert_eq!(
            failure.stage,
            if redirect_on == 1 {
                Stage::VerifyOutput
            } else {
                Stage::VerifyPath
            }
        );
        assert_eq!(
            failure.cause,
            Cause::IdentityChanged,
            "redirection {redirect_on}"
        );
        assert_eq!(retained(&failure).target, ObservedTarget::TargetDifferent);
        assert_eq!(failure.target, target);
        assert_eq!(
            std::fs::read(&target).unwrap(),
            expected,
            "model-owned output preserved"
        );
        assert_eq!(
            std::fs::read(competitor).unwrap(),
            expected,
            "same-data competitor preserved"
        );
        unchanged(&vault, &body, &disk);
    }
}

#[cfg(target_os = "linux")]
#[test]
fn linux_real_parent_replacement_is_detected_before_read_and_at_final_checkpoint() {
    let (dir, vault) = synthetic();
    let body = serde_json::to_vec(vault.body()).unwrap();
    let disk = std::fs::read(vault.path()).unwrap();
    for swap_on in [1, 2] {
        let parent = dir.path().join(format!("parent-{swap_on}"));
        std::fs::create_dir(&parent).unwrap();
        let target = parent.join("out.csv");
        let moved_parent = parent.with_extension("moved");
        let p = parent.clone();
        let t = target.clone();
        let m = moved_parent.clone();
        let applied = std::rc::Rc::new(Cell::new(false));
        let a = applied.clone();
        let io = namespace_probe("Linux parent replacement", move |op, occurrence| {
            if op == Op::Open && occurrence == swap_on {
                std::fs::rename(&p, &m)?;
                std::fs::create_dir(&p)?;
                std::fs::write(&t, b"competitor sentinel")?;
                a.set(true);
            }
            Ok(())
        });
        let failure = export_with(&vault, &target, &io).unwrap_err();
        assert!(applied.get(), "parent swap {swap_on} not applied");
        assert_eq!(
            failure.stage,
            if swap_on == 1 {
                Stage::VerifyOutput
            } else {
                Stage::VerifyPath
            }
        );
        assert_eq!(
            failure.cause,
            Cause::IdentityChanged,
            "parent swap {swap_on}"
        );
        assert_eq!(retained(&failure).target, ObservedTarget::TargetDifferent);
        assert_eq!(std::fs::read(&target).unwrap(), b"competitor sentinel");
        assert!(
            std::fs::read(moved_parent.join("out.csv"))
                .unwrap()
                .starts_with(b"name,url,username,password,category,notes\n")
        );
        unchanged(&vault, &body, &disk);
    }
}

#[cfg(windows)]
#[test]
fn windows_parent_rename_is_denied_with_open_child_even_with_delete_sharing() {
    let (dir, vault) = synthetic();
    let body = serde_json::to_vec(vault.body()).unwrap();
    let disk = std::fs::read(vault.path()).unwrap();
    let parent = dir.path().join("parent");
    std::fs::create_dir(&parent).unwrap();
    let target = parent.join("out.csv");
    let moved = parent.with_extension("moved");
    let p = parent.clone();
    let m = moved.clone();
    let attempted = std::rc::Rc::new(Cell::new(false));
    let a = attempted.clone();
    // ProbeIo::create uses Rust's default READ|WRITE|DELETE sharing, unlike the
    // production SHARE_READ owner. Parent rename still has the open-child rule:
    // https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/ns-ntifs-_file_rename_information
    let io = namespace_probe("Windows parent rename denied", move |op, occurrence| {
        if op == Op::Open && occurrence == 1 {
            let error = std::fs::rename(&p, &m)
                .expect_err("Windows must retain the parent while its child is open");
            assert_eq!(
                error.kind(),
                io::ErrorKind::PermissionDenied,
                "unexpected parent rename failure: {error}"
            );
            assert!(p.is_dir());
            assert!(!m.exists());
            a.set(true);
        }
        Ok(())
    });
    // A competing operation denied by the OS does not itself make export fail.
    assert_eq!(export_with(&vault, &target, &io).unwrap(), 3);
    assert!(attempted.get());
    let output = std::fs::read(&target).unwrap();
    assert!(output.starts_with(b"name,url,username,password,category,notes\n"));
    unchanged(&vault, &body, &disk);
    // After the owned and verifier handles close, the same rename can succeed.
    std::fs::rename(&parent, &moved).unwrap();
    assert!(!parent.exists());
    assert_eq!(std::fs::read(moved.join("out.csv")).unwrap(), output);
}
