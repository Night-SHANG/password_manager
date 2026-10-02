# Owned CSV Output Implementation Plan

> Implement regression-first, then independently review output ownership and the
> caller/normal-close boundary. Preserve the existing CSV format and encrypted vault.

**Goal:** Complete the existing synchronous CSV export's output ownership, memory, and visible failure boundary without changing the CSV format.

**Architecture:** Exclusively create the selected final file, retain it on all failures, and verify an identity/content receipt before reporting success. Serialize with csv-core into owned zeroizing chunks and decrypt active entries in one traversal. Keep an independent generation-bound App warning and normal-close confirmation.

**Tech Stack:** Rust, Iced 0.14, csv-core 0.1.13, sha2 0.11 with zeroize; Linux and Windows ordinary-file adapters.

**Spec:** `docs/owned-csv-export.md` describes the retained-output contract and limitations.

## Global Constraints

- Preserve `name,url,username,password,category,notes`, LF, UTF-8, necessary doubled-quote escaping, active order, unchanged values and explicit risk acknowledgment.
- No plaintext staging files, path deletion, truncation, overwrite, destructor I/O, or encrypted transaction algorithm changes.
- Post-create errors always report `MayRemain`, even before the first accepted byte. Capture the absolute attempted path without rewriting symlink/`..` semantics.
- Success is an observed identity/content checkpoint, not atomic pathname/content ownership or power-loss durability.
- One unresolved notice blocks another export; warnings survive navigation, lock and recovery. Explicit current-generation acknowledgment or normal-exit confirmation is required.
- This group remains synchronous. Entered-operation cancellation, responsive locking and drain belong to the next background-operation group.
- All fixtures are synthetic. Dependency changes are exactly the direct csv-core edge and sha2 zeroize feature.

## Review Focus

- An external rename/replacement must never authorize removal of either file (Task 2).
- An error after creation but before bytes still needs the full-path residual warning (Tasks 2 and 4).
- Quotes or UTF-8 split across tiny chunks must match the established dialect (Task 3).
- A path swap during readback and same-inode corruption must prevent success (Task 2).
- A stale acknowledgment or close confirmation must not bypass a later warning (Task 4).

## Task 1: Pin compatibility and reproduce unsafe retention

Files: `tests/export.rs`, `src/export.rs` test seam/tests.
Interfaces: Existing `export_plaintext_csv(&VaultSession, &Path, PlaintextExportAcknowledgement) -> Result<usize>`.
- [x] Add exact header/row corpus, deleted filtering, admission/collision, nested path tests.
- [x] Add later-secret failure and namespace-replacement regression. Run against baseline and retain expected failing assertions.
- [x] Add Linux private-mode regression before changing creation.

## Task 2: Own and verify output

Files: `src/export.rs`, `src/export/io.rs`, `src/export/tests.rs`, `src/error.rs`.
Interfaces: `ExportFailure { target, stage, cause, output }`, `OutputDisposition::{NotCreated, MayRemain { observation }}`; same public successful result.
- [x] Record baseline retention/replacement red failures, then expand fault regressions for identity/write/reveal/flush/sync/read/checkpoint and namespace schedules.
- [x] Implement no-clobber create, retained owner, sanitized typed causes and diagnostic observations. Keep first failure and poison explicit writer operations.
- [x] Add bounded zeroized digest readback and terminal full-target identity/length reopen. Cover same-length corruption, missing/aliased/nonregular/replaced targets and bounded extra data.
- [x] Verify all failure paths preserve vault bytes/body and perform no destructive path calls or destructor write/flush.

## Task 3: Own serializer scratch and linear traversal

Files: `src/export/encoder.rs`, `src/storage.rs`, `Cargo.toml`, `Cargo.lock`, exporter tests.
Interfaces: storage-owned `active_entries_with_secrets()` iterator; six-field encoder over `Write` with a fixed owned buffer.
- [x] Add tiny chunk/dialect/differential/progress tests and compile-time sha2 zeroize check; verify against the pinned reference and fixed byte goldens.
- [x] Use exact csv-core configuration, explicit delimiter/terminator/finish loops, zeroized scratch and digest arrays; enable only specified dependency edges.
- [x] Add direct-entry decrypt iterator and instrument traversal/decrypt counts. Test named owners' cleanup on return/error/unwind, with no freed-memory inspection.
- [x] Run focused export/storage checks and inspect resolved dependency delta.

## Task 4: Preserve warnings and guard normal exit

Files: `src/app.rs`, `src/app/actions.rs`, `src/app/export_notice.rs`, `src/app/ui.rs`, `src/app/ui/forms.rs`, `src/app/tests.rs`.
Interfaces: independent notice + generation, `AcknowledgeExportNotice`, `CloseRequested`, `KeepOpen`, `ConfirmExportExit` messages.
- [x] Record warning-loss/close-route red failures; add handler, navigation/lock/recovery, repeat-admission and stale-generation regressions.
- [x] Install notice before ordinary status, render full wrapped/scrollable path in every shell, disable export while unresolved.
- [x] Disable Iced auto-close, route window ID close requests, lock first and demand current generation-bound confirmation. Keep App Drop clipboard cleanup.
- [x] Test actual rendered interactions/long Unicode paths at 960×640 and established larger sizes; retain fresh screenshots.

## Task 5: Verification and limits

Files: `docs/owned-csv-export.md`, README, Windows acceptance checklist.
- [x] Run fmt, check all targets, full test suite, strict Clippy, GUI interactions/captures and release smoke with logs.
- [x] Include Windows-native sharing/path tests for actual Windows CI; label local cross-check limitations honestly.
- [x] Record exact results, dependency-source ownership review, remaining synchronous/crash/ACL/namespace limits, and freeze code for independent review.

Publication is performed separately after independent review; this implementation does not stage, commit, push or trigger CI.

## Review corrections

- Close-warning input gating must still drain invalidated picker and screenshot-protection completions and allow the already generation-bound clipboard acknowledgment. Three state regressions and an actual rendered-button regression first demonstrated the blocked behavior, then passed after the narrow gate correction.
- A window close action executes after the current Iced message batch. Both final close paths now lock and enter terminal admission before emitting that action. Red/green regressions prove queued same-batch export and unlock cannot start after final close intent, and duplicate close messages emit no additional close action.
- Buffer evidence includes late secret-bearing write/read failure/unwind, a hasher-ingestion unwind, and an unwind while both digest arrays are live. The probes cover named owned buffers, not private dependency/backend temporaries.

## Local verification result

The final Linux run passed 269 ordinary Rust tests and all 28 separately invoked headless GUI tests, producing 119 fresh screenshots. Formatting, all-target compilation, strict all-target/all-feature Clippy, debug/release builds and the release executable's synthetic self-test passed. Local Python CI-policy tests passed 12 cases and skipped 8 PowerShell-only cases. No dependency version changed. Actual Windows-native CI, Windows 10 acceptance and publication remain separate gates; local Linux models do not satisfy them.

## Final local and native validation

The frozen source passed 269 Rust tests, 28 headless GUI tests, formatting,
all-target check, strict all-feature Clippy, debug/release builds and release
binary self-test. Python policy checks passed 12 tests with 8 PowerShell-only
checks skipped locally. Independent backend review found no blocking issue;
all four close-lifecycle findings were corrected and passed targeted re-review.
Source-data and sensitive-log guards also passed.

An actual Linux window running the frozen release then exported a two-entry
synthetic vault successfully, refused an occupied target without changing it,
and retained a partial CSV after the second entry's intentionally damaged
secret failed to decode. The prominent full-path warning survived navigation,
status replacement, lock/unlock and KeepOpen after a window-close request.
A repeated export remained blocked; explicit exit closed the application and
left the residual file unchanged. Both synthetic vault hashes and the competing
file's hash stayed unchanged. Native screenshots were inspected in the test
session; they are not standalone repository image artifacts.

This does not establish native Windows sharing/ACL behavior, real clipboard
coexistence (unsupported on Linux), native file dialogs, Win10, IME or DPI.
The exact-source Windows CI, package and artifact-hash gates remain next.
Dependency lock SHA-256:
`13af5775bbb4d34271bbfd1cb7d65b08e4f97300637b624aba7785f1d4be938b`.

## Remaining existing-v1 work

After this group's Windows gate: the shared background operation/lock-drain
lane and measured large-vault performance, same-DEK master-password change,
unsaved-editor decisions and the remaining specified interaction/readability
controls, then final exact-revision automated gates and a consolidated Windows
10 acceptance checklist. Native-vault merging remains outside this bounded
implementation pending resolution of the existing scope conflict.
