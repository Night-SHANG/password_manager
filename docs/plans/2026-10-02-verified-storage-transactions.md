# Verified storage transactions implementation plan

> Implement regression-first, then independently review the complete storage and
> caller boundary. Preserve the existing card GUI and encrypted file format.

**Goal:** preserve the previous encrypted vault and competing files during
existing-file saves, with truthful failure states and usable recovery.

**Baseline:** `6cafb167ba1fb95a48492ffb15677e0a12c12220`, Preflight #34 passed.

**Architecture:** one existing-file transaction for save/import/confirmed
overwrite restore, independent encrypted preimage, retained actual displaced
file, and exact-byte plus semantic verification. Typed uncertain outcomes lock
the session and preserve recovery material; no blind overwrite rollback.

**Tech stack:** existing Rust/serde/uuid/tempfile/Windows bindings; Linux-only
direct `rustix = 1.1.5` with `fs`, already present in Cargo.lock (MSRV 1.65,
below project 1.88). Keep all dependency versions otherwise unchanged.

**Specification:**
- https://app.notion.com/p/3e8fbd029cd28126a23cd761a0728894
- https://app.notion.com/p/3e8fbd029cd28188bf04e8e38712c20d
- https://app.notion.com/p/3e8fbd029cd281049f32d891ed508941

## Global constraints and accepted engineering policies

- Synthetic fixtures only; no real credentials, databases, user desktop or vault.
- No encrypted schema/header change, sync/merge engine, key rotation or new
  password-recovery mechanism. No main merge or formal release.
- New-file create/export/restore(false) retain their existing no-clobber path.
- Existing-file publication never falls back to clobbering rename/create when
  the expected destination disappears or an atomic capability is unsupported.
- A stable sidecar lock serializes cooperating app writers only. Never unlink
  it after use. Hash/file-ID observations are not filesystem compare-and-swap.
- Concurrent noncooperating replacement before publication may be displaced,
  but its actual bytes must be retained and cause a recovery-required result.
  After-publication replacements must not be overwritten by automatic rollback.
- Supported contract: local same-volume/filesystem regular files, stable parent,
  nonmalicious managed transaction namespace. Detect/reject unsupported final
  links/reparse points/hardlink aliases rather than pretending locks cover them.
  Network filesystems, malicious directory substitution and arbitrary in-place
  external writers are not claimed to be solved.
- Do not delete unknown legacy .bak, manual exports, uncertain recovery material
  or any only verified recovery copy. No recursive deletion of unknown children.
- Accepted rolling-success policy: retain latest one verified owned preimage;
  register/verify its replacement before retiring the old owned success backup.
  A small descriptor may track at most one previous owned backup pending cleanup.
  This is a new explicit engineering policy consistent with retaining the
  preceding encrypted backup, not an old numeric user setting.
- Cleanup/descriptor failure after verified publication cannot turn success into
  a false save failure. Preserve material, warn, and block further accumulating
  saves until bounded maintenance/recovery is resolved, with an actionable UI.
- In this batch omit automatic rollback/repair entirely. Uncertain progress
  returns recovery-required; never emit a fictional verified-rollback outcome.
- Current synchronous operation timing remains explicit. Async crypto/commit
  arbitration and master-password rewrap are the next group, not claims of this
  transaction test suite. Do not introduce an always-valid fake cancellation gate.

## Review focus

1. A failed OS replacement may have progressed; preserve all roles before any
   destructor runs and distinguish it from a rejected prepublication attempt.
2. The actual displaced file can be a competitor, despite a valid saved preimage.
3. Post-publication read/hash/sync/verification failure must never invoke an
   overwrite rollback or leave a live session claiming the old file is current.
4. Backup rotation must survive descriptor/cleanup failures and restart without
   deleting unknown files or silently accumulating an unbounded success history.
5. Recovery UI must be usable while locked, validate selected encrypted copies,
   and restore only to a new file by default without automatically choosing one.

## Transaction model

Use a focused storage submodule and a small platform seam, not more boolean
arguments on `atomic_replace`. Suggested roles are `SourceExpectation`,
`PreparedCandidate`, `CommitReceipt`, `PersistFailure` and `RecoveryInfo`.
Names can follow repository style; semantic distinctions below are mandatory.

Source expectation binds canonical physical parent/destination, vault identity,
revision and exact baseline source hash. Candidate bytes and semantic verifier
remain immutable throughout publication. The normal-save verifier must compare
old bytes against the saved source expectation, not the already-edited body.

Outcomes:
- Verified commit: exact intended bytes authenticated at live path, expected
  displaced bytes authenticated/hashed, required supported synchronization done.
  Adopt header/hash/revision exactly once; expose maintenance warning separately.
- Rejected before publication: this transaction did not replace the live file.
  Busy/temporary prepublication failures may retain a matching session; external
  change/missing/unsupported source requires reload and invalidates write state.
- Recovery required: publication may have progressed, or live/displaced/sync
  verification is uncertain. Retain encrypted evidence and lock; never claim the
  original live file or old password is unchanged.

Keep primary and secondary failure information separately. Nonsecret recovery
metadata may be displayed; do not debug/log keys, plaintext or file byte buffers.
Existing in-memory body rollback must not downgrade disk disposition.

## Task 1: typed transaction engine and bounded verification

Files: new storage transaction/recovery modules, src/storage.rs, src/error.rs,
focused unit/integration tests; Cargo.toml/Cargo.lock only for rustix direct edge.

- [ ] Write failing tests for prepublication preservation, external change,
  actual displaced mismatch, postpublication verification failure and cleanup
  success-vs-warning distinctions before implementing the engine.
- [x] Replace touched unbounded file reads with limit+1 bounded reads; validate
  ordinary file metadata and reject over-limit/growing input without allocation
  beyond the bound. Preserve the 64 MiB limit and add a small-limit helper test.
- [x] Exclusively create a same-parent private transaction directory containing
  synced/read-back independent old bytes, candidate bytes and publication copy.
  Use immutable bounded receipt metadata with constrained relative role names;
  do not treat marker/time/filename as authentication or deletion authority.
- [x] Before first publish attempt, disarm automatic pathname/directory cleanup.
  After Linux exchange the publication slot contains displaced data, not an
  expendable temp file. Drop must never publish, roll back or delete that slot.
- [x] Recheck source immediately before publish. Verify actual displaced bytes
  and freshly read live bytes afterward, using a verifier over the same captured
  bytes that were hashed. Check revision increments for overflow.
- [x] Keep preimage/candidate/displaced evidence on uncertainty. Never perform
  automatic occupied-target rollback. Preserve primary and later errors.

## Task 2: cooperative locks and preserving platform publication

Files: platform modules and focused Windows/Linux adapter tests.

- [x] Stable sidecar opened/created without truncation; nonblocking exclusive OS
  lock and typed Busy. Key by physical parent plus destination filename. Retain
  the inode/path across transactions, and release only the handle/lock on Drop.
- [x] Windows: existing-target ReplaceFileW with a unique absent backup path.
  No pre-deletion of .bak, no exists()-selected clobbering fallback, no reliance
  on unsupported REPLACEFILE_WRITE_THROUGH. Record Win32 error immediately.
- [x] Model 1175, 1176-with-backup, 1177 and unknown errors with actual namespace
  effects. Generic failure cannot mean unchanged without matching observations;
  1177 may already have moved old target to backup and must preserve material.
- [x] Linux: rustix renameat_with(EXCHANGE) on opened directories, preserving
  the displaced slot. Sync relevant directories. Unsupported/exdev capability
  fails closed, never falls back to rename-overwrite. Other unsupported targets
  receive an explicit capability error for existing-file writes.
- [ ] Real synthetic adapter tests cover success/displaced bytes, lock contention
  and native Windows sharing failures; model tests remain labeled as model tests.
  Preserve all existing no-clobber regressions.

## Task 3: bounded successful-backup retention

Files: transaction recovery/retention module and deterministic tests.

- [x] Retain one verified preimage after successful commit. Clean redundant
  owned candidate/displaced files only after verification; foreign material stays.
- [x] Use one bounded versioned successful-backup descriptor in a managed
  namespace, with exact allowed paths, destination identity, digest/size and one
  optional old-success pending-retirement descriptor. No secret fields.
- [x] Persist/read back new descriptor before deleting prior registered owned
  backup. Revalidate provenance/identity/content and allowed directory children;
  unknown, modified, malformed or symlinked objects disable deletion.
- [x] Cleanup or descriptor failure preserves both backups, returns committed
  with warning, and makes the next modifying save fail with clear recoverable
  maintenance status rather than generating another untracked transaction.
- [x] Tests: successive saves steady-state bounded retention, descriptor failure,
  cleanup failure, crash before/after registration/retirement, foreign .bak,
  unexpected children, altered owned file, and sole verified copy preservation.

## Task 4: caller integration and minimal locked recovery UI

Files: src/storage.rs, src/import/plan.rs, App actions/state/forms, picker reuse,
synthetic App/headless tests and docs.

- [x] Route ordinary save, import commit and explicitly confirmed overwrite
  restore through the engine. Remove/unreach the old blind rollback/deleting
  adapter paths. Restore binds destination to active session expectation while
  candidate source is captured/authenticated once with its own password.
- [x] Adopt verified receipt/session state only after commit; do not reopen
  outside transaction and leave old session alive on a later failure. Keep
  in-memory rollback for rejected mutation/import, preserve typed disposition.
- [x] External conflict/recovery-required saves nonsecret recovery summary then
  uses normal lock cleanup, clearing reveal/editor/import/picker generations and
  clipboard permits. Ordinary retry cannot continue a stale session.
- [x] Locked recovery surface displays stage/current-file observation, role
  labels, folder/path and explicit next actions. Reuse native chooser/state
  guards and no-clobber restore-to-new; never automatically pick by timestamp.
  Selected-copy authentication is explicit, inputs masked/zeroizing, cancellation
  and lock invalidate pending work, source remains read-only.
- [x] On selected-vault startup/open, inspect bounded direct sibling managed
  transaction records without following links. Residual unclassified material is
  shown, not replayed/removed; successful registered backups do not cause a false
  recovery alarm. Unknown .bak may be labeled unverified, never auto-adopted.
- [x] Tests cover mutation/import/restore rejection versus recovery lock, repeated
  actions, navigation/stale events, wrong-password/corrupt recovery source,
  existing recovery destination preservation, and explicit successful new copy.
- [x] Add subprocess termination tests at prepublish/afterpublish/beforeverify
  and restart evidence listing, with deterministic synchronization (no sleeps).
  This proves process-kill behavior, not physical power-loss durability.

## Task 5: review and verification

- [x] Full fmt/check/strict Clippy/tests, debug self-test, source/log guards,
  policy tests and immutable lock hash; preserve real red/green evidence.
- [x] Independent storage/caller review; resolve data-loss and lifecycle findings.
- [x] Headless GUI real interactions at 960x640/1280x800/1600x900, pixels reviewed.
  No automatic golden approval.
- [x] Additional native Linux synthetic recovery-to-new flow.
- [ ] Development push, exact tree/SHA CI, Windows adapter tests, package/hash and
  pre/post-package self-tests. No main merge or formal release.
- [x] Document remaining real Windows sharing/ACL, Win10 22H2, suspend/lock during
  async operations, IME/DPI and physical power-loss tests accurately.

## Primary API references

- https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-replacefilew
- https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-lockfileex
- https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-flushfilebuffers
- https://docs.rs/rustix/1.1.5/rustix/fs/fn.renameat_with.html
- https://docs.rs/rustix/1.1.5/rustix/fs/fn.flock.html
- https://doc.rust-lang.org/std/fs/struct.OpenOptions.html#method.create_new
- https://man7.org/linux/man-pages/man2/rename.2.html
- https://man7.org/linux/man-pages/man2/fsync.2.html


## Implementation and evidence qualifications (2026-10-02)

Tasks 1–4 code and synthetic coverage are implemented for review. The two open
checkboxes above are deliberate evidence qualifications, not silent completion:

- Baseline behavioral RED was recorded for independent preimage loss, the missing
  final source recheck and postpublication rollback/classification. Additional
  caller/recovery, secondary-error, sync-checkpoint and descriptor-ownership
  regressions were also observed RED then GREEN. The rest of the deterministic
  matrix was added against the engine; not every fault case was independently
  observed failing before its implementation. No retroactive RED claim is made.
- Native Linux adapter/lock execution is green. Native Windows sharing tests are
  implemented but await Windows CI. Production Windows platform files compile in
  an isolated API-check crate; the full Linux-to-MSVC check stopped at missing
  `lib.exe` in bundled SQLite. API compilation and namespace models are not
  Windows runtime verification.

Rolling maintenance intentionally blocks after an interrupted cleanup rather
than silently resuming it. The locked authenticated restore-to-new flow is the
bounded user recovery route. Static overwrite restore is fail-closed; the active
session method returns the verified replacement session directly. See
`docs/verified-storage-recovery.md` for the API migration and supported contract.

Only synthetic data was used; no real vault, real credential or user-desktop
operation was part of validation. Windows publication remains a separate gate.

## Accepted independent-review corrections

The finite review-fix pass addresses B1–B3 and C1–C3:

- [x] Keep a bounded persistent maintenance witness through final descriptor,
  cleanup and required synchronization checkpoints; gate the live session too.
  Removing that witness is the last operation, without a later required sync.
  Power loss may conservatively resurrect it; durable cleanup is not promised.
- [x] Share existing-Windows-path normalization between session and discovery,
  preserve known missing-target evidence and case-sensitive distinct filenames.
  A native Windows case/OS-queried 8.3 integration regression is included.
- [x] Reject oversized encoded candidates before namespace mutation and candidate
  hashing/authentication; cover the exact limit and limit+1.
- [x] Keep manual path keystrokes editable; inspect at explicit open or committed
  open-file chooser selection instead.
- [x] Show persistent clipboard warning and generation-bound acknowledgment on
  recovery, including after later storage/password status messages.
- [x] Classify current-source verification failures as invalidating typed source
  dispositions, retaining their cause and current observation.

Both targeted re-reviews marked all six findings addressed without a new blocker.
Final exact-source Linux validation passed 233 Rust tests and all 24 headless GUI
tests, including real path editing and clipboard-warning recovery interactions
at all three logical sizes. Formatting, all-target check, strict all-feature
Clippy, debug build and binary self-test passed. Source-data and sensitive-log
guards passed; Python policy checks passed 12 tests with 8 PowerShell-only skips.
The fixed actual Linux window also kept an empty/edited path on the normal form,
where the preserved earlier binary had reproducibly opened recovery by mistake.
The actual native Linux recovery flow then rejected a wrong password and cleared
the field, rejected an occupied destination without changing its hash, restored
the explicitly selected previous version to a new file while remaining locked,
and reopened that version successfully. The original vault and recovery source
hashes stayed unchanged. These tests used isolated synthetic data and manual path
entry; they do not prove OS-native picker, Win10, IME or DPI behavior.

Dependency lock SHA-256:
`d79a1e7fcdafd2bf8e522840518d77eb2c05bed2c4cbe82588c33f4425f8ab24`.
Windows native alias/sharing execution, complete Windows build/packaging and
exact-source artifact verification remain separate gates. Local API compilation
is not a native-Windows runtime pass.
