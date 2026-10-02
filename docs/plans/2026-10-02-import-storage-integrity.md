# Import and restore integrity implementation plan

> Agentic implementers: execute the tasks with regression-first development;
> preserve the existing card GUI and confirmation boundaries.

**Goal:** prevent ambiguous or stale imports from silently duplicating or
overwriting entries, and enforce restore's explicit no-overwrite contract.

**Baseline:** `77f1dded5aeba9067a2a39b799d658710eadbb28`, Preflight #33 passed.

**Architecture:** keep the existing parse, preview, explicit decision, one-save
transaction. Add unambiguous identity material and private preview bindings;
validate all write intentions before mutating the session. Reuse the existing
exclusive file publisher for restore(false).

**Tech stack:** Rust, existing serde/sha2/uuid/zeroize/tempfile, Iced 0.14.
No new dependency or encrypted schema/header version.

**Spec:** existing import design and Batch B deletion semantics:
- https://app.notion.com/p/3e8fbd029cd2811aa401e36598698846
- https://app.notion.com/p/3e9fbd029cd281aa894ff6026f343569
- https://app.notion.com/p/3e8fbd029cd281049f32d891ed508941

## Global constraints and decisions

- Synthetic test data only. Never inspect or modify the user's real vault.
- Parse/preview never writes; commit remains explicit. Secrets stay zeroizing.
- Preserve partial/deferred update reporting, one save and complete rollback.
- Recycle-bin entries require explicit restore/keep-deleted/keep-both decisions.
- Permanent deletion remains true removal. A later import requires fresh
  preview/commit; this batch does not introduce persistent tombstones.
- Native-vault merging, asynchronous KDF and master-password changes are separate.
- Do not change GUI's explicitly confirmed overwrite=true restore behavior.
- Existing Iced controls/scroll containers only; no new rendering layer.
- No main merge or formal release. Publish only to dev/rust-rewrite-v1 after
  local gates and independent review, then monitor exact-SHA CI to terminal state.

## Review focus

1. Legacy delimiter collisions must not hide local modifications under either
   strong or weak identity matching.
2. Rows claiming one identity with different contents must not use source order
   to select a winner; multiple writes to one UUID must fail before mutation.
3. Reopened/cloned sessions and unsaved body changes must invalidate previews,
   even when vault ID and persisted revision are unchanged.
4. Old UI decisions must not apply after re-analysis, path edits, navigation or lock.
5. Competing files published before/after restore(false) must remain untouched.

## Task 1: unambiguous content and source identity

Files: src/import/mod.rs, src/import/legacy.rs, src/import/plan.rs;
tests/import_plan.rs, tests/legacy_migration.rs and focused unit tests.

- [x] Add red tests for the U+001F password/notes boundary collision, old
  provenance hiding a local modification, and independent DBs sharing entry:1.
- [x] Stream a version-domain prefix and fixed-width byte lengths plus field
  bytes into SHA-256; avoid a non-zeroizing canonical plaintext allocation.
- [x] Recompute incoming item fingerprints at preview construction rather than
  trusting the publicly supplied fingerprint field.
- [x] Snapshot compatibility accepts a legacy fingerprint only when all current
  string fields contain no U+001F. New fingerprint is always preferred. Both
  strong and weak update detection share this unchanged-since-import rule.
- [x] Scope legacy DB IDs by the decoded, verified salt with domain-separated
  SHA-256: db:<salt-digest>:entry:<row-id>. Renaming/copying the same DB preserves
  identity; independent salts do not alias.
- [x] Legacy provider + unscoped entry:N matches are confirmation-only candidates.
  Changed content is Conflict, never automatic UpdateCandidate. Exact content
  may skip but never silently adopts a new DB namespace.
- [x] Verify old unambiguous fingerprints still permit incremental updates and
  new control-character content supports later legitimate updates.

## Task 2: deterministic preview and bound commit

Files: src/import/plan.rs, src/storage.rs (in-memory session identity only),
src/app.rs, src/app/actions.rs, src/app/ui/forms.rs, tests/import_plan.rs,
src/app/tests.rs.

- [x] Red tests: duplicate new rows; conflicting duplicate strong ID; ambiguous
  weak-key rows in both orders; two decisions writing the same local UUID.
- [x] Collapse only identical source identity plus complete content into an
  explicit SourceDuplicate class with visible statistics, without invented UUIDs.
  Different strong IDs are not silently aliased merely because contents match.
- [x] Duplicate scoped strong ID with differing contents fails the whole preview
  with row numbers/type only, never secret values. Ambiguous weak-identity rows
  all become Conflict; no-target conflicts offer skip or import independently.
- [x] Give each create/open session a non-persisted instance ID. A preview
  privately binds session ID, vault ID, revision and the complete encrypted-body
  snapshot. Expose immutable row access and a preview ID.
- [x] Bind options and UI decision/apply events to that preview ID. Validate
  row bounds, allowed class, candidate UUID/state and unique write target before
  any body mutation. Reject stale bindings rather than reclassifying under old
  decisions. Reject replay after a successful no-op/deferred application too.
- [x] Add regression tests for unsaved edits/category/recycle changes, wrong
  vault, reopened same vault, wrong preview ID/row/class/UUID, stale UI events,
  path edits, lock, successful application and failed-save rollback.
- [x] Preserve staged contents if the external source changes after preview:
  do not silently re-read a new source at commit.
- [x] Assert rollback of complete body, categories, provenance, import history,
  revision and preservation of externally changed disk bytes.

## Task 3: exclusive restore publication

Files: src/storage.rs, tests/backup_restore.rs and storage unit tests.

- [x] Red deterministic tests: destination appears as file/directory before
  publish; destination replaced after publish; same-ID/revision divergent file.
- [x] overwrite=false uses TempPath + platform::atomic_create_new exclusively.
  Verify full expected source hash as well as vault identity/revision.
- [x] Post-publication failure must not delete a destination of unproven
  ownership. Keep overwrite=true's existing explicit-confirmation semantics.
- [x] Reuse existing before/after publish hooks without sleeps; assert no orphan
  temporary files, wrong-password/corrupt-source preservation and valid roundtrip.

## Task 4: integration, review and exact-source verification

- [x] Focused red-to-green commands recorded with failures preserved.
- [x] Full serial cargo fmt/check/strict all-feature Clippy/all-target tests,
  debug self-test, source-data/log guards and Python CI policy checks.
- [x] Headless GUI tests at 960x640, 1280x800 and 1600x900; preserve prior generated
  review captures separately, inspect new pixels, never auto-approve goldens.
- [x] Independent source review of this batch; resolve substantive findings.
- [ ] Publish grouped code/tests/docs; confirm remote tree and exact-SHA CI.
  Inspect Windows logs, package/source manifests and hashes before delivery.
- [x] Record Win10 real dialog, IME/DPI and actual OS lifecycle checks as final
  machine acceptance, not as proven by Linux/headless/Windows Server CI.

## Implemented behavior and review closure

The new fingerprint streams domain-separated length-framed fields. Compatibility
with old fingerprints is limited to unambiguous current field values. Salt-scoped
legacy database identities keep copied/renamed databases stable while preventing
independent databases from sharing row identities. Old unscoped provenance is
never silently assigned a new namespace.

Preview and decision APIs now bind explicit IDs; the unbound default-options API
was removed. This is an intentional source API change, not a vault-format change.
All-deleted ambiguous groups preserve explicit restore choices, while mixed groups
offer active overwrite targets only. Successful no-op/deferred applications also
consume their in-memory preview epoch; failed transactions remain retryable.

Independent review identified two additional exact-match dependencies: an update
could replace the only local entry backing another row's automatic skip, and
several strong identities could alias through one weak local match. Both received
failing regressions before correction. Preview now exposes those ambiguities as
conflicts; commit validates selected writes against private exact dependencies.
Changing a strong identity counts even if content bytes remain equal. Skipping a
source row is explicit and does not promise another row cannot update that same
local target. KeepBoth can preserve both values without a new alias schema.

Restore(false) now exclusively publishes and reopens to verify exact source hash.
Its competing file/directory/link and post-publish replacement tests are
deterministic. Restore(true)'s existing confirmed replacement branch is unchanged;
general transaction-owned rollback and concurrent save/replace guarantees remain
a separate storage prerequisite, not a claim of this batch.

The independent re-review marked both import findings addressed with no new
blocker. The isolated restore review also found no blocker. The final local
aggregate passed 190 Rust tests, formatting, all-target check, strict Clippy,
debug build and binary self-test. All 21 headless GUI tests passed, including
real clicks through the new duplicate/conflict choices at all three sizes;
actual review pixels were inspected with no secret values displayed.
Python checks passed 12 tests with 8 local
PowerShell skips. Source-data/log guards passed and the lock hash is unchanged:
`026f076a16c5a64b9ce5d3a174de328d4a075bb44f66904a843b124692ccaf82`.
Windows CI, release packaging and final Win10 machine acceptance are separate
gates; no formal release or main merge is implied.
