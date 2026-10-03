# Owned background vault operations

This existing-v1 group moves GUI vault work onto one named, reusable worker:
`password-manager-vault-worker`. It does not add a cloud vault, a new renderer or
master-password change. Synchronous public library entry points remain supported.

## Integrated operations

The lane owns startup/locked recovery inspection, create/open, current-file
verification, all existing entry/category mutations and saves, import staging,
analysis and application, encrypted backup, restore over the current vault,
restore-to-new, and plaintext CSV export. The UI passes typed owned requests,
not storage closures or fabricated permits. Disk publication uses opaque leases
bound to the admitted operation, security epoch, original session/source/body
and exact prepared candidate. Existing-target transaction and CSV output rules
remain documented in their respective storage/export documents.

The metadata coordinator holds no password, entry body, preview, file handle or
large result. There is one secret-bearing request/result slot and one fixed-shape
retirement bundle, not a secret job queue. Native monitor registration tokens
bind readiness and revocation to the exact live registration; deferred UI
readiness cannot restore authority after failure. Raw close revokes before the
Iced notification. Late form, session, preview and display messages cannot adopt
old results or authorize new publication.

## Cancellation, locking and closing

Before commit claim, cancellation prevents publication. After a successful claim,
the worker finishes the existing write/verification contract, even if lock or
close occurs. Normal cancellation can return the unchanged original session;
destruction of a sole session owner also retires its live authority. Replacement
session candidates require current adoption authority.

Lock immediately hides the workspace and detaches UI-owned secrets for worker
retirement. The request remains occupied through KDF, result transit and guarded
owner destruction. Only the actual worker's cleanup acknowledgment, together with
UI detachment, establishes a full lock. A stuck OS call is a masked, responsive
finishing state of unbounded duration, not successful cancellation. No UI-thread
join, dropped thread handle, timeout or Task abort certifies cleanup.

A separate retained terminal slot carries late file-risk results. Finished becomes
visible only after result storage/readiness. Normal exit waits for terminal
consumption as well as actual cleanup. CSV warnings have their own current
confirmation generation; encrypted maintenance/recovery warnings also have a
generation, so a previously visible warning cannot acknowledge a later outcome.
Final clipboard-shutdown completion rechecks current exit conditions. Forced
termination, process abort, power loss and forced OS shutdown can bypass all
in-memory warnings; restart does not scan or delete CSV files.

## Memory and accepted limits

Argon2 0.6.0's `zeroize` feature is enabled. The application additionally supplies
its own fallibly allocated guarded `Block` vector and guarded output; the feature
alone does not wipe an internally allocated block vector. Existing accepted KDF
parameters and output bytes are unchanged, including accepted high-memory inputs.

Import readers/copies are bounded at their existing limits, including SQLite
input/snapshot handling. Full captured-byte digests and source/provenance meaning
are preserved. Import indexing retains first-ID lookup semantics and candidate
order, including accepted duplicate UUID records. Exact body bindings and preview
epoch/no-op consumption remain enforced.

A 64 MiB encoded-file/source cap is not a total-process memory cap. Simultaneously
live encrypted originals/candidates, decoded bodies, parsed rows, previews,
indexes, KDF blocks and toolkit render allocations must be accounted separately.
Secret application-owned buffers are wiped where the implementation controls
ownership; no whole-process, toolkit, compiler/register, OS cache, swap, dump or
physical secure-erasure guarantee is made. Allocation abort and abrupt process
termination remain outside destructor cleanup guarantees.

## Bounded existing views

The existing card styling is preserved with 24 cards per page. Import rows and
conflict candidates use eight per page; category navigation uses 24 per page.
Search, category filtering, sorting, total counts, unresolved decisions and Apply
eligibility operate across the full dataset. Resolutions remain across pages.
Data changes clamp page positions; hidden/off-page detail targets lose validity.
Visible controls and keyboard paging keep all accepted rows reachable. Pagination
does not truncate accepted input or introduce a smaller storage limit.

## Large individual fields remain a responsiveness limit

Pagination bounds the number of visible records, not the size of one accepted
field. Existing EditEntry, Reveal and CopyPassword still decrypt a complete
entry secret synchronously. Stock Iced notes-editor construction and first layout
also remain on the UI thread; each notes action reads back the complete text.

A bounded release diagnostic on the Linux host below used one accepted 1 MiB
single-line note in a 4,992,474-byte vault. The real EditEntry handler took
266.351 ms, first layout 216.512 ms, and the subsequent first pixel snapshot
441.381 ms. A 64 KiB note measured 20.501/11.684/65.864 ms respectively. These are
individual synthetic observations, not percentiles or universal bounds.
A separate near-limit encoded vault (67,057,904 bytes; 14,086,941 note bytes)
measured decrypt/parse at 23.172 ms, Reveal at 28.433 ms and the Linux CopyPassword
handler at 28.230 ms; native clipboard completion was not measured.

No larger shaping run, lower acceptance cap, alternate renderer or paged editor
was introduced. Supporting all accepted large fields within UI budgets still
requires an explicit editor-design or compatibility decision. A movable Content
owner alone is insufficient evidence: text construction shares the toolkit font
lock and first layout can reshape the whole physical line.

The ignored `perf_background_single_entry_editor_diagnostic` test records each
phase before starting it. Run release diagnostics in separately time-bounded
processes with `PM_EDITOR_MODE=content` or `app`, `PM_EDITOR_BYTES`, and an explicit
`PM_EDITOR_REPORT` JSON path; `near-decrypt` uses the accepted near-limit fixture
and skips editor shaping. A timeout is a failed measurement with a lower bound,
never a responsiveness pass. These diagnostics supplement the operation matrix;
they do not replace full regression or native acceptance.

## Validation status and commands

Deterministic regressions exercise real-worker cancellation/disconnection, native
registration races, panic/poison cleanup, store-before-ready delivery, delayed
CSV terminal delivery, encrypted warning replacement, preview retirement and
preference-deadline synchronization. Source guards supplement these behavioral
tests; source pattern checks alone do not establish safety or responsiveness.

The 2026-10-03 Linux local gate passed default-parallel
`cargo test --all-targets --locked` (370 library tests and 56 integration tests;
50 ignored), formatting, all-target compilation, strict all-target/all-feature
Clippy, release build and executable self-test. The full headless GUI invocation
completed with 33 passed and one stale display-fixture failure. That test added a
row directly after initializing the cached view index; its explicit fixture
index refresh and the strengthened real Add/Edit→Save→search test then passed
in a separate two-test invocation. Formatting and strict Clippy passed again.
Only those two ignored test bodies changed after the aggregate; no production
or shared-helper change was made. The failed full-GUI result remains recorded,
and is not described as a green aggregate. Exact-revision Windows CI still
needs to run the full final-source GUI suite.

Independent bounded reviews cover authority/runner, native revocation,
prepared/KDF, import indexing/retry and pagination repairs. Completed synthetic
operation matrices and the post-import-fix measurements remain bound to their
respective source snapshots; they are not universal accepted-input or native
acceptance claims. The large-field editor gap above remains open.
The release-only operation harnesses write samples and resource data under
`target/background-perf/`:

- `PM_PERF_ENTRIES=1000` (then `10000`, `50000`) with
  `ICED_TEST_BACKEND=tiny-skia cargo test --release --lib perf_background_views_responsiveness --locked -- --ignored --test-threads=1 --nocapture`
- `cargo test --release --lib perf_background_import_indexed_analysis --locked -- --ignored --test-threads=1 --nocapture`
- `cargo test --release --lib perf_background_import_actual_source_limit --locked -- --ignored --test-threads=1 --nocapture`
- `ICED_TEST_BACKEND=tiny-skia cargo test --release --lib perf_background_sidebar_50k_categories_bounded --locked -- --ignored --test-threads=1 --nocapture`

Baseline measurements justified the limited indexing/pagination changes: import
classification performed 5N² predicate examinations; 1k-card/conflict first layout
and pixels exceeded 100 ms; a 50k-category sidebar sample took about 2 seconds.
These are demonstrated old hotspots, not final performance acceptance. Ten
operation samples never justify a duration p99. Input p95/p99 require the stated
at-least-1000 timestamped event samples; maxima, blocked calls and cleanup latency
are recorded separately from mask latency.

Linux evidence uses synthetic data on an AMD EPYC 9V74 cloud host with nine visible
logical processors and about 9.7 GiB reported memory. It is not the specified
4-core/8-GiB/SSD reference machine. Headless Iced pixels do not establish native
Windows 10 event-to-frame, IME/DPI, monitor, clipboard, ACL/sharing or suspend
behavior. Exact-revision Windows CI/package checks and the real-machine checklist
remain required.

## Finite remaining v1 work

Finish exact-revision CI and native acceptance. Segmented editing for oversized
notes has been approved as a separate follow-on: preserve complete data and the
existing format, leave ordinary notes unchanged, and do not lower accepted limits.
Reveal/Copy/Edit decryption remains synchronous and requires an explicit follow-on
ownership change if it is moved onto the existing lane. Then implement the
separately planned same-DEK master-password change. Preserve the existing finite
interaction checklist and complete exact-source packaged Windows validation and
Windows 10 22H2 lifecycle/IME/DPI acceptance. No main merge or formal release is
implied by a passing development-branch check.

## Native Linux functional check

The frozen Linux release was exercised with 49 synthetic entries, 25 categories,
and a nine-row import conflict preview with nine candidates per row. Actual
Ctrl+PageUp/PageDown, Alt+PageUp/PageDown and candidate-row/page shortcuts reached
the final pages; global search found an entry outside the original card page.
Changing card pages dismissed the old detail target. Import choices and candidate
pages survived navigation, while all seven remaining unresolved rows kept Apply
disabled. No import was executed, and fixture hashes stayed unchanged.

Manual lock from the populated preview cleared the workspace and eventually
reported that background materials had been released; normal window close then
completed. These were native functional observations on Linux, not timed
Windows or IME/DPI acceptance. Tab did not traverse from search to buttons in
this check and remains part of the outstanding keyboard-interaction work.


## CI39 monitor-admission correction

Development commit `f4bcee7467dad1d65f841fb50f8f71a2511e3d1b` passed
all 34 Windows headless GUI tests in Preflight #39. Lock-inputs, secret scan,
and dependency policy also passed. The ordinary Windows library suite stopped
at three failures, so packaging and its downstream gates did not run.

Two failures came from synthetic open fixtures that initialized the backend as
ready without initializing the Windows UI readiness precondition. The fixtures
now express both conditions. The third exposed a real regression: recovery's
monitor-unready return retained the submitted password in the form. Current
recovery-generation and authentication inputs now transfer to the existing
zeroizing retirement lane when readiness rejects submission. File paths and
recovery listings remain available for retry; stale generations cannot clear
another form's password.

Admission also rechecks authoritative readiness after a failed admission, covering
native revocation between the initial UI check and the coordinator decision.
Displayed readiness cannot override backend revocation. Initial startup retry and
a second permitted retry during held cleanup now detach their real UI owners and
wait for actual worker drain before fresh explicit authentication can proceed.
The correction does not manufacture readiness, cleanup witnesses, or successful
adoption, and does not change native registration or runner authority.

Regression models cover the rejected-admission interleaving, both startup retry
schedules, real held cleanup, stale input, delayed Ready, and Busy/picker input
preservation. Windows screen-capture effects are disabled only in the synthetic
startup model, which has no native window responder; application defaults remain
unchanged. Independent review found no remaining blocker in the bounded repair.
The final Linux repair passed formatting, all-target compilation, strict
all-target/all-feature Clippy, 432 ordinary tests (376 library and 56 integration;
50 intentionally ignored), all 34 headless GUI tests, and the release build plus
executable self-test. Exact-revision Windows results remain a separate gate. These state models and
headless pixels do not establish Windows 10 native monitor, focus, suspend,
clipboard, IME, or DPI acceptance.
