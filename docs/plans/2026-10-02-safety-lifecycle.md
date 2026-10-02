# Safety lifecycle: idle lock, focus masking, managed clipboard

Baseline: `f2fed2db1fd61b8a802ac7cbc077074b82a63ba5` (Preflight #31).

## Requirements and explicit implementation choices

The v1 specifications require idle locking, re-masking on focus loss, an
adjustable auto-lock time, and short-lived password clipboard contents that do
not overwrite a later foreign copy. They do not prescribe idle minutes or an
activity definition. The legacy Python implementations contain no idle setting.

This batch explicitly chooses a conservative, reversible five-minute default,
with 1/5/10/15/30 minute options. Five minutes is a new implementation default,
not a historical user preference. The established password-copy default remains
30 seconds; the small settings control permits 15/30/60 seconds for future copies.
Neither control disables Windows lock/suspend handling or offers a Never option.

References:
- https://app.notion.com/p/3e8fbd029cd28126a23cd761a0728894
- https://app.notion.com/p/3e8fbd029cd28188bf04e8e38712c20d
- https://app.notion.com/p/3e8fbd029cd281049f32d891ed508941
- https://bitwarden.com/help/vault-timeout/ (mature app-local inactivity pattern)

## Idle and focus behavior

Iced's native event subscription observes captured as well as uncaptured user
input. Keyboard presses, click, wheel, touch and IME composition/commit count as
activity while this window is focused. Mouse movement, redraw, focus change,
background results and timer events do not keep a vault unlocked. A monotonic
one-second timer enforces the deadline; every incoming App message checks expiry
before performing its action. Input received after expiry cannot extend it.
Successful unlock/create/restore starts a fresh timer. Lock destroys the session,
clears decrypted reveal/editor state, revokes clipboard writes, and invalidates
pending native file-selection results.

Losing focus immediately drops the zeroizing revealed-password buffer and masks
an editor's password. It does not lock the entire vault or invalidate a legitimate
native file dialog. Returning focus does not reveal again. Editor show/copy
messages bind the current page generation so an old message cannot re-reveal or
copy from a newly reopened editor.

Windows create/unlock is gated on session-monitor readiness. Initialization
waiting and terminal failure have distinct messages. A failed active monitor
locks the vault. Bounded clean startup retries are permitted; runtime monitor
failure requires a clean application restart rather than reusing a potentially
broken owner thread. Recovery never unlocks automatically.

## Settings storage

Preferences are device-local and separate from the encrypted vault format:
Windows LOCALAPPDATA/PasswordManager/settings.json; Linux XDG_CONFIG_HOME or
HOME/.config/password-manager/settings.json. Tests use injected temporary paths.
Only version, auto_lock_minutes and clipboard_seconds are serialized. Reads are
bounded to 4 KiB, reject unknown/duplicate/missing fields and invalid values, and
fall back to five minutes/30 seconds with a visible warning on corruption or I/O
failure. Missing files do not trigger writes. Saving validates, writes and syncs
a sibling temporary file, then atomically replaces settings. App applies new
values only after success; a failed save preserves prior effective values.

## Clipboard boundary

The prior Iced clipboard effect had no OS success acknowledgement, yet a later
message sampled a sequence number and armed cleanup. A failed copy could bind
unrelated content. A reused native timer also allowed an old queued WM_TIMER to
clear a newer copy prematurely. KillTimer does not remove already queued messages.

The existing native security-window thread now owns password and username writes,
receipt creation, deadlines, bounded retries and conditional cleanup together.
Commands enqueue synchronously through a bounded/coalescing typed queue; wakeup
messages carry no raw secret pointer. Copy completions contain only session ID,
request ID, kind and outcome and update status only. No App API can arm arbitrary
clipboard contents. Opaque per-unlock permits are revoked before delayed writes
can publish, including native WTS lock/suspend handling before App notification.

A private per-copy marker, native owner, verified Unicode contents and a nonzero
sequence bind the write. CloseClipboard can synthesize formats/change sequence,
so binding verifies after close instead of trusting a later arbitrary sample.
Cleanup revalidates the receipt after opening. Foreign replacements must never
be cleared or silently adopted. Monotonic per-copy deadlines handle stale timer
messages. Failure paths retain no plaintext indefinitely and do not report
success merely because an operation was queued.

Revealed editor text inputs previously bypassed that boundary through Ctrl+C/X.
A small Iced clipboard-event adapter now routes those writes through the same
managed pipeline with zeroizing payloads. It delegates layout, draw, state and
normal input handling to the original text input; no new renderer is introduced.
Password cut is intercepted before Iced can mutate its local input value, then
deferred until the native copy succeeds and the same editor still contains the
unchanged original draft. The adapter tracks preceding edits within the same
native event batch; cutting without selection is a no-op. Its grapheme offsets
reuse the same locked unicode-segmentation version as Iced, without putting the
password into a temporary cursor-value buffer. If editing continues before the
copy completes, the deletion is cancelled and the original selection is retained. Failure, navigation, focus loss, lock, a
newer copy, or intervening password edits cancel the pending deletion. The
original/replacement buffers are zeroizing. This prevents asynchronous Ctrl+X
from losing a password when the OS copy fails. Paste remains the standard
explicit user action. Notes and ordinary non-password
editor fields are not claimed to be password-copy operations.

App shutdown always invokes a bounded process-local cleanup barrier, even after
Lock has relinquished its live token. It covers retired receipts and queued work.
Cleanup failure is persistent warning state, not just a status string that a
subsequent lock could overwrite. It remains visible while locked/unlocked until
an explicit current acknowledgement or a matching verified new copy; stale
acknowledgements cannot dismiss newer failures. OS contention can prevent
clearing; this remains best-effort with visible failure
while the app is running and a non-sensitive exit diagnostic if shutdown fails.

Native references:
- https://github.com/iced-rs/iced/blob/0.14.0/runtime/src/clipboard.rs
- https://learn.microsoft.com/en-us/windows/win32/api/winuser/nf-winuser-killtimer
- https://learn.microsoft.com/en-us/windows/win32/api/winuser/nf-winuser-setclipboarddata
- https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-globalunlock
- https://github.com/wine-mirror/wine/blob/master/dlls/user32/tests/clipboard.c

## Evidence and remaining acceptance

Red-to-green regressions cover idle expiry, late activity, focus buffer release,
monitor failure, stale editor re-reveal, editor keyboard-copy bypass, preference
validation/persistence, and the native clipboard state machine's ordering/error
paths. GUI settings use real menu selection at the three established logical
sizes. Native Windows types are additionally checked using the official Rust
Windows target in an isolated harness; this is compilation evidence, not Windows
execution or a replacement for the full CI build.

The actual cloud Linux GUI created a synthetic vault/entry, re-masked on focus
switch without locking, automatically locked after one-minute inactivity, and
retained the setting after restart. Its isolated settings JSON held only the
version and timers. No real credentials or system clipboard contents were read.
Screenshots were inspected in the native tool; no inaccessible screenshot path is
presented as a downloadable artifact.

Windows clipboard sequence/synthesis/ownership, contention, WTS suspend/lock,
shutdown timing, Win10 22H2, IME and DPI require final real-machine acceptance.
Linux clipboard copy intentionally fails closed because the Windows owner/cleanup
contract is not implemented there. This batch does not complete nonblocking KDF,
import transaction/duplicate handling, master-password change, or the remaining
editor/navigation feature work.

## Final local verification (2026-10-02)

- 141 Rust tests passed in one complete serial validation command, followed by
  20 explicit headless GUI tests. The 59 platform-focused tests are a subset of
  the Rust coverage, not additional independent test counts.
- rustfmt, all-target check, all-target/all-feature Clippy with warnings denied,
  debug build and synthetic binary self-test passed.
- Actual native Windows modules passed isolated cross-target Clippy with tests
  and warnings denied. The harness substitutes minimal surrounding error/event
  declarations; the full Windows application still requires CI.
- The final native Linux build also confirmed selected Ctrl+X copy failure leaves
  the full draft intact and unselected Ctrl+X deletes nothing. Cancelling without
  saving preserved the synthetic vault hash.
- Final lock SHA-256:
  `026f076a16c5a64b9ce5d3a174de328d4a075bb44f66904a843b124692ccaf82`.
  Locked metadata validation did not rewrite the lock.
- Python CI tests: 12 passed, 8 PowerShell-dependent tests skipped locally.
  Sensitive-log and forbidden-source-data guards passed.
- Gitleaks, cargo-deny, PowerShell checks, Windows release build/packaging and
  packaged EXE self-tests remain CI gates; they are not described as local passes.
- Independent source review reported no remaining high/medium blocker.

An earlier worker aggregate run lost an integration-test executable during
concurrent rebuilds. That interrupted run was not treated as a pass; the final
aggregate above was rerun serially after source edits stopped. Captures are
synthetic review evidence, not automatically approved golden baselines.
