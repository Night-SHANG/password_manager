# Native file dialogs and exclusive new-file publication

Baseline: `887a83f76949dd048d36871c82ae31e9bbc2441a` (Preflight #30).

## Scope and reused pattern

The six existing path fields now provide native selection: existing vault,
new vault, import source, encrypted backup destination, restore source, and
plaintext CSV destination. Manual entry remains available. This preserves the
legacy card layout and all explicit analyze/create/restore/export actions.

The implementation follows Iced 0.14's official editor example:
`window::oldest` → `window::run` → `rfd::AsyncFileDialog` bound to the main
window → asynchronous `Task`. The direct dependency is pinned to rfd 0.17.2.
No alternate rendering layer or custom filesystem browser is introduced.

- https://github.com/iced-rs/iced/blob/0.14.0/examples/editor/src/main.rs
- https://docs.rs/rfd/0.17.2/rfd/struct.AsyncFileDialog.html

## Interaction and safety contract

- Selection only returns a path. It never opens/decrypts/imports/writes a vault.
- Building the dialog only prepares an owned directory hint; it does not stat
  potentially unavailable/network directories on the UI thread.
- At most one native dialog is in flight. Both UI and update reject repeated
  launch/file-operation messages until it returns.
- Each result carries its request ID. Navigation, lock/reset, auth-mode changes,
  path edits, and operation changes invalidate it. The slot stays occupied until
  the OS dialog returns, preventing multiple dialogs after navigation.
- A result for an older request cannot clear the current request. Leaving then
  reopening the same panel does not make an old result valid again.
- Cancel leaves the field intact. Backend failures that rfd returns as `None`
  cannot be distinguished from cancel, so the message states both possibilities
  and preserves manual input. Missing main windows have a separate error.
- Path conversion rejects empty, NUL-containing, and non-Unicode paths instead
  of silently changing them. Chinese, emoji, spaces, and long Unicode paths are
  preserved. Native save dialogs can append extensions; the actual returned
  path is shown before the existing explicit action.
- Import path changes discard previews/resolutions and old source passwords.
  Restore path changes discard the old password and replacement confirmation.
  CSV destination changes reset the plaintext-risk acknowledgement.
- Authentication scroll content has an 8px scrollbar gap and bottom padding;
  overflow must not cover the path field or crop the final text.

## Exclusive publication

New vault and encrypted-backup creation previously checked existence, performed
work, then used an overwrite-capable rename. Deterministic regressions place a
competing file immediately before publication and reproduce its destruction.

New-file publication now uses Windows `MoveFileExW` with WRITE_THROUGH but without
REPLACE_EXISTING, or the already-pinned tempfile no-clobber primitive elsewhere.
The temporary file is still fully written and synced before publication. A
collision preserves the competing destination and cleans the staged file.
Post-publication verification remains mandatory; failures preserve the target
because the application cannot prove that another writer has not replaced it.
Two additional regressions reproduce and prevent the former unsafe deletion.

Normal vault saves and explicitly confirmed restore replacement are unchanged.
CSV already uses `create_new(true)`. The non-GUI `restore(overwrite=false)`
check-then-replace race is a known separate API limitation; this change does not
claim that API is fixed. The current GUI intentionally invokes confirmed restore
with `overwrite=true`.

## Verification and remaining platform checks

Regression tests cover six routes, exact messages, disabled repeated clicks,
cancel/error results, invalid/hidden targets, manual path changes, reopening,
lock and platform lock, stale request IDs, no-I/O selection, confirmation reset,
Unicode paths, and real wheel scrolling at 960×640, 1280×800, and 1600×900.
No screenshots are approved golden baselines; captures are review evidence.

The native cloud Linux app was launched with the default llvmpipe/OpenGL backend.
Open/save invocation reaches rfd, but this environment has neither the desktop
portal service nor zenity. It returns an explanatory status, remains responsive,
and accepts manual input. Official zenity installation was attempted and blocked
by the cloud package-manager permission/environment boundary; no workaround was
used. Successful real native selection/cancellation/modality is NOT validated
by headless state tests. The tiny-skia native runtime also showed shadow
accumulation that did not occur with the default renderer.

Windows CI must compile this dependency/Win32 primitive, run the exact shared-lock
security, Rust and GUI gates, build/package, and run EXE and unpacked self-tests.
Win10 22H2 actual dialog modality, keyboard/focus, lock while a dialog is open,
DPI/IME, permissions, UNC/removable paths and unsupported-extension behavior stay
on the consolidated final real-machine acceptance checklist. Linux/Windows Server
CI results cannot prove those items.

## Local validation record (2026-10-02)

- rustfmt, all-target check, strict all-target/all-feature Clippy: passed.
- 57 Rust tests passed; 16 explicit tiny-skia GUI tests passed.
- Lock preparation: read-only, SHA-256
  `27eb0215d1ec46586a573cb4928d72c51c3000873210b80a1fb4ff60cd4583d6`.
- Python CI checks: 12 passed, 8 PowerShell-dependent checks skipped on Linux.
- Sensitive-log and forbidden-source-data static guards passed.
- Gitleaks, cargo-deny, PowerShell packaging and Windows executable validation
  remain enforced by CI; they were not claimed as local Linux passes.
- Independent code review reported no remaining blocker.
