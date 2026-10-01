# GUI repair: legacy Python interaction baseline

Status: approved by user; implementation and CI verification in progress.

## Basis

- Legacy `password_manager/ui/theme.py`: light theme, blue #2563EB, Microsoft YaHei UI.
- Legacy `password_manager/ui/main_view.py`: 250 logical-pixel sidebar, search/clear/add toolbar, five-column password table, row selection, double-click edit and context actions.
- Existing Rust vault, migration, backup and platform services remain authoritative. No vault-format or cryptographic changes in this batch.

## This batch

1. Replace the permanent three-column shell with legacy sidebar + table workspace.
2. Separate create/open authentication and give editing, import and settings their own bounded, scrollable working space.
3. Restore category counts, selection, safe category deletion/reordering, row selection, double-click edit and a right-click action panel.
4. Use Iced 0.14.0's own table and iced_test 0.14.0 simulator. Add real widget-click/input/navigation tests and headless PNG captures in Windows CI.
5. Upload captures for review. A newly generated snapshot is evidence of rendering, NOT an approved golden reference or visual acceptance.

## Verification and limits

- Tests must use generated synthetic vaults only; never ingest user vaults or password exports in CI.
- Keep existing import/security regression suites. Do not silently relax gates.
- Simulated text input is not real Chinese IME testing. Logical window sizes are not OS DPI tests. Headless captures do not validate Win10 WDA/session/sleep behavior.
- Native file pickers, complete legacy column resizing/hover parity, long-list virtualization and nonblocking KDF/import execution are not closed by this layout batch.
- Existing missing native-vault merge import, repeated-import edge cases and clipboard ownership review remain open. No claim that only manual L4 remains.
- Previous Win10 hash/self-test report remains historical evidence for its exact binary, not evidence for this revision.

## Review sequence

CI format/check/tests/Clippy -> UI interaction tests -> headless captures -> review captures -> target GUI package -> focused user acceptance. Stop polling after push.
