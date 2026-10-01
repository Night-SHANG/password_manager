# GUI CI repair implementation plan

> Execution: inline. Continue the approved legacy GUI repair; do not redesign the UI or change the vault format.

Goal: unblock compilation and make dependency policy, GUI review and packaging validate the same source and dependency snapshot.

Baseline: dev/rust-rewrite-v1 at 796d634fb44935e851d9addb44afdcd63d0fc52a. The authoritative GUI run is 36814801689; it failed formatting and compilation, not a clipboard Option<str> callback. No GUI screenshots were generated.

## Work and evidence

1. Apply the exact rustfmt patch from GUI artifact 11141091404. Verify original and formatted Git blob hashes before editing. Limit action helper visibility to pub(super), add the Iced 0.14 Palette warning field and an explicit Theme type for table styling. Preserve all existing tests.
2. Prepare Cargo.lock once. A one-time, narrowly authorized transition recognizes the exact previous lock blob a8038e0ba407c4aab83a7e3b46a1a9cacabeda44 and runs cargo update -p yoke-derive --precise 0.8.4. This also resolves the already-declared iced_test development dependency. Other lockfiles are checked with --locked, never silently regenerated. Test this transition with synthetic lockfiles and a fake Cargo runner.
3. Share that lockfile and its SHA-256 as one run-local artifact. Dependency policy, reusable GUI Review and Windows Preflight must verify and consume those exact bytes. GUI Review remains a separate workflow file, called by Preflight; manual GUI runs use the committed lockfile. Do not run independent push-triggered resolvers.
4. Preserve Gitleaks, cargo-deny, rustfmt, check, tests, strict Clippy, release self-tests and packaging gates. Only commit a changed lock after all automated gates, including GUI tests, succeed, and only on the unchanged development branch. No main/tag/Release writes.
5. Inspect the patch and workflow dependency graph, run local Python tests and parse YAML/TOML. Rust and GUI execution remain pending CI because this editing container has no Rust toolchain. New screenshots are review evidence, not approved baselines or Win10 Level 4 evidence.

## Remaining product work

Native file dialogs; full column resize/hover parity; rendering performance; nonblocking KDF/import; native-vault merge import; duplicate-import edge cases; clipboard ownership audit; actual Windows 10 GUI/security acceptance. Batch E must remain open.
