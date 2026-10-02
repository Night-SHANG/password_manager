# Detail scrolling and action lifetime correction

Recorded: 2026-10-02 15:31 北京时间（UTC+08:00）.
Base: `7fa759762918dac0f4015cf41a5cf43d9b547de0` on `dev/rust-rewrite-v1`.
Scope: existing legacy-card UI; no renderer, dependency, encryption or vault-format change.

## Reproduced defects and native solution

- Iced's default vertical scrollbar floats over its content. The detail column filled the same width, so the rightmost CJK/emoji glyphs were covered. A synthetic tiny-skia screenshot reproduced this and a new geometry assertion failed. Use the existing Iced `Scrollable::spacing(8)` to embed the 10px scrollbar and reserve an additional 8px clear gap. Do not compensate by truncating text or adding a new renderer.
- Closing details previously only changed visibility. `RevealedPassword` stayed alive. All dismissal paths now use one helper that drops this zeroizing buffer. Navigation, copy, editor, confirmations, failed actions, cancel and lock continue to clear it. This is not a guarantee of zeroizing toolkit-owned render allocations.
- Select/edit/context UUID messages lacked the card-action visibility guard. They now reject absent, filtered, locked and non-workspace targets. Delayed selected actions also check their workspace target before decryption, clipboard task creation or mutation.
- Detail buttons previously sent unscoped selected-action messages. A real button-message regression showed an action created for A changing B after selection switched. All detail actions, including Close, now carry the UUID and context generation. Closing, switching or reopening the same entry invalidates older messages before synchronously dispatching the existing action handler.

The card mask, metadata-only hover, explicit reveal, opaque overlay, fixed action/close rows and confirmed destructive/restore/export handlers are preserved. No real vault, database, user screenshot or credential was used.

## Tests and observations

The original baseline passed 37 ordinary Rust tests. New state regressions were observed failing before implementation for stale targets, retained reveal buffers, reveal outside open details, and a stale hidden-selection clipboard task. The new gutter GUI regression failed before `spacing(8)`. The A-to-B real-button regression failed before target/generation binding. This is runtime evidence, not source-contract matching.

The previous implementation could already reach the end of long metadata; the defect was horizontal scrollbar overlap and missing regression coverage, not proof of an unreachable bottom. New tests actually wheel to the end and back, assert the final field is fully visible and verify fixed action positions at 960×640, 1280×800 and 1600×900 in light and dark themes. Synthetic captures were visually inspected before and after the change. They are review evidence, not approved golden baselines.

Details actions are tested across switching to a second visible entry, closing, and closing/reopening the same entry. Test selectors enter the context panel explicitly because a text-only selector may match an obscured card button with the same label.

Linux compilation exposed three pre-existing strict-Clippy errors in Windows-only imports, a parameter and a helper. Narrow cfg/parameter handling fixes them without changing the Windows implementation or suppressing warnings globally.

## Validation boundary

Local execution uses Linux, Rust stable 1.99.0 and the committed lockfile. Windows-specific PowerShell, Gitleaks, cargo-deny, optimized Windows packaging and Windows security lifecycle remain separate CI/target-machine gates. No Windows 10 acceptance is inferred from Linux screenshots or GitHub-hosted Windows Server.

The existing shared lock/hash, formatting, check, tests, strict Clippy, secret/log checks, GUI-before-package, binary self-test and unpacked self-test gates are unchanged. After the development push, stop CI polling and report the triggered run without treating it as passed. No main merge, release tag or formal release is part of this change.

Native file dialogs remain the next bounded UI group. Nonblocking KDF/import, native-vault merge/reimport boundaries, performance, clipboard ownership/races and actual Windows 10 22H2 acceptance remain open. Batch E is not closed.

## References

- `docs/plans/2026-10-01-card-gui-correction.md`
- `docs/plans/2026-10-01-metadata-readability.md`
- https://github.com/iced-rs/iced/blob/0.14.0/widget/src/scrollable.rs
- https://github.com/iced-rs/iced/blob/0.14.0/test/src/simulator.rs

## Local verification record

- `cargo fmt --all -- --check`: passed.
- `cargo check --all-targets --locked`: passed.
- `cargo clippy --all-targets --all-features --locked -- -D warnings`: passed without warnings.
- `cargo test --all-targets --locked`: 41 passed; 13 explicitly ignored GUI tests run separately.
- `cargo run --locked -- --self-test`: passed on the Linux debug binary (`release_smoke=ok` is the program's fixed output string, not evidence of an optimized Windows build).
- Python CI policy suite: 12 passed; 8 PowerShell runtime cases skipped because PowerShell is absent. The Windows CI requirement remains unchanged.
- `scripts/prepare-ci-lock.py`: passed, `refreshed=false`; Cargo.lock unchanged, SHA-256 `538464aa0083488980544f5c788045e529fca90d84f8b112d5af052eb2dd0add`.
- Forbidden tracked-file and sensitive-log-pattern scans: passed; `git diff --check`: passed.
- Independent read-only review: the initial stale-detail-action finding was fixed with UUID/generation binding; re-review reported no blocking findings.
- `ICED_TEST_BACKEND=tiny-skia cargo test --lib gui_ --locked -- --ignored --test-threads=1`: all 13 passed on the final source tree. Final light/dark gutter and scrolled-end pixels were inspected; these captures do not certify Windows DPI/IME or approve a golden baseline.
