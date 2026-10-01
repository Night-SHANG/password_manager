# Legacy screenshot correction: cards, not a table

Recorded: 2026-10-01 17:28 北京时间（UTC+08:00）.
Status: implementation prepared; Rust compilation, GUI rendering and visual approval pending CI.
Base: `36005590f174b65dcf5c3dc99860420058a4007b` on `dev/rust-rewrite-v1`.

## Authoritative visual target

The user's two screenshots supplied on 2026-10-01 show a centered white unlock card and a workspace with a left category sidebar, a top search/add toolbar and individual password cards. This corrects the earlier assumption in `gui-legacy-parity.md` that a five-column table was the intended legacy UI. Do not treat the table assumption or mandatory third column as the current visual requirement.

The screenshots are references, not evidence of new Rust behavior. They are not committed because they include the user's desktop and account context. Runtime fixtures must remain synthetic.

## Bounded implementation

- Keep Rust/Iced and the existing encryption, vault format, storage, migration, backup and confirmation handlers.
- Use Iced's existing container, row wrapping and vertical scroll primitives. No new renderer, dependency or storage format.
- Bound the unlock card before centering it in the full viewport. Keep create/open and file-path controls, with the path collapsed on the ordinary unlock screen.
- Use a 250 logical-pixel sidebar, 272-pixel password cards and a wrapping, vertical-scrolling workspace. Password cards always display a fixed mask; they do not decrypt credentials while rendering.
- Bind copy/favorite/website actions to each card's UUID and reject targets that are not in the visible unlocked workspace. This prevents reuse of an unrelated previously selected entry.
- Keep editor/import/settings builders in `src/app/ui/forms.rs`, including the fixed editor save/cancel row and existing import-conflict and plaintext-export acknowledgements.
- Retain the explicit close action for the opaque context panel. Do not install a click-to-dismiss wrapper around its interactive contents.

## Regression evidence and verification

The previous Preflight #22 (run `36828128893`) passed dependency policy, formatting and `cargo check`, then reported 2 GUI tests passed and 1 failed at `iced_tiny_skia`'s `Build quad rectangle`. Only auth/create/editor captures were produced. An unbounded horizontal table layout is a hypothesis, not a locally reproduced root cause. The screenshot-driven card replacement removes that layout path; it still must pass the rendering regression.

Seven explicit headless GUI tests now cover centered auth geometry, card button routing, search/edit/save, multi-size card rendering, import, settings, context/dark mode, and empty/long-text states. Capture BEGIN/END markers and `RUST_BACKTRACE=1` retain the failing scenario if another renderer panic occurs. The five regular app tests include a UUID-target/stale-target regression; the existing 500-entry filter test is not a performance benchmark.

Local checks performed: exact uploaded Git-blob hashes, whitespace, message-variant references, form-module visibility, card source contracts, test registration, YAML parsing and required workflow commands. These are static checks, not Rust type-checking or GUI execution. No Rust/rustfmt toolchain is present locally, so no local compiler, formatter or runtime pass is claimed. The strict format gate and GUI-before-package dependency remain in force.

A generated screenshot is review evidence, never automatic approval of a golden baseline. After push, stop polling and wait for the user to request the CI results; inspect screenshots before delivering a new test package.

## Still open

Native file dialogs, complete tooltip/long-text treatment, performance and nonblocking KDF/import operations, native-vault merge import, reimport edge cases, clipboard ownership/race handling, and real Windows platform verification remain open. Table column dragging is not a requirement of this default card layout. Batch E is not closed by this change.

## Fixed-version references

- https://docs.rs/iced/0.14.0/iced/widget/row/struct.Row.html
- https://docs.rs/iced/0.14.0/iced/widget/container/struct.Container.html
- https://github.com/iced-rs/iced/blob/0.14.0/test/src/simulator.rs
- https://github.com/iced-rs/iced/blob/0.14.0/selector/src/target.rs
