# Card metadata readability continuation

Recorded: 2026-10-01 19:12 北京时间（UTC+08:00）.
Base: `2f2adc0844b42ba80584446c002cbed79def4852` on `dev/rust-rewrite-v1`.
Status: implementation and tests prepared; new Rust/GUI/Windows verification pending CI.

## Recovered evidence

Rust Preflight #24, run `36850147665`, completed successfully at 2026-10-01 18:52 Beijing, testing `fa439e28e847d0b12f271f0d0f3730d9270b7051`. All five jobs succeeded. The Windows job reports format/check/test/Clippy, release build, binary self-test, packaging, unpacked self-test and artifact upload successful. The bot then committed the checked lock as `2f2adc0844b42ba80584446c002cbed79def4852`.

GUI artifact `11156125089` was downloaded and its archive SHA-256 matched `f01471cb0b6cf264c4f58fee5f1bd5a3168898c4ba44519f33442cd5386b8805`. All 14 capture BEGIN/END pairs completed. Visual inspection covered the centered authentication card, wrapped cards, editor, import, settings, context panel, dark/empty states and long-text fixture. The previous render crash did not recur in these captures; this is not proof about every rendering path or actual Windows 10.

The long-text capture and source both show hard-clipped card metadata with no hover/details fallback. This was already an open item in the approved card-GUI continuation, not a new layout direction.

## Bounded change

- Reuse Iced 0.14 Tooltip, container clipping, WordOrGlyph wrapping and vertical scroll. No new dependency or custom renderer.
- Add delayed hover hints only to name, username and website. The tooltip has a bounded preview plus a visible instruction to right-click for full contents. Arbitrarily long metadata remains fully available in the scrollable context details; the card itself intentionally remains compact.
- Constrain the context panel to a finite size. Keep its action rows and close button outside the details scroll region. An explicitly revealed password uses the same scroll region, so it cannot displace those controls.
- Do not decrypt passwords or notes for a hover. Keep the fixed password mask, UUID action routing, existing reveal/lock lifecycle and all storage/crypto/migration handlers.

## Verification and limits

The original local UI copy was verified against Git blob `52d9a7d757e3a29dd2afa4ece92b7ad7a3f33bda` before editing. Seven local source-contract checks were run before and after: six missing-readability checks failed on the old source and passed on the new source; the unchanged password-mask check passed both times. These are static checks, NOT behavioral Rust tests.

Three new ignored `gui_` tests are registered in the existing GUI CI command: delayed metadata hover pixel changes across three sizes and two themes; username/website hover versus a non-hovering password mask; and long context details with visible actions/close, explicit reveal and lock. Website comparison starts after hover styling but before the tooltip delay, so a button color change alone cannot satisfy it. Synthetic values only are used. Screenshots remain review evidence, not approved golden baselines.

There is no local Rust/rustfmt toolchain. No local compilation, Rust test pass, Clippy pass, formatting pass or new screenshot result is claimed. Keep all existing CI gates unchanged and stop polling after the push. Review the next CI and its actual screenshots before calling this change verified.

Native file dialogs, full sidebar/other-page hover treatment, nonblocking KDF/import, performance, native-vault merge, reimport boundaries, clipboard ownership and real Windows 10 platform checks remain open. Batch E is not closed.

## Fixed-version references

- https://github.com/iced-rs/iced/blob/0.14.0/widget/src/tooltip.rs
- https://github.com/iced-rs/iced/blob/0.14.0/test/src/simulator.rs
- https://github.com/iced-rs/iced/blob/0.14.0/selector/src/target.rs
