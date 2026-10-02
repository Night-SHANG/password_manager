# Preserve the last detail row across fractional text heights

Recorded: 2026-10-02 15:54 北京时间（UTC+08:00）.
Base: `a3c26183dbafcaea6a530e6478c1f39b256098c3`.

## CI evidence

Rust Preflight #29 failed its Windows GUI gate: 12 GUI tests passed and
`gui_long_details_scroll_to_end_and_back_without_moving_actions` failed with
`last field is clipped` at the first light 960×640 scenario. Formatting and
Windows cargo check passed in that job; the aggregate preflight/build/package
job was skipped. No new installation package was produced.

- Run: https://github.com/Night-SHANG/password_manager/actions/runs/36979675353
- Job: https://github.com/Night-SHANG/password_manager/actions/runs/36979675353/job/110751269560
- Artifact: https://github.com/Night-SHANG/password_manager/actions/runs/36979675353/artifacts/11215117696
- ZIP SHA-256 verified locally: `d17fb647078a7cc3b5de3937d85760eabc5644f52481bfa006f245b846a1a46f`.

The actual Windows end screenshot was inspected. The horizontal scrollbar
clearance worked; the final category row sat on the lower clipping boundary.
The Windows font metrics wrapped the fixture URL into one additional line
relative to the Linux fixture. An earlier Linux-only pass therefore did not
establish complete bottom visibility for other line counts.

## Reproduction and root cause

The locked `iced_widget 0.14.2` rounds scrolling translations to whole logical
pixels in `scrollable::State::translation`. Text line heights remain fractional.
When the maximum offset rounds down, a flush-bottom final row can lose part of
its layout rectangle.

Changing only the synthetic URL from 40 repeated path segments to 44 reproduced
the same failure on Linux before the fix:

- viewport: y=119.4, height=316.0
- last field height: 37.799995
- visible last field height: 37.600006
- lost height: approximately 0.2 logical pixels

## Bounded fix and regression

Give the existing detail column 8 logical pixels of bottom padding. The scroll
rounding discrepancy now falls within trailing whitespace rather than the last
field. The 8px horizontal scrollbar gap, fixed buttons, panel size, card layout,
secret lifecycle, vault format and dependencies remain unchanged.

Keep the existing full-height assertion at its original 0.1px tolerance. Add a
44/48/52/56-segment fixture regression, including actual wheel-to-end behavior
and a minimum 7.4px bottom clear-space assertion (8px minus the toolkit's at-most
half-pixel rounding). Failure output now includes geometry and scenario names,
never credential content. Capture each fractional-line scenario for review.

The new regression failed before the production fix and passed after it. This
is a layout correction, not a skipped test or increased clipping tolerance.

## Verification boundary

Re-run local formatting, all-target check/tests, strict Clippy, explicit GUI
suite and synthetic executable self-test, then rerun CI for the exact new
commit. Inspect the Windows captures before treating the Windows geometry issue
as resolved. A hosted Windows Server result still does not establish Windows 10
22H2 DPI, IME, clipboard, session or screenshot-protection acceptance.

The user clarified that dot may monitor builds autonomously; the earlier
stop-polling constraint concerned ordinary Chat. Report significant results and
fix recoverable failures without requiring the user to relay CI status.

## Local results before resubmission

- Formatting, all-target check and strict Clippy: passed without warnings.
- All-target Rust suite: 41 passed; 14 GUI tests explicitly run separately.
- Explicit tiny-skia GUI suite: all 14 passed, including original end/back tests
  in three logical sizes and two themes and the new fractional-height cases.
- Linux debug binary synthetic self-test: passed. This is not a Windows release test.
- Python CI policy checks: 12 passed, 8 PowerShell cases skipped on Linux.
- Cargo.lock and all CI workflow files unchanged; sensitive-log and forbidden
  tracked-file checks passed. Independent static re-review found no blocker.
- Final Linux scrolled-end screenshot inspected: the last category has visible
  bottom whitespace. New Windows CI and its captures remain to be checked.
