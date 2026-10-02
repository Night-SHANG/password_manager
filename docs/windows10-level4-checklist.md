# Windows 10 Level 4 acceptance

This is the final real-machine gate for the Windows-first v1 release. A GitHub-hosted Windows Server runner does not count as Windows 10 Level 4 evidence.

## Preconditions

- Use a real Windows 10 22H2 workstation.
- Use only synthetic test credentials and synthetic CSV fixtures.
- Download the release artifact produced by the Windows Release workflow.
- Keep `password-manager.exe` and `SHA256SUMS.txt` in the same directory.
- Run:

```powershell
powershell -ExecutionPolicy Bypass -File .\scripts\windows10-l4.ps1 -ReleaseDirectory <release-directory>
```

The script verifies the release SHA-256 and runs the packaged binary's `--self-test`. It also creates `windows10-level4-report.txt` with the manual acceptance list.

## Manual security/lifecycle checks

The report must explicitly record PASS/FAIL for:

- Windows lock, logoff-relevant lifecycle, and sleep/resume auto-lock.
- screenshot protection on/off behavior with supported Windows capture paths.
- 30-second password clipboard cleanup.
- clipboard sequence protection when unrelated content is copied after a password.
- no plaintext password in logs or the report.

## Manual UX/platform checks

The report must explicitly record PASS/FAIL for:

- Chinese IME in all editable text fields.
- Unicode, emoji, and long text persistence.
- DPI 100%, 125%, 150%, and 200%.
- Ctrl+F / Ctrl+N / Ctrl+S / Ctrl+L.
- create/open/lock, CRUD, favorites, recycle bin, backup/restore.
- Google/Chrome CSV import Preview and reimport conflict behavior.

## Closure rule

Batch E is not fully closed until:

1. Rust Preflight is green.
2. Windows Release workflow builds, hashes, packages, unpacks, and self-tests successfully.
3. A real Windows 10 Level 4 report is completed without unresolved release-blocking failures.

## Plaintext CSV ownership and warning acceptance

Use only synthetic vaults/exports. Record the exact executable/source/lock hashes.

- Export empty and multilingual/quoted records; compare six-column LF bytes and import round trip. Verify the encrypted vault is unchanged.
- Verify preexisting file/directory/link refusal, nested Unicode local paths, readback success, and supported path restrictions in `owned-csv-export.md`. Confirm ADS/device/UNC and non-local volume refusal occurs before plaintext creation. Windows ACLs are inherited from the selected parent; do not record owner-only ACL protection unless independently inspected.
- Run native sharing tests: while the created output handle is held with `FILE_SHARE_READ`, read-only verification succeeds and new write/delete/rename opens are denied. Namespace fault-model tests deliberately use relaxed test sharing and are not evidence of real production rename feasibility.
- Inject post-create failure using the automated synthetic fault suite; verify no automatic removal and a persistent full-path warning in Settings, locked and recovery views. Check scrolling long Unicode paths at the minimum window size and target DPI settings.
- An unresolved warning blocks another export. Acknowledgment is explicit and does not say deletion was verified. Close first masks/locks; Keep open retains warning and lock. Only the current prompt's explicit exit confirmation closes normally. Check clipboard shutdown still occurs on normal close.
- Record the current limitation: an entered synchronous export can delay lock/close/native messages while write/sync/read blocks. This is not responsive cancellation or background drain acceptance.
- The synthetic forced-exit test can leave a prefix/moved output and competitor. On restart no CSV scan/deletion occurs and no in-memory warning is restored. Do not interpret absence of a restarted warning as absence of plaintext.
