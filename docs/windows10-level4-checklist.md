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
