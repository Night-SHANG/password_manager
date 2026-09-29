# Password Manager

Windows-first local password manager being rebuilt in Rust.

## Architecture

- Rust + Iced native desktop UI
- no WebView, local HTTP API, or browser DOM
- Argon2id master-password KDF
- random vault DEK wrapped by a KEK
- HKDF domain-separated subkeys
- XChaCha20-Poly1305 authenticated encryption
- whole-vault encryption plus per-entry secret envelopes
- Windows atomic replacement with encrypted previous-file backup
- read-only migration adapters for legacy and external password exports
- Windows lifecycle security isolated behind the platform layer

## Current migration / backup model

The formal Rust branch now has one normalized import pipeline for:

- generic 4-column and 6-column password CSV
- Google Chrome / Google Password Manager CSV
- old `vault.enc`
- old `passwords.db`

Repeated imports distinguish exact duplicates, update candidates, conflicts, and locally deleted items. Weak CSV identities never silently overwrite conflicting local data. Legacy SQLite migration uses its stable entry id as a strong source identity.

Native backup is different from import: an encrypted `.pmvault` backup preserves the whole vault identity, revision, entry ids, and encrypted data. Plaintext CSV export exists only as an explicit compatibility path and requires an acknowledgement at the API boundary.

## Desktop UI status

The Iced desktop UI is connected directly to the encrypted vault and currently includes:

- create / unlock / lock
- three-column navigation, search, categories, favorites, recycle bin
- add and edit login entries
- password hidden by default, explicit reveal and copy
- OS-CSPRNG password generation
- safe HTTP/HTTPS website opening through the system browser
- encrypted recycle-bin restore and confirmed permanent deletion
- import Preview with update/conflict/locally-deleted decisions
- encrypted backup creation and transactional restore
- explicit-risk plaintext CSV export
- dark/light appearance toggle
- keyboard shortcuts: Ctrl/Cmd+F, N, S, L

## Windows security lifecycle

The Windows platform layer now provides:

- Iced top-level HWND access through `raw-window-handle`
- screenshot/capture exclusion using `WDA_EXCLUDEFROMCAPTURE`, enabled by default and user-controllable
- a dedicated hidden Win32 window registered for WTS session notifications
- automatic vault lock on Windows session lock, logoff, or system suspend notification
- password clipboard cleanup after 30 seconds only when the clipboard sequence number still matches the password copy
- immediate conditional clipboard cleanup when the vault locks
- fail-closed behavior when the clipboard sequence number or Windows security monitor is unavailable

Screenshot affinity reduces capture through supported Windows capture paths but is not treated as absolute protection against every capture method.

## Development

Formal development happens on `dev/rust-rewrite-v1`.

The Python implementation currently kept in this branch is legacy reference material only. The Rust code under `src/` is the new authority.

The repository Preflight checks formatting, compilation, tests, Clippy, lockfile state, and forbidden tracked files. Synthetic fixtures are generated during tests; real vaults, databases, and password exports must never be committed.


## Quality gates and release

The formal branch now uses a layered CI path:

- Gitleaks scans repository history for committed secrets.
- cargo-deny checks dependency advisories and the approved license set.
- Rust format / check / test / Clippy remain hard gates.
- a static guard rejects obvious password/secret logging patterns.
- every Preflight builds the optimized Windows executable.
- the release executable runs `--self-test` against a synthetic encrypted vault.
- the same executable is packaged into a Windows x64 ZIP with SHA-256 hashes.
- CI extracts the ZIP and runs `--self-test` again from the packaged artifact.
- a green development Preflight uploads the validated EXE, ZIP, and SHA-256 manifest for 7 days so the exact CI artifact can be used for Windows 10 Level 4 testing.

The `Windows Release` workflow can be run manually to produce an Actions artifact without publishing a GitHub Release. A pushed `v<package-version>` tag must match `Cargo.toml`; only then can the workflow publish the EXE, ZIP, and `SHA256SUMS.txt` to GitHub Releases and create provenance attestations for the executable and archive.

## Windows 10 Level 4

GitHub-hosted Windows runners are useful build evidence but are not accepted as a substitute for the target workstation. Final v1 closure requires the real-machine procedure in `docs/windows10-level4-checklist.md`.

On the Windows 10 test machine, run:

```powershell
powershell -ExecutionPolicy Bypass -File .\scripts\windows10-l4.ps1 -ReleaseDirectory <release-directory>
```

The script verifies the release hash, runs the packaged `--self-test`, records OS/build information, and creates the manual acceptance report for DPI, Chinese IME, Unicode, screenshot protection, clipboard behavior, session lock/suspend, backup/restore, and import/reimport flows.
