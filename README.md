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

## Current migration / backup model

The formal Rust branch now has one normalized import pipeline for:

- generic 4-column and 6-column password CSV
- Google Chrome / Google Password Manager CSV
- old `vault.enc`
- old `passwords.db`

Repeated imports distinguish exact duplicates, update candidates, conflicts, and locally deleted items. Weak CSV identities never silently overwrite conflicting local data. Legacy SQLite migration uses its stable entry id as a strong source identity.

Native backup is different from import: an encrypted `.pmvault` backup preserves the whole vault identity, revision, entry ids, and encrypted data. Plaintext CSV export exists only as an explicit compatibility path and requires an acknowledgement at the API boundary.

## Development

Formal development happens on `dev/rust-rewrite-v1`.

The Python implementation currently kept in this branch is legacy reference material only. The Rust code under `src/` is the new authority.

The repository Preflight checks formatting, compilation, tests, Clippy, lockfile state, and forbidden tracked files. Synthetic fixtures are generated during tests; real vaults, databases, and password exports must never be committed.
