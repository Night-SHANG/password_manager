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

The Python implementation currently kept in this branch is legacy reference material only. The Rust code under `src/` is the new authority.

## Development

Formal development happens on `dev/rust-rewrite-v1`.

The repository Preflight checks formatting, compilation, tests, Clippy, lockfile state, and forbidden tracked files before a full release build is introduced.
