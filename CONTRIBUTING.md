# Contributing to dmage (dotMage CLI)

The command-line client for dotMage — an E2E-encrypted `.env` secret manager.
All encryption happens here, on your machine; the server only ever sees
ciphertext. A Rust workspace of three crates:

```
dmage/    the `dmage` binary — CLI commands and argument parsing
client/   transport, config, keychain, storage backends
crypto/   the cryptography (XChaCha20-Poly1305, Argon2id, envelope, invites)
```

## Setup

Stable Rust via [rustup](https://rustup.rs).

```bash
cargo build
```

## Checks (CI runs the same on Linux, macOS and Windows)

```bash
cargo fmt --all -- --check
cargo clippy --all-targets -- -D warnings
cargo test --all
```

## Run against a server

```bash
cargo run -p dmage -- auth --server https://your-server
cargo run -p dmage -- apps
```

## Ground rules

- **Crypto stays client-side.** The `crypto` crate is the trust boundary —
  secrets are encrypted and decrypted locally, keys never leave the machine.
  Never send plaintext or keys to the server; blobs are AEAD-bound to
  `app|env|rev`.
- **The API is a contract** (`/api/v1`). It's defined in the private
  `dotmage-spec` repo, where changes are visible PRs.
- **Self-update** verifies downloads against the release `SHA256SUMS`; keep that
  path intact (signing the checksums with minisign is planned — see the
  `TODO(minisign)` marker in `cmd/upgrade.rs`).

## Commits & releases

Short, imperative Conventional Commits (`feat:`, `fix:`, `docs:`, `ci:`). Keep
the CHANGELOG's `[Unreleased]` section current. A release is an annotated
`vX.Y.Z` tag — CI cross-checks it against `dmage/Cargo.toml`, builds the binaries
with a `SHA256SUMS`, and updates the Homebrew formula. Pushing to `main` builds
nothing user-facing.
