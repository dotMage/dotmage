# dotmage

**dmage** — CLI for [dotMage](https://github.com/dotMage), an E2E-encrypted `.env` secret manager.

## Install

### Download binary

Pre-built binaries for macOS, Linux, and Windows are available on the [Releases](https://github.com/dotMage/dotmage/releases) page.

### Build from source

```
cargo install --git https://github.com/dotMage/dotmage.git
```

## Quick start

```bash
# 1. Authenticate (first time creates account)
dmage auth --server https://secrets.example.com

# 2. Push your .env
dmage init myapp

# 3. On another machine
dmage auth --server https://secrets.example.com
dmage pull myapp

# 4. Run with secrets in memory (safest)
dmage exec myapp -- npm run dev
```

## Commands

| Command | Description |
|---------|-------------|
| `dmage auth` | Authenticate and cache key in OS keychain |
| `dmage init <app>` | Create app from current `.env` |
| `dmage push <app>` | Push local `.env` as new revision (empty file → error; `--allow-empty` to override) |
| `dmage pull <app>` | Pull and decrypt to `.env` |
| `dmage exec <app> -- <cmd>` | Run command with secrets in memory |
| `dmage diff <app>` | Compare local vs remote (values masked) |
| `dmage history <app>` | Show revision history |
| `dmage rollback <app> --rev N` | Rollback to revision N |
| `dmage apps` | List applications |
| `dmage status` | Show sync status |
| `dmage env list <app>` | List environments |
| `dmage lock` | Remove key from keychain |
| `dmage logout` | Full logout (key + tokens) |

## Security

- E2E encryption: server never sees plaintext secrets
- XChaCha20-Poly1305 (AEAD) with Argon2id key derivation
- AK cached in OS keychain with configurable TTL
- `.gitignore` guard on push/init

## Contributing

Every user-visible change updates `CHANGELOG.md` under `[Unreleased]` in the same PR —
entries are written for users, not committers. Release process:
[dotmage-spec/RELEASING.md](https://github.com/dotMage/dotmage-spec/blob/main/RELEASING.md).

## License

AGPL-3.0 — see [LICENSE](LICENSE).
