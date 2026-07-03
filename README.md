# dotmage

**dmage** — CLI for [dotMage](https://github.com/dotMage), an E2E-encrypted `.env` secret manager.

## Install

### Download binary

Pre-built binaries for macOS, Linux, and Windows are available on the [Releases](https://github.com/dotMage/dotmage/releases) page.

### Build from source

```
cargo install --git https://github.com/dotMage/dotmage.git
```

### Upgrade

```bash
dmage upgrade            # direct-binary installs: verified self-update
brew upgrade dotmage     # Homebrew installs
```

`dmage upgrade` downloads the release binary, verifies it against the release's
`SHA256SUMS`, sanity-checks it, and atomically replaces itself. Homebrew/cargo installs
are detected and delegated to the package manager. `--check` only reports,
`--version X.Y.Z --force` allows downgrades.

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
| `dmage lock` | Remove key from keychain (`--all` for every server) |
| `dmage logout` | Full logout (key + tokens) |
| `dmage server list/add/map/rm/use` | Manage multiple servers (see below) |
| `dmage upgrade` | Self-update from GitHub releases (sha256-verified) |

Inside a project directory the app name defaults to the directory name — `dmage push`
with no arguments just works.

## Beyond .env

Any file works — DataGrip datasource XML, kubeconfig, service-account JSON. The file
name and format are stored *inside* the encrypted payload, so the server never sees them,
and `dmage pull` on another machine recreates the file under its original name:

```bash
dmage init dbconf --file dataSources.xml
# on another machine:
dmage pull dbconf          # writes dataSources.xml
dmage push dbconf          # picks up dataSources.xml automatically
```

Formats: `env` (key diff, `exec` injection), `text` (line/byte diff), `binary`
(sha256 compare) — detected from the extension, override with `--format`.
`exec` works only with env-format apps. Requires dmage ≥ 1.3 on all devices for
non-env apps; existing `.env` apps are unaffected and stay compatible with older CLIs.

## Multiple servers (work / personal)

Optional — with a single server nothing changes. Map project directories to servers
(like git's `includeIf`), and every command picks the right server from your CWD:

```bash
dmage server add work https://secrets.corp.com --path ~/code/work
dmage auth --server work
dmage server add personal https://home.example.com --path ~/code/personal
dmage auth --server personal

cd ~/code/work/billing-api
dmage push                    # → work, app "billing-api"
cd ~/code/personal/blog
dmage pull                    # → personal, app "blog"
```

Resolution order: `--server <name>` flag → `DOTMAGE_SERVER` env var → longest matching
mapped path → `dmage server use <name>` default. Ambiguity is an error, never a guess.
With 2+ servers every push/pull prints which server it hit (`→ work (secrets.corp.com)`),
and `dmage status` explains why that server was picked.

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
