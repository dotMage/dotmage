# Changelog

All notable changes to the dotMage CLI (`dmage`) are documented here.
Format: [Keep a Changelog](https://keepachangelog.com/en/1.1.0/); versioning: [SemVer](https://semver.org/).

## [Unreleased]

### Added
- `--json` on `status`, `diff`, `history`, `apps`, `whoami` — machine-readable output
  for scripts, CI and editor integrations. One JSON document on stdout, errors stay on
  stderr; schemas are a semver contract (spec §5). `diff --json` never includes secret
  values, even with `--show-values`.
- Prebuilt Linux aarch64 binary (`dmage-linux-aarch64`) — Raspberry Pi and ARM VPS
  are covered by releases and `dmage upgrade`; install one-liners now pick the
  binary via `uname -m`.

### Changed
- TLS switched from OpenSSL to rustls: Linux binaries no longer require `libssl`
  at runtime and run on any glibc distro out of the box.
- Releases are no longer cut automatically on push to `main`: a release is an
  annotated tag (`git tag -a vX.Y.Z && git push origin vX.Y.Z`) — the pipeline starts
  only from the tag, cross-checks it against `Cargo.toml`, and main quietly collects
  features between releases.

### Fixed
- `dmage env new --copy-from` produced an environment whose every pull failed with
  "AEAD authentication failed": the server copied the encrypted blob byte-for-byte,
  but ciphertext is bound to `app|env|rev`. The copy now happens client-side —
  decrypt the source, re-encrypt for the new environment, push as rev 1.
- `dmage rotate-key` no longer aborts (and blocks rotation forever) when it hits a
  revision it cannot decrypt: the broken revision is kept byte-for-byte, marked with
  the new key generation, and reported loudly at the end.

### Security

## [2.0.2] - 2026-07-06

### Added
- After `dmage auth --invite`, the CLI offers to map a project directory to the new
  server (Enter accepts the current dir, `-` skips) — no more mandatory manual `server map`.

## [2.0.1] - 2026-07-06

### Added
- On `dmage auth`, the CLI adopts the server's advertised name (`DOTMAGE_SERVER_NAME`)
  as the local server name — no more manual `dmage server rename` after joining.
- `dmage clean --server <name>` wipes a single server (key + tokens + config entry);
  the global `dmage clean` now warns loudly before wiping every server.

### Changed
- Global `dmage clean` points to `dmage server rm` / `--server` for single-server removal.

## [2.0.0] - 2026-07-03

### Added
- **Team mode**: invite colleagues with their own master passwords over a shared vault.
  `dmage user invite/list/role/rm`, `dmage auth --invite <token>`, `dmage whoami`.
  Invitations are one-time sealed tokens (the server cannot open them); roles
  (owner/editor/viewer) are enforced server-side. Requires dotmage-server with
  `DOTMAGE_MODE=team`.
- Offboarding chain: `dmage user rm` deletes the member's key wraps, revokes their
  devices and offers a key rotation on the spot — the safe path is the default path.

### Changed
- Solo setups are untouched: with a solo-mode server (the default) nothing about team
  mode is visible, and existing accounts migrate to a "team of one" automatically.

### Security
- A removed member's cached key stops decrypting anything pushed after the chained
  rotation. Rotate the secret values they saw and destroy pre-rotation backups — the
  docs offboarding runbook covers both.

## [1.4.0] - 2026-07-03

### Added
- `dmage rotate-key` — re-encrypt every revision with a fresh Account Key (spec Appendix L).
  Client-driven, resumable after interruption, key generations tracked per blob. Requires
  dotmage-server with the `rotation` feature.

### Security
- Closes the documented v1 gap "a leaked Account Key decrypts all history forever":
  rotation makes old cached keys useless for anything pushed after it. Note: backups
  taken before a rotation remain decryptable by the old key — destroy or re-encrypt them
  when rotating after a device compromise.

## [1.3.0] - 2026-07-03

### Added
- Store any file, not just `.env` — DataGrip XML, kubeconfig, JSON (`dmage init dbconf
  --file dataSources.xml`). The file name/format travel inside the encrypted payload
  (server never sees them); `pull`/`push` use the stored name automatically; `diff`
  adapts to the format; `exec` clearly refuses non-env apps. Non-env apps require this
  version on all devices; existing `.env` apps are untouched.
- Multiple servers (work/personal): `dmage server add/map/list/rm/use/rename`, global
  `--server <name>`, `DOTMAGE_SERVER` env var. Project directories map to servers in the
  global config (like git `includeIf`) — commands pick the right server from your CWD.
  Single-server setups are unaffected; legacy configs migrate automatically.
- App name defaults to the current directory name: `dmage push` with no arguments.
- `dmage lock --all` / `dmage logout --all` — act on every configured server.
- `dmage upgrade` — self-update from GitHub releases: verifies `SHA256SUMS`, sanity-checks
  the new binary, replaces itself atomically. `--check`, `--version`, `--force`, `-y`.
  Homebrew/cargo installs get a hint to use their package manager instead.

### Changed
- Pushing an empty `.env` (0 keys, including comments-only files) now fails with an error.
  Pass `--allow-empty` to `dmage push` / `dmage init` if intentional.

### Security
- Release binaries ship with a `SHA256SUMS` asset; `dmage upgrade` refuses releases
  without it.

## [1.2.1] - 2026-07-01

### Fixed
- Update checker compares versions with proper semver ordering.

## [1.2.0] - 2026-07-01

### Added
- `dmage app rm` — delete an application and all its environments.

## [1.1.0] - 2026-06-11

### Added
- App folders: `/` in app names groups apps in `dmage apps` output (`work/myapp`).
- Multi-device auth flow, scoped CI tokens (`dmage gen-ci-token`), web-admin login token.

## [1.0.4] - 2026-06-09

First stable release line: auth, init/push/pull/exec/diff/history/rollback, environments,
enrollment tokens, local FsBackend mode, Homebrew formula.

[Unreleased]: https://github.com/dotMage/dotmage/compare/v2.0.2...HEAD
[2.0.2]: https://github.com/dotMage/dotmage/compare/v2.0.1...v2.0.2
[2.0.1]: https://github.com/dotMage/dotmage/compare/v2.0.0...v2.0.1
[2.0.0]: https://github.com/dotMage/dotmage/compare/v1.4.0...v2.0.0
[1.4.0]: https://github.com/dotMage/dotmage/compare/v1.3.0...v1.4.0
[1.3.0]: https://github.com/dotMage/dotmage/compare/v1.2.1...v1.3.0
