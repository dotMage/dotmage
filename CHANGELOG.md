# Changelog

All notable changes to the dotMage CLI (`dmage`) are documented here.
Format: [Keep a Changelog](https://keepachangelog.com/en/1.1.0/); versioning: [SemVer](https://semver.org/).

## [Unreleased]

### Added
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

### Fixed

### Security

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

[Unreleased]: https://github.com/dotMage/dotmage/compare/v1.2.1...HEAD
