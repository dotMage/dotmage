# Changelog

All notable changes to the dotMage CLI (`dmage`) are documented here.
Format: [Keep a Changelog](https://keepachangelog.com/en/1.1.0/); versioning: [SemVer](https://semver.org/).

## [Unreleased]

### Added

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
