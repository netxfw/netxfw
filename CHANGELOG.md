# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- **Unified IP Map**: Merged IPv4 and IPv6 BPF maps into a single 128-bit LPM Trie for simpler maintenance and better performance.
- **Config Sync**: Added `system sync` command (`to-config` / `to-map`) to bridge the gap between runtime BPF state and configuration files.
- **Rule Import**: Restored `rule import` command for bulk loading of blocklists.
- **Documentation**: Added `ARCHITECTURE.md`, `CONTRIBUTING.md`, and `SECURITY.md` for open source readiness.
- **Test Suite**: Organized integration tests into `/test/integration` with automated scripts.

### Changed
- **Internal Architecture**: Refactored `internal/xdp` to handle IPv4 addresses as IPv4-mapped IPv6 addresses (`::ffff:a.b.c.d`) internally.
- **CLI**: Improved `rule list` output to correctly distinguish between allow/deny lists.
- **CLI**: Fixed `rule remove` command to ensure changes are persisted to disk when `system sync` is used.

### Fixed
- Fixed a bug where `rule list deny` would display whitelisted IPs.
- Fixed a bug where `rule remove` would not persist changes across restarts (now supported via `system sync`).
- Fixed CLI argument parsing for `rule import` to support `deny` alias.

## [v1.0.6] - 2025-XX-XX
- (Previous changes...)
