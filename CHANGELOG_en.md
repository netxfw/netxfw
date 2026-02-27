# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Fixed
- **Multi-NIC**: Fixed -i -c parameters issue for multi-NIC support
- **BPF Maps**: Fixed nil pointer issue in clearmap
- **Binary Compression**: Fixed bin.zst logic issue after refactoring

## [v1.0.23] - 2026-02-23

### Changed
- **CLI Docs**: Updated CLI documentation
- **Default Settings**: Disabled auto-updates by default and updated documentation
- **Docs**: Updated README download links to use latest release instead of hardcoded version

## [v1.0.22] - 2026-02-21

### Changed
- **Docs**: Updated documentation renaming related content

## [v1.0.21] - 2026-02-23

### Changed
- **Config**: Finalized comment refactoring and fixed minor field issues
- **CI**: Allow GoReleaser to replace existing artifacts and fix v2 deprecations

## [v1.0.20] - 2026-02-23

### Fixed
- **Lint**: Refactored showConntrackHealth to reduce complexity and fix lint errors

### Added
- **System**: Added auto-update support via CLI and enhanced deployment script
- **Config**: Restore default port 22 allow rule in config template

## [v1.0.19] - 2026-02-23

### Changed
- **Config**: Cleaned up comments in DefaultConfigTemplate and fixed nil context lints in CLI
- **CLI**: Enhanced health check logic for LRU maps (Conntrack/DynBlacklist)
- **Standalone**: Optimized BPF path (bitwise/scaling) and refactored Go config sync logic

## [v1.0.18] - 2026-02-21

### Added
- **Multiple releases**: Contains features and fixes from versions 1.0.9 through 1.0.18
- **Enhanced stability**: Various improvements and bug fixes
- **Performance optimizations**: Continued performance improvements

## [v1.0.8] - 2025-02-20

### Added
- **Unified IP Map**: Merged IPv4 and IPv6 BPF maps into a single 128-bit LPM Trie for simpler maintenance and better performance.
- **Config Sync**: Added `system sync` command (`to-config` / `to-map`) to bridge the gap between runtime BPF state and configuration files.
- **Rule Import**: Restored `rule import` command for bulk loading of blocklists.
- **Documentation**: Added `ARCHITECTURE.md`, `CONTRIBUTING.md`, and `SECURITY.md` for open source readiness.
- **Test Suite**: Organized integration tests into `/test/integration` with automated scripts.
- **License Files**: Added Apache-2.0 LICENSE for Go code and Dual BSD/GPL for BPF code.

### Changed
- **Internal Architecture**: Refactored `internal/xdp` to handle IPv4 addresses as IPv4-mapped IPv6 addresses (`::ffff:a.b.c.d`) internally.
- **CLI**: Improved `rule list` output to correctly distinguish between allow/deny lists.
- **CLI**: Fixed `rule remove` command to ensure changes are persisted to disk when `system sync` is used.
- **CI/CD**: Updated GitHub Actions to run only unit tests, excluding integration tests that require real environment.

### Fixed
- Fixed a bug where `rule list deny` would display whitelisted IPs.
- Fixed a bug where `rule remove` would not persist changes across restarts (now supported via `system sync`).
- Fixed CLI argument parsing for `rule import` to support `deny` alias.
- Fixed XDP load time calculation to show actual program uptime instead of system uptime.
- Fixed data race conditions in test suite by adding proper mutex protection.

## [v1.0.7] - 2025-02-18

### Added
- **Hot Reload**: Support for zero-downtime hot reload with state migration.
- **Auto-Blocking**: Automatic IP blocking when rate limit thresholds are triggered.

### Changed
- Improved BPF map management and cleanup.

## [v1.0.6] - 2025-02-15

### Added
- Initial public release.
- Core XDP/TC packet filtering.
- Connection tracking (Conntrack).
- Rate limiting with Token Bucket algorithm.
- Web UI for monitoring.
- Prometheus metrics exporter.

---

For older versions, see [GitHub Releases](https://github.com/netxfw/netxfw/releases).
