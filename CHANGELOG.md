# Changelog

All notable changes to AccordLock will be documented in this file.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and the project uses [SemVer](https://semver.org/) for published
releases. Before `1.0.0`, compatibility is not guaranteed; breaking changes
must still be called out explicitly.

## [Unreleased]

### Security

- Updated `h2` from `0.4.15` to `0.4.16` in the runtime and desktop
  lockfiles to address `RUSTSEC-2026-0258`.
- Updated `event-listener` from `5.4.1` to `5.4.2` in the distributed desktop
  graph to address `RUSTSEC-2026-0221`.
- Made `bat` optional behind the existing `tui` feature, excluding `bat` and
  its `bincode` 1.x dependency from the protected no-default-features desktop
  graph while preserving TUI-enabled builds.
- Added a fail-closed RustSec audit for the exact `goose-cli` graph shipped on
  Windows x64, macOS Intel, and macOS ARM64. Each graph is resolved on a native
  host, bound to the productive packaging command and script digest, and checked
  against the complete lockfile without advisory ignores or target or severity
  filters.
- Restricted the Windows package to ten named sidecar, marker, and support
  files. Packaging rejects extra files, directories, links, non-x64 PE files,
  and wildcard DLL collection.
- Restricted the macOS package to eleven named sidecar, marker, and support
  files. Both platforms reject redirected staging directories, and the seven
  authored support wrappers are checksum-bound before packaging.
- Isolated each native release build in new, platform-specific Cargo target
  directories that are removed after staging. On the required exclusive build
  runner, both source checkouts are revalidated against the release lock before
  signing and again before Electron Forge runs.
- Corrected Windows 8.3 path-alias handling by comparing native stable file or
  directory identities instead of normalized path strings. Terminal executable
  identity is also checked before and after hashing.
- Bound the four text-based native packaging helpers to LF checkouts on every
  host and made CI verify that attribute contract before auditing their exact
  raw-byte hashes.
- Added the exact durable-control catalog fingerprint produced by the
  checksum-pinned PostgreSQL 17.11 CI image while retaining the PostgreSQL 17.4
  fingerprint. Each fingerprint is bound to its exact server version, and any
  other version or catalog representation still fails closed.

## [0.1.0-alpha.1] - 2026-09-01

Initial public engineering alpha, published as a source-only prerelease.

### Added

- Public governance, security, contribution, support, trademark, and release
  policies.
- Public architecture, trust-boundary, limitation, roadmap, and brand guides.
- Repository sanitation and publication validation checks.
- A provider-neutral request-to-result conformance engine with ordered trace
  construction, evidence provenance, calibration admission, and conservative
  enforcement outcomes.
- A durable, redacted agent activity ledger with per-session snapshots,
  bounded pagination, domain-separated page digests, revocation history, and
  file-recovery events.
- Signed Slack, Microsoft Teams, Telegram, and WhatsApp approval challenges;
  Slack and WhatsApp signature verification; Telegram webhook-secret checks;
  externally verified Teams claim binding; durable replay protection; and a
  crash-detecting encrypted delivery outbox that dead-letters expired
  in-flight leases instead of resending them.
- Fixed-authority outbound request adapters for Slack, Telegram, WhatsApp
  Cloud API, and the commercial Teams Bot Framework service, with ephemeral
  redacted credentials, bounded transport contracts, provider receipt checks,
  conservative retry classification, a one-step outbox worker, and durable
  authenticated terminal reason codes. No live HTTPS client is bundled.

### Changed

- Hardened the desktop dependency graph and packaging toolchain; the checked
  pnpm lockfile now reports no known vulnerabilities.
- Replaced the JavaScript DMG builder with a native macOS packaging flow that
  verifies the application, final stapled disk-image signature, Gatekeeper
  assessment, disk-image structure, and mounted contents.
- Refreshed the pinned RustSec advisory database revision used by reproducible
  security checks.
- Adopted the AccordLock product name across packages, commands, protocol
  identifiers, database objects, schemas, infrastructure, and documentation.
- Introduced v2 authorization, approval, policy-evaluation, and execution-record
  contracts. Local state from private alpha builds requires an explicit export
  and reset; no in-place SQLite or PostgreSQL upgrade is claimed.
- Classified the planned first public release as a technical preview.
- Rejected first-time backdated session revocations while preserving exact
  idempotent retries.
- Bound audit continuation pages to a per-session ledger revision so unrelated
  task activity cannot invalidate an export.

### Removed

- Removed the optional upstream PCTX-based code-execution mode and its stale
  telemetry dependency graph from the AccordLock desktop source distribution.
- Historical fixtures that depended on files outside the repository.
