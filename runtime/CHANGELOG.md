# Changelog

All notable changes to AccordLock will be documented in this file.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and the project uses [SemVer](https://semver.org/) for published
releases. Before `1.0.0`, compatibility is not guaranteed; breaking changes
must still be called out explicitly.

## [Unreleased]

## [0.1.0-alpha.1] - 2026-09-01

Initial public engineering alpha, published as part of the source-only
AccordLock monorepo prerelease.

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

- Historical fixtures that depended on files outside the repository.
