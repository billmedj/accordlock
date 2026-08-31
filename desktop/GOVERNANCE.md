# AccordLock Repository Governance

This document governs the AccordLock distribution maintained in this
repository. It describes current decision authority without assigning authority
to unrelated organizations, former maintainers, or unverified accounts.

## Principles

- **Security first:** changes fail closed at authorization, credential, and
  execution boundaries.
- **Evidence over assertion:** decisions and release claims are backed by code,
  tests, review, and reproducible validation.
- **Clear ownership:** active authority is determined by repository settings.
- **Open technical record:** non-sensitive decisions are recorded in issues,
  discussions, pull requests, and documentation.
- **Least complexity:** new mechanisms must justify their operational and
  maintenance cost.

## Roles

### Contributors

Anyone may report problems, propose improvements, review changes, improve
documentation, or submit a pull request under the repository's contribution
rules.

### Reviewers

Reviewers provide technical feedback but do not gain merge, release, or
security-response authority merely by reviewing a change.

### Maintainers

Maintainers are the accounts or teams granted the relevant role in the
repository settings. Those settings are the canonical authority record. This
repository intentionally does not publish a static maintainer list until each
listed identity and role can be verified.

Maintainers are responsible for:

- issue triage and scope decisions;
- code review and merge decisions;
- protection of security and release settings;
- release readiness and accurate product claims;
- dependency, license, and attribution review; and
- enforcement of the Code of Conduct.

## Decision process

Routine changes are decided through pull-request review. Significant product,
architecture, protocol, compatibility, or governance changes should begin in an
issue or repository discussion when discussions are enabled.

The preferred process is:

1. state the problem and affected users;
2. document constraints and trust boundaries;
3. compare viable options;
4. record the selected approach and verification plan; and
5. implement it in a focused pull request.

Maintainers seek technical consensus. When consensus is not available, the
maintainer with the relevant repository responsibility may decide and must
record the rationale. If no verified maintainer owns the decision, the change
is deferred rather than assigned to an invented authority.

Security reports and sensitive incident details are handled privately under
[SECURITY.md](SECURITY.md). A security fix may use an abbreviated public design
process until coordinated disclosure is safe.

## Merge and release authority

Only identities authorized in repository settings may merge protected branches,
change security settings, or publish releases. Branch protection and required
checks should enforce review where the hosting plan supports them.

A release must distinguish local validation from production evidence and must
not claim production readiness without the required deployment and security
validation.

## Governance changes

Changes to this document use the same issue and pull-request process as other
significant changes. The pull request must explain the authority or process
being changed and why the new text matches repository settings.

Licensing and attribution remain documented in `LICENSE`, `NOTICE`, and
`THIRD_PARTY_NOTICES.md`. Legal attribution does not confer active governance
authority over this repository.
