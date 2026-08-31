# AccordLock governance

AccordLock uses a founder-led open-source governance model during its technical
preview. The goal is to make decisions transparent while keeping security and
release responsibility unambiguous.

## Roles

### Project lead

Bilal Medjani is the initial project lead and final decision-maker for roadmap,
release, security embargo, governance, and trademark matters. The project lead
may appoint or remove maintainers and may transfer project stewardship through a
public governance update.

### Maintainers

Maintainers review contributions, triage issues, operate releases, and protect
the project's security and compatibility commitments. The project lead names
maintainers through a public governance update after they consent to the role.
A `CODEOWNERS` file may be added only after every listed user or team has been
verified and granted the required repository access.

### Contributors

Anyone may propose changes. Contributors gain responsibility through sustained,
constructive work, sound review judgment, and adherence to the project's
security and conduct policies. Contribution does not automatically confer
maintainer status or trademark rights.

## Decisions

Routine changes are decided through public issues and pull requests. Maintainers
seek rough consensus, supported by tests and explicit trade-offs. The project
lead resolves deadlocks.

The following require approval from the project lead and at least one qualified
maintainer reviewer when one is available:

- releases and supported-status changes;
- wire-format, cryptographic, authorization, or trust-boundary changes;
- removal or weakening of a security control;
- new runtime dependencies with meaningful supply-chain impact;
- licensing, governance, contribution-policy, or trademark changes; and
- public security advisories.

Security reports may be handled privately under an embargo. The eventual fix and
advisory should disclose enough information for users to assess impact without
unnecessarily exposing reporters or affected systems.

## Releases

A release is official only when it follows `.github/RELEASE_CHECKLIST.md`, is
published through the official repository, and is identified by a signed or
otherwise verifiable version tag. Release notes must state the support level,
known limitations, test evidence, compatibility impact, and whether independent
security review has occurred.

No local test, model-checking result, or AI-assisted review may be described as
independent validation. Independent review means work performed by a suitably
qualified party that is organizationally separate from the implementation
process and can report findings without direction from project leadership.

## Provenance and automation

The initial repository was developed with extensive AI-assisted tooling under
human direction. Future material AI assistance must be disclosed in accordance
with [CONTRIBUTING.md](CONTRIBUTING.md). Human contributors remain responsible
for review, verification, licensing, confidentiality, and sign-off.

Automated checks inform decisions but do not replace accountable review.
Security claims must be tied to a versioned artifact, stated assumptions, and
reproducible evidence.

## Amendments

Governance changes are proposed through a public pull request with a rationale
and transition plan. During the founder-led phase, the project lead approves the
final text. Material changes are recorded in release notes or a dedicated
governance announcement.
