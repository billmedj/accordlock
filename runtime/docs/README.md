# AccordLock documentation

Start here if you are evaluating, integrating, or auditing AccordLock.

## Current documents

- [Architecture](ARCHITECTURE.md) — system boundaries and component roles.
- [Trust boundary](TRUST_BOUNDARY.md) — trusted inputs, untrusted inputs, and
  enforcement assumptions.
- [Task-alignment evidence](INTENT_CONFORMANCE_ARCHITECTURE.md) — separation of
  access, qualified task evidence, authorization, and execution.
- [Threat model](THREAT_MODEL.md) — assets, adversaries, controls, and residual
  risk.
- [Known limitations](KNOWN_LIMITATIONS.md) — open security and operational
  work, with explicit closure criteria.
- [External evidence gates](EXTERNAL_GATES.md) — cloud, pilot, and independent
  dependencies that local code cannot close.
- [Local readiness report](LOCAL_READINESS_REPORT_2026-08-30.md) — current
  account-free validation results for evaluation records, execution lineage,
  formal models, benchmarks, runtime, and their claim boundaries.
- [Resource requirements](RESOURCE_REQUIREMENTS.md) — exact accounts,
  environments, and independent evidence still required.
- [Roadmap](ROADMAP.md) — the gates from technical preview to production.
- [Installation and evaluation](INSTALLATION.md) — supported local paths and
  prerequisites.
- [Offline demo](DEMO.md) — one-command proof, expected result, and exact
  coverage boundary.
- [GitHub publication setup](GITHUB_SETUP.md) — repository identity and external
  security settings.
- [Brand guide](BRAND.md) — canonical name, positioning, and naming rules.

## Historical evidence

The files in [`history/`](history/) are dated local engineering records. They
are preserved for transparency, but they do not describe the current source
tree unless a newer document explicitly incorporates their results.

- [Local validation report, 2026-08-15](history/LOCAL_VALIDATION_REPORT_2026-08-15.md)
- [Security review, 2026-08-16](history/SECURITY_REVIEW_2026-08-16.md)
- [Reproduction report, 2026-08-16](history/REPRODUCTION_REPORT_2026-08-16.md)
- [Protocol v2 migration record, 2026-08-16](history/PROTOCOL_V2_MIGRATION_2026-08-16.md)

Passing local tests is not an independent security review, certification, or
production validation. See [SECURITY.md](../SECURITY.md) before reporting a
security issue or evaluating a real deployment.
