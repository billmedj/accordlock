# Contributing to AccordLock

AccordLock welcomes focused contributions that make the execution boundary safer, more testable, easier to operate, or easier to understand.

The project is an Engineering Alpha. Do not use a public issue to disclose a vulnerability; follow [SECURITY.md](SECURITY.md).

## Good first contributions

- deterministic tests for an existing behavior;
- documentation corrections tied to source evidence;
- clearer failure messages and operator copy;
- platform compatibility fixes that preserve fail-closed behavior;
- benchmark cases with an explicit expected outcome and rationale;
- reproducibility, packaging, and publication-hygiene improvements; and
- narrowly scoped connector improvements with no new credential exposure.

## Changes that require a design proposal

Open a design discussion before changing:

- task authority or approval semantics;
- canonical encoding or cryptographic commitments;
- evidence admission, provenance, or aggregation;
- authorization lifetime, replay, or consumption;
- transaction phases, recovery, or effect classification;
- credential custody or process boundaries;
- filesystem, process, network, cloud, or Kubernetes execution;
- audit redaction or recovery behavior; or
- a public security claim.

A useful proposal states the invariant, threat, trust assumption, failure behavior, migration impact, and evidence needed to accept the change.

## Development workflow

1. Create a small branch from the current default branch.
2. Read the component's local build instructions before changing it.
3. Add a failing test that captures the problem when practical.
4. Implement the narrowest change that preserves existing trust boundaries.
5. Run formatting, type, unit, integration, publication, and assurance checks relevant to the changed paths.
6. Update architecture, threat-model, limitation, schema, and claim-map material when the change affects them.
7. Submit a pull request with reproducible commands and exact results.

Do not commit credentials, tokens, private keys, personal paths, real customer data, local databases, logs, generated packages, or provider callback payloads.

## Security-change checklist

A change to protected execution should answer all of these questions:

- What untrusted input reaches the new code?
- Which trusted state is loaded independently?
- What exact object is authorized?
- What prevents replay, substitution, and stale-state use?
- Which component holds credentials?
- What happens after timeout, crash, or lost response?
- Can another path perform the same effect without the control?
- What is recorded, redacted, recoverable, and exportable?
- Which test or model would fail if the invariant regressed?
- Does any user-facing claim need to become narrower?

## Tests and evidence

Do not treat fixture output as product performance. Do not treat a Lean theorem as proof of implementation behavior. Do not treat a local integration test as live-provider acceptance.

Pull requests should label evidence accurately:

- unit or property test;
- local integration test;
- formal property of a named model;
- bounded model-checking result;
- retained external-system run; or
- independent review.

## User-interface copy

Use plain English. Describe the decision and the next action. Keep protocol names, hashes, and provenance in expandable details or export surfaces.

Avoid claims such as “safe,” “verified,” or “protected” unless the exact qualifying evidence is present. An empty evidence set is **Not verified**. An allowed action is not automatically a correct action.

## Licensing

Unless a file states otherwise, contributions are submitted under the Apache License 2.0 used by the project. Preserve upstream notices and attribution for the Goose-derived desktop and third-party components.
