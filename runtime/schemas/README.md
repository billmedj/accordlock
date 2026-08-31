# AccordLock schema status

Everything in this directory is a **provisional local engineering candidate**.
It is not a frozen public protocol, an interoperability promise, an independent
review result, or a production security claim.

- `accordlock-local-candidate.cddl` mirrors the canonical CBOR arrays currently
  emitted by `crates/accordlock-protocol/src/canonical.rs`.
- `reason-codes.json` mirrors the current `ReasonCode` enum and numeric mapping
  in `crates/accordlock-protocol/src/types.rs`.
- `execution-lineage.schema.json` defines the exact, content-minimized
  commitment chain from the approved task and tool proposal through the
  execution request, decision, single-use authorization, and completed
  execution record. It still
  contains sensitive operational metadata and must be protected accordingly.
- `agent-plan-checkpoint.schema.json` and `tool-call-proposal-v3.schema.json`
  define the exact content-minimized assistant-turn checkpoint and the live tool
  proposal that carries it into the authorization boundary.
- `pre-execution-live-intent-bundle.schema.json` and
  `complete-live-intent-bundle.schema.json` define the typed request-to-action
  and request-to-result records. Missing qualified evidence yields review, never
  automatic authority.
- `completed-execution-evidence.schema.json` defines schema 4 of the persisted
  new-write wrapper. It embeds one complete `ExecutionLineage` plus its
  domain-separated commitment. Historical trace schemas remain read-only.
- `session-audit-page.schema.json` defines the strict schema-5 Desktop audit
  page and every currently emitted event variant.
- `intent-conformance-record.schema.json`, `intent-evidence-request.schema.json`,
  and `intent-evidence-response.schema.json` define the provider-neutral
  measurement and evidence exchange records. They carry evidence, not authority.
- `external-evidence-disclosure-grant.schema.json` defines the strict schema-1
  signed authorization for one exact, short-lived external evidence disclosure.
- `task-control-projection.schema.json` defines the bounded audit projection
  derived from a verified authorization decision. It records whether execution
  stayed within approved access or required exact human review; it never treats
  a score as authority.
- `task-control-provenance.schema.json` distinguishes current lineage-bound
  projections from embedded or reconstructed historical control evidence.

These files deliberately do not assign trust from shape. An object that parses
correctly remains untrusted until its source, signature, scope, freshness,
authority state, and cross-record bindings have passed the applicable checks.
See `docs/TRUST_BOUNDARY.md`.

Before the public schema freeze, every payload change may renumber, add, remove,
or reshape a record. Any such change must update Rust, CDDL, the reason registry,
fixtures, and the requirement-to-test map in one reviewed change.

`examples/` contains Rust-locked serialization goldens. The dependency-free
`tests/test_public_schema_contracts.py` suite validates every golden against its
schema and proves that missing fields, unknown fields, version drift, and
unknown enum values are rejected.
