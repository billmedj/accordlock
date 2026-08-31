# accordlock-connectors

`accordlock-connectors` is the transport-independent trusted connector boundary for
the initial EKS deployment vertical. An untrusted caller supplies one request
identifier and four opaque lookup identifiers. The caller cannot supply review
outcomes, build results, artifact verdicts, target state, timestamps, validity
windows, authority state, issuer names, key identifiers, signing keys, grades,
or policy verdicts.

At trusted bootstrap, a composition root fixes four source adapters, four
source URI routes, four evidence signing identities, a trusted clock, the
authority vector, and a bounded validity profile. `ConnectorRuntime::collect`
then reads one Review, Build, Artifact, and Target snapshot, validates their
request and lookup bindings, validates their common repository, commit, build
output, artifact, and target route, enforces time and monotonic-source rules,
maps them to the four exact `accordlock_protocol::EvidencePayload` variants, and
signs each canonical assertion under its evidence-kind COSE domain.

The adapter implementations and the code that constructs the runtime are in
the trusted computing base. The traits in this crate are not proof that an
upstream service authenticated a response. In particular, this crate contains
no GitHub, build-system, artifact-registry, AWS, EKS, or Kubernetes API client.
A production deployment still needs separately reviewed adapters that verify
TLS and service identity, use least-privilege credentials, validate provider
response schemas and pagination/completeness, preserve provider object
identity and monotonic cursors, and fail closed on ambiguity. It also needs
durable rollback checkpoints. The in-process checkpoint ledger here prevents
rollback only within the lifetime of one runtime instance.

The crate does not assign authority grades and does not evaluate policy. Its
output is provenance evidence for the independent AccordLock kernel.

`TrustedEvidenceSet.request_id` is checked against all four trusted snapshots
and set by this runtime. The current protocol's individual
`EvidenceAssertion` schema does not contain `request_id`, so that association
is not independently covered by each COSE signature. The connector-to-kernel
handoff must therefore remain authenticated and non-malleable, or a future
protocol version must add an explicit signed request-binding field. Likewise,
the artifact and target route facts that do not exist in `EvidencePayload` are
validated here but are not independently re-verifiable from the four protocol
payloads alone.
