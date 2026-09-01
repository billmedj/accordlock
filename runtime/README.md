# AccordLock

> **Everything agrees. Then it runs.**

**Execution integrity for AI and cloud automation.** AccordLock binds reviewed
inputs, policy, authority, artifacts, and current target state to one exact
action before it runs. Qualified live task evidence remains an integration
gate.

AccordLock is currently an **unreleased engineering alpha for local
evaluation**. The repository contains a substantive local reference
implementation and adversarial test suite; it has not yet completed an
end-to-end EKS deployment or independent security review. Do not use it to
authorize production resources.

## The problem

Identity and policy systems answer: **“May this actor perform this class of
action?”** They do not necessarily prove that the exact action sent to the
provider is still the reviewed action, built from the reviewed source, using
the approved artifact, against the same live target state.

AccordLock narrows that gap. For its first profile, it:

1. authenticates a bounded deployment intent;
2. verifies typed review, build, artifact, and target evidence;
3. evaluates the evidence deterministically;
4. issues a short-lived, single-use authorization bound to the exact mutation;
5. rechecks current authority and target state at consumption;
6. constructs the constrained Kubernetes patch; and
7. records enough state to reject replay and reason about ambiguous outcomes.

The initial operation is deliberately narrow:

```text
DEPLOY_EKS_IMAGE_V1
```

It changes one container image in one existing Kubernetes Deployment. It does
not authorize arbitrary Kubernetes mutations.

## Status at a glance

| Capability | Status |
|---|---|
| Deterministic protocol and policy core | Implemented locally |
| Signed, state-bound, single-use authorizations | Implemented locally |
| PostgreSQL lifecycle and replay controls | Implemented locally |
| Adversarial conformance corpus | Implemented locally |
| Offline end-to-end decision-chain validation | Implemented locally |
| Native policy-evaluation records and monotonic payload/resource controls | Implemented locally |
| Local agent runtime with bounded filesystem and command execution broker | Implemented locally; every command requires a single-use execution authorization, terminal programs are opt-in, and no shell interpreter is accepted |
| Durable runtime ledger with a redacted audit projection | Implemented locally with revision-bound pagination, domain-separated page digests, bounded private frames, revocation records, and file-recovery events; the trusted local database retains complete tool proposals for validation and recovery |
| Request-to-result task alignment | Goose captures the actual assistant-turn plan; the runtime builds, revalidates, and persists typed pre-execution and complete-trace bundles. `AuthorizationDecision` schema 4 binds the pre-execution evaluation hash. Audit schema v6 adds a bounded **Task check** and **Task evidence** projection. The connected free-text profile has no qualified evidence, so it returns `REVIEW` and is displayed as **Not verified**. A pinned local provider can verify only an explicitly configured artifact digest; no production evidence provider for natural-language task alignment is connected |
| Completed-action provenance | `TaskControlProjection` schema 2 and `ExecutionLineage` schema 2 bind the exact pre-execution evaluation hash; audit schema v6 exposes the pre-execution and complete-trace hashes plus their categorical task-check projections. This establishes chain integrity, not task correctness |
| Slack, Teams, Telegram, and WhatsApp approval contracts | Signed challenges, inbound authentication boundaries, strict outbound adapters, a fixed-authority rustls/WebPKI client, an encrypted fail-closed queue worker, authenticated dead-letter reasons, durable replay protection, Desktop secure storage, gateway enrollment, connection tests, and signed-decision receipt import are implemented locally; no live provider account, reachable callback service, private gateway-to-Desktop transport, or Entra verifier is bundled |
| Terminal descendant lifecycle containment | Implemented locally with Windows Job Objects and Unix process groups; executable identity is held stable on Windows and Linux. This is not an OS sandbox, and non-Linux Unix targets still use path-based spawn with identity checks around it |
| Strict HTTPS broker contract | Desktop can opt into exact lowercase domains and then mounts atomic GET/HEAD execution through a direct public-WebPKI, public-IP-only, redirects-disabled, bounded native transport. Every request remains approval-controlled; no live-provider acceptance evidence, enterprise-proxy profile, private CA profile, or mutating HTTP method is claimed |
| Credential-free execution-worker protocol and bridge | Implemented locally |
| Read-only GitHub, ECR, and Kubernetes provider adapters | Implemented locally with bounded authenticated HTTPS transports in the dedicated preflight runner; real-account acceptance evidence is pending |
| Protected GitHub Actions evidence producer | Implemented as a dependency-free Node 24 action with separate Ed25519 build and artifact authorities; action-to-Desktop contract tests pass |
| Execution-worker composition root | Implemented locally; connector and transport identities are intrinsically committed before I/O |
| Signed deployment-preflight receipt | Implemented locally with independent receipt verification and zero-effect result fields |
| Desktop deployment-preflight workflow | Saved environments, authenticated EKS discovery, protected credential handoff, CI evidence import and pinning, project binding, check history, portable receipt export and the read-only result surface are implemented locally; signed-package and real-account validation remain release gates |
| Signed action approval for external actions | Implemented locally; the Ed25519/COSE approval record is action-bound, authority-bound, fresh, and single-use |
| Bounded TLA+ lifecycle models | Implemented locally |
| Credential-free Kubernetes request exhibit | Implemented locally; it revalidates one exact authorized Deployment snapshot, derives the exact compact JSON Patch used by the native executor, consumes the durable dispatch and approval replay slots, and returns `NotSent`. It has no credential, transport, network I/O, or readiness override |
| Disposable kind exhibit | Provided; a successful run must still be retained from this revision |
| Authenticated GitHub, ECR, and EKS chain | Not yet demonstrated |
| Independent security review | Not yet performed |
| Production readiness | **No** |

The precise trust assumptions and open work are documented in the
[threat model](docs/THREAT_MODEL.md), [TRUST_BOUNDARY.md](docs/TRUST_BOUNDARY.md), and
[KNOWN_LIMITATIONS.md](docs/KNOWN_LIMITATIONS.md).

## Quick start

The primary offline validation requires the pinned Rust toolchain and no Docker,
Kubernetes, database, or cloud credentials. The demo logic performs no network
request; on a fresh machine, Cargo may first download the pinned toolchain and
dependencies:

The v2 public contracts are a pre-release reset boundary. If an earlier private
alpha created local SQLite or PostgreSQL state, export anything needed for audit
and recreate that disposable state before running this revision; no in-place
upgrade is claimed.

```sh
cargo run --locked -q -p accordlock-cli -- offline --compact
```

Expected behavior: the CLI emits one machine-readable JSON report with
`production_ready: false`. It exercises the real local chain from signed
ingress through evidence evaluation, authorization issuance and verification,
transactional consumption, replay refusal, and validation of the constrained
Kubernetes patch. It also names every live-production check that it does not
exercise. See the [offline demo guide](docs/DEMO.md).

The lower-level scenario corpus remains available for focused regression work:

```sh
cargo run --locked -q -p accordlock-cli -- demo --scenario all
```

The dedicated read-only deployment-preflight runner can be checked separately:

```sh
cargo check --locked -p accordlock-preflight-runner
cargo test --locked -p accordlock-preflight-runner
```

Its authenticated provider path requires a strict saved profile, protected
credential handoff and configured build and artifact trust records. A passing
fixture is not a substitute for a disposable real-account acceptance run.

These commands are functional and security-regression exhibits, not
performance benchmarks or production evidence.

After the Rust dependencies are cached, enforce a disconnected build with
`cargo run --offline --locked -q -p accordlock-cli -- offline --compact`.

Run the repository's fast static and unit checks:

```sh
cargo fmt --all -- --check
cargo check --workspace --locked --all-targets
cargo test --workspace --locked
python3 -m unittest discover -s tests -v
```

The complete fail-closed reproduction runner also requires PostgreSQL 17.11,
Java, a pinned TLA+ tools jar, and a pinned RustSec advisory database. The
documented Windows 17.4 reproduction profile remains accepted for local
compatibility; every other server version fails closed until explicitly
calibrated. See
[scripts/README.md](scripts/README.md) before running:

```powershell
.\scripts\run-all.ps1
```

```sh
./scripts/run-all.sh
```

For all supported evaluation paths, see
[docs/INSTALLATION.md](docs/INSTALLATION.md). For the account-free Kubernetes exhibit, see
[infra/local/k8s/README.md](infra/local/k8s/README.md). It uses a disposable
`kind` cluster and public deterministic test keys. It is not EKS or production
evidence.

## Architecture

```text
authenticated intent
        |
        v
authenticated evidence -> deterministic kernel
        |                         |
        +-------------------------+
                                  v
                         constrained authorization
                                  |
                                  v
                    transactional single use
                                  |
                                  v
                   exact Kubernetes operation
                                  |
                                  v
                      observation + audit trail
```

The Rust workspace separates policy, authorization, execution, audit,
connectors, and service boundaries. Provider credentials are absent from the
serializable worker protocol and remain inside transport implementations. The
worker binds its connector evidence to the source and transport objects it
owns. A production checkpoint is represented by a signed, action-specific
approval record, not by a controller-supplied Boolean or digest. See the full
[architecture](docs/ARCHITECTURE.md) and [documentation index](docs/README.md).

## Security model

AccordLock is fail-closed within its stated trust boundary: missing required
evidence, stale state, replay, authority drift, route mismatch, or unavailable
safety-critical state produces a refusal.

That statement is conditional. This engineering alpha does not yet establish
production key custody, exclusive cloud credentials, authenticated evidence
connectors, an independently verified provider observation path, or complete
mediation of every cluster mutation. Read [SECURITY.md](SECURITY.md) before
evaluating the software and report vulnerabilities privately through the
process described there.

## Repository layout

| Path | Purpose |
|---|---|
| `crates/` | Rust protocol, enforcement, state, service, and CLI components |
| `conformance/` | Positive and adversarial machine-readable scenarios |
| `schemas/` | Protocol and reason-code definitions |
| `migrations/` | Transactional PostgreSQL state schema |
| `models/` | Bounded TLA+ lifecycle models |
| `infra/` | Local and Kubernetes evaluation profiles |
| `containers/` | Reproducible container build definitions |
| `scripts/` | Fail-closed validation and reproduction runners |
| `docs/` | Architecture, trust boundary, limitations, roadmap, and evidence |

## Project principles

- **The model proposes; it never becomes the authority.**
- **Authorization is bound to exact evidence and exact live state.**
- **An authorization is short-lived, single-use, and narrowly scoped.**
- **Unknown outcomes are reconciled, never guessed.**
- **Claims never exceed retained, reproducible evidence.**

## Contributing

Contributions are welcome after reading [CONTRIBUTING.md](CONTRIBUTING.md),
[SECURITY.md](SECURITY.md), and the [code of conduct](CODE_OF_CONDUCT.md).
Protocol and security-boundary changes require adversarial tests and updated
conformance material.

Project decisions and release discipline are documented in
[GOVERNANCE.md](GOVERNANCE.md), [CHANGELOG.md](CHANGELOG.md), and the
[release checklist](.github/RELEASE_CHECKLIST.md).

## License and name

Source code is licensed under the [Apache License 2.0](LICENSE). The license
does not grant permission to use the AccordLock name or branding; see
[TRADEMARKS.md](TRADEMARKS.md).
