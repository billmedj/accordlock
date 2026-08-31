<p align="center">
  <img src="desktop/ui/desktop/src/images/icon.svg" width="96" height="96" alt="AccordLock logo" />
</p>

<h1 align="center">AccordLock</h1>

<p align="center"><strong>Agents can be wrong. Their actions do not have to be.</strong></p>

<p align="center">
  An open desktop agent and transactional execution runtime for consequential work.
</p>

<p align="center">
  <a href="https://github.com/billmedj/accordlock/actions/workflows/ci.yml"><img alt="Source CI" src="https://github.com/billmedj/accordlock/actions/workflows/ci.yml/badge.svg" /></a>
  <a href="LICENSE"><img alt="Apache 2.0" src="https://img.shields.io/badge/license-Apache--2.0-2563eb.svg" /></a>
  <a href="docs/PRODUCT_STATUS.md"><img alt="Engineering Alpha" src="https://img.shields.io/badge/status-engineering%20alpha-d97706.svg" /></a>
</p>

> [!IMPORTANT]
> AccordLock is an **engineering alpha** for local evaluation and security research. It is not a supported production security boundary. There is no signed public installer, completed live EKS validation, or independent security review yet.

## Why this exists

An agent can hold valid credentials and still do the wrong thing. The model may misunderstand the task, follow an injected instruction, invent a fact, act on stale state, exceed a shared limit, or retry an operation whose outcome is unknown.

Identity and policy systems answer whether an actor may perform a class of action. AccordLock asks a narrower question immediately before execution:

> Does this exact action still agree with the approved task, trusted evidence, current state, available authority, and shared constraints?

If the answer cannot be established, AccordLock does not convert uncertainty into permission. It denies the action, requests a focused review, or records an unknown outcome for reconciliation.

## The transaction boundary

```text
Human objective
      |
      v
Fixed task contract ---- workspace, expiry, allowed capabilities
      |
      v
Untrusted model -------- may propose; cannot grant authority
      |
      v
Normalized action ------ exact tool, arguments, target, state commitment
      |
      v
AccordLock runtime ----- intent | evidence | state | authority | resources
      |
      +---------- deny / review
      |
      v
Single-use authorization
      |
      v
Brokered effect -------- credentials remain at the execution boundary
      |
      v
Observed result or UNKNOWN ---- audit, reconciliation, recovery
```

The model is useful precisely because it can explore. It is untrusted precisely because exploration is not authority.

## What changes in practice

| Failure mode | AccordLock behavior |
|---|---|
| Prompt injection changes a proposed tool call | The proposal receives no new authority. Exact policy and task constraints are evaluated outside the model. |
| The model invents evidence or a deployment fact | Model output is not trusted evidence. Missing or inconclusive evidence cannot authorize automatically. |
| Approved arguments are changed before execution | The authorization no longer matches and is rejected. |
| Policy, configuration, or target state changes | Stale authority and stale state fail closed. |
| An authorization is captured and replayed | Consumption is atomic and single-use. |
| A network response is lost after a mutation may have been sent | The effect becomes `UNKNOWN`; blind retry is blocked pending reconciliation. |
| Concurrent agents compete for a protected resource | Componentwise limits and exclusive reservations are checked before dispatch. |
| A safe read is within the task contract | It can proceed without interrupting the user. Approval is reserved for a real boundary. |

AccordLock contains the **effects** of prompt injection and hallucination at execution time. It does not claim to detect every injection, make a model truthful, or secure channels that bypass the runtime.

## Product surface

### Desktop agent

- Projects and task history rather than an undifferentiated chat list.
- A concise task contract: objective, workspace, capabilities, protected paths, and expiry.
- Automatic bounded reads; exact previews for file changes and terminal commands.
- Model choice through supported providers, including Anthropic, OpenAI, Mistral, OpenCode Zen, OpenRouter, and Ollama/local models.
- Protected filesystem operations, opt-in terminal programs, and an HTTPS GET/HEAD network broker with exact-domain controls.
- Action history, exportable audit records, recovery events, and scoped revocation.
- Foundations for signed Slack, Teams, Telegram, and WhatsApp approval decisions. Live provider acceptance and a deployable private gateway remain release work.

### Independent Rust runtime

- Typed, signed transaction objects and canonical commitments.
- Deterministic policy and evidence aggregation.
- Current-authority, current-state, revocation, and validity-window checks.
- Short-lived, action-bound, single-use execution authorization.
- Durable lifecycle state, replay tombstones, dispatch fencing, and resource reservations.
- Brokered execution and explicit unknown-outcome reconciliation.
- Read-only GitHub, ECR, and Kubernetes preflight adapters.
- A deliberately narrow Kubernetes deployment profile and a credential-free request exhibit.

### Cloud path

The repository contains the engineering path for GitHub build evidence, ECR artifact evidence, EKS discovery, signed deployment preflight receipts, exact Kubernetes patch construction, and an execution worker that does not expose production credentials to the model.

The authenticated GitHub–ECR–EKS chain has not yet been demonstrated against real accounts. The included cloud workflow is therefore a testable implementation path, not a production-readiness claim.

## Run the provider-free proof

The fastest path exercises the real Rust decision chain without an LLM, Docker, Kubernetes, cloud account, or production credential:

```powershell
cd runtime
cargo run --locked -q -p accordlock-cli -- offline --compact
```

The report is machine-readable and deliberately includes `"production_ready": false`. It covers signed ingress, evidence evaluation, authorization issuance, transactional consumption, replay refusal, and constrained Kubernetes patch validation. It also lists the live checks the offline run cannot establish.

After dependencies are cached, the same proof can run without network access:

```powershell
cargo run --offline --locked -q -p accordlock-cli -- offline --compact
```

See [the demo package](demos/README.md) for the adversarial walkthrough and AccordBench adapter once the full report is needed.

## Verify the public source boundary

One standard-library command checks required public files, source provenance, generated artifacts, credentials and personal paths, documentation links, pinned GitHub Actions, component publication guards, and the claim-to-evidence map:

```powershell
python scripts/check_publication.py
```

This is a source-hygiene and traceability gate. It does not replace the Rust, desktop, Lean, TLA+, PostgreSQL, live-provider, packaging, or independent-review gates. Those layers run separately so a missing tool cannot be mistaken for a pass.

Run the fast source suite with `python scripts/test_all.py`. Add `--runtime`, `--formal`, or `--desktop` to opt into each heavier layer; `--all` selects all three. The formal layer requires the checksum-pinned TLC jar to be fetched explicitly, and the desktop layer may install its locked dependencies.

## Assurance, with the claim boundary intact

AccordLock includes:

- **81 Lean theorems** over selected properties of small abstract authorization models;
- **8 TLA+ models** for bounded lifecycle and concurrency exploration;
- **73 AccordBench cases** covering intent conformance, transaction lifecycle, shared resources, and safe autonomy;
- **10 public assurance claims** linked to 221 concrete proof, model, source, and test references.

Run the traceability gate:

```powershell
python assurance/verify.py --root runtime --json
python -m unittest discover -s assurance/tests -t assurance -v
```

A passing report means the declared theorem names, configured invariants, implementation paths, test functions, and versioned contracts still exist at that revision. It does **not** prove that Lean or TLA+ refines the Rust implementation, that bounded exploration covers every state, or that AccordLock is formally verified end to end. Read [the assurance contract](assurance/README.md) before citing the result.

The exact post-assembly commands, bounded state counts, passed gates, and unexecuted external gates are recorded in [Local validation](docs/LOCAL_VALIDATION.md).

## Build the desktop application

The desktop is an AccordLock distribution of [Goose](https://github.com/aaif-goose/goose), with the protected task and execution path integrated into the native experience.

```powershell
cd desktop
./scripts/build-windows.ps1 -Development -RuntimeRepo ../runtime
```

This creates a development build. Release packaging has stricter clean-tree and build-marker gates. Until an installer is signed and tested on a clean machine, build from source and treat it as evaluation software. Detailed platform instructions live in [desktop/README.md](desktop/README.md).

## Repository map

| Path | What it contains |
|---|---|
| [`desktop/`](desktop/) | Desktop agent, provider integrations, task UX, protected tool bridge, and upstream Goose attribution |
| [`runtime/`](runtime/) | Rust authorization/runtime stack, schemas, migrations, cloud adapters, formal models, and conformance corpus |
| [`assurance/`](assurance/) | Machine-checkable claim-to-evidence manifest and fail-closed linter |
| [`demos/`](demos/) | Provider-free adversarial demonstration and benchmark adapter |
| [`docs/`](docs/) | Architecture, threat model, product status, limitations, and research provenance |

## Current status

| Area | Status |
|---|---|
| Local desktop task flow | Functional engineering alpha |
| Filesystem and exact-command mediation | Implemented; terminal containment is not a complete OS sandbox |
| Network mediation | Exact-domain HTTPS GET/HEAD path implemented; broader enterprise profiles pending |
| Durable audit, revocation, and recovery records | Implemented locally |
| Intent-conformance framework | Implemented; no production-qualified general free-text evidence provider |
| Formal and adversarial assurance assets | Included; scoped claims only |
| GitHub/ECR/EKS preflight path | Implemented locally; real-account acceptance pending |
| Remote approval channels | Signed contracts and local foundations implemented; live gateways pending |
| Signed installer and automatic updates | Pending |
| Independent security assessment | Pending |
| Production readiness | **No** |

The complete boundary is documented in [Product status](docs/PRODUCT_STATUS.md), [Threat model](docs/THREAT_MODEL.md), and [Known limitations](docs/LIMITATIONS.md).

## Design principles

1. **The model proposes. The runtime decides.**
2. **Authority is exact, current, narrow, and single-use.**
3. **Evidence may restrict a decision; it cannot silently expand authority.**
4. **Uncertainty is represented explicitly.**
5. **Audit records describe what the system can establish, not what it hopes happened.**
6. **Safe work should remain fluid.** Security that requires approving every read is not useful autonomy.

## Research provenance

AccordLock's configuration-provenance model is informed by the published paper *Whence: The Fourth Coordinate of Computational Authority* ([DOI 10.5281/zenodo.20905713](https://doi.org/10.5281/zenodo.20905713)). The repository contains the product implementation and its public assurance artifacts. It does not include unpublished research manuscripts or claim that the paper proves this software correct.

## Contributing and security

Read [CONTRIBUTING.md](CONTRIBUTING.md) before changing a security boundary. Vulnerabilities should not be filed as public issues; follow [SECURITY.md](SECURITY.md).

The complete functional source is public under the [Apache License 2.0](LICENSE). AccordLock is derived in part from Goose and preserves its notices and third-party attribution. See [NOTICE](NOTICE) and [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md).

Community expectations, support scope, decision rights, and brand use are documented in [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md), [SUPPORT.md](SUPPORT.md), [GOVERNANCE.md](GOVERNANCE.md), and [TRADEMARKS.md](TRADEMARKS.md).
