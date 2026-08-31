# Research Provenance

**Scope:** public concepts and assurance artifacts that inform AccordLock · **Claim policy:** research motivates design; repository evidence supports product claims

## Published foundation

AccordLock's treatment of mutable authority is informed by:

> Bilal Medjani (2026), *Whence: The Fourth Coordinate of Computational Authority — An Algebra of Configuration Provenance for State Machines with Mutable Authority*. Zenodo. [https://doi.org/10.5281/zenodo.20905713](https://doi.org/10.5281/zenodo.20905713)

The paper's relevant design question is the origin of the configuration under which an action is considered authorized. In a mutable system, an actor, action, and resource do not fully describe authority. The active policy, trust roots, key set, destination registry, and configuration history also determine whether the same request remains valid.

AccordLock applies that observation by treating configuration provenance as authorization state rather than ambient context.

## From configuration provenance to runtime controls

| Research concern | AccordLock mechanism | Evidence in the repository | Claim boundary |
| --- | --- | --- | --- |
| Which configuration authorized this action? | policy and configuration epochs repeated in request and authorization records | strict schemas, Rust verification, Lean abstract properties, adversarial tests | depends on truthful activation and protected configuration storage |
| Where did the active trust state come from? | rooted principal, key, evidence-source, destination, and signer registries | typed registry records, purpose-separated verification, database migrations | production activation workflow and key custody remain deployment obligations |
| Can old authority be replayed after configuration changes? | epoch currentness checks, short validity windows, durable replay state | authorization tests, PostgreSQL tests, formal properties | live rollback and failover behavior still require production validation |
| Can a logical alias redirect authority? | canonical destination identity and physical-resource registration | EKS profile code, resource-reservation state, bounded models | provider ownership and complete alias coverage must be proved externally |
| Can an execution record omit its governing configuration? | end-to-end lineage commitments include task and policy context | execution-lineage schemas and audit validation | lineage integrity does not establish semantic correctness |

The paper does not prove AccordLock correct. The product's claims must be supported independently by source, executable tests, formal artifacts, deployment evidence, and review.

## Broader engineering foundations

AccordLock also builds on established systems and security ideas. These are engineering foundations, not claims of novelty by themselves.

### Reference monitoring and complete mediation

Protected effects pass through an independent decision and execution boundary. The model-facing component cannot approve its own request. Production strength depends on eliminating alternate effect paths.

### Capability security and least privilege

Execution authority is narrow, short-lived, audience-bound, request-specific, and single-use. It cannot exceed the fixed task policy. Credential possession is separated from action planning.

### Transaction processing

Durable issuance, consumption, claims, reservations, worker acquisitions, observations, and retirement create explicit linearization points. External effects remain separate transactions, so unknown outcomes and reconciliation are modeled directly.

### State-machine safety

Authorization and execution phases are represented as monotone transitions. TLA+ explores bounded interleavings for replay, concurrency, failure, and recovery. Lean checks selected properties of abstract definitions.

### Content-addressed integrity

Canonical encodings and cryptographic commitments link the approved request, recorded plan, normalized action, current state, evidence, authorization, and result. Substitution changes the commitment and fails verification.

### Software-supply-chain evidence

The deployment profile consumes review, build, artifact, and target evidence and binds immutable artifact digests to an exact destination mutation. This complements build attestations and policy systems; it does not replace them.

### Destination-side enforcement

The Kubernetes profile uses validating admission as a final state-backed check on the admitted object. The design assumes API-server caller authentication, fail-closed configuration, exclusive executor identity, and controlled administrative bypass.

### Explicit abstention

Missing or unqualified evidence produces review. A favorable evaluator response cannot add authority. Unknown execution outcomes cannot be treated as success or safe non-delivery.

## Product research questions

The implementation turns several research questions into testable interfaces.

### Can action authority remain exact across an agent stack?

The desktop fixes task scope; the backend commits the actual plan and tool call; the runtime normalizes the proposal; the authorization repeats the exact commitments; the executor constructs the effect from typed inputs; the result closes the lineage.

The current evidence establishes this chain locally. A production claim requires complete mediation and live provider validation.

### Can evidence improve safety without becoming a new authority source?

The evaluation engine begins from the independent task-policy decision. Evidence aggregation can preserve that decision or increase restriction. Uncertainty is classified for review; contradiction is classified as blocking. This restrict-only rule appears in code, tests, and abstract Lean properties. The current desktop projects the categorical result separately from structural access.

The open problem is representative, qualified evidence for general natural-language tasks. The product currently abstains on the connected free-text path.

### Can autonomous execution recover safely after ambiguous failure?

The transaction model distinguishes authorization, dispatch, observation, and effect knowledge. Unknown outcomes retain their reservation and require authenticated reconciliation. Bounded models and implementation tests cover selected failure interleavings.

Live fault injection across database, process, network, admission, and provider boundaries remains necessary.

### Can shared constraints compose across concurrent agents?

The formal core models componentwise resource bounds. The runtime uses canonical physical-resource reservations and generation-fenced worker acquisition. AccordBench includes shared-resource and contention cases.

Production scheduling, fairness, throughput, and multi-region behavior have not been established.

### Can the security boundary remain understandable to an operator?

The product maps internal decisions to concise states such as **Within approved access**, **Review required**, **Reviewed**, **Outside task**, and **Blocked**. Technical provenance remains available in details and exports.

Usability is an empirical question. Representative user testing and review-burden measurements are still required.

## Assurance artifacts

The public repository contains three complementary forms of research evidence.

### Lean 4 model

The standalone project contains 81 theorems over abstract definitions for authority binding, authorization integrity, capability restriction, transaction lifecycle, evidence monotonicity, effect knowledge, resource reservations, and final dispatch.

The theorem count is not a quality score. Each claim should name the relevant definition and theorem. The project does not prove cryptographic primitives, database isolation, operating-system enforcement, provider behavior, or implementation refinement.

### TLA+ models

Eight bounded state machines cover operational interleavings that the Lean model abstracts away: authorization lifecycle, dispatch claims, physical reservations, admission, broker journal, terminal retirement, durable control queue, and durable acquisition.

Model checking establishes the configured invariants for explored bounds. It does not cover unmodeled code, larger state spaces, or a deployed environment.

### AccordBench

AccordBench provides 73 deterministic, reviewable cases for request-to-action conformance, transaction lifecycle, shared resources, and safe autonomy. Metamorphic cases test invariance under harmless transformations and required outcome changes after meaningful changes.

The corpus defines a contract and regression surface. It is not a representative production sample, population estimate, or proof of general semantic understanding.

## Evidence hierarchy

Public claims should identify their evidence level.

| Evidence level | Supports | Does not support |
| --- | --- | --- |
| Design document | architecture and intended assumptions | implemented behavior |
| Type or schema | accepted data shape and explicit fields | runtime currentness or source truth |
| Unit or property test | behavior under generated or fixed local inputs | external interoperability |
| Integration test | composed local behavior | production identity, scale, or operations |
| Lean theorem | property of named abstract definitions | implementation or deployment correctness |
| TLA+ result | invariants in the explored model and bounds | complete state-space or code correctness |
| Retained provider run | behavior in one documented external environment | universal compatibility or long-term reliability |
| Independent review | assessment of the reviewed snapshot and scope | future versions or unreviewed deployments |

This hierarchy prevents a valid result at one layer from silently becoming a stronger claim at another.

## Citation

When discussing the configuration-provenance basis, cite the paper directly:

```bibtex
@misc{medjani2026whence,
  author       = {Bilal Medjani},
  title        = {Whence: The Fourth Coordinate of Computational Authority --- An Algebra of Configuration Provenance for State Machines with Mutable Authority},
  year         = {2026},
  publisher    = {Zenodo},
  doi          = {10.5281/zenodo.20905713},
  url          = {https://doi.org/10.5281/zenodo.20905713}
}
```

When evaluating AccordLock, cite the exact software version or commit and the specific assurance artifact used. Do not cite the paper as evidence that a product build or deployment is secure.

See [Engineering Case Study](ENGINEERING_CASE_STUDY.md), [Architecture](ARCHITECTURE.md), and [Product Status](PRODUCT_STATUS.md).
