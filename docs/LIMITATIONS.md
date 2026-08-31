# Limitations and Release Gates

**Release stage:** Engineering Alpha · **Purpose:** define what AccordLock does not yet establish and the evidence required to close each gap

This document is part of the product contract. A missing capability, test, or deployment proof must remain visible until reproducible evidence replaces it.

## 1. No production security claim

The repository is suitable for source review, local evaluation, and controlled demonstrations. It has not completed the operational, infrastructure, distribution, and independent-review work required for production use.

**Closure evidence:** a versioned release checklist with retained results for every gate in this document, plus independent review of the final deployment profile.

## 2. No prompt-injection immunity

Hostile content can still influence the model's answer, plan, and proposed tool calls. AccordLock reduces the authority of that output by evaluating protected effects outside the model. It does not prove that the model recognized or ignored the hostile instruction.

The containment claim also depends on complete mediation. An unbrokered tool, alternate credential, overbroad task, compromised trusted process, or administrator bypass can escape the boundary.

**Closure direction:** maintain the narrow claim, inventory every effect path, eliminate bypass routes, and run adversarial tests against the composed release. Prompt-injection immunity should not be claimed.

## 3. General task correctness is not verified

The runtime records and revalidates the approved request, actual agent plan, exact action, and observed result. The connected free-text path has no qualified production evidence provider. It therefore abstains and presents **Not verified**.

An exact artifact provider can verify a configured digest. This establishes byte identity only. It does not establish that an edit, command, or deployment preserves the user's intended meaning.

**Closure evidence:** authenticated evidence providers, explicit trust and calibration policy, independently reviewed evaluation data, measured error and abstention rates, and live authorization tests showing that missing or contradictory evidence produces the documented outcome.

## 4. Formal assurance is selective

Lean checks properties of the repository's abstract definitions. TLA+ explores bounded state-machine instances. Neither proves that the full Rust, TypeScript, SQL, Electron, operating-system, cryptographic, or cloud implementation refines those models.

**Closure direction:** keep a machine-checked claim map from each public property to theorem, model, code, and executable test; add refinement arguments for the highest-risk transitions; retain independent review. Even then, claims must name the verified scope.

## 5. The process broker is not an OS sandbox

The controlled terminal path uses explicitly allowed executables, direct argument vectors, one-time authorization, executable identity checks where supported, and descendant tracking. It does not isolate an allowed program from the host with namespaces, seccomp, a virtual machine, or an equivalent platform boundary.

An allowed executable can have broad behavior, load configuration, spawn children, interpret inputs, or reach resources through its own capabilities.

**Closure evidence:** a hardened runner profile with tested filesystem, process, network, device, secret, and resource isolation on each supported operating system. The desktop should continue to label the current broker accurately.

## 6. Controlled network access is narrow

The local network broker supports exact configured domains, HTTPS, public WebPKI, public IP destinations, `GET` and `HEAD`, no redirects, bounded responses, and exact approval. It does not support mutating methods, arbitrary sockets, private certificate authorities, authenticated enterprise proxies, private network targets, or a general egress policy language.

DNS, proxy, TLS interception, captive networks, and enterprise endpoint controls need live acceptance testing.

**Closure evidence:** platform-specific network tests, DNS and address-substitution tests, proxy and certificate-policy profiles, route enforcement evidence, and documented behavior under partial failure.

## 7. Cloud connectors lack retained real-account acceptance

The read-only GitHub, ECR, and Kubernetes adapters and the deployment-preflight composition exist locally. Current evidence does not establish interoperability with real accounts, organization policies, pagination limits, throttling, identity federation, enterprise proxies, or provider changes.

**Closure evidence:** disposable-account runs from the release revision, least-privilege policies, retained redacted receipts, negative tests, rate-limit behavior, and replayable setup instructions.

## 8. The Kubernetes mutation path is not live-proven

The repository contains policy, state, broker, transport, executor, admission, and reconciliation components for changing one container image in one existing Deployment. The account-free exhibit performs no provider I/O and reports `NotSent`.

There is no retained successful end-to-end EKS mutation demonstrating exact RBAC, token audience, API route, admission caller origin, credential exclusivity, state revalidation, effect observation, and terminal retirement together.

**Closure evidence:** first a complete disposable kind run, then an EKS run with retained setup, identities, effective RBAC, admission configuration, signed inputs, transaction timeline, exact resulting object, cleanup, and negative-path evidence.

## 9. Complete mediation is not established

The intended guarantee assumes that every protected mutation uses the exclusive executor and destination-side enforcement. Alternate service accounts, cluster-admin credentials, disabled admission, direct host tools, or an unreviewed extension can bypass that path.

A Kubernetes cluster administrator remains inside the trusted computing base and can disable admission controls.

**Closure evidence:** an explicit bypass inventory, effective permissions, admission ownership, credential issuance paths, workload identities, break-glass policy, and adversarial proof that the protected principal cannot mutate the target through another route.

## 10. Production key custody is absent

The implementation uses purpose-separated signing and verification profiles. It does not yet establish isolated KMS or HSM custody, workload identity, anti-backdating controls, rotation, revocation, recovery, dual control, or production audit for every key role.

**Closure evidence:** a documented key hierarchy and threat model, deployed restricted signers, rotation and revocation exercises, compromise recovery, and independent review.

## 11. Evidence truth remains an external assumption

Signature, freshness, scope, and provenance checks establish who made an assertion and what it commits to. They do not prove that an activated source is truthful or uncompromised.

**Closure direction:** minimize each source's authority, require independent evidence for high-consequence actions where practical, expose provenance, test source disagreement, and document continuity behavior when a source is unavailable.

## 12. Unknown outcomes may require manual resolution

PostgreSQL and a remote provider are separate systems. A crash or lost response can leave the effect unknown. AccordLock retains the reservation and refuses blind redispatch, favoring safety over availability.

This can block later work until authenticated observation or a human resolution procedure establishes the outcome.

**Closure evidence:** a fault-injection matrix covering crash points, timeouts, partitions, duplicate delivery, stale reads, worker takeover, database failover, and provider observation; documented operator resolution with no unsafe retry path.

## 13. Durable-state operations are incomplete

The local PostgreSQL profiles exercise migrations, TLS, channel binding, transaction state, and adversarial behavior. Production role separation, high availability, replication, backup, point-in-time recovery, restore, monitoring, and disaster recovery have not been demonstrated.

**Closure evidence:** infrastructure-as-code, least-privilege database roles, backup and restore drills, rollback protections, failover tests, capacity limits, alerting, and retained recovery reports.

## 14. Remote approvals are protocol foundations, not a hosted service

Slack, Microsoft Teams, Telegram, and WhatsApp adapters, signed challenges, replay protection, secure local storage, queue behavior, and receipt import exist locally. The repository does not bundle a live public callback service or private gateway-to-desktop transport.

Provider-account configuration, callback authentication, Microsoft identity verification, certificate operations, abuse controls, rate limits, delivery guarantees, and multi-device behavior remain unproved.

**Closure evidence:** deployed gateway architecture, provider-specific acceptance suites, key enrollment and revocation, replay and substitution tests, delayed-event behavior, delivery metrics, and incident procedures.

## 15. Distribution is unsigned

There is no public signed installer or trusted automatic-update channel. A local package-integrity check is not code signing, notarization, or clean-machine acceptance.

**Closure evidence:** Authenticode-signed Windows artifacts; signed and notarized macOS artifacts; reproducible source provenance; SBOM and dependency reports; clean install, update, rollback, uninstall, and data-retention tests; verified download and update metadata.

## 16. Desktop isolation needs independent review

The design keeps runtime tokens, backend secrets, credential storage, workspace selection, and native approval operations outside the renderer. Electron configuration, IPC exposure, navigation policy, extension loading, local file handling, update behavior, and renderer compromise still need a complete security assessment.

**Closure evidence:** explicit IPC inventory, renderer-to-main authorization review, web security configuration checks, malicious-renderer tests, dependency audit, and independent desktop assessment.

## 17. Filesystem behavior is platform-dependent

Canonical path checks and protected paths are implemented, but real filesystems add symlinks, junctions, reparse points, network shares, case folding, alternate streams, race conditions, antivirus hooks, and permission changes.

**Closure evidence:** platform matrices and adversarial tests on supported Windows, macOS, and Linux filesystems, including time-of-check/time-of-use cases and recovery behavior.

## 18. Performance and operator burden are not characterized

AccordBench is a deterministic conformance corpus, not a latency or field-accuracy study. The project has no representative production measurements for decision latency, approval frequency, false refusals, safe completion, recovery time, or remote-notification delivery.

**Closure evidence:** instrumented design-partner workloads, preregistered metrics, representative task distributions, confidence intervals, and a published distinction between fixture results and field observations.

## 19. Compliance is not automatic

Audit continuity, exact approvals, access controls, and export can support a compliance program. They do not certify conformity with the EU AI Act, SOC 2, ISO 27001, financial regulation, health regulation, or any other framework.

**Closure evidence:** organization-specific control mapping, legal review, retention and privacy policy, operational evidence, and the relevant external assessment.

## 20. Availability is secondary to safety in the current design

Missing critical state, expired evidence, unavailable signer, stale authority, or unresolved effect causes refusal. This is deliberate, but it can interrupt work.

Continuity policy and emergency access are deployment decisions. A bypass that silently weakens the protected guarantee is not an acceptable availability feature.

**Closure evidence:** explicit continuity modes, separately authenticated emergency access, time-bounded activation, independent audit, post-event review, and tests proving that ordinary automation cannot activate the exception.

## Release priorities

### P0: required before any production pilot with real effect authority

- complete mediation and credential isolation;
- successful retained kind and EKS compositions;
- production key custody;
- authenticated evidence and observation paths;
- hardened runner isolation;
- production database operations;
- signed distribution;
- fault-injection and recovery evidence; and
- independent security review.

### P1: required for credible enterprise evaluation

- live GitHub, AWS, ECR, Kubernetes, and messaging acceptance;
- operator and administrator setup documentation;
- clean-machine installation and diagnostics;
- measured latency, review burden, safe completion, and false refusals;
- incident, continuity, and emergency-access procedures; and
- design-partner feedback from representative workflows.

### P2: required for a durable public project

- stable public protocol versioning;
- automated claim-to-evidence traceability;
- reproducible releases and long-term dependency maintenance;
- governance for security-boundary changes;
- compatibility matrices; and
- independently reviewed benchmark expansion.

See [Product Status](PRODUCT_STATUS.md) for the current capability matrix and [Threat Model](THREAT_MODEL.md) for the security assumptions behind these gates.
