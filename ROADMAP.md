# AccordLock roadmap

This roadmap moves the current engineering alpha toward a reproducible public
release and a production candidate. Each phase has an exit condition.

## Current position

The public monorepo contains the complete distributable source for the desktop,
runtime, assurance package, and provider-free demo. The project remains an
engineering alpha. One Windows desktop lint job is failing. Signed installers,
retained live integration results, and independent review are not complete.

## 1. Stabilize the public alpha

- Fix the Windows desktop lint failure and restore the skipped desktop tests.
- Verify the provider-free demo and source build from a clean clone.
- Check install, update, and removal on clean Windows and macOS systems.
- Publish a source tag with checksums, an SBOM, and recorded CI results.
- Keep product, limitation, and evidence claims synchronized through CI.

**Exit:** the public branch is green, a clean machine can reproduce the local
evaluation path, and the release record lists every unexecuted gate.

## 2. Make Effect Transaction Protocol the native dispatch boundary

[Effect Transaction Protocol (ETP)](https://github.com/billmedj/etp) defines
product-neutral records and executor rules for protected effects.

- Map file, program, network, and infrastructure actions to stable ETP records.
- Require one ETP decision and grant path for every protected broker.
- Remove parallel authority paths.
- Add cross-implementation conformance fixtures.
- Preserve unknown outcomes and reconciliation through the desktop workflow.

**Exit:** no protected broker can dispatch without a valid ETP transaction, and
the conformance suite covers the complete lifecycle.

## 3. Validate external integrations

- Run PostgreSQL and disposable Kubernetes acceptance tests.
- Retain evidence from a GitHub, ECR, EKS, and Kubernetes preflight chain.
- Validate Slack, Teams, Telegram, and WhatsApp delivery and receipt checks.
- Measure decision latency, approval latency, false refusals, unknown outcomes,
  and recovery time.

**Exit:** each supported integration has a repeatable environment, redacted
evidence package, and documented failure behavior.

## 4. Establish the production boundary

- Isolate the enterprise runner and credential-custody path.
- Establish complete mediation for each supported effect class.
- Add key rotation, high availability, backup, recovery, and incident runbooks.
- Define and test break-glass behavior.
- Sign installers and updates through controlled release identities.
- Complete an independent security review.
- Run a design-partner pilot with production-like workloads.

**Exit:** the deployment boundary, operating controls, and residual risks have
external evidence and named owners.

## Deferred scope

The current roadmap does not include unrestricted shell access, arbitrary
network egress, universal rollback, automatic approval from messaging clients,
or a claim that semantic evaluation can prove user intent.
