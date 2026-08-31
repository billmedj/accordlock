# External evidence gates

Some AccordLock properties cannot be completed by changing local source code.
This public register defines the dependency identifiers used in
[KNOWN_LIMITATIONS.md](KNOWN_LIMITATIONS.md). `OPEN` means that no completion
claim is made for the current engineering alpha.

## Local integration

| ID | Status | Required evidence |
|---|---|---|
| LOCAL-001 | OPEN | One retained successful disposable `kind` run with exact inputs, outputs, validation artifacts, and no failure marker |

## GitHub

| ID | Status | Required evidence |
|---|---|---|
| GH-001 | OPEN | Official repository, protected default branch, reviewed ownership, immutable release process, and a clean-checkout reproduction |
| GH-002 | OPEN | Control of the `accordlock.io` DNS name used as the Kubernetes annotation and label namespace, or a pre-release migration to a DNS prefix the project controls |
| GH-003 | OPEN | Least-privilege authenticated connector for protected review and branch state, including webhook/API replay and substitution tests |
| GH-004 | OPEN | Real workflow and artifact attestations tied to exact repository, ref, workflow identity, inputs, run, commit, and image digest |
| GH-005 | OPEN | Provisioned, isolated, patched, monitored, and tested `accordlock-tlc` self-hosted runner before enabling automatic exhaustive-workflow triggers |
| GH-006 | OPEN | Tested private vulnerability reporting plus live private security and conduct contact channels that do not require public disclosure |

## AWS sandbox

| ID | Status | Required evidence |
|---|---|---|
| AWS-001 | OPEN | Dedicated non-production AWS account or equivalent isolation boundary, with billing limits, audit retention, and no production or customer data |
| AWS-002 | OPEN | Separate least-privilege identities for connector, control, signer, broker, executor, observer, and break-glass operations, with real allow/deny tests |
| AWS-003 | OPEN | Authenticated ECR digest, provenance, signature, and quarantine evidence plus substitution and freshness tests |
| AWS-004 | OPEN | Fixed `DEPLOY_EKS_IMAGE_V1` effect through the exclusive EKS route, with bypass, admission, audience, RBAC, and post-state evidence |
| AWS-005 | OPEN | Purpose-constrained KMS/HSM-style signing, rotation, disable, recovery, audit, and cross-purpose rejection |
| AWS-006 | OPEN | Authenticated PostgreSQL identity, least-privilege roles, synchronous durability assumptions, immutable records, backup, restore, crash, and failover exercises |
| AWS-007 | OPEN | Restricted network paths, telemetry, redaction, alarms, incident evidence, and tested webhook caller-origin controls |

## Pilot environment

| ID | Status | Required evidence |
|---|---|---|
| CUST-001 | OPEN | One bounded, named design-partner workflow and accountable technical/security owners |
| CUST-002 | OPEN | Reviewed inventory of every mutation route, identity, credential, approval, bypass, rollback, and break-glass path |
| CUST-003 | OPEN | Agreed systems of record and residual-trust register for review, build, artifact, target, policy, grant, identity, and revocation facts |
| CUST-004 | OPEN | Staging or non-critical shadow evaluation with installation evidence, traffic corpus, latency, denial, utility, and false-refusal analysis |
| CUST-005 | OPEN | Rehearsed rollback, recovery, support, and break-glass procedures with retained results and accountable owners |
| CUST-006 | OPEN | Explicit acceptance of residual risk and accountable authorization before any enforced production use |

## Independent review

| ID | Status | Required evidence |
|---|---|---|
| EXT-001 | OPEN | Independent systems-security review of threat model, complete mediation, trust boundaries, failure, and recovery |
| EXT-002 | OPEN | Independent cryptographic/protocol review of canonicalization, signatures, key separation, grants, authorizations, replay, and wire compatibility |
| EXT-003 | OPEN | Independent model-to-code and model-to-SQL correspondence review with reproduced formal-model results |
| EXT-004 | OPEN | Independent application-security assessment of ingress, tenant isolation, connectors, signer misuse, verifier substitution, credentials, and executor bypass |
| EXT-005 | OPEN | Independent cloud/infrastructure review of IAM, KMS, EKS, networking, PostgreSQL, immutable storage, backup, restore, and disaster recovery |
| EXT-006 | OPEN | Independent reproduction of security, latency, refusal, recovery, storage, and integration-cost measurements |

An AI-assisted or maintainer-authored review cannot close an `EXT-*` item. A
schema, test, local model, or synthetic fixture cannot close an AWS, GitHub, or
pilot item by itself.
