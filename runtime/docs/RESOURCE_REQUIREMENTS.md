# Resource Requirements

This register separates core product dependencies from evidence needed to make
public or production claims. AccordLock does not require every integration to
be enabled for every installation.

## No account required

The following can be developed and tested on one workstation:

- Rust, Python, TypeScript, Lean, and specification-model test suites;
- the desktop application with demo data;
- the deterministic evaluation kernel and AccordBench;
- controlled filesystem and terminal execution;
- notification protocol validation without sending messages;
- a disposable kind cluster once a container engine is healthy;
- local PostgreSQL profiles with or without authenticated TLS; and
- source, publication, dependency, and package-integrity checks.

## Accounts required for release evidence

### Source distribution

- one GitHub owner account and an organization for the public repositories;
- protected branches, reviewed ownership, release environments, and private
  vulnerability reporting;
- a GitHub App or fine-grained installation credential for live connector
  validation; and
- control of the public DNS prefix used by Kubernetes annotations and labels,
  or a migration to another controlled prefix.

### AWS deployment path

- one dedicated non-production AWS account with MFA, billing alerts, and audit
  retention;
- a disposable ECR repository and EKS cluster;
- separate least-privilege workload identities for observation, control,
  signing, execution, and emergency recovery;
- KMS keys for purpose-separated signing tests; and
- durable PostgreSQL, either managed in the sandbox or supplied as an isolated
  test service.

The AWS sandbox is evidence infrastructure. It is not required to run the
desktop demo or the offline evaluation suite.

### Remote notifications

Each enabled channel needs its own administrator-controlled test tenant:

- Slack workspace and Slack app;
- Telegram bot;
- Microsoft Entra tenant and Teams application; and
- Meta developer application with a WhatsApp Cloud API test number.

These accounts are required only for authenticated delivery and remote-review
evidence. Protocol, replay, redaction, and substitution behavior is already
testable offline.

### Model and artifact providers

At least one real model route is needed to measure end-to-end agent utility.
This can be a hosted provider credential or a suitable local model. Separate
test identities are needed for any provider presented as a supported built-in
connection, including model gateways or Hugging Face artifact access.

The transaction core is provider-neutral. No single model vendor is a hard
dependency.

### Signed desktop distribution

- a Windows code-signing identity accepted by the selected release channel;
- an Apple Developer account for macOS signing and notarization;
- clean Windows and macOS build runners; and
- retained release attestations and update-channel verification.

## People and environments required for production evidence

- one bounded design-partner workflow in staging or shadow mode;
- accountable customer security and infrastructure owners;
- an independent systems-security and cryptographic review;
- an independent model-to-code and model-to-database correspondence review;
- an application and cloud-infrastructure assessment; and
- independent reproduction of latency, refusal, recovery, and integration-cost
  measurements.

Maintainer-authored fixtures and reviews cannot close independent or customer
evidence gates.

## Recommended acquisition order

1. repair the local container runtime and close the disposable local profile;
2. create the GitHub organization, repositories, and protected release path;
3. establish the public DNS prefix and signed desktop build identities;
4. create the isolated AWS sandbox and reproduce GitHub–ECR–EKS evidence;
5. enable one notification channel and one model route end to end;
6. run a bounded design-partner evaluation; and
7. commission independent reviews before making a production claim.
