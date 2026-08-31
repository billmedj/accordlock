# AccordLock local reproduction report — historical snapshot

> This report predates the AccordLock public-release cleanup. Product and
> identifier names were normalized later; the recorded results were not rerun
> against the current source tree. See this directory's README.

**Date:** 2026-08-16  
**Workspace:** AccordLock pre-release workspace  
**Profile:** fixed local `DEPLOY_EKS_IMAGE_V1` candidate  
**Result:** complete local runner passed  
**Claim class:** internal AI-assisted reproduction, not independent validation

## Command

PowerShell:

```powershell
.\scripts\run-all.ps1 -TlaJar .\.local\tools\tla2tools.jar
```

The runner used its default local PostgreSQL mode. The project-local
PostgreSQL 17 server was already running on `127.0.0.1:55432`; the runner
verified and reused it. No remote database, AWS account, Kubernetes cluster,
or customer system was contacted.

## Recorded tools

| Tool | Recorded version or identity |
|---|---|
| Rust compiler | `rustc 1.97.1 (8bab26f4f 2026-07-14)` |
| Cargo | `cargo 1.97.1 (c980f4866 2026-06-30)` |
| Python | `3.13.1` |
| Java | Oracle Java `20.0.1+9-29` |
| Git | `2.48.1.windows.1` |
| cargo-audit | `0.22.2` |
| TLC | TLA+ Tools release `v1.7.4`; TLC engine banner `2.19`, revision `5a47802`; jar SHA-256 `936a262061c914694dfd669a543be24573c45d5aa0ff20a8b96b23d01e050e88` |
| PostgreSQL | project-local PostgreSQL `17` profile |
| RustSec database | commit `69f93e1d081d8b6fbee010e48f0b5e0d13661415` |

The Rust toolchain, cargo-audit version, TLC jar hash, and RustSec commit are
checked by the runner. Java, Python, Git, and PostgreSQL versions are recorded
but are not all locked as downloadable byte-identical distributions.

## Results

| Stage | Result |
|---|---|
| Source manifest | 113 Git-visible source files, exact at runner start and end |
| Rust dependency contract | 9 workspace packages; 166 external registry packages with lock checksums and nonempty license metadata |
| RustSec | 1,216 advisories loaded; 175 dependencies scanned; 0 vulnerabilities; 0 warnings; 0 ignores or filters |
| Static repository contract | 11 JSON documents, 33 reason codes, 14 provisional CDDL arrays |
| Conformance corpus | 7 synthetic scenario manifests and 18 legacy vectors validated structurally |
| Python | 29 tests passed |
| Rust ordinary suite | 197 successful non-ignored test executions, including one compile-fail doctest |
| PostgreSQL opt-in suite | 27 successful executions: 25 state-suite targets, including the child-process helper used by the race test, one CLI library path, and one binary prepare/validate path |
| Formatting and compilation | rustfmt, all-target Cargo check, and workspace Clippy with warnings denied passed |
| CLI determinism | Two byte-identical runs, four synthetic scenarios, `benchmark=false` |
| Authorization lifecycle model | 886 generated states, 306 distinct states, depth 10, no invariant violation |
| Dispatch-claim model | 37,121 generated states, 4,218 distinct states, depth 9, no invariant violation |

RustSec was run with yanked-crate checking disabled because that check requires
a current crates.io index. The dependency-license stage checks that metadata is
present; it does not parse SPDX or make a legal compatibility determination.
The bounded TLA+ results are not proofs of Rust, SQL, network, or Kubernetes
behavior.

## Reproduced security-relevant traces

The local suites include negative and concurrency traces for:

- caller identity, audience, registry-root, evaluator, signer, and signature
  substitution;
- authorization v1/v2 domain separation, canonical encoding, unknown fields, replay,
  authority rotation, revocation, deadline, and grant-use exhaustion;
- trusted-time rollback after successful and rejected grant registration,
  issuance, consumption, claim creation, claim revalidation, and attempt
  marking;
- PostgreSQL single-winner consumption, multi-process claim exclusion for one
  consumed authorization, fence monotonicity, lost commit responses, schema drift, and
  tuple corruption;
- Kubernetes patch mutation, sidecar and service-account injection, target
  identity, full post-admission delta, and Deployment-to-ReplicaSet-to-Pod
  ownership.

These tests exercise and reproduce only the named local traces under their
premises.
Durable claim exclusion is scoped to one authorization/AUTHORIZATION_ID, not to one physical
resource across different authorizations.

## What was not reproduced

- No successful Docker, kind, or EKS execution was obtained.
- The live PowerShell runner still calls `kubectl` directly and does not use
  the dispatch claim or `AuthorizedProviderAttempt` as its exclusive effect
  path.
- No GitHub, ECR, EKS, KMS, HSM, production PostgreSQL, connector, broker,
  executor, provider fence, or authenticated effect-observation integration
  was tested.
- No AgentDojo, CaMeL, utility, refusal, escalation, or latency benchmark was
  run.
- No customer workflow, paid pilot, independent reviewer, external red team,
  or security certification participated.
- The run used a mutable local working tree with cached dependencies and an
  existing disposable database. It was not an independent clean-checkout or
  network-independent reproduction.

## Source-state limitation

At the time of this report, the product workspace has no commit on its initial
Git branch and all product files are untracked. The source manifest covers the
Git-visible files, but it is not a substitute for an immutable commit, signed
release, remote repository, or independent checkout. Those remain manual
publication gates.
