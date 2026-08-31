# Source release checklist

This checklist governs the first public source release and every later tag. It does not convert AccordLock into a supported production security boundary.

Record the candidate commit, runner images, command output, reviewer, and date. A missing or skipped required gate blocks the tag.

## Candidate identity

- [ ] The candidate is a clean checkout of one immutable commit on `main`.
- [ ] `CHANGELOG.md`, `CITATION.cff`, desktop package metadata, and the proposed tag use the same version.
- [ ] `python scripts/check_source_provenance.py` passes and both assembled component trees match the candidate commit.
- [ ] Every source adjustment after component import is recorded in `SOURCE_PROVENANCE.json`.
- [ ] The tag will be signed or otherwise verifiable. No existing tag or artifact will be replaced.

## Public boundary

- [ ] `python scripts/check_publication.py` passes from a clean checkout.
- [ ] The root Source CI and Reproducibility smoke workflows pass for the candidate commit.
- [ ] No credential, private key, personal path, customer data, local state, generated package, or unpublished manuscript is tracked.
- [ ] Apache-2.0 licensing, Goose attribution, dependency notices, and trademark terms have been reviewed.
- [ ] Relative documentation links and GitHub issue, security, and contribution paths resolve.

## Runtime evidence

- [ ] `cargo fmt --all -- --check` passes in `runtime/`.
- [ ] `cargo check --workspace --locked --all-targets` passes.
- [ ] `cargo clippy --workspace --locked --all-targets -- -D warnings` passes.
- [ ] `cargo test --workspace --locked` passes with ignored tests listed rather than silently counted as passed.
- [ ] The PostgreSQL adversarial and upgrade tests pass against a disposable database.
- [ ] The checksum-pinned RustSec audit and locked supply-chain checks pass.
- [ ] The provider-free native proof reports `production_ready: false` and its output matches the candidate.
- [ ] Demonstration tests run against candidate-built native binaries, not an oracle or fixture-only substitute.

## Assurance evidence

- [ ] The assurance manifest and its unit tests pass.
- [ ] The pinned Lean project builds, contains no proof placeholder or declared axiom, and reports the expected theorem count.
- [ ] The independent Lean environment checker passes.
- [ ] All eight TLA+ models complete the documented bounded smoke searches without an invariant violation.
- [ ] The exact TLC state counts, configurations, and bounded-search limitations are retained with the candidate logs.
- [ ] Public wording distinguishes traceability, abstract proof, bounded model checking, executable tests, live acceptance, and independent review.

## Desktop evidence

- [ ] The desktop publication guard and Rust formatting check pass.
- [ ] Protected backend tests pass with the `accordlock-distribution` feature.
- [ ] The exact packaged backend configuration builds from the locked dependency graph.
- [ ] Type checking, linting, English catalog validation, and unit tests pass with Node 24.10.0 and pnpm 10.30.0.
- [ ] The development application starts and the first-run, project, task contract, approval, audit, revocation, recovery, provider, and settings paths are manually exercised.
- [ ] Interface text states the decision or next action in plain English and does not overstate safety or verification.

## Claims and limitations

- [ ] `README.md`, `docs/PRODUCT_STATUS.md`, `docs/LIMITATIONS.md`, and release notes agree on current support and unexecuted gates.
- [ ] No live provider, cloud, Kubernetes, EKS, notification, update, signing, or audit claim is made without retained acceptance evidence.
- [ ] No model behavior is described as truthful, injection-proof, or formally verified end to end.
- [ ] Independent review is described as pending unless a qualified, organizationally separate reviewer has delivered a report for this candidate.

## Artifact decision

For `v0.1.0-alpha.1`, the intended deliverable is source code and reproducible logs only.

- [ ] No unsigned installer, portable executable, update manifest, or sidecar binary is attached to the release.
- [ ] If a later release includes binaries, code signing, checksums, SBOMs, clean-machine install/update/uninstall tests, and platform support statements become mandatory.
- [ ] Release notes label the release **Engineering Alpha**, state **not production ready**, and link the known limitations.

## Sign-off

- [ ] The project lead reviewed the final diff and candidate logs.
- [ ] A security-boundary reviewer approved changes to authorization, cryptography, evidence, execution, credentials, audit, or recovery when one was available.
- [ ] All release-blocking findings are closed or the candidate is abandoned.
- [ ] The final tag and release notes point to this exact commit.
