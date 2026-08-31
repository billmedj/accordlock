# AccordLock release checklist

This checklist is mandatory for an official public release. Mark an item complete
only when evidence exists for the exact source revision being released. Record
exceptions in the release notes with an owner and follow-up issue.

## 1. Identity and repository controls

- [ ] The AccordLock name has received appropriate legal and similarity review
      for the intended jurisdictions and goods or services.
- [ ] The official repository URL, organization, domains, and social accounts are
      controlled by the lawful project owner.
- [ ] The project controls the `accordlock.io` DNS prefix used in Kubernetes
      annotations and labels, or all such identifiers were migrated before the
      public compatibility boundary was frozen.
- [ ] The `@accordlock/maintainers` team exists, has the intended members, and
      resolves cleanly in `.github/CODEOWNERS`.
- [ ] Default-branch protection requires pull requests, passing checks, resolved
      conversations, and code-owner review for sensitive paths.
- [ ] The exhaustive workflow remains manual-only unless the labelled
      self-hosted TLC runner has been provisioned, isolated, secured, and tested.
- [ ] Maintainer accounts require phishing-resistant multi-factor authentication
      where the platform supports it.
- [ ] GitHub private vulnerability reporting is enabled and tested.
- [ ] The repository description, topics, social preview, and public contact
      channels are accurate.
- [ ] Issue and pull-request labels referenced by templates and Dependabot exist
      (`bug`, `enhancement`, `triage`, `dependencies`, `rust`, and
      `github-actions`).

## 2. Ownership, licensing, and provenance

- [ ] `LICENSE`, `NOTICE`, `TRADEMARKS.md`, `CONTRIBUTING.md`, and
      `CODE_OF_CONDUCT.md` are present and linked from the root documentation.
- [ ] Copyright ownership and any employment, contractor, or prior-project IP
      obligations have been reviewed.
- [ ] Every bundled third-party work has a compatible license and required
      notices. Cargo license metadata alone is not treated as legal
      compatibility review.
- [ ] An SPDX-compatible dependency and source inventory is retained with the
      release evidence.
- [ ] Material AI-assisted development is disclosed; affected work has received
      accountable human review; no tool output is assumed to establish
      originality, licensing, or correctness.
- [ ] Contributor sign-offs and contribution provenance are complete.
- [ ] A qualified lawyer has reviewed the open-source, trademark, and contributor
      policy before commercial or customer production use.

## 3. Public-data and secret hygiene

- [ ] The complete Git history and release tree have been scanned for credentials,
      private keys, tokens, passwords, cloud account data, private endpoints,
      customer identifiers, personal information, and confidential files.
- [ ] Findings have been removed from both the current tree and history, and any
      exposed credential has been revoked and rotated.
- [ ] Example identifiers, domains, accounts, certificates, and logs are clearly
      synthetic or reserved for documentation.
- [ ] Ignored local state, database directories, build output, editor metadata,
      and temporary logs are absent from the release archive.
- [ ] CI logs and test artifacts do not disclose secrets on either success or
      failure paths.

## 4. Security and claim boundary

- [ ] `SECURITY.md`, the threat model, trust boundary, known limitations, and
      supported-version policy match the release.
- [ ] Release notes state whether independent security review occurred and do not
      describe internal, AI-assisted, or automated review as independent.
- [ ] No documentation claims production readiness, complete mediation,
      certification, compliance, customer validation, or benchmark superiority
      without version-specific evidence.
- [ ] Authentication, authorization, key custody, replay controls, state recovery,
      break-glass behavior, and fail-closed behavior are tested for the supported
      deployment profile.
- [ ] All security-relevant known issues have a documented disposition: fixed,
      explicitly accepted for this support level, or release-blocking.
- [ ] Dependency, advisory, and supply-chain checks pass against pinned inputs.

## 5. Build and verification

- [ ] The version in workspace metadata, packages, schemas, CLI output,
      documentation, and citation metadata agrees.
- [ ] The source manifest has been regenerated after the final edit and verifies
      against a clean checkout.
- [ ] The locked, fail-closed test suite passes from a clean checkout on every
      claimed platform.
- [ ] Formal-model outputs are tied to the exact model, configuration, tool hash,
      assumptions, and source revision.
- [ ] Installation and quick-start commands have been executed exactly as written
      by someone other than the final author when possible.
- [ ] Release artifacts are reproducible or any nondeterminism is explained and
      bounded.
- [ ] Container base images, actions, tools, and fetched artifacts are pinned by
      immutable identity and verified where supported.

## 6. Release artifacts

- [ ] The release archive contains source and required license and notice files,
      and excludes local-only or sensitive material.
- [ ] An SBOM is generated for each distributed binary or container image.
- [ ] Checksums are published for all artifacts.
- [ ] Tags and artifacts are signed using documented project release identities.
- [ ] Container images are published by digest, use a minimal runtime image, run
      as a non-root user where possible, and include provenance attestations.
- [ ] Upgrade, downgrade, rollback, data compatibility, and uninstall behavior
      are documented for the supported profile.

## 7. Release notes and communications

- [ ] Release notes identify the support level (`technical preview`, `beta`, or
      `supported`), exact scope, changes, breaking changes, limitations, and known
      issues.
- [ ] Security fixes use coordinated disclosure and link to an advisory when safe.
- [ ] Metrics and comparison claims include method, denominator, environment,
      uncertainty, and reproducible evidence.
- [ ] The citation version and release metadata are updated.
- [ ] Support and incident contacts are live and have been tested.

## 8. Final authorization

- [ ] A maintainer who did not perform the final code edit reviewed the release
      diff and evidence when another maintainer is available.
- [ ] The project lead approved the release scope and residual risk.
- [ ] The release commit is immutable, the working tree is clean, and CI passed
      on that exact commit.
- [ ] A rollback or advisory owner is available for the release window.

## 9. After publication

- [ ] Verify checksums, signatures, SBOMs, install instructions, links, and image
      digests from a fresh environment.
- [ ] Monitor security reports, dependency alerts, CI failures, and user-reported
      false refusals or bypasses.
- [ ] Record release evidence and lessons learned without retaining credentials or
      customer-confidential data.
