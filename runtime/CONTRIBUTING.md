# Contributing to AccordLock

Thank you for helping improve AccordLock. Security-sensitive infrastructure
benefits from small, reviewable changes and evidence that another person can
reproduce.

## Before you start

- Use GitHub Discussions for design questions when Discussions is enabled.
- Open an issue before undertaking a large feature, protocol change, public API
  change, or new dependency.
- Search existing issues and pull requests to avoid duplicate work.
- Report vulnerabilities through the private process in [SECURITY.md](SECURITY.md),
  never through a public issue.

## Development workflow

1. Fork the repository and create a focused branch.
2. Make the smallest coherent change.
3. Add or update tests, models, schemas, and documentation where the contract
   changes.
4. Run the relevant local checks. Before requesting final review, run the
   fail-closed repository suite when your environment supports it:

   ```sh
   sh scripts/run-all.sh
   ```

   On Windows PowerShell:

   ```powershell
   ./scripts/run-all.ps1
   ```

5. Open a pull request using the repository template. Explain the threat-model
   impact, compatibility impact, and exact verification performed.

The pinned toolchain is defined in `rust-toolchain.toml`. Rust code must respect
the workspace lint policy, including the ban on `unsafe` code and fallible
shortcuts prohibited by the workspace configuration.

## Commit sign-off

Contributions use the [Developer Certificate of Origin 1.1](https://developercertificate.org/).
Add a `Signed-off-by` trailer to every commit:

```sh
git commit -s
```

By signing off, you certify that you have the right to submit the contribution
under the repository license. Maintainers may ask you to correct commits that
are missing a valid sign-off.

## AI-assisted contributions

AI-assisted contributions are welcome when they meet the same provenance,
review, and quality standards as any other contribution. In the pull request:

- disclose material use of generative tools and identify the affected files or
  areas;
- describe the human review and verification performed;
- confirm that no credentials, customer information, confidential material, or
  unlawfully sourced code was provided to a tool or included in the change; and
- take responsibility for correctness, security, licensing, and originality.

Do not submit generated output you cannot understand, validate, or lawfully
license. Tool output is not evidence that a change is correct.

## Security-sensitive changes

Changes to canonical encoding, signatures, identity, authorization, replay
control, state transitions, dispatch, credential handling, Kubernetes
enforcement, or audit receipts require:

- explicit threat-model analysis;
- negative and adversarial tests;
- compatibility analysis for stored or signed data;
- fail-closed behavior for unknown or ambiguous states; and
- explicit review by a verified maintainer identified through the public
  governance process.

Do not weaken a check merely to make a test, benchmark, or demonstration pass.
Record limitations and non-results precisely.

## Dependencies and generated files

- Explain why each new runtime dependency is necessary.
- Prefer pinned, reproducible inputs and preserve lockfiles.
- Do not manually edit generated manifests or artifacts unless their generation
  process explicitly requires it.
- Update third-party attribution when a dependency or bundled work requires it.

## Review and acceptance

Maintainers evaluate technical merit, scope, security impact, reproducibility,
maintenance cost, and alignment with the project roadmap. Submission does not
guarantee acceptance. Contributions accepted into this repository are licensed
under Apache License 2.0 unless a file clearly states otherwise.

All participation is governed by [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md).
