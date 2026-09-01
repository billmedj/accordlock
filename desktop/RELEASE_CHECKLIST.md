<!-- Modified by AccordLock contributors; see UPSTREAM.md. -->
# AccordLock release acceptance checklist

Record the operating-system version, installer digest, application version,
monorepo commit, assembled desktop and runtime trees, model provider, and tester
for each run. A failed item blocks release until a new candidate passes.

This checklist governs a binary release. The source-only engineering alpha is
governed by the exact-commit workflow and no-binary rules in `RELEASE.md`; it
does not claim that the items below have passed.

## Install and update

- [ ] A clean install succeeds without a developer toolchain.
- [ ] The installed publisher, version, icon, shortcuts, and uninstall entry
      are correct.
- [ ] Launching from the Start menu opens one responsive AccordLock window.
- [ ] Upgrading from the previous supported version preserves settings,
      projects, task history, and credential-vault entries.
- [ ] Uninstall removes application files without deleting user projects or
      audit exports.

## First run

- [ ] A user with no configured provider reaches model setup.
- [ ] Provider setup cannot finish without both a provider and model.
- [ ] Secrets are stored through the operating-system credential vault and do
      not reappear in the renderer, logs, diagnostics, or exports.
- [ ] A user can create a project, choose a workspace, describe a task, review
      access, and start work without documentation.

## Protected execution

- [ ] Read access stays inside the approved workspace and protected paths stay
      inaccessible.
- [ ] File changes show the exact target and content before one-time approval.
- [ ] Terminal execution is unavailable until an exact program is allowed, and
      each invocation still requires approval.
- [ ] Controlled network access accepts only configured HTTPS GET or HEAD
      destinations and rejects redirects or destinations outside the allowlist.
- [ ] Revoked, expired, reused, malformed, or mismatched authorization fails
      closed and produces an understandable record.
- [ ] Stopping or crashing the runtime cannot silently widen access.

## Approvals and audit

- [ ] Pending approvals appear in the task and Approval Center without
      duplication.
- [ ] Approve, deny, revoke, and expiry states survive a normal restart.
- [ ] Slack, Teams, Telegram, and WhatsApp test alerts use the configured
      channel without exposing task secrets.
- [ ] A remote decision is accepted only when its signed receipt matches the
      exact pending action, channel enrollment, and expiry.
- [ ] Audit search and filters match the displayed protected records.
- [ ] Audit export verifies against its ledger revision and digest.
- [ ] A supported recovered file can be restored, and the restoration is
      recorded as a new action rather than rewriting history.

## Deployment preflight

- [ ] GitHub, AWS, ECR, and Kubernetes routes are fixed to the saved
      environment.
- [ ] New AWS credentials require a temporary access key, secret key, and
      session token; stored credentials are never returned to the renderer.
- [ ] A valid candidate checks the approved code, build, immutable image, and
      current Kubernetes target and produces a signed receipt.
- [ ] Repository, workflow, account, region, image, deployment UID, or current
      state mismatches fail closed with a specific reason.
- [ ] Every result clearly states that the preflight is read-only and performed
      no deployment.

## Package integrity

- [ ] The candidate was built on an ephemeral, exclusive runner with no
      concurrent writer to either source checkout; both checkouts remained on
      the locked commits and clean through the final pre-package check.
- [ ] Native release sidecars came from newly created Cargo target directories;
      `src/bin` contained no tracked sources, reviewed platform wrappers were
      copied, re-hashed, and assigned their reviewed modes in a real
      in-repository staging directory, and all temporary target directories
      were removed after staging.
- [ ] Every output directory and recursive cleanup target was a real non-link
      descendant of the verified desktop output boundary.
- [ ] The macOS DMG and ZIP were mounted or extracted into fresh controlled
      directories. Each contained exactly one AccordLock application payload
      whose file set, digests, native modes, architectures, and release
      signature matched the verified staged payload and packaged application;
      both distributed copies retained a valid stapled ticket and passed
      Gatekeeper assessment.
- [ ] `accordlock-artifact-manifest.json` lists every shipped artifact with the
      correct digest and source identity.
- [ ] `SHA256SUMS` verifies without omissions or extra files.
- [ ] Installer and protected-sidecar signatures validate on a clean system.
- [ ] CycloneDX inventories are present, valid, and non-empty.
- [ ] Publication hygiene, critical test suites, type checking, localization,
      formatting, and dependency policy checks all pass from the tagged source.
- [ ] Release notes describe supported profiles and every known limitation
      without claiming production behavior that was not tested.
