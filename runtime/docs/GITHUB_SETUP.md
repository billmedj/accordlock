# Publishing AccordLock on GitHub

This is the external setup checklist for the first public repository. It does
not authorize publication before the mandatory release checklist is complete.

## Repository identity

- Owner: a GitHub account or organization controlled by the project lead
- Repository: `accordlock`
- Default branch: `main`
- Visibility during preparation: private
- Suggested description: `Execution integrity for AI and cloud automation.`
- Suggested topics: `ai-agents`, `cloud-security`, `devsecops`, `kubernetes`,
  `provenance`, `rust`, `software-supply-chain`, `zero-trust`

Add a homepage only after the domain is controlled by the project owner. Do not
publish a placeholder or an unverified social account.

The source currently uses `accordlock.io` as its Kubernetes annotation and
label DNS prefix. Before publication, prove that the project owner controls
that DNS name or migrate every protocol, fixture, manifest, and test to a DNS
prefix the owner does control. This is a compatibility and namespace-ownership
decision, not merely a homepage choice.

## Required owner setup

1. Verify that the importing account is controlled by the project lead.
2. Require phishing-resistant two-factor authentication where available.
3. If an organization is used, add only consenting maintainers and grant each
   listed user or team the required repository access.
4. Add `CODEOWNERS` only after every listed owner resolves and its access has
   been verified. The source tree intentionally omits an unenforceable
   placeholder owner.

## Required repository security settings

- enable the dependency graph and Dependabot alerts;
- enable secret scanning and push protection where the account tier supports
  them;
- enable private vulnerability reporting;
- publish and test private security and conduct contact channels before public
  intake; the temporary request-for-private-channel fallback is not the target
  operating process;
- disable force pushes and branch deletion on `main`;
- require pull requests, resolved conversations, and passing checks; require
  code-owner review for sensitive paths once a verified `CODEOWNERS` file
  exists;
- restrict release creation and environment secrets to maintainers;
- keep GitHub Actions permissions read-only by default and grant narrower write
  permissions per job only when required;
- do not allow unreviewed workflows from forks to access secrets.

## First import

Before the first commit, configure the intended public Git author name and
email. Inspect them explicitly:

```sh
git config user.name
git config user.email
```

Do not reuse an unrelated company, client, or private email identity by
accident. The author identity becomes public commit metadata.

Import the clean release tree, not the parent drafts directory and not a ZIP of
the working folder. Build outputs, local databases, logs, private archives, and
ignored tool state must remain outside Git history.

## Before switching to public

- complete `.github/RELEASE_CHECKLIST.md` for the exact revision;
- verify the AccordLock name and owner;
- verify ownership of the `accordlock.io` Kubernetes DNS prefix or complete its
  migration before freezing the first public wire and manifest formats;
- confirm the Apache-2.0, NOTICE, contributor, and trademark decisions;
- run a complete secret and history scan;
- run the clean-checkout verification documented in the release evidence;
- verify every relative documentation link;
- confirm the README says unreleased engineering alpha and not production-ready;
- prepare one concise release note and one reproducible demo command.

## Suggested first release

Use `v0.1.0-alpha.1` only after the source revision passes the public technical
preview gate in [ROADMAP.md](ROADMAP.md). Sign the tag, attach checksums and an
SBOM when binary or container artifacts are distributed, and preserve the
exact validation report for that tag.
