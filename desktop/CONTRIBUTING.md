# Contributing to AccordLock

Thank you for helping improve this repository. Bug reports, threat analysis,
documentation, design feedback, code, tests, and reproducible validation are all
valuable contributions.

By participating, you agree to follow [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md).
Report security issues through the private process in [SECURITY.md](SECURITY.md),
not through a public issue.

## Start with the problem

Before making a substantial change:

1. Search the repository issues for existing work.
2. Open a bug report or feature request with the relevant template.
3. Explain the user impact, constraints, security implications, and how the
   result can be verified.
4. Use a repository discussion for early design exploration when discussions
   are enabled.
5. Wait for scope agreement from a maintainer before investing in a large
   implementation.

Repository issues and pull requests are the durable decision record. There is
no external project board or chat channel required by this repository.

## Pull requests

Keep each pull request focused and reviewable. A pull request should:

- link the issue or discussion that establishes its context;
- describe behavior and trust-boundary changes, not only edited files;
- include tests for success, denial, malformed input, and relevant failure
  paths;
- list the exact validation commands that were run;
- update user documentation and security documentation when behavior changes;
- contain no credentials, private data, machine-specific paths, or runtime
  artifacts; and
- use clear, standard English in source, schemas, logs, and user-facing copy.

User-interface changes should include screenshots or a short recording when
that materially helps review. Generated files should be regenerated from their
source rather than edited by hand.

## Security-sensitive changes

Changes to authorization, credential custody, process execution, filesystem
access, network access, canonical encoding, signatures, audit records, or
production connectors require explicit threat analysis and fail-closed tests.
Do not weaken a security boundary merely to preserve compatibility.

Never include a real secret in a fixture. Use an unmistakably synthetic value
and document why the fixture is safe.

## Development checks

The repository includes Rust services and an Electron desktop application. The
development environment can be activated with Hermit when available:

```bash
source bin/activate-hermit
```

Run the checks relevant to your change. Common Rust checks are:

```bash
cargo fmt --all -- --check
cargo check --workspace
cargo test --workspace
cargo clippy --workspace --all-targets -- -D warnings
```

The desktop application can be started with:

```bash
just run-ui
```

Follow the package scripts in `ui/package.json` and `ui/desktop/package.json`
for targeted desktop tests and linting. If a complete suite is impractical,
state exactly what was and was not run.

## AI-assisted contributions

AI assistance is permitted. The contributor remains responsible for every
line, test, dependency, claim, and generated artifact. Review generated changes
for unnecessary complexity, permissive error handling, copied private data,
and tests that only mirror the implementation.

## Review and authority

Maintainers and reviewers are designated through the repository settings.
Submitting a contribution does not guarantee acceptance. Review prioritizes
security, correctness, product clarity, maintenance cost, and alignment with
the repository roadmap.

Licensing and attribution are recorded in `LICENSE`, `NOTICE`, and
`THIRD_PARTY_NOTICES.md`. Contributions must preserve those records.
