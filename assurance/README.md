# AccordLock assurance manifest

This directory makes selected AccordLock safety claims reviewable and hard to
silently detach from their evidence.

`claims.yaml` maps each claim to four distinct evidence layers:

1. Lean theorems over small abstract definitions;
2. configured TLA+ invariants over bounded state machines;
3. Rust source files that implement the corresponding boundary;
4. executable Rust tests that exercise the implementation.

The manifest is deliberately narrower than the product documentation. A claim
belongs here only when it has an exact statement, an explicit scope, at least
one Lean theorem, a concrete runtime path, an executable test, and written
limitations. TLA+ coverage is optional because inventing a state-machine link
would be weaker than recording the gap.

## Run the traceability check

From the monorepo root:

```sh
python assurance/verify.py --root runtime
```

For machine-readable output:

```sh
python assurance/verify.py --root runtime --json
```

The command is cross-platform, requires Python 3.10 or newer, performs no
network access, and has no third-party runtime dependency. Exit status `0`
means every declared link was found. Exit status `1` means the manifest could
not be loaded or at least one link is stale.

`claims.yaml` uses the JSON subset of YAML 1.2. This is intentional: the Python
standard library can parse it deterministically, duplicate keys are rejected,
and normal JSON and YAML tools can both consume it.

## What the linter verifies

The linter fails when:

- the manifest contains an unknown or duplicate field;
- a repository path is absolute, non-canonical, escapes the repository, has
  the wrong extension, or does not exist;
- a referenced Lean theorem or lemma is not declared in the named file;
- a referenced TLA+ operator is missing from the model;
- a TLA+ invariant exists but is not selected by the named TLC configuration;
- a Rust test name is absent or is not attached to a recognized test
  attribute;
- a source-contract version has moved while the manifest or its reviewed
  documents still use stale wording.

The last check currently pins audit v6 to
`SESSION_AUDIT_PAGE_SCHEMA_VERSION`. If the runtime advances the constant, both
the manifest expectation and any versioned wording must be updated in the same
change.

## What a passing report means

A passing report establishes traceability at the checked revision:

- the abstract theorem names exist;
- the named bounded invariants are configured for model checking;
- the implementation files exist;
- the named implementation tests exist;
- explicitly versioned documentation matches the source constant.

It prevents a renamed theorem, removed test, moved implementation, unconfigured
invariant, or stale contract version from leaving a green documentation-only
claim.

## What a passing report does not mean

A passing report does **not** establish any of the following:

- that Lean, TLC, or Cargo tests were executed by the linter;
- that the Lean definitions refine the Rust implementation;
- that a TLA+ transition refines a SQL transaction or distributed execution;
- that bounded model checking proves an invariant for an unbounded system;
- that cryptographic libraries, clocks, operating systems, databases, cloud
  services, model providers, or network observations are correct;
- that the application is formally verified end to end;
- that a semantic evidence provider correctly understands arbitrary natural
  language;
- that passing tests eliminate undiscovered defects.

The strongest accurate release wording is:

> AccordLock includes machine-checked proofs of selected properties of its
> abstract authorization model, bounded state-machine models, and an executable
> traceability manifest linking those claims to implementation tests.

Do not shorten this to “formally verified” or “proved safe.”

## Required CI layers

The linter is the first assurance gate, not the complete assurance run. A
release workflow should execute these layers separately and retain their logs:

```sh
python assurance/verify.py --root runtime --json
python -m unittest discover -s assurance/tests -t assurance -v
```

Then run the repository's pinned Lean build, configured TLC runners, Rust test
suites, benchmark suite, and publication checks. Each report must be tied to
the exact source commit. A skipped tool is not a passing tool.

## Updating a claim

1. State one externally meaningful property without implementation marketing.
2. Keep the scope smaller than the evidence.
3. Link only theorem and invariant names that say something material about the
   property.
4. Link the narrowest runtime files that own the boundary.
5. Link adversarial or concurrency tests, not only happy-path tests.
6. Record assumptions and gaps in `limitations`.
7. Run the linter and the underlying proof, model-checking, and test tools.

Do not add unpublished research manuscripts, personal notes, generated build
outputs, credentials, user data, or local test databases to this directory.
