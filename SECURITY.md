# Security Policy

## Release status

AccordLock is an Engineering Alpha. There is no supported production release, public signed installer, or production security boundary at this time.

The default branch is available for review and local evaluation. Security fixes may change pre-1.0 protocols, schemas, state, or compatibility without a stable-release migration guarantee.

## Reporting a vulnerability

Use GitHub private vulnerability reporting for this repository when available:

1. open the repository's **Security** tab;
2. select **Advisories**; and
3. create a private report.

If private reporting is unavailable, do not publish exploit details in an issue or discussion. Use the maintainer contact in the repository metadata to request a private channel.

Include:

- affected commit, platform, and build mode;
- affected component and trust boundary;
- prerequisites and exact reproduction steps;
- observed and expected behavior;
- security impact, including the authority or data crossed;
- whether credentials, real infrastructure, or user data were involved; and
- a minimal proof of concept when safe to share.

Never include live credentials, private keys, customer data, or unredacted provider callbacks.

## High-priority findings

Reports are especially useful when they show:

- protected execution without a valid current authorization;
- approval or authorization replay;
- argument, target, task, plan, state, or policy substitution;
- renderer access to runtime secrets or credential material;
- an unbrokered path to a protected effect;
- filesystem escape from the approved workspace;
- process or network execution outside the configured boundary;
- remote-decision forgery or replay;
- audit modification, cross-workspace disclosure, or recovery without the original record;
- unsafe retry after an unknown outcome;
- resource-reservation bypass or concurrent protected effects; or
- a release or publication path that exposes secrets or unreviewed deployment authority.

## Scope notes

The current process broker is not an operating-system sandbox. A fully compromised host, trusted administrator, cluster control plane, or activated evidence source is outside the stated alpha guarantee. These limitations do not make a bypass in AccordLock's documented boundary unimportant; report any case where the implementation behaves more permissively than its public contract.

For a vulnerability inherited unchanged from Goose or another dependency, report it upstream as well when appropriate. If it affects an AccordLock security boundary, report it privately to AccordLock even if an upstream report already exists.

## Disclosure process

The project will validate reports against the affected snapshot, determine the claim and release impact, and coordinate disclosure after a fix or documented mitigation is available. Response timing is best-effort during the Engineering Alpha; this policy makes no production support commitment.

Security fixes should include a regression test and updates to the threat model, limitations, or public claim map when applicable.
