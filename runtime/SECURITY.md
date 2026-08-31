# AccordLock security policy

Security reports are welcome and should be handled privately. Thank you for
helping protect users and the project.

## Supported versions

AccordLock is currently a technical preview. Security fixes are applied to the
latest published pre-release and the default development branch at maintainer
discretion. Older snapshots and forks are not supported unless their maintainers
state otherwise.

| Version | Security updates |
| --- | --- |
| Latest pre-release | Best effort |
| Default branch | Best effort |
| Older versions | No |

The current preview has not received an independent security audit. Use it only
in isolated, non-production environments unless a later release explicitly
states a broader supported scope.

## Reporting a vulnerability

Use **Security → Report a vulnerability** in the official GitHub repository to
open a private vulnerability report. Before public launch, repository owners
must enable GitHub private vulnerability reporting.

If that option is unavailable, open a minimal public issue titled "Private
security contact requested." Include no vulnerability details, credentials,
customer information, logs, or exploit material. A maintainer will establish a
private channel.

Please include when available:

- the affected version, tag, or full commit hash;
- the affected component and deployment assumptions;
- a clear impact statement and realistic attack preconditions;
- minimal reproduction steps or a proof of concept using synthetic data;
- whether the issue is already public or known to another project; and
- a safe way to contact you privately.

Never test against systems or data you do not own or have explicit permission to
assess.

## What to expect

The project aims to acknowledge a complete report within three business days,
provide an initial triage within seven business days, and send weekly updates
while remediation is active. These are best-effort targets, not a service-level
agreement.

Maintainers will coordinate validation, severity, remediation, release timing,
credit, and disclosure with the reporter. Complex or disputed findings may take
longer. Please allow a reasonable remediation period before disclosure and tell
us if you have a fixed disclosure deadline.

## Scope priorities

High-priority reports include vulnerabilities involving:

- signature, canonical-encoding, identity, or audience verification;
- authorization bypass or authority-state rollback;
- replay, double consumption, or cross-target authorization confusion;
- credential, key, token, or sensitive-evidence exposure;
- dispatch or Kubernetes enforcement bypass;
- durable-state corruption that can authorize an unintended effect; and
- build, release, dependency, or CI supply-chain compromise.

Documentation corrections, hardening ideas without an exploitable condition,
and findings that require a user to deliberately disable documented controls may
be handled as ordinary issues.

## Coordinated disclosure and credit

The project will credit reporters who request it and will not publish personal
details without consent. Advisories will distinguish confirmed impact from
hypotheses and identify affected and fixed versions whenever possible.

## Safe-harbor intent

The project supports good-faith security research that follows this policy,
avoids privacy violations and service disruption, uses only authorized systems,
and gives maintainers a reasonable opportunity to remediate. The project will
not recommend legal action solely for accidental, good-faith violations that are
promptly reported and corrected. This statement does not authorize testing of
third-party systems and cannot bind third parties.
