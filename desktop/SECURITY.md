# Security Policy

AccordLock is an AI agent distribution that can read files, invoke tools, start
approved programs, and make policy-controlled network requests. Treat every
enabled capability as access to the account and machine that run it.

## Report a vulnerability

Do not disclose a suspected vulnerability in a public issue, discussion, pull
request, log, or screenshot.

Use GitHub private vulnerability reporting:

1. Open this repository's **Security** tab.
2. Select **Report a vulnerability**.
3. Describe the affected version or commit, impact, prerequisites, and the
   smallest safe reproduction you can provide.
4. Remove credentials, personal data, and production data from every artifact.

Repository administrators should keep private vulnerability reporting enabled.
If it is unavailable, do not publish the details. A repository administrator
must enable a private reporting channel first.

Maintainers designated in the repository settings triage private reports. No
response or remediation deadline is promised until a report has been assessed.

## Safe use

- Use a dedicated account, virtual machine, or container with least privilege.
- Keep production credentials in a trusted execution worker, not in a model
  prompt, desktop session, workspace, or diagnostics archive.
- Review and constrain filesystem, terminal, extension, and network access.
- Treat repositories, web pages, tool output, and retrieved documents as
  untrusted input that may contain prompt-injection instructions.
- Review proposed external actions and the resulting audit record.
- Do not use a technical preview as a production control unless its release
  notes explicitly state that the relevant deployment profile is supported.

## Supported code

Security fixes target the actively maintained default branch and any release
explicitly identified as supported in its release notes. Older previews and
unreleased local builds may require an upgrade or clean installation.

## Coordinated disclosure

Allow maintainers reasonable time to validate and repair a confirmed issue
before publishing technical details. Credit is offered when requested and when
doing so does not compromise reporter confidentiality.
