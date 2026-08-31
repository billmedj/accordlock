# AccordLock deployment evidence action

This dependency-free JavaScript action creates the two signed provenance records
consumed by an AccordLock deployment preflight. It binds one GitHub Actions run
and commit to one immutable ECR image digest. It performs no network requests and
does not deploy anything.

This integration is an early release. Treat the authority setup, workflow
protection, and evidence transfer as security-sensitive deployment controls.

## 1. Create the environment authorities once

Run this command locally with Node.js 24 or later. `--show-secrets` is required so
private material cannot be printed accidentally.

```text
node src/setup-authorities.mjs --environment-id 29caac27-a7e7-4c22-9c8e-d5fbc80c6f42 --show-secrets
```

The command writes one JSON object to standard output and does not create files.
Copy the two values under `github_secrets` directly into protected GitHub
environment secrets:

- `ACCORDLOCK_BUILD_AUTHORITY_SEED`
- `ACCORDLOCK_ARTIFACT_AUTHORITY_SEED`

Retain the two public fingerprints under `enrollment` through an approved
administrator channel. On the first evidence import, AccordLock displays those
fingerprints before pinning the authorities. Do not save, upload, commit, paste
into chat, or attach the private seeds to a ticket. Close the terminal or clear
its retained output after the secrets and public fingerprints have been stored
in their intended systems.

Use separate authority pairs for every AccordLock environment. Rotation creates
a new trusted enrollment and invalidates evidence signed only by the old keys.

## 2. Protect the workflow

Store both seeds in a protected GitHub Environment used only by the release job.
Restrict who can modify the workflow and who can approve access to that
environment. The two secrets are deliberately separate. Do not reuse either seed
for image signing, source signing, or another environment.

The action needs no GitHub API permission. The surrounding build will usually
need `contents: read` to check out the exact commit:

```yaml
permissions:
  contents: read

jobs:
  release:
    environment: production
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@<pinned-commit-sha>

      # Build, publish, and verify the immutable artifact before this step.
      - id: accordlock-evidence
        uses: ./integrations/github-actions/deployment-preflight-evidence
        with:
          environment-id: 29caac27-a7e7-4c22-9c8e-d5fbc80c6f42
          workflow-ref: .github/workflows/release.yml
          ecr-registry-id: "123456789012"
          ecr-region: eu-west-1
          ecr-repository: payments/api
          image-digest: ${{ steps.publish.outputs.image-digest }}
          input-manifest-root: ${{ steps.manifest.outputs.sha256 }}
          artifact-signature-valid: ${{ steps.verify.outputs.signature-valid }}
          artifact-quarantined: ${{ steps.quarantine.outputs.quarantined }}
          build-authority-seed: ${{ secrets.ACCORDLOCK_BUILD_AUTHORITY_SEED }}
          artifact-authority-seed: ${{ secrets.ACCORDLOCK_ARTIFACT_AUTHORITY_SEED }}
```

When this directory is used from a separate repository, reference a reviewed,
immutable commit of the repository that publishes the action. Never use a moving
branch or tag for a release authority.

The step creates exactly one JSON package at the workspace root. Its path and
digest are available as `evidence-path` and `evidence-sha256`. A later,
separately pinned upload step may transport that file to the administrator.
In AccordLock, use **Add build proof** for the first package and **Import build
proof…** for later runs.

The first import is a trust-on-first-use event. Compare both fingerprints in
the native confirmation with the public setup record before accepting them.
AccordLock then pins the keys and rejects silent replacement. The package's
signatures detect record tampering; without that independent comparison, a
complete package-and-key substitution cannot establish the original authority's
identity.

## What is signed

The build record binds the repository, workflow path, Actions run ID, commit,
input-manifest commitment, image digest, and validity window. The artifact record
binds the same run and commit to the ECR account, region, repository, image
digest, signature-verification result, quarantine result, and validity window.

Both records use Ed25519 over the exact domain-separated hash expected by the
AccordLock Rust verifier. Unknown fields, noncanonical encodings, zero digests,
cross-environment keys, route changes, expired records, and altered signed fields
are rejected.

The action attests to the results supplied by the protected workflow. It does not
replace the build system, image-signature verifier, quarantine service, GitHub
Environment review, or out-of-band administrator enrollment.

## Local verification

```text
npm test
```

The test suite uses only Node.js built-ins and covers deterministic signature
vectors, tampering, route and environment substitution, expiry, secret-log
absence, and the GitHub Actions boundary.
