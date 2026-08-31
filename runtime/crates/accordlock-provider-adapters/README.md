# AccordLock provider adapters

This crate is the small, read-only bridge between enterprise providers and
`accordlock-connectors`.

It provides concrete source adapters for:

- GitHub pull-request decisions;
- GitHub Actions build attestations;
- AWS ECR digest-bound artifact observations;
- Kubernetes/EKS Deployment target observations.

## Security boundary

The crate does **not** contain an HTTP client, an AWS SDK, a shell fallback or
credentials. Production runners inject the three authenticated transport
traits. Those transports own TLS roots and sessions, GitHub tokens, AWS
credentials and SigV4 intermediates, and Kubernetes bearer tokens or client
certificates. Transport errors are categorical; response bodies are redacted
from `Debug`; request specs contain no headers or credential slots.

Each transport receives a typed request with a fixed authority, path, method,
operation and `DENY` redirect policy. The GitHub transport may need to combine
multiple authenticated provider reads to produce the minimal review/build
observation. In particular, GitHub's ordinary run object does not itself prove
the hermetic input root or output image digest. The transport must obtain the
workflow's authenticated attestation; the adapter does not invent either fact.
Likewise, ECR signature/quarantine facts must come from the runner's configured
AWS trust integration. This crate only validates the resulting strict
projection and binds it to the request.

No transport implementation is faked here. Unit tests use deterministic trait
doubles only to exercise the parsing and binding boundary.

## Why the request UUID is inside each lookup

The existing `ReviewSource::fetch`, `BuildSource::fetch`, `ArtifactSource::fetch`
and `TargetSource::fetch` traits receive only a lookup identifier. They do not
receive the enclosing request UUID. The canonical `al1/...` lookup forms embed
that UUID rather than guessing it or weakening request binding. Each strict
provider observation must repeat the same UUID, and the resulting snapshot
passes it to `accordlock-connectors` for its independent cross-source check.

ECR lookups accept only canonical `sha256:<lowercase-hex>` digests. There is no
tag constructor, and `tag/latest`-style lookups fail before transport.

The real ECR provider operation remains a SigV4-authenticated `POST /`. Its
connector snapshot uses a separate canonical logical evidence URI below
`/accordlock/ecr/`, binding registry, repository and immutable sha256 digest.
This keeps trusted source-route validation unambiguous without pretending that
the logical evidence URI was a second network request.

## Intentionally not included

- mutations of GitHub, AWS, ECR, EKS or Kubernetes;
- redirects or caller-selected hosts/routes/methods;
- raw provider errors or response logging;
- a general-purpose provider SDK;
- credential delivery to the model, desktop UI or serialized requests.
