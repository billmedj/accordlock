# `accordlock-eks-profile`

This crate defines the single immutable route profile that the EKS credential
broker, TLS transport, executor, dispatch import, and admission boundary must
share. Its job is to turn endpoint/profile drift into an explicit, fail-closed
mismatch before a Secret is created or a provider request is sent.

## Bound facts

`EksRouteProfile` commits to all of these fields, in a fixed tagged order under
the `accordlock:v1:eks-route-profile\0` domain:

1. cluster trust domain;
2. cluster identity;
3. authenticated API-server identity;
4. canonical DNS/SNI server name;
5. explicit port;
6. one explicit canonical IP socket target and its port;
7. the SHA-256 commitment to the exact CA trust set;
8. namespace;
9. Deployment name and immutable UID;
10. attempt ServiceAccount name and immutable UID; and
11. exact token audience.

All strings must already be canonical. Constructors do not trim, lowercase,
resolve, or otherwise normalize caller input. DNS aliases (case changes,
trailing dots, IP literals), path aliases (`.`/`..`, percent encoding),
non-canonical Kubernetes names/UUIDs, implicit/ambiguous socket spellings, and
unsafe socket classes are rejected.

The CA helper sorts the certificate byte strings, rejects duplicates, and
commits to the set under the separate `accordlock:v1:eks-ca-trust-set\0` domain.
It does not parse X.509: the TLS transport must build its root store from the
same exact byte strings.

## Integration contract

- Build the profile once from authenticated bootstrap/control-plane data.
- Pass the same profile (or its durable commitment plus revalidated full
  fields) to broker, transport, executor, and admission configuration.
- When both full profiles are available, require `exactly_matches`; use the
  commitment for authenticated persistence and cross-process comparison.
- Compare `cluster_trust_domain`, `api_server_identity`, `namespace`, and
  `deployment_uid` to dispatch `PhysicalResourceId`.
- Compare `cluster_identity`, `namespace`, `deployment_name`,
  `deployment_uid`, and `token_audience` to the signed Deployment template.
- Compare API-server identity, DNS/SNI name, port, socket target, and CA
  commitment to the native broker/transport destination.
- Compare namespace, ServiceAccount name/UID, and audience to `TokenRequest`,
  JWT, and `TokenReview` facts. Exact per-token credential/AUTHORIZATION_ID binding is a
  separate mandatory check; it is intentionally not a static route field.
- Recheck the route commitment immediately before Secret create, token issue,
  provider send, admission authorization, and Secret deletion.

`first_mismatch` returns one of the 13 exact `RouteField` variants for a
non-secret diagnostic. `Debug` for the profile, socket target, CA commitment,
and route commitment is redacted.

## What this does not prove

This value proves only canonical construction and exact equality of the facts
it contains. It does **not** prove that:

- the profile is activated by the current control plane;
- an AWS account/region/cluster name exists or is owned by the tenant;
- the cluster identity maps injectively to one physical Kubernetes API server;
- the DNS name resolves to the pinned address or that the address belongs to
  that cluster;
- the committed CA bytes are valid X.509 roots, authenticate the DNS name, or
  are the bytes actually loaded by TLS; or
- Kubernetes admission completely mediates every mutation path.

Those are external registry, AWS attestation, TLS-handshake, network, and
deployment invariants. Production must establish them independently and bind
their authenticated outputs into this profile.
