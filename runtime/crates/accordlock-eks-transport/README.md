# Native EKS transport

This crate is a synchronous HTTP/1.1-over-TLS implementation of
`accordlock_executor::NativeEksTransport` for the single
`DEPLOY_EKS_IMAGE_V1` executor profile.

It receives one complete `accordlock_eks_profile::EksRouteProfile` and derives all
destination facts from it. Caller-supplied DER roots are accepted only when
their order-independent CA-set commitment exactly equals the profile value.

It provides the following narrow properties:

- one profile-derived API-server DNS name, port, socket address, and logical
  `api_server_identity`;
- a rustls trust store containing only caller-supplied DER CA certificates;
- WebPKI certificate-chain and DNS-name verification, with SNI and an exact
  `http/1.1` ALPN requirement;
- a new TCP/TLS connection for each GET or PATCH;
- no proxy, redirect following, automatic authentication, or request retry;
- exact GET and JSON Patch request construction with bounded paths, bearer
  credentials, request bodies, response headers, and response bodies;
- conservative PATCH failure classification: after application-data emission
  begins, every transport or parsing failure is `OutcomeUnknown`;
- a one-shot executor authorization consumed after TLS authentication, ALPN,
  peer pinning, and request construction but immediately before the first HTTP
  byte; rejection closes the socket as `DefinitelyNotSent`;
- a channel commitment that binds the actual peer certificate chain,
  negotiated TLS version and cipher suite, ALPN, DNS name, connected socket,
  explicit CA bundle, and configured logical API-server identity.

The configured socket address is pinned. This crate does not perform DNS
resolution, consume proxy environment variables, or fail over to another IP.
The operator must resolve and update EKS endpoint addresses through a trusted
configuration workflow. Certificate DNS validation still applies to the
configured EKS endpoint name.

The bearer is borrowed from the executor and written directly into the TLS
plaintext stream. It is never formatted into an owned request buffer or
included in `Debug` or error output. rustls, the allocator, the operating
system, and the credential issuer can still retain copies outside what Rust
can prove. Credential custody remains a deployment invariant.

This implementation does not provide certificate revocation, CRL, or OCSP
checking. rustls/WebPKI validates the supplied trust anchors, certificate time,
DNS identity, signatures, and supported constraints. EKS endpoint and CA
rotation, DNS resolution, host-clock integrity, bearer issuance, process
isolation, and kernel/network integrity remain operational dependencies.

The unit suite exercises the HTTP codec, framing ambiguity rejection, bounds,
request validation, CA commitment substitution, secret redaction, and pre-send
failure classification. It does not claim a live EKS interoperability test or
independent security review.
