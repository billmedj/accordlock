# AccordLock approval channels

This crate defines the security boundary between AccordLock and external
notification channels. It supports Slack, Microsoft Teams, Telegram, and
WhatsApp payloads without treating any messaging platform as execution
authority.

For interactive approval, the control plane signs a short-lived challenge
bound to the exact task, policy decision, action, recipient, channel, and safe
display content. That message carries only an opaque interaction token. A
response is accepted only after the trusted channel transport has authenticated
the external actor, AccordLock has mapped that actor to an active approver
enrollment, the signed challenge and token match, and a replay store consumes
the challenge once.

For outbound notification without an inbound callback service,
`build_review_notification_delivery` emits fixed display-only copy that directs
the recipient to the latest local Approval Center status. The copy does not
claim that an approval is still pending, so a provider-accepted message remains
accurate if the local decision wins a race with delivery. These payloads contain no button,
callback token, review URL, protected action content, path, or command, and the
transport accepts only their exact provider-specific shapes.

AccordLock Desktop uses that display-only builder through a separate verified
runtime process. Its encrypted outbox stores the fixed provider payload,
destination, expiry-bound credential reference, and deterministic
approval/channel idempotency key. It never stores a provider credential. The
worker rechecks the queued shape and local expiry before credential resolution
and network I/O.

The verified remote decision is still not an execution authorization. The
trusted approval plane must apply policy and, when appropriate, create the
existing action-specific approval proof. A delivery receipt, button click, or
message body can never grant access by itself.

## Included

- signed, expiring, recipient-bound approval challenges;
- opaque 256-bit interaction tokens suitable for channel callback limits;
- Slack HMAC-SHA256 verification with a five-minute signed timestamp window;
- Meta `X-Hub-Signature-256` verification over exact WhatsApp request bytes;
- constant-time Telegram webhook-secret verification;
- exact Teams tenant, user, audience, and lifetime checks over claims supplied
  by an injected cryptographic OIDC verifier;
- duplicate-key and multi-event rejection for the supported inbound payloads;
- authenticated-actor and enrollment checks;
- framework-neutral inbound adapters that authenticate and parse the exact
  Slack, Teams, Telegram, and WhatsApp callback shapes emitted by this crate;
- a dedicated SQLite callback registry that resolves opaque tokens by digest,
  persists only signed challenges and approver bindings, serializes revocation
  against consumption, and never stores the bearer token;
- single-use replay-store contract, an in-memory implementation for tests, and
  a durable SQLite implementation for one host;
- a provider-neutral, encrypted SQLite delivery outbox with atomic leases,
  bounded retries, idempotent delivery acknowledgement, dead-letter state, and
  bounded retention cleanup;
- minimal interactive and display-only notification payload builders for
  Slack, Teams, Telegram, and WhatsApp;
- a fixed-copy connection-test payload for each channel, dispatched once
  without retry or approval semantics;
- strict outbound request adapters for Slack Web API, Telegram Bot API,
  WhatsApp Cloud API, and the commercial Teams Bot Framework service;
- fixed HTTPS authorities, an exact validated Teams conversation service URL,
  bounded
  request/response sizes and timeouts, and provider-specific receipt parsing;
- a native rustls/WebPKI HTTPS client plus an injectable transport boundary,
  both with explicit not-sent versus possibly-sent failure classification;
- a bounded one-step worker that resolves credentials ephemerally, dispatches
  display-only notifications once, and settles each encrypted job
  transactionally;
- safe defaults that omit action content, paths, commands, and credentials.

## Outbound request boundary

`prepare_channel_delivery` converts a builder-produced `ChannelDelivery` into one exact
HTTPS `POST` request. It rejects channel, destination, payload, body-hash, and
credential substitution. Slack, WhatsApp, and Teams credentials are placed in
redacted authorization headers. Telegram's validated bot token is placed in a
redacted fixed-authority URL, as required by its API. Credentials and prepared
request data use zeroizing in-memory allocations and cannot be serialized or
printed through `Debug`.

`dispatch_channel_delivery` calls an injected `BoundedHttpsTransport` exactly
once. It does not retry. It accepts a delivery only when the provider-specific
response contains a receipt identifier. Rate limits produce a bounded retry
delay. Timeouts and failures after bytes may have been sent remain ambiguous,
which prevents an unsafe blind retry. Response bodies are bounded and reduced
to a digest and byte count for audit output.

`WebPkiHttpsTransport` is the native public-provider implementation. It uses
rustls with the static Mozilla WebPKI root set, TLS 1.2 or 1.3, SNI, and exact
HTTP/1.1 ALPN. It opens a fresh direct TCP/TLS connection for each attempt,
uses no proxy, sends no early data, keeps no session cache, follows no
redirect, retries nothing, requests no response compression, rejects private
or special-use DNS results, and accepts only the authority already fixed for
the selected channel. DNS concurrency, resolution results, total request time,
response headers, and decoded response bodies are bounded. HTTP framing is
accepted only as one unambiguous Content-Length or strict chunked encoding.

Failures through DNS, TCP connect, socket configuration, TLS authentication,
and ALPN occur before any HTTP request byte is emitted and are reported as
`NotSent`. Immediately before the first HTTP write, classification changes to
`MayHaveBeenSent`; every write, flush, timeout, response-read, framing, or size
failure after that point remains ambiguous. Provider credentials must be
loaded from host secure storage immediately before dispatch. The encrypted
outbox retains only an opaque secure-store reference; the transport layer never
writes a provider credential to disk. The Teams adapter accepts only the
public Bot Framework authority and requires the exact `serviceUrl` from an
authenticated conversation reference.

## Inbound callback boundary

`DurableRemoteApprovalGateway` closes the local interactive-response path
without adding an HTTP framework to the trusted computing base. The host maps
its HTTPS route to one of `process_slack_callback`,
`process_telegram_callback`, `process_whatsapp_callback`, or
`process_teams_callback` and supplies the exact raw body and provider
authentication fields. Parsing happens only after provider authentication.

Each adapter accepts one callback value in the exact shape produced by the
interactive payload builder. The gateway hashes the opaque 256-bit token,
loads the signed challenge and approver enrollment from its dedicated SQLite
database, verifies signature, freshness, channel, tenant, recipient, actor,
decision scope, and token binding, then atomically changes the challenge from
`ACTIVE` to `CONSUMED`. Revocation uses the same immediate-transaction
boundary. A callback that loses the race to revocation is refused. Restart
does not restore a consumed or revoked challenge, and a provider event cannot
be reused for another challenge.

The registry is durable against normal restart and concurrent local access; it
does not claim rollback resistance against an administrator who can replace or
restore the database and its WAL files. A deployment that includes that threat
must protect the directory and anchor lifecycle state in an external monotonic
checkpoint. `prune_expired` accepts trusted monotonic time and deletes a record
only after its signed acceptance window has closed.

Teams remains an explicit cryptographic-verifier boundary: the host must
validate the Microsoft token, issuer, algorithm, signing key, and audience
before implementing `CryptographicallyVerifiedTeamsClaims`. The adapter then
requires the Activity tenant and actor to repeat those verified claims and
uses the Activity ID, not the token ID, as the replay event.

`VerifiedRemoteDecision` is evidence only. It has no constructor exposed to
untrusted callers and contains no execution credential. The control plane must
still apply current policy and create the existing action-specific approval
proof, if appropriate.

### Trusted outbound runtime integration

The native worker path has five explicit inputs and must run only in the
trusted main process or enterprise runner:

The durable worker currently accepts only the exact display-only notification
shapes produced by `build_review_notification_delivery`. It does not infer an
interactive capability from queued JSON. The callback gateway now durably
binds inbound interactive responses, but interactive outbound payloads are not
yet admitted to the encrypted delivery outbox.

1. Open `DeliveryOutbox` with its OS-protected 32-byte key.
2. Implement `DeliveryMaterialResolver` so the opaque
   `credential_reference()` selects a secret in the OS credential store. The
   resolver returns `ResolvedDeliveryMaterial::new(endpoint, credential)` and
   must never expose either value to renderer IPC.
3. Implement `TrustedTimeSource` with the host's monotonic wall-clock policy.
4. Construct `WebPkiHttpsTransport::new()` once for the worker.
5. Call `process_exact_delivery(job_id, &mut outbox, config, &mut clock, &mut
   resolver, &mut transport)` when handling an approval-bound wake-up. This
   path never falls through to another ready job. The broader
   `process_one_delivery` API is reserved for a trusted general worker.
   Schedule another step only from trusted worker state; never loop inside a
   renderer request.

The endpoint and credential shapes are closed:

| Channel | Endpoint configuration | Credential constructor | Destination |
| --- | --- | --- | --- |
| Slack | `DeliveryEndpointConfig::slack()`; fixed `https://slack.com/api/chat.postMessage` | `DeliveryCredential::slack(token)`; printable bearer value, 16–4096 bytes | uppercase Slack conversation ID beginning with `C`, `D`, `G`, or `U` |
| Telegram | `DeliveryEndpointConfig::telegram()`; fixed `https://api.telegram.org` | `DeliveryCredential::telegram("<numeric-bot-id>:<token>")` | signed decimal chat ID |
| WhatsApp Cloud | `DeliveryEndpointConfig::whatsapp_cloud("v<major>.<minor>", "<phone-number-id>")`; fixed `https://graph.facebook.com` | `DeliveryCredential::whatsapp_cloud(token)`; printable bearer value, 16–4096 bytes | decimal E.164 recipient without `+` |
| Microsoft Teams | `DeliveryEndpointConfig::teams_bot_public(authenticated_service_url)`; exact `https://smba.trafficmanager.net/<path>/` | `DeliveryCredential::teams_bot(token)`; printable Bot Framework bearer value, 16–4096 bytes | validated conversation ID encoded as one path segment |

Desktop configuration should persist only channel enablement, non-secret
routing metadata, and an opaque credential-store locator. Account setup,
credential entry, callback enrollment, and token refresh remain separate host
responsibilities. The renderer may request configuration changes, but the
trusted process must validate and commit them; it must never return credential
bytes, prepared URLs, raw provider responses, lease tokens, or outbox keys.

The desktop local-evaluation adapter enrolls one Ed25519 gateway public key and
imports a bounded, gateway-signed decision receipt through a native file
picker. The receipt repeats the fields of `VerifiedRemoteDecision` and commits
the exact desktop Approval Center binding. This is a private integration
contract, not a substitute for the provider-authentication gateway above. The
desktop never accepts provider callback bytes from renderer IPC.

## Local delivery outbox

`DeliveryOutbox` stores pending Slack, Teams, Telegram, and WhatsApp deliveries
for one local host. Destination, provider payload, secure-store reference, and
idempotency input are never stored in plaintext. Provider credentials are not
stored at all. AES-256-GCM authentication binds each encrypted envelope to its
schema, job, channel, destination hash, idempotency hash, and request hash. The
stored hashes are keyed, so predictable destinations and idempotency values
cannot be tested offline without the local key. A separately derived HMAC
authenticates the complete lifecycle state, including attempts, leases,
completion, terminal reason, attempt-summary digest, and timestamps. SQLite
uses `STRICT` tables, WAL mode, and immediate transactions for enqueue, claim,
acknowledgement, retry, dead-letter, and prune operations.

The trusted host supplies the database path, a 32-byte key loaded from
OS-backed secure storage, and trusted time. A worker receives an opaque lease
token when it claims a delivery. The token can acknowledge or retry only that
active lease. An expired in-flight lease is moved to authenticated dead-letter
state and is never reclaimed for automatic delivery. Attempt counts, lease
duration, retry delay, record size, database capacity, and prune batches are
bounded.

The worker retries only an explicit rate limit or a transport failure proven
to have occurred before request bytes were sent. A timeout, possibly-sent
failure, malformed receipt, permanent rejection, exhausted retry budget, or
expired lease becomes dead-letter and requires manual reconciliation. This
avoids blind duplicate notifications at the cost of automatic delivery
liveness after a crash. Dead-letter reason codes and secret-free attempt
summary digests survive restart and are covered by the lifecycle HMAC.
Provider-side idempotency is not claimed. Authentication detects field
substitution and corruption, but it cannot detect deletion or replacement
with a previously valid row or database snapshot unless the host maintains a
monotonic external checkpoint.

This is a local outbox with a live outbound transport; it does not configure
accounts, OAuth, webhooks, provider applications, phone numbers, tenants, bot
permissions, or public callback routing. It does not provide distributed
leasing across separate hosts. The host must keep the database path outside
renderer control and must not expose the encryption key or lease token through
logs or untrusted IPC.

## Not included

- bundled provider credentials, account provisioning, HTTP server, public
  callback route, TLS termination, or denial-of-service controls;
- provider account setup, OAuth flows, or external service configuration;
- Microsoft Entra discovery, JWT parsing, signature verification, key refresh,
  or issuer policy; the Teams adapter accepts only claims produced by a trusted
  verifier supplied by the host application;
- identity-provider enrollment or SSO;
- a distributed replay database for multiple control-plane hosts;
- a distributed delivery outbox for multiple hosts;
- an execution or authorization endpoint.

Those responsibilities belong to trusted channel transports and the
AccordLock control plane. The in-memory replay store is for one-process local
evaluation only. Meta and Telegram do not provide a signed request timestamp
at this boundary. Their freshness guarantee therefore comes from the signed,
short-lived AccordLock challenge, plus atomic consumption of the authenticated
provider event ID. Slack applies both that mechanism and its signed timestamp
window.
