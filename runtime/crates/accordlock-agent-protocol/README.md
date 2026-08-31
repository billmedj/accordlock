# accordlock-agent-protocol

Model- and harness-neutral protocol records for governing one exact agent tool
action. The profile binds the session, run, tool-call identity, workspace,
extension, tool, canonical argument hash, policy epoch, task policy, and
validity window all the way from request to decision, single-use authorization,
and execution record. Automatic decisions also bind the exact policy-decision
commitment and a sorted set of conformance-evaluation hashes. An automatic
`ALLOW` without that evidence is invalid.

This crate deliberately does not map agent tools to Kubernetes or EKS. It also
does not make an LLM authoritative: trusted policy enforcement issues the decision and
authorization, and a trusted executor atomically consumes that authorization immediately
before the action.

The included store is process-local and intended for deterministic tests and
single-process prototypes. Production deployments require a durable,
transactional implementation with the same single-use behavior.
