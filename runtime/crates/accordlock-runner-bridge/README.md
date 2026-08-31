# accordlock-runner-bridge

This crate is the narrow bridge between credential-free desktop/control-plane
orders and the existing trusted AccordLock connector and EKS execution stack.

It has two deliberately small responsibilities:

1. turn an enrolled `OBSERVE_SUPPLY_CHAIN` dispatch into the lookup-only input
   accepted by `accordlock-connectors`;
2. reconstruct the exact EKS deployment template from an enrolled dispatch and
   prove that it is byte-for-byte committed by the already-issued single-use
   AccordLock action authorization. The resulting `PreparedDeployment` retains
   the state-created transaction identifier already committed by the exact
   deployment action; a later request builder cannot substitute it.

Both paths require the complete canonical policy evaluation `PolicyDecisionRecord`.
The bridge checks its digest, task, action, policy epoch and resource
reservation against the execution-worker dispatch before doing either conversion. A
`BLOCK` decision is terminal. An approval decision needs an exact signed action approval;
`OBSERVE`, `PREPARE_AND_ASK` and `BOUNDED_AUTOMATIC` are enforced as distinct
profiles. Conformance metrics therefore cannot create authority or downgrade a
pre-existing policy decision.

It never loads GitHub, AWS, ECR or Kubernetes credentials. Those remain in the
configured connector adapters and the outbound execution worker or EKS broker.
The bridge is pure and deterministic, so substitutions are rejected before an
external action reaches a credential-bearing process.
