# accordlock-ingress-state

This crate is the narrow production adapter between `accordlock-ingress` and the
durable replay ledger in `accordlock-state`. The exact configured audience is the
opaque replay scope. State failures, clock rollback, retry exhaustion, and
commit ambiguity all fail closed as replay-state unavailability.

The adapter does not authenticate requests by itself and is intentionally not
wired into the Kubernetes `AdmissionReview` webhook path.
