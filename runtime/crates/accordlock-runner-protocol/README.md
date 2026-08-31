# AccordLock execution-worker protocol

**Wire schema:** version 3

This crate defines the bounded, credential-free records exchanged between the
AccordLock control plane and an execution worker. It deliberately contains no
GitHub token, AWS key, Kubernetes bearer, kubeconfig, or generic command string.

The protocol binds one worker registration and one environment profile to an
exact, short-lived dispatch. A dispatch can either observe the fixed
GitHub/ECR/EKS evidence chain or deploy one immutable image digest to the exact
Kubernetes object state named by UID and `resourceVersion`.

Each dispatch also commits the immutable task, principal, policy evaluation,
resource reservation, optional action approval, and single-use execution authorization.
The action commitment includes the container index and the complete prior
Kubernetes annotation/state tuple, so a controller update or target
substitution changes the dispatch identity. A deployment action also carries
the non-nil transaction identifier created by single-use consumption. That
identifier is inside the policy, approval, and dispatch commitments; it is not
a free parameter added later by the Kubernetes adapter. Production bounded autonomy is
representable only with a separate approval commitment in the environment
profile.

The execution worker must resolve credentials from its own trusted configuration after
validating the dispatch. The model, desktop renderer, and serialized protocol
records never receive those credentials.

This crate is a transport contract, not a network service and not execution
authority by itself. Productive execution still requires AccordLock's consumed
single-use authorization, durable dispatch state, credential broker, provider-specific
postcondition checks, and a signed or otherwise authenticated execution record channel.
