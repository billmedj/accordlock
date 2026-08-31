# Known strictness gaps exposed by conformance tests

This file records gaps without changing or bypassing production APIs.

1. `EvidencePayload`, `AttesterScope`, `AgentProposal`, `DeploymentTemplate`,
   `ExecutionAuthorization`, and the envelope structs reject unknown JSON fields. Executable
   tests cover the two internally tagged enums. This closes the parser defect found
   during the local audit, but does not constitute a schema freeze.
2. `principals` has set behavior, and canonical encoding now requires its JSON
   representation to be strictly sorted with no duplicates. Order-only changes
   and duplicate insertions are rejected rather than normalized silently. The
   conformance suite covers both cases.
3. These tests establish local signature binding and parser behavior only. They do
   not establish signer custody, complete mediation, credential confinement,
   provider execution, source freshness, or external adversarial validation.
