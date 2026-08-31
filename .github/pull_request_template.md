## Change

Describe the user-visible or engineering outcome.

## Boundary

State which authority, policy, evidence, transaction, credential, audit, recovery, or interface boundary changes. Write `None` when none changes.

## Evidence

List the exact commands run and their results. Mark every check that was not run.

- [ ] Root publication gate
- [ ] Relevant Rust tests
- [ ] Relevant desktop tests
- [ ] Assurance manifest
- [ ] Lean or TLA+ model, when affected
- [ ] External-system acceptance, when claimed

## Failure behavior

Explain what happens when required state, evidence, authority, connectivity, or capacity is missing or stale.

## Public surface

- [ ] Documentation and limitations match the implementation.
- [ ] Interface text is plain English and states the decision or next action.
- [ ] No credential, personal path, customer data, build output, or private research material is included.
- [ ] Licensing and upstream attribution remain correct.
