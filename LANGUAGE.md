# Public language standard

AccordLock public material uses controlled technical English. The objective is
consistent meaning, not formal compliance with ASD-STE100.

## Basic rules

- Use one term for one concept.
- Use active voice when the actor is known.
- Keep most sentences below 25 words.
- Put the condition before the result.
- State a limit in the same section as the capability.
- Use ASCII punctuation in source documentation.
- Remove slogans, filler, and claims that lack a named artifact or test.

## Claim subject

Name the subject of each material claim:

- **The desktop** describes a user interface or local workflow.
- **The runtime** describes an authorization, broker, or record operation.
- **This repository** describes the public source composition.
- **A deployment** describes behavior verified in a stated environment.

Do not use *AccordLock* as an ambiguous subject when only one component has the
property.

## Stable terms

| Term | Meaning |
| --- | --- |
| Approved task | The goal, scope, restrictions, and expiry accepted for one task |
| Proposed action | One normalized external action requested by an agent |
| Policy decision | `ALLOW`, `APPROVAL_REQUIRED`, or `DENY` |
| Approval | A human decision bound to one proposed action |
| Execution grant | A short-lived, single-use authority consumed before dispatch |
| Broker | A trusted component that performs one supported action class |
| Dispatch | The point at which a broker starts an external effect |
| Observed result | The outcome that the broker can establish |
| Unknown outcome | A dispatch whose result cannot yet be established |
| Reconciliation | A state check used to resolve an unknown outcome |
| Currentness | Evidence that relevant state still matches the decision |
| Complete mediation | Protected effects cannot bypass the runtime |

Use *single-use* for grant consumption. Do not use *exactly once* unless the
external system supplies that guarantee.

## Interface terms

Use **Approve** for a human decision and **Allow** for a policy decision.

- **Denied**: policy prohibits the action.
- **Approval required**: a reviewer can decide.
- **Failed**: dispatch returned a confirmed failure.
- **Unknown**: the runtime cannot confirm the result.
- **Not sent**: an evaluation stopped before external dispatch.

## Claim boundaries

- Say **engineering alpha**, not production-ready.
- Say **formal artifact**, not verified implementation, unless a refinement
  proof covers the executable code.
- Say **prompt-injection containment on mediated actions**, not immunity to
  prompt injection.
- Say **implemented locally** when tests and a local path exist.
- Say **live-validated** only when retained external evidence exists.
- Say **native Effect Transaction Protocol (ETP) mediation** only when ETP is
  the sole authority for protected dispatch. The public specification is at
  <https://github.com/billmedj/etp>.
- Say **supported recovery** for the implemented file path. Do not call it a
  universal rollback.

## Evidence

Each assurance claim must name at least one source path, deterministic test,
formal model, retained external result, or independent review. A fixture does
not establish customer performance, production reliability, or external
interoperability.

## Avoid

Do not use promotional superlatives, three-part slogans, rhetorical contrasts,
or claims such as *revolutionary*, *world-class*, *bulletproof*, *seamless*, or
*state of the art*. Do not present implementation detail as a user benefit.
