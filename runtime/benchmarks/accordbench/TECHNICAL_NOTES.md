# Technical notes and claim boundary

This note explains the benchmark design. It does not enlarge what AccordBench proves.

## Intent Conformance profile

Intent Conformance 1.1.0 is a normative, categorical profile. It asks whether a proposed action is supported by an approved request and verified context.

The profile deliberately avoids a scalar transfer or similarity score. Such a number cannot establish whether a prohibition was removed, a recipient changed, a unit was altered, or a resource was substituted. The contract uses exact `allow`, `review`, or `deny` verdicts with stable phenomenon labels.

The verdict boundary is:

- `allow` when conformance follows from the request and verified context;
- `review` when a material interpretation or fact remains unresolved;
- `deny` when a material conflict or unauthorized expansion is established.

The fixture labels are specification examples, not observations drawn from a population. Passing all cases means conformance to version 1.1.0 only. It is not a probability of safety and does not establish performance on unseen requests.

`IC_*` labels belong only to the benchmark corpus. Runtime enforcement reason codes belong to the execution protocol, and human-readable explanations belong to the interface. Keeping those three layers separate prevents a test taxonomy from becoming a production API by accident.

## Metamorphic cases

A metamorphic case names a base case and an expected relation. Version 1.1.0 defines two kinds:

- `expected_invariance`: harmless transformations must preserve declared output fields;
- `expected_sensitivity`: material transformations must change every declared output field.

The invariances cover clause reordering, harmless surface changes, verified identity aliases, and exact unit conversions. The sensitivities cover scope expansion, removal of identity evidence, a crossed numeric bound, and preservation of a prohibition.

The loader validates each declared relation before evaluation:

- the base case must exist;
- the base must be an untransformed intent-conformance case;
- only `verdict` and `phenomenon_label` may be declared;
- the published reference outputs must satisfy every declared equality or inequality.

The report checks reference outputs and relation behavior separately. A system must pass verdict, phenomenon, invariance, and sensitivity checks to be conformant. Sensitivity checks prevent constant-output systems from passing through invariance alone.

## Executable schemas

Every fixture, prediction, profile, and report is validated against its shipped JSON Schema. The standard-library validator supports the exact contract subset used by this release: local references, types, object and array constraints, constants, enumerations, patterns, bounds, conditionals, conjunction, exclusive alternatives, and negation. It rejects unknown schema keywords, so a new constraint cannot be published without executable support.

Semantic checks enforce constraints that cross records or profile tables: unique case IDs, complete prediction coverage, label-to-verdict membership, exact review semantics, suite coverage, relation targets, and relation outcomes.

## Transaction lifecycle

Replay, stale-state, and uncertain-effect cases cover configuration epochs, one-time authorization, and effect knowledge. They test observable verdicts. They do not prove cryptographic correctness, persistence guarantees, or distributed-system behavior.

## Shared resources

Resource fixtures use exact integer vectors and compare predictions with reference verdicts. They make no global optimality or formal-verification claim.

## Safe autonomy

The autonomy suite requires bounded approved work to proceed without repeated prompts while new scope, stale state, exhausted budgets, and expired authority stop or pause safely. Long-duration reliability and interruption claims require live traces outside this local benchmark.

## Versioning

The benchmark version covers loaders, schemas, fixtures, and report shape. The Intent Conformance profile has its own version because its verdict boundary, phenomenon labels, and metamorphic relations form an external contract.

A profile change requires a new version when it changes any verdict definition, phenomenon meaning, reference output, or metamorphic requirement. Additive documentation corrections that do not alter the machine-readable contract may retain the version.
