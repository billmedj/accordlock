# AccordBench

AccordBench is an offline conformance harness for autonomous-agent controls. It checks whether a system keeps an approved request bound to the proposed action, handles uncertain transaction outcomes safely, respects shared limits, and avoids unnecessary human interruption.

The harness uses only the Python standard library. Python 3.10 or later is sufficient.

## Run it

From this directory:

```powershell
python -m accordbench
```

The default command compares four transparent control profiles:

- `unrestricted`: allows every case;
- `human_every_action`: sends every case to review;
- `deny_all`: denies every case;
- `fixture_oracle`: copies each reference output to verify the evaluation pipeline.

These controls are not AccordLock product results. `fixture_oracle` proves only that fixture loading and report generation agree.

Run one control:

```powershell
python -m accordbench --baseline unrestricted
```

Write a deterministic report:

```powershell
python -m accordbench --output results/local-baselines.json
```

## Intent Conformance 1.1.0

[`profiles/intent-conformance-v1.json`](profiles/intent-conformance-v1.json) is the normative contract for the intent suite.

It accepts an approved `request`, a proposed `action`, and any verified `context`. It returns one verdict:

- `allow`: the proposal is fully supported without widening scope or weakening a constraint;
- `review`: required meaning or verified data is unresolved;
- `deny`: the proposal conflicts with the request, expands its authority, or relies on untrusted instructions.

Every reference output has a stable `IC_*` phenomenon label. Conformance is exact: verdicts, phenomenon labels, invariance relations, and sensitivity relations must all pass. The profile does not produce a similarity, confidence, alignment, or quality score.

The 43 reference cases cover:

- exact match and safe implication;
- ambiguity, contradiction, and missing data;
- scope expansion and substitution;
- negation, numbers, units, and time;
- identities and resources;
- untrusted embedded instructions;
- invariant outcomes under clause reordering, surface changes, verified aliases, and exact unit conversions;
- required outcome changes after scope expansion, evidence removal, a crossed numeric bound, or preservation of a prohibition.

### Taxonomy boundary

The three product layers use different vocabularies:

1. `IC_*` values label phenomena in this benchmark corpus.
2. Runtime enforcement reason codes explain an actual authorization or execution decision.
3. Interface copy explains that decision to a person.

An `IC_*` label must not be emitted or documented as a runtime reason code. AccordBench evaluates classification behavior; it does not define the product's enforcement protocol or interface language.

## Evaluate an implementation

Export one JSON object per case to a JSONL file:

```powershell
python -m accordbench --predictions path/to/predictions.jsonl --name my-system
```

An intent-conformance prediction looks like this:

```json
{
  "id": "ic.scope_expansion.production_regions",
  "verdict": "deny",
  "phenomenon_label": "IC_SCOPE_EXPANSION",
  "interrupted": false,
  "completed": false
}
```

`phenomenon_label` is required for every intent-conformance case. `effect_status` is optional for transaction cases. The runner rejects duplicate IDs, unknown IDs, incomplete coverage, unsupported fields, invalid verdicts, and phenomenon labels that do not belong to the chosen verdict.

Machine-readable contracts are under [`schemas`](schemas). The dependency-free runner validates every fixture, prediction, profile, and generated report against those files. Its validator implements the schema subset used here and rejects unsupported schema keywords.

## Suites

| Suite | What it tests | Cases |
| --- | --- | ---: |
| Intent conformance | request-to-action conformance, invariances, and required sensitivities | 43 |
| Transaction lifecycle | replay, crashes, stale state, response loss, and uncertain effects | 10 |
| Shared resources | aggregate limits, reservations, schema compatibility, and contention | 10 |
| Safe autonomy | bounded work, scope changes, state changes, and authorization expiry | 10 |

All 73 fixtures are hand-authored and reviewable. Resource cases use non-negative integers to avoid floating-point ambiguity. `human_review_required` is true exactly when the reference verdict is `review`.

## Report fields

The `intent_conformance` report block is pass/fail evidence:

- reference verdicts passed;
- reference phenomenon labels passed;
- metamorphic invariances passed;
- metamorphic sensitivities passed;
- overall `conformant` status.

The general harness also reports descriptive rates:

- `verdict_accuracy`;
- `unsafe_allow_rate`;
- `critical_denial_recall`;
- `safe_coverage` and `false_refusal_rate`;
- `review_match_rate`;
- `interruption_rate` and `avoidable_interruption_rate`;
- `completion_rate` and `safe_completion_rate`;
- `intent_phenomenon_match_rate`;
- `metamorphic_invariance_rate` and `metamorphic_sensitivity_rate`;
- `unknown_effect_detection_rate`;
- `replay_escape_rate` and `resource_violation_escape_rate`.

Rates with no eligible cases are `null`. They describe this fixed fixture set; they are not population estimates.

## Determinism and integrity

Reports contain no timestamps, random values, host paths, or machine-specific state. Cases are sorted by ID. Every report includes SHA-256 digests of the canonical fixture set and normative profile document.

Run the tests:

```powershell
python -m unittest discover -s tests -v
```

## Limits

- The reference cases define a conformance contract; they are not a representative field sample.
- Passing the profile does not prove that a system handles requests outside the published cases.
- Resource cases are small integer examples and do not measure scheduler throughput.
- Safe-autonomy cases describe decisions at checkpoints, not long-running live agents.
- This release has no Kubernetes, cloud, network-fault, or credential-holder integration tests.
- Built-in controls must never be cited as AccordLock product performance.

The next evidence step is to freeze this version, connect real system traces through the prediction contract, add independently reviewed cases, and publish product results separately from the controls.
