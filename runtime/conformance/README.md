# AccordLock synthetic conformance corpus

This directory contains strict JSON manifests for the first local differential and adversarial corpus for AccordLock Deploy Authorization.

## Status and evidentiary boundary

The corpus is synthetic. It is not an observed customer workflow, a benchmark result, a production security result, independent validation, or evidence that Gate G0 has passed. In particular, these manifests do not satisfy the requirement for three real discriminating cases from at least two organizations.

The expected results are test oracles for a proposed implementation. They do not state that the current Rust workspace already produces those results. A runner may report a scenario as passing only after it has executed the specified events and checked every expected state, count, reason code, resource projection, and forbidden output.

## Comparator discipline

The plain-policy comparator is deliberately stronger than an allow-all gateway. It authenticates the caller, defaults to deny, validates the typed deployment action, checks static resource constraints, and consumes independently retrieved status attributes. Its declared boundary is that it does not authenticate or retain the cross-object GitHub-to-build-to-artifact relation, does not bind mutable source versions into a single-use consumption protocol, and does not enforce the complete post-admission Kubernetes delta.

This is a property of the frozen comparator profile, not a limitation of Cedar, OPA, AuthZEN, or policy engines in general. If an enhanced baseline implements the missing relation, refresh, or admission control and rejects a differential case, the result must be recorded. The baseline must not be weakened to preserve an AccordLock advantage.

## Files

- `corpus.json` indexes the corpus and freezes corpus-wide rules.
- `common-fixture.json` defines the common identities, source facts, target state, authority state, clock, and comparator profile.
- `scenarios/DP-000.json` is the positive control.
- `scenarios/DP-101.json`, `DP-102.json`, and `DP-103.json` are the three primary differential cases.
- `scenarios/DP-101R.json`, `DP-102R.json`, and `DP-103R.json` are repaired twins.

All organization names, account numbers, identities, digests, timestamps, and
cluster coordinates are synthetic examples. They are not customer data or live
credentials.

## Execution contract

Every scenario must run in isolated fresh state. The baseline and AccordLock modes receive the same fixture version and action proposal. A conforming runner must:

1. compute, record, and verify fixture and manifest hashes before execution;
2. stop at each named barrier and apply only the declared mutation;
3. record the full ordered lifecycle, stable reason codes, object counts, provider calls, and final Kubernetes projection;
4. fail on an extra authorization, credential, handoff, patch, retry, or stored effect;
5. replay the retained AccordLock decision without a model and compare the replay commitment;
6. run a second time from a fresh copy and report any nondeterminism;
7. preserve every subprocess exit code and fail on a skipped required stage.

Counts are exact. A missing observation is not interpreted as zero. A provider call is counted when the request crosses the connector-to-Kubernetes boundary. A stored protected effect is counted only when the Kubernetes object persists the requested logical mutation. An unauthorized post-admission delta is a security failure for the comparator even if the provider returned success.

## Validation

Run the fail-closed corpus validator from the repository root:

```sh
python3 conformance/validate.py
```

On Windows, use `python` instead when that command resolves to Python 3.13 or
newer.

It checks duplicate keys, frozen object shapes, cross-fixture consistency,
scenario outcomes, repair links, counts, and the complete on-disk index.

For a syntax-only JSON check, all manifests can be parsed from the repository
root with:

```powershell
Get-ChildItem conformance -Recurse -Filter *.json | ForEach-Object {
  Get-Content -LiteralPath $_.FullName -Raw | ConvertFrom-Json | Out-Null
}
```

Parsing proves only JSON syntax. Schema validation and executable runners remain implementation work.
