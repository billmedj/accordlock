# AccordBench system adapter contract

The adapter consumes one bounded JSON object per line and emits one result per line. It executes the native `accordlock offline` command for every scenario used in a run. It extracts only `scenarios[].accordlock`, never the comparison baseline in the native report.

## Input

```json
{"schema_version":1,"case_id":"stale-authority","driver":"accordlock_offline_native","scenario_id":"DP-102"}
```

The four fields are mandatory and no other field is accepted. In particular, `expected`, `oracle`, `label`, and `baseline` fields are rejected so benchmark truth cannot become a system decision by accident.

`scenario_id` is currently restricted to the real native offline scenarios `DP-000`, `DP-101`, `DP-102`, and `DP-103`. This is a narrow adapter, not a claim that the current CLI can execute arbitrary AccordBench tasks.

## Output

Each result includes:

- the adapter and schema versions;
- an `ALLOW`, `DENY`, or `INDETERMINATE` decision derived from the native system output;
- bounded reason codes;
- the exact `accordlock` portion of the native result;
- the executed binary version and SHA-256;
- explicit metadata that the system ran and no oracle or reference baseline was consumed.

The adapter does not score itself. AccordBench owns labels, scoring, aggregation, and statistical analysis outside the system boundary.

## Honest scope

This v1 adapter exercises deterministic native decisions with public test keys and process-local state. It does not exercise the Desktop UI, model providers, durable PostgreSQL state, Kubernetes, EKS, a production runner, or network services. It is suitable for regression and adapter integration, not a production benchmark claim.
