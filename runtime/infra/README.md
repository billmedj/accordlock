# AccordLock infrastructure

This tree separates a safe local demonstration from production-candidate
artifacts. Nothing here applies resources to AWS or Kubernetes automatically.

| Path | Purpose | Changes live infrastructure? |
| --- | --- | --- |
| `local/k8s/` | End-to-end `kind` demonstration with synthetic attestations | Creates or reuses only a local `accordlock` kind cluster |
| `local/postgres/` | Disposable loopback PostgreSQL 17.11 state store | Starts only a project-local database on `127.0.0.1:55432` |
| `kubernetes/admission/` | Hardened, fail-closed webhook deployment candidate | No; checked-in sentinels deliberately prevent deployment |
| `kubernetes/activation/` | Offline validation of captured EKS activation evidence | No; reads one local JSON file only |

For the fastest product demonstration, start with
[`local/k8s/README.md`](local/k8s/README.md). For any real cluster, read both
Kubernetes READMEs completely: static validation does not replace image
provenance, secret provisioning, a tested EKS caller boundary, or independent
security review.
