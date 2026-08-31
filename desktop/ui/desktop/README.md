<p align="center">
  <img src="src/images/icon.svg" width="104" height="104" alt="AccordLock" />
</p>

# AccordLock Desktop

AccordLock is a desktop AI agent that works inside a folder you approve. It can read files; file changes require one-time approval. Command execution is off by default. Users must first allow specific programs, and every invocation still requires one-time approval. Each decision and recorded action appears in an exportable activity log.

It is designed for people and teams that want useful local agents without giving a model unrestricted access to a workstation or production credentials. Projects can also be bound to saved deployment environments so an operator can run a read-only GitHub–ECR–Kubernetes preflight without exposing cloud credentials to the model or renderer.

## How it works

1. Connect your preferred model provider.
2. Choose a project and folder, then describe the result you want.
3. Review the task's fixed access and end time.
4. Approve each exact file change or command once.
5. Handle pending decisions in the Approval Center.
6. Review, restore supported deleted files, and export the task activity.

The activity view labels the revalidated task-alignment result **Task check**
and its qualified records **Task evidence**. Results are categorical:
**Verified**, **Not verified**, or **Blocked**. **Verified** requires at least
one qualified evidence item and only supported findings; the connected
free-text profile currently shows **Not verified**.

Network access is off by default. Under **Settings → Security**, a user can add
exact domains for controlled HTTPS traffic. The runtime restarts with that fixed
allowlist and exposes only GET and HEAD. Each exact request still requires
one-time approval; the model cannot add a destination itself.

Approval alerts can be sent to Slack, Microsoft Teams, Telegram, or WhatsApp.
Each configured channel has a **Send test** action. Remote decisions require a
separately operated approval gateway: the desktop pairs its public key, accepts
only signed decisions that match one exact pending action, and records each
receipt once before applying it. The local evaluation path imports a signed
receipt through a native file picker; provider callback bodies are never
accepted from the renderer.

For a project with a deployment environment:

1. Save its exact GitHub repository and workflow, AWS account and ECR
   repository, and Kubernetes Deployment under **Settings → Connections**.
2. Bind that environment in the project editor.
3. Select **Verify deployment** from the project workspace.
4. Provide one pull request, build run and immutable image digest.
5. Review the four checks and export the signed receipt.

Deployment Preflight is read-only. It does not merge, build, push, deploy or
change the cluster. Every result states **No deployment was performed.**

The model proposes work. AccordLock decides what may run. A separate local runtime owns task policy, approvals, authorizations, and execution records; model output is never treated as authorization. The protected agent backend accesses model-provider keys through the operating-system credential vault. A separate preflight runner owns bounded cloud credentials and returns independently verifiable, signed read-only receipts. Production mutation credentials remain outside this alpha's scope.

## Security model

- Task access is fixed before work starts.
- Approvals apply to one exact action and cannot be reused.
- Missing, malformed, expired, mismatched, or reused authorization is rejected.
- The model does not receive model-provider keys stored in the operating-system
  credential vault. Production execution credentials are outside this alpha.
- File deletions use recovery storage when the runtime supports it.
- Audit exports are pinned to one durable ledger revision and digest-checked.
- Post-restart audit access requires the same main-process-authorized workspace.
- Saved deployment credentials are encrypted by the operating-system credential
  store and are never returned to the renderer.
- Deployment candidate URLs are reduced to identifiers and must match the
  environment's fixed repository and workflow routes.
- Preflight results are bound to the environment version, observed Deployment
  identity and immutable image digest.
- Remote approval receipts are bound to the pending action, task, channel,
  gateway enrollment and expiry. Receipt and provider-event replay survives a
  normal desktop restart.

## Current status

This repository is an unreleased engineering alpha for local evaluation. It requires compatible AccordLock runtime and preflight-runner artifacts. The local product path and automated fixtures do not constitute real-account evidence: GitHub, ECR and Kubernetes acceptance runs, live messaging accounts and callback routing, Microsoft identity verification, and an independent security review are still required. Do not treat it as a production security boundary.

## Local development

Requirements:

- Node.js 24.10 or newer
- Corepack with pnpm 10.30 or newer
- Rust and Cargo
- the pinned Microsoft NuGet 7.9.0 executable for Windows packaging
- a compatible AccordLock runtime repository or verified runtime artifact directory

From the repository root, stage debug binaries without installing JavaScript dependencies or creating an installer:

```powershell
./scripts/build-windows.ps1 -Development -AllowDirty -RuntimeRepo C:\path\to\accordlock -NuGetToolPath C:\path\to\nuget.exe
corepack pnpm --dir ui/desktop run start-gui
```

Dirty-source development requires `ACCORDLOCK_ALLOW_DIRTY_BUILD=1`. Release packaging rejects dirty sources and creates no package unless every embedded binary marker passes verification.

See `ACCORDLOCK_DISTRIBUTION.md` for the desktop/runtime integration contract.
