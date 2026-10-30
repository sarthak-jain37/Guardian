# Orchestration integration boundaries

The module is integrated with the merged FastAPI backend and Streamlit/terminal
review workflows. This document describes current responsibilities, not an
unimplemented team handoff. [VERIFY.md](VERIFY.md) covers component checks;
[the demo runbook](../../docs/demo-runbook.md) covers the actual pilot.

## Who owns what

| Component | Current responsibility |
| --- | --- |
| Audit collector / evidence services | Exact usage, coverage, provenance, current identity/consumer snapshots and archives |
| Backend analysis store | Intake, immutable capture/report, scoped jobs, leases/fencing, budgets and fresh/context revisions |
| `service_worker.py` | Preview graph, actual configured inference, durable checkpoints and leased publication through HTTP |
| Deterministic graph policy | Known operation IDs, protection/eligibility, bounded tools and exact subset rendering |
| Backend governance store | Authenticated immutable human decisions, deadlines/revocation, holds and durable outbox |
| Backend execution store | Independent preparation, exact action authority, conditional dispatch, verification, baselines, recovery and receipts |
| UI / review CLI | Display exact stored content and submit decisions to the same scoped backend |

The deployed inference Runtime uses `BackendEvidencePort`, `BackendBudgetPort`,
`BackendReviewPort`, `PreviewVerificationPort` and no execution port. A model
worker cannot approve its own report or directly patch a Role. It can release its
model session after report publication; the backend executor does not require
inference uptime to process stored authority.

## Supported action and evidence

The current actuator changes only `/rules` on one existing dedicated namespaced
Role with a known ServiceAccount/controlled workload and supported finite rules.
Bindings remain unchanged. Shared/unknown consumers, alternate grants, unsupported
restrictions, stale/missing usage and unresolved relevant workflows block narrowing.
Initial hardening requires no old approved baseline or permission answer sheet.

Pod-context exports are supplemental. Their adapter validates selected UID,
ServiceAccount, time and scope; it does not invent complete usage or collection
health. JSON file contents are not proof of source authenticity. Runtime inputs
never receive evaluator labels or expected removals.

## Generic consumer contracts versus service wiring

`BackendReviewAdapter` and `BackendGovernanceAdapter` support driver-based
consumers for validated decisions, preflight and receipts. They are distinct from
the current preview worker's concrete HTTP ports. Do not infer that every generic
port is an HTTP endpoint with the same method name.

Reusable `WorkItem` deliveries identify stored runs/decisions. Duplicate delivery
must be idempotent. Receipt reconciliation reads backend evidence without new
model calls, arbitrary writes or recovery planning. Incompatible checkpoint
versions and uncertain outcomes require explicit reconciliation/fresh review;
editing saved version fields does not restore authority.

## Authority and outcome requirements

A positive decision binds the exact stored revision/hash and current principal.
Independent current evidence, real dry-run/access/application checks and execution
conditions are repeated before dispatch. The backend persists intent before the
conditional UID/resourceVersion patch. An unknown response is not blindly retried.

Completion requires confirmed apply, required verification and baseline activation.
Recovery requires separate exact consent, a qualifying failure, current conditions
and verified restoration. A pending checkpoint, advisory severity score, test
receipt or old Redis baseline cannot satisfy those conditions.

## Deployment and acceptance

The packaged deployment uses one active backend/collector/worker on one storage
host with local persistent SQLite and OS locking. Inference/dashboard identities
have no Kubernetes token or raw archive credentials. Model configuration and
resolved deployment digest are pinned; the default laptop provider is Ollama.
See [deployment.md](../../docs/deployment.md) for actual identities/storage and
[execution.md](../../docs/execution.md) for the trusted harness contract.

The local pilot completed real initial narrowing with verified retained Pod read,
denied Secret read and baseline activation. Recording tests separately cover
failure/recovery paths. Independent university reproduction, a controlled live
recovery drill, external durable backup/key custody and reviewed held-out/human
quality measurements remain outstanding; see [current results](../../docs/project-report.md).
