# Orchestration integration handoff

The orchestration implementation includes governed review/receipt consumers,
bounded model/tools/worker behavior, producer context validation and development
evaluation. Real backend/collector/executor acceptance and university deployment
remain external integration gates. See `VERIFY.md` for commands and exact claims.

## Current supported scope

One dedicated namespaced Role with a known ServiceAccount/application and complete
consumer inventory; supported finite resource/verb/group combinations; exact
conditional `/rules` replacement; unchanged binding preview. Initial hardening
accepts a null approved baseline and no permission answer document. Unsupported
restrictions, unresolved consumers/alternate grants, incomplete usage, rare
unexercised operations and unavailable meaningful verification block narrowing.

Main's pod inventory/audit/Hubble/Tetragon exports are supplemental context.
`adapters.pod_context.attach_pod_context` consumes the actual pod-evidence response
shape, validates selected UID/SA/time/scope, projects bounded allowlisted metadata
and keeps shared-identity attribution explicit. It does not replace UsageSummary,
advance collection freshness, invent complete coverage or manufacture dependencies.
The configured client establishes the cluster association; the current pod-export
body does not itself carry a trusted cluster envelope. A JSON file is untrusted
context, not proof of collection authenticity.

## Backend integration

Use `BackendReviewAdapter(driver)` and `BackendGovernanceAdapter(driver)` with
backend-owned transport/session configuration. The proposed driver methods and
required semantics are recorded in decision 0004. They are not implemented HTTP
routes. Keep acceptance pending until owners agree and real adapter fixtures pass.

Backend supplies:

- EvidencePort returning strict immutable scoped evidence and current refreshes.
- Authoritative reviewer authentication, scope authorization, immutable decisions,
  exact preconditions, expiry/revocation and atomic durable resume delivery.
- VerificationPort with `simulation_only=False`, actual dry-run/access/functional
  checks and failure history. The executor repeats current checks before writing.
- Durable BudgetPort, including model/repair/tool reservations and atomic
  `begin_action(action_key)`: true for its first reservation, false afterward.
- Durable action receipt lookup and idempotent outcome projection, including
  notification intent. Backend owns baseline activation and independent recovery.
- Durable queue/outbox, run/target coordination, scheduling and retry policy.

The integration session factory constructs `Runtime(evidence=..., model=...,
review=BackendReviewAdapter(driver), verification=..., execution=None,
budget=..., governance=BackendGovernanceAdapter(driver))`, and builds the graph
with a supported durable checkpointer. Pass that session factory and the backend
WorkQueuePort to `run_worker`. The session factory closes model/connections on
job completion or review waiting. It must save/export the selected run/profile
through the application's storage implementation; the file CLI is a dev adapter.

Deliver `WorkItem(kind="analyze", request=...)` using request mode `governed` only
when those real ports are configured. Resume deliveries contain just the stored
decision ID. Receipt deliveries use `kind="reconcile"` with only the stored run
ID. Each reconciliation reads one receipt; external scheduling decides when to
deliver another. No model call, recovery plan or write is performed by that route.

The module's local CLI intentionally cannot enable governed mode or create a
production decision. Captured files stay previews. `record_test_decision` cannot
authorize a non-simulated proposal. A model/service account cannot approve its
own proposal through these consumers.

## Execution and recovery contract

Preflight must pass all named checks, bind the exact IDs/hashes/UID/version and
remain within the decision's execution deadline. An approval accepted before
review expiry retains its independent execution window. Uncertain dispatch is
reconciled from a stored receipt, never blindly resubmitted. Backend still owns
intent-before-write, idempotency, leases and the API-server conditional operation.

COMPLETED requires actual verification references and baseline activation.
ROLLED_BACK requires a verified restoration receipt, explicit backend recovery
authority ID, exact original rules hash, forward/restored versions and notification
intent. The graph does not grant recovery consent or execute restoration. Backend
must verify exact per-action consent, trigger, expiry, incident/pause and unchanged
post-apply state. Terminal manual outcomes need a separate operator reconciliation
process; the worker refuses a silent rewrite into success.

## Worker configuration and deployment inputs

| Item | Input supplied by this module / requirement |
| --- | --- |
| Runtime | Python >=3.11, locked dependencies; LangGraph/checkpointer in `uv.lock` |
| Profiles | Strict `config/test.toml`, `dev-laptop.toml`, `lab.toml`; replace placeholder file/endpoint/model revision |
| Providers | Lazy llama.cpp CPU or configured vLLM; JSON Schema plus independent validators |
| Concurrency | One active job per worker; bounded recording queue 1–64; real delivery coordination external |
| Defaults | Six model calls; one repair per stage across restart; two lookup rounds/four calls; recursion limit 32 |
| Human waiting | Acknowledges job/releases model session; backend later delivers stored decision ID |
| Persistence | Checkpoints, budgets and authoritative review/action history must survive restart; local SQLite is single-worker development |
| Identity | Worker needs scoped evidence/read and backend request-by-ID access; no direct Role mutation, Secret-body or reviewer credentials |
| Transport | Protected configured model/backend endpoint; credentials from named worker environment/secret configuration, never model inputs |
| Health | File CLI exit status/WorkOutcome for dev; real queue/lease readiness belongs to deployment/backend entrypoint |
| Resources | Laptop smoke: four CPU inference threads; no GPU in routine tests. Lab allocation, memory/latency/capacity must be measured |
| Upgrade | Graph/state/report v7, request v5, worker v2, model config/result v2, prompt v4. Preserve incompatible runs; no automatic authority migration |

The model config records requested revision separately from observed identity.
Unknown resolved revision remains null. Configured context size is not proof of
server capacity. Evaluation records source/profile/input hashes, exact stage
results, available tokens, durations and failures. A dirty source tree is labeled.

No Helm chart, backend service, workload manifest or teammate implementation was
created by this orchestration handoff. Supply this table to the deployment owner
for the real worker entrypoint/PVC/model endpoint and disabled-execution install.

## Outstanding acceptance evidence

1. Owner-approved contracts and compatible real UsageSummary/inventory exports.
2. Authenticated decisions, durable delivery, conditional apply/adoption and
   actual verification/receipt/recovery adapter tests.
3. Pinned real workload/image, meaningful functional checks and protected model
   endpoint on confirmed lab allocation.
4. Frozen development/held-out split and metric definitions, equivalent-input
   deterministic/LLM comparison, actual run provenance and failures.
5. Real initial hardening, later drift, blocked authority/coverage cases and
   governed recovery on the team's disposable lab environment.

The local development evaluator and recording contract tests supply preparation
and consumer evidence. They do not satisfy those integrated release gates.
