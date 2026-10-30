# Governed execution and exact recovery

The backend implements the actual conditional Role actuator, verification and
exact recovery protocol. Execution is **disabled by default**. Automated tests use
the actual graph, HTTP APIs, authentication, SQLite ledger and Streamlit controls
with explicit recording cluster/harness boundaries. The separate local Kind pilot
has also completed real initial narrowing, verified retained/removed access and
activated its baseline. Live recovery and independent university acceptance are
not established by that success. See [current results](project-report.md),
[deployment](deployment.md) and the [demo runbook](demo-runbook.md).

## Workflow

1. Queue analysis and inspect its immutable report as described in `analysis.md`.
   The model proposes a bounded removal; its preview cannot authorize a write.
2. On **Analysis and review**, select **Prepare exact Role change** or explicit
   baseline adoption, then **Queue independent readiness checks**. This is a
   durable background job. Refresh to see DONE or the concrete BLOCKED reason.
3. The backend independently recomputes evidence/eligibility, inventory, consumer
   and workload identity, current authority controls and candidate failure history.
   A real configured behavioral profile must demonstrate startup, normal use and
   restart before removal is eligible. Pre-change SubjectAccessReviews establish
   that the actual subject can currently perform the exact operations. They do
   not simulate hypothetical post-change authorization. Admission dry-run uses
   the exact conditional JSON patch with `dryRun=All` forced inside the driver.
4. Preparation atomically creates a separate immutable governed action review,
   exact diff and binding snapshot, verification/recovery contracts and pending
   baseline. Its hash binds these contents. The original analysis remains intact;
   readiness and action outcomes are shown separately. Preparation lease loss
   cannot publish. A newer analysis or action review invalidates an undispatched
   older action.
5. A human reviews the exact action and accepts residual risks. Separate recovery
   consent is optional and **unchecked by default**. Approval uses the existing
   scoped `/governance/reviews/{id}/decisions` API and repeats real current checks.
   Actor, credential fingerprint, timestamps and deadlines are server-owned.
6. Decision, credential-bound authority and durable outbox commit together. A
   backend-only worker consumes it without requiring model/LangGraph uptime.
   Inference workers cannot claim these action deliveries. A local OS lock plus
   persisted action identity prevents two workers dispatching the same action.
7. The worker repeats current checks, persists its intent, then replaces **only
   `/rules` on one existing namespaced Role**. The JSON patch tests Role UID and
   resourceVersion; it never updates a binding, creates a Role or accepts caller
   YAML/commands. Initial hardening needs no old approved baseline.
8. An acknowledged response is stored before verification. Post-change SARs must
   show retained operations allowed and removed operations denied. At least two
   bounded propagation attempts, meaningful application checks and the configured
   observation period must pass. The ledger records actual duration and evidence
   references. Only then are the new desired baseline, receipt and in-app notice
   committed atomically. Explicit adoption captures current desired state with
   no Role patch and no new model calls; it does not claim functional narrowing.

Review lasts 24 hours from server publication. The independent five-minute
execution-start deadline begins when approval is recorded. A valid issued write
can still be reconciled/verified after that deadline; expiry does not grant a
second write. Current credential revocation, pause, incident, new use, changed
consumers/identity/context, policy/profile changes or stale versions stop a new
write. RBAC conditions cannot freeze concurrent edits to bindings or workloads;
this pilot requires a controlled namespace and coordinated administrators.

## Recovery and uncertainty

Advance consent authorizes at most **one logical exact restoration** of the
captured pre-change rules, inside the displayed bounded recovery window (600
seconds by default, beginning at approval). It binds the restoration hash,
triggers and risks, including security findings that restoration can reintroduce.
A repeatable failure of a previously passing required operation or functional
check, with a healthy runner and dependencies, can trigger it. General baseline
reversion is unavailable. `fresh_human_only` policy never grants advance recovery.

Immediately before restoration the backend checks the same UID, acknowledged
post-write resourceVersion and rules, unchanged consumers/workload/image/context,
current profile/policy, exact still-valid consent, credential, holds and prior
baseline. Timeout, missing evidence, unknown apply, unhealthy dependencies or
changed context require manual intervention. Restoration also uses forced dry-run
and a conditional `/rules` patch; it is never an unconditional overwrite.

A restore API response alone is insufficient. Restored rules, effective access
and application behavior must verify before `rolled_back`. Failure or uncertainty
leaves `manual`. The previously active baseline is preserved; failed narrowing
never activates the candidate. Repeatable policy regressions are recorded against
candidate, target/workload/image and policy context to prevent automatic reuse.

If advance recovery was declined/expired/unavailable, a confirmed failed action
can offer **new explicit human consent** for its displayed exact recovery. The
backend repeats triggers and all current preconditions. It cannot convert an
unknown apply or infrastructure outage into authority, extend the one-action
budget, or silently renew old consent. New recovery/all revocation after that
fresh consent stops its dispatch. This is a separate reconciliation workflow;
consumers must not treat a later fresh-recovery receipt as an ordinary replay of
an earlier terminal manual receipt.

Lost API responses remain unknown even if current rules happen to match. The
backend records a live observation and correlated audit references for diagnosis;
without an acknowledged exact post-write version it does not infer ownership,
activate a baseline, restore or retry. Crashes after a persisted forward/restore
acknowledgement resume verification without another patch. Historical receipts
and failure records are append-only. Outcome notifications are persisted for the
reviewer; explicit in-app acknowledgement records delivery acknowledgement and
never pauses monitoring or clears an incident. No external messages are sent.

## Operator configuration and harness contract

Copy `config/execution.example.toml` into private operator configuration, bind the
actual Role/ServiceAccount/workload UIDs and running image digest, install a real
reviewed harness and replace every artifact SHA256. Set
`GUARDIAN_EXECUTION_POLICY=/absolute/path/execution.toml`, configure scoped auth,
cluster ID and `GUARDIAN_CONTROLLED_NAMESPACES` consistently, and restart the
backend. The template stays disabled and its placeholders cannot pass a check.
Enable only after the disposable lab setup and manual prechecks. Never
turn missing coverage, behavior or UID assertions into passing constants.

The harness is a **trusted operator boundary**, not a sandbox or model-chosen
command. It must genuinely exercise the dedicated workload's startup, ordinary
required reads and restart, distinguish a healthy runner/dependency from a policy
failure, and keep retrievable check artifacts. The runner hashes fixed absolute
executables/artifacts (including interpreter/scripts when applicable), uses fixed
argv without a shell, an explicit environment allowlist, a 1–60 second timeout,
64 KiB stdout cap, and terminates its subprocess group. Artifact changes invalidate
readiness. Interpreter imports/dependencies and allowlisted external credentials
remain operator-controlled deployment inputs; hashing a script is not a supply
chain attestation. Pin and review that environment too.

One JSON request on stdin:

```json
{
  "schema_version": "guardian.functional-request.v1",
  "phase": "pre",
  "cluster_id": "client-dev", "namespace": "guardian-demo",
  "target_uid": "actual-role-uid", "workload_uid": "actual-workload-uid",
  "image_digest": "actual-running-digest", "subject": {"...": "exact Subject envelope"}
}
```

Return a strict `guardian.functional-proof.v1` object with that phase, workload UID
and image digest; UTC `started_at`/`completed_at` inside this invocation; strict
`runner_healthy`/`dependencies_healthy` booleans; exactly `startup`, `normal` and
`restart` checks valued `pass`, `fail` or `unknown`; and nonempty `evidence_refs`.
Exit zero alone is insufficient. The full schema is generated by
`backend.app.models.execution.FunctionalProof.model_json_schema()`. `observe`,
`pre`, `post` and `restored` phases all require actual evidence. Recording proofs
in tests are explicitly synthetic and must never be installed as a live harness.

The first actuator profile supports one dedicated namespaced Role, one verified
ServiceAccount/controlled workload, supported exact resource/verb rules, a
nonempty resulting Role and at most 16 exact original operations. Wider patterns
remain explainable by analysis and blocked for this actuator. Stored active
baselines describe approved desired state, independently of current observations.
SQLite/WAL and the executor lock require one host with local persistent storage;
multi-host execution and network filesystem locking are not supported here.

## API and permissions

All routes require a scoped bearer credential. No actor, rules, command or YAML
is accepted by the execution API. Scope comes from the stored source/action.

| Endpoint | Purpose |
| --- | --- |
| `GET /execution/capabilities` | Scoped execution/recovery policy capability; default disabled. |
| `POST /execution/reviews` | Human `review`; queue preparation with source run ID, exact report hash, action and idempotency key. |
| `GET /execution/preparations/{id}` | Scoped durable preparation state/error. |
| `GET /execution/reviews` and `/{id}` | Saved action, checks/contracts, current blockers, consent and latest receipt. |
| `POST /governance/reviews/{id}/decisions` | Exact human approval/adoption/reject/acknowledge/context. Positive decisions require independently prepared backend plan and residual-risk acceptance. |
| `POST /execution/decisions/{id}/revoke` | Human owner or scoped operator; revoke forward, recovery or all outstanding authority. |
| `POST /execution/actions/{key}/recovery` | New human consent bound to current failed receipt sequence and exact recovery hash. |
| `POST /execution/preflight` and `/requests` | Separate service `execute` permission; exact stored decision/action/key only. Requests queue existing durable authority, never dispatch caller instructions. |
| `GET /execution/receipts/{key}` | Strict `guardian.execution-receipt.v1` projection. |
| `GET /execution/baselines` | Scoped immutable baseline snapshots and activation projection. |
| `GET /execution/notifications` and `POST /notifications/{id}/ack` | Scoped persistent notices; only the human recipient acknowledges. |

Default inference credentials have `read,publish,deliver`, with no `execute`.
The deterministic in-process executor needs no inference credential. Public
preflight is informative to strict consumers; execution repeats checks instead of
trusting a previously returned preflight. Supplying forged passing gates through
review publication cannot create a backend plan or positive authority.

## Local verification and recording demo

```bash
.venv/bin/python -m unittest tests.test_execution_ports tests.test_execution tests.test_execution_workspace -v
.venv/bin/python -m unittest discover -s tests -q
GUARDIAN_RUN=$(mktemp -d)
.venv/bin/python -m agents.guardian.demo --directory "$GUARDIAN_RUN" --skip-tests
```

The targeted suite demonstrates initial narrowing, a later drift against an
adopted baseline, reject/adoption, approval through HTTP/UI, separate unchecked
consent, verified advance/fresh recovery, stale/new-use/superseded/expired/revoked/
paused/incident cases, denied inference-worker execution access, ambiguous
responses, crash recovery and outcome acknowledgement. It uses no live cluster.
The existing JSON demo separately validates the 20 consumer schemas and synthetic
development scenarios; it does not stand in for live workload acceptance.

For nonwriting report review and real Ollama analysis, use [analysis.md](analysis.md).
The live execution demo requires the real workload/harness and private operator
configuration documented in [demo-runbook.md](demo-runbook.md) and
[deployment.md](deployment.md). The disabled example policy is not an executable
passing configuration.
