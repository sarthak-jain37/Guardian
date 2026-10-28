# 0004: Governed orchestration and receipt reconciliation

Status: orchestration consumer implemented; backend/executor acceptance pending.

Request v5 adds an explicit `governed` mode. Graph/state/report advance to v7;
WorkItem/WorkOutcome advance to v2. Older pending checkpoints remain inspection
only. Test decisions remain a separate simulation-only schema. The file CLI
continues to support simulation or captured preview and cannot enable governance.

Governed mode requires captured evidence, an authoritative ReviewPort, a
non-simulated VerificationPort and a configured GovernancePort. Schemas alone do
not authenticate a record. BackendReviewAdapter and BackendGovernanceAdapter
consume a backend-owned driver; no HTTP endpoints, authentication, database,
outbox, executor, baseline transaction or queue are implemented here. Driver
methods are a proposed Python integration interface, not an assertion that the
current backend exposes them. Backend owners must agree transport/semantics.

GovernedDecision v1 separates authenticated backend records from local decisions.
Preflight v1 binds stored proposal/decision/action IDs, evidence/candidate/approval
hashes, target UID/version and bounded timestamps. All named authorization, pause,
incident, snapshot, consumer, baseline, policy, verification and dry-run checks
must pass. Backend must enforce these again when claiming/executing the action.
Adoption uses the same authority/deadline checks without requesting a Role patch.

Before dispatch, durable BudgetPort.begin_action reserves the action key. Replay
first reads the backend receipt. A reservation with no recovered receipt produces
manual intervention, not another request. Timeouts/unknown results never become
success. Local reservations do not replace backend leases, intent-before-write,
conditional Kubernetes updates or deduplication. The driver must honor the
provided 1–30 second deadline and return bounded JSON; it supplies protected
transport/session configuration. Exceptions become stable errors. The adapter
does not retry or receive actor/authority from a queue delivery.

ExecutionReceipt v1 correlates IDs/hashes/scope and monotonic sequence/timestamps.
Confirmed apply requires its returned resourceVersion. Completion requires
verification evidence and confirmed baseline activation; adoption has its own
non-mutation completion semantics. Unknown apply becomes manual intervention.
Restoration is projected only from a verified receipt with the explicit recovery
authority ID, exact original-rules hash, forward and restored versions, check
references and notification intent. This graph never grants recovery authority,
initiates a recovery write or runs a model recovery loop. Backend owns per-action
consent, trigger/scope/expiry/incident/pause checks and restoration verification.

One `reconcile` worker delivery reads one receipt by the stored action key. It can
project VERIFYING, COMPLETED, ROLLED_BACK, STALE, FAILED or manual intervention
after forward authority expires, without another model or mutation call. Exact
duplicates are harmless; conflicting/regressing receipts and terminal rewrites
are refused. Operator reconciliation of a terminal manual outcome requires a
separate reviewed backend process. Authoritative outcome projection is persisted
before checkpoint projection, and must itself be idempotent by receipt/sequence.

Backend driver handoff:

- Governance: get_decision, validate_preconditions, execute_approved,
  adopt_approved_snapshot, get_execution_receipt, project_execution_outcome.
- Review: publish_review, get_proposal, publish_report, get_report, finalize_run,
  get_proposal_status, project_proposal, get_proposal_decision, request_revision,
  get_revision, get_successor.
- Every method accepts timeout_seconds. Inputs to forward execution/adoption are
  only stored proposal/decision/action IDs. Outcome projection uses stored
  receipt ID/sequence. Review publication carries the typed analysis outputs.
- Supply real EvidencePort, VerificationPort, BudgetPort, durable checkpointer
  and worker session factory. Review publication must return the same immutable
  content. Outcome/report history must remain append-only with a current projection.

Recording-backend tests exercise consumer semantics; they do not establish
authenticated HTTP behavior, API-server writes, real verification or lab success.
