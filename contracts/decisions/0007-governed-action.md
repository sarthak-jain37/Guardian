# 0007: Backend-prepared action authority and independently verified recovery

Status: local graph/API/ledger/actuator-protocol/UI integration verified with
recording Kubernetes and functional-harness boundaries; live acceptance pending.

The Phase 3 analysis graph remains preview-only and its report stays immutable.
A backend preparation job validates its grounded investigation/plan against the
original evidence, independently refreshes eligibility and runs the operator's
real checks. It creates a separate hash-bound governed review and pending
baseline. An externally published ready-looking review cannot create the private
prepared sidecar, credential-bound authority or backend outbox ownership.

Existing Proposal v2, Readiness v1, GovernedDecision v1, Preflight v1 and
ExecutionReceipt v1 cross real serialized API/consumer boundaries without changing
their meaning or runtime graph versions. HTTP decision input adds explicit
`opt_in_recovery=false` plus its matching exact hash; authentication adds service
`execute` permission, which inference credentials lack. The default runtime still
reports execution unavailable. Operator policy, meaningful identity-bound
verification and controlled inventory are required to enable a scoped action.
The new policy/proof DTOs have separate v1 schema identifiers and strict OpenAPI
models; they do not silently replace one of the existing 20 consumer contracts.

Positive decisions, independent execution/recovery deadlines, credential identity
and outbox are atomic. The deterministic backend executor needs no model uptime.
It persists intent before one conditional Role /rules request and acknowledged
post-write state before verification. Only independently verified completion
activates desired state. Adoption is separately authenticated and records current
rules without mutation. Unknown responses are preserved for manual diagnosis;
matching live rules or audit metadata alone cannot prove an owned acknowledged
write. Confirmed-response crash recovery verifies without replaying mutation.

Recovery is separate opt-in, restores only captured exact rules, revalidates its
own authority/deadline/context and has a one-logical-action budget. It requires a
repeatable pre-passing operation/functional failure and healthy dependencies;
timeout, infrastructure ambiguity, pause, incident or uncertain apply do not
trigger restoration. Restored rules/access/application must verify before
ROLLED_BACK. A failed action can receive new explicit human recovery consent
through a separate reconciliation endpoint. Consumers must explicitly enter that
workflow rather than accepting a changed terminal receipt as an ordinary replay.
New revocation fences queued fresh consent. Previous active desired state and all
original receipts remain preserved. In-app notice intent and explicit recipient
acknowledgement are distinct from monitoring pause and incident controls.

Acceptance evidence: tests/test_execution_ports.py (actual bounded subprocess and
SDK wire boundary), test_execution.py (actual producer/graph/HTTP/auth/SQLite with
recording actuator/harness), and test_execution_workspace.py (actual Streamlit
consent/receipt controls against that scoped API). Phase 5 must install the real
pinned workload/harness, validate collector coverage, scoped deployment identities,
restart/restore, effective access and a measured disposable-cluster pilot. These
local protocol tests establish neither model quality nor live application safety.
