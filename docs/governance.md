# Authenticated governance foundation

Phase 1 adds the authority/storage boundary. Kubernetes execution remains disabled.
The old `/approval/*/decision`, `/approval/*/revert`, `/baselines/*/apply`,
`/baselines/*/rollback` and `/telemetry/permission-proposals/*/decision` routes
return `410 legacy_execution_retired`. Their historical read endpoints remain.
The dashboard displays legacy findings as read only.

Startup and external apply events retain observations without approving a baseline
or deleting old baseline data. Legacy baseline responses carry
`authority_verified=false`; existing `ACTIVE` labels are historical records.

## Configuration

Set these before starting the backend using its normal run command:

```sh
export GUARDIAN_GOVERNANCE_DB=/absolute/private/persistent/guardian/governance.sqlite3
export GUARDIAN_AUTH_FILE=/absolute/private/guardian/reviewers.auth.json
```

The default ledger is `data/guardian/governance.sqlite3`, ignored by Git. The
directory must be writable and persist across backend restarts. SQLite WAL needs
local persistent disk on a single host; do not place it on a shared network
filesystem. This is separate from the development LangGraph checkpoint store.
Database, WAL/SHM files and private registries are ignored. A consistent operational
backup/restore procedure is part of phase 5; copying just an active SQLite DB file
without its WAL is not an established backup procedure.

Credentials are operator-issued opaque bearer tokens, with SHA-256 digests and
expiry in a strict registry. Deliver the token privately to its named owner. Use
TLS for remote access; loopback is acceptable for local development. No default
reviewer, shared `admin` token, header-supplied actor or development bypass exists.
This initial deployment uses operator provisioning, not a public login/SSO flow.

Issue a reviewer token from the repository root (prints the secret **once**):

```sh
.venv/bin/python -m scripts.guardian_auth \
  --registry /absolute/private/guardian/reviewers.auth.json issue \
  --actor alice --kind human --cluster guardian-lab --namespace guardian-demo \
  --permission read --permission review --hours 8
```

Issue separate service credentials for the worker with `--kind service`, `read`,
`publish` and `deliver` permissions. Service credentials cannot have `review` or
`operate`. Human credentials cannot have `publish` or `deliver`. An operator may
issue a separate human credential with `read`/`operate` for pause and incident
holds. Grants bind exact cluster/namespace pairs; wildcard grants are rejected.
Token lifetime defaults to 8 hours; the issuance CLI accepts 1–720 hours. Register
additional credentials deliberately; keep their scope and lifetime bounded.

Governance POST bodies are limited to 2 MiB before JSON parsing, including chunked
requests. Larger bodies return `413`. Publication/report arrays also retain their
existing contract bounds.

Send credentials in `Authorization: Bearer <token>`. `/governance/me` returns the
server-derived principal and `execution_available=false`. Do not put bearer values
in URLs, model inputs, committed `.env` files or screenshots. The registry contains
digests only and is atomically replaced with mode `0600` by the issuance CLI.

Revoke by the token's SHA-256 digest recorded in the private registry:

```sh
.venv/bin/python -m scripts.guardian_auth \
  --registry /absolute/private/guardian/reviewers.auth.json revoke \
  --token-sha256 <digest>
```

Every governance request reloads the registry. Expiry/removal/scope changes apply
without restarting the backend. Missing/invalid authentication returns `401`;
insufficient scope returns `403`; a missing/corrupt configured registry or ledger
returns `503`. Without `GUARDIAN_AUTH_FILE`, no governance access is granted.
Existing monitoring endpoints remain the legacy local interface; comprehensive
dashboard/evidence access integration is scheduled in phases 2–3.

## Review and decision API

| Endpoint | Caller and effect |
| --- | --- |
| `POST /governance/reviews` | Scoped publisher service; strict `ReviewPublication` with the existing Proposal v2 and AnalysisReport v7. Simulated records and mismatched scopes are rejected. |
| `GET /governance/reviews?cluster_id=...&namespace=...` | Scoped reader; latest 100 metadata summaries, configurable bounded limit. Fetch exact payload by ID. |
| `GET /governance/reviews/{proposal_id}` | Scoped reader; immutable original payload, server review deadline and current status. |
| `GET /governance/reviews/{proposal_id}/history` | Scoped reader; ordered append-only history, at most 100 events per page. Pass `after_sequence` from `next_after_sequence` for the next page. |
| `POST /governance/reviews/{proposal_id}/decisions` | Scoped human reviewer; expected revision/hash and idempotency key are required. |
| `GET /governance/decisions/{decision_id}` | Scoped reader/service; authoritative decision in the LangGraph governed-decision v1 contract. |
| `POST /governance/deliveries/claim` | Scoped delivery service; bounded leased batch of WorkItem v2 resume records. |
| `POST /governance/deliveries/{delivery_id}/ack` | Owning delivery service; exact current lease token required. |
| `POST /governance/holds` | Scoped human operator; append pause/incident state with a reason. |
| `GET /governance/holds?cluster_id=...&namespace=...` | Scoped reader; latest independent pause/incident records. |

Example decision body (the actor and UTC timestamps come from the server):

```json
{
  "kind": "reject",
  "expected_revision": 1,
  "expected_approval_hash": "<hash from the stored proposal>",
  "idempotency_key": "review-request-001",
  "note": "Retain pending workload context"
}
```

`reject`, `acknowledge` and `request_context` create immutable decisions and durable
resume records. In phase 1 they do not themselves resume a running graph, reject an
old Redis queue entry or regenerate analysis. Those adapters/dispatcher are phase
3. `approve_remediation` and `adopt_baseline` return `503` without recording any
authority or delivery. Client actor/authority/deadline/recovery fields are rejected.
No positive decision can be enabled by accepting residual risk or supplying
passing model-produced gates. Exact recovery consent belongs to phase 4.

Review expiry is server publication time plus 24 hours. Publication replay cannot
renew it. Conflicting contents under an existing ID, skipped case revisions,
changed case scope, mismatched expected hash/revision or a second decision fail.
An exact decision replay returns the original record, including after expiry,
without new authority, timestamps or deliveries. An expired undecided review is
recorded as expired when read/decided. Scheduled closure/renewal and the independent
five-minute positive execution window are integrated in phases 3–4.

Decision, history, state projection and resume intent commit together. The queue
holds at most 64 unacknowledged records per scope; a full queue rolls back a new
decision instead of silently losing its delivery. A delivery lease defaults to
30 seconds (1–300 supported); a claim batch is 1–32 items. Lease expiry permits
redelivery of the same WorkItem. A former owner cannot acknowledge a replacement
lease. Consumers must durably process the item before acknowledging it; duplicate
graph deliveries must remain idempotent. This is at-least-once delivery, not an
exactly-once external-write guarantee.

## Verification without services

```sh
MODEL_PATH=/tmp/guardian-tests-no-model.gguf .venv/bin/python -m unittest \
  tests.test_governance_auth tests.test_governance_store tests.test_governance_api \
  tests.test_approval_api tests.test_permission_proposals -q

MODEL_PATH=/tmp/guardian-tests-no-model.gguf \
  .venv/bin/python -m unittest discover -s tests -q
```

The deliberately absent model path keeps legacy drift tests from invoking real
inference. These tests use temporary private registries, actual SQLite transactions,
graph-produced synthetic publications and mocked cluster clients. They do not
prove lab deployment, real Kubernetes conditional writes or application recovery.
