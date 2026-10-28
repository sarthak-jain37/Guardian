# Run and verify the LangGraph implementation

Phases 1–5 have local orchestration implementation and verification tooling. Real
backend/executor acceptance, team-held-out evaluation and university deployment
remain integration gates. The current dashboard still uses the legacy summary
path. Start with the local commands below to exercise the new graph.

## 1. Environment

```bash
cd /home/dionysus/Projects/Guardian
git branch --show-current
git status --short
uv sync --locked --inexact --extra verification
```

Current branch: `feat/langgraph_part2`. Use Python >=3.11. The shared backend now
requires llama.cpp >=0.3.36; the `local-model` extra pins the same 0.3.36 runtime.
Its first installation may compile native code. Do not overwrite the existing `.env`.
The CPU demo needs no Redis, Kubernetes, Docker, GPU or GGUF file.

Old phase-1–3 directories remain historical. Graph/state/report are now v7,
request v5, worker contracts v2, model config/result v2, and prompt v4. Old pending
runs must not acquire new authority by editing stamps. Use fresh directories.

## 2. Complete CPU verification and demonstration

```bash
GUARDIAN_RUN=$(mktemp -d "$PWD/personal_docs/all-phases-XXXXXXXX")
.venv/bin/python -m agents.guardian.demo --directory "$GUARDIAN_RUN"
echo "$GUARDIAN_RUN"
```

Expected: **163 tests pass**, **20 schemas validate**, and `passed: true` in
`demo-summary.json`. Allow about half a minute on the current laptop. All command
steps use separate processes; inference is explicitly scripted. The demo checks:

| Area | Observable result |
| --- | --- |
| Foundations/initial analysis | Useful Role preview without baseline/answer sheet; exact UID/version patch checks |
| Restart | Same pending review and two model calls in a new process |
| Reject/acknowledge | REJECTED / NO_CHANGE; zero execution requests |
| Simulated approval/redelivery | EXECUTION_REQUESTED; one recording action; duplicate resume adds none |
| Adoption without usage | Zero model calls; recording adoption; baseline remains inactive |
| Context revision | Old run STALE; revision 2 has a new run ID and new review |
| Missing usage/gap/monthly path | BLOCKED with zero execution requests |
| Invented decision ID | STALE with zero execution requests |
| Separate worker | Checkpoint handoff and duplicate delivery without repeated inference |
| Governed contracts, in unit tests | Backend decision/preflight rejection, lost dispatch/receipt reconciliation, exact outcome/recovery projection |
| Producer handoff, in unit tests | Actual main pod helpers consumed as supplemental context without fabricated usage |
| Development evaluation | Useful complete fixture; protected/missing-evidence cases score correctly |

For a presentation after tests have passed separately:

```bash
ANOTHER_RUN=$(mktemp -d "$PWD/personal_docs/presentation-XXXXXXXX")
.venv/bin/python -m agents.guardian.demo --directory "$ANOTHER_RUN" --skip-tests
```

That run records `tests_run=false`. Do not call it a fresh full test run.

Inspect these files:

```bash
cat "$GUARDIAN_RUN/tests.log"
.venv/bin/python -m json.tool "$GUARDIAN_RUN/demo-summary.json"
cat "$GUARDIAN_RUN/approve/role-preview.yaml"
.venv/bin/python -m json.tool "$GUARDIAN_RUN/approve/result.json"
.venv/bin/python -m json.tool "$GUARDIAN_RUN/evaluation/evaluation.json"
```

Summary/source hashes and dirty-state flags distinguish a tested committed release
from a development working tree. Each case retains evidence, report, manifest,
SQLite checkpoint/test records and per-run history. Preview files appear only
when a proposal exists. The demo refuses a nonempty output directory to preserve
earlier evidence. Do not redirect a log into an empty evaluation directory before
starting it; that would make the directory nonempty.

## 3. Run tests independently

```bash
.venv/bin/python -m unittest discover -s tests -v
.venv/bin/python -m unittest discover -s tests/orchestrator -v
```

Expected: 163 repository tests / 118 orchestration tests, ending in `OK`.

Focused groups:

```bash
# Phase 1
.venv/bin/python -m unittest tests.orchestrator.test_foundations -v
# Phase 2, including injected-clock expiry/renewal and new context
.venv/bin/python -m unittest tests.orchestrator.test_review_routes tests.orchestrator.test_revisions -v
# Phase 3
.venv/bin/python -m unittest tests.orchestrator.test_modeling tests.orchestrator.test_evidence_tools tests.orchestrator.test_worker -v
# Phase 4: recording trusted-backend fixtures, zero real writes
.venv/bin/python -m unittest tests.orchestrator.test_governance -v
# Phase 5: evaluation isolation and actual main producer helper compatibility
.venv/bin/python -m unittest tests.orchestrator.test_validation_handoff -v
# Teammate's tests from main, unchanged
.venv/bin/python -m unittest discover -s tests -p 'test_telemetry*.py' -v
.venv/bin/python -m unittest discover -s tests -p test_pod_evidence.py -v
```

Codex's restricted sandbox has stalled the in-memory FastAPI TestClient in this
environment. The complete checks were run outside that sandbox. A normal user
terminal is the intended environment; this does not require an application fix.

## 4. Manual review demonstration

Keep these Bash helpers in the same terminal:

```bash
WALKTHROUGH=$(mktemp -d "$PWD/personal_docs/walkthrough-XXXXXXXX")
guardian() { .venv/bin/python -m agents.guardian.runner "$@"; }
review() {
  local case_dir="$1" decision_kind="$2" stored_id
  stored_id=$(guardian --directory "$case_dir" decide "$decision_kind" |
    .venv/bin/python -c 'import json,sys; print(json.load(sys.stdin)["decision_id"])') || return
  guardian --directory "$case_dir" resume --decision-id "$stored_id"
}
```

Start/restart/inspect/reject:

```bash
guardian --directory "$WALKTHROUGH/reject" start
guardian --directory "$WALKTHROUGH/reject" status
cat "$WALKTHROUGH/reject/role-preview.yaml"
review "$WALKTHROUGH/reject" reject
```

Expect PENDING_REVIEW → REJECTED, two model calls, zero action requests. The Role
retains get/list pods and proposes removing get secrets. The binding is a preview
of the unchanged binding. Neither a baseline nor a permission answer sheet is
required. Complete each case promptly: frozen fixture sources have a ten-minute
lag allowance; a delayed review can correctly fail freshness checks.

Simulate approval in a different directory:

```bash
guardian --directory "$WALKTHROUGH/approve" start
review "$WALKTHROUGH/approve" approve_remediation
.venv/bin/python -m json.tool "$WALKTHROUGH/approve/result.json"
```

Expect EXECUTION_REQUESTED and one local recording action. Receipt fields
`cluster_write_performed`, `verification_performed` and `baseline_activated` are
all false. This is not a verified completed cluster action.

Independent adoption:

```bash
guardian --directory "$WALKTHROUGH/adopt" start --intent adopt_baseline --scenario missing-usage
review "$WALKTHROUGH/adopt" adopt_baseline
```

Expect zero model calls/no patch and a separate recording adoption request, with
no actual baseline activation. The remediation execution-request counter stays zero.

Context/revision:

```bash
guardian --directory "$WALKTHROUGH/context" start
review "$WALKTHROUGH/context" request_context
guardian --directory "$WALKTHROUGH/context" next
```

Expect old run STALE and a new revision-2 pending review requiring a new decision.
Production answer collection/delivery is external. Renewal tests advance a fake
clock; there is no need to wait 24 hours or edit approval timestamps. `renew` is
only valid after an unused review/approval expires; then `next` starts its successor.

Blocked routes:

```bash
for scenario in coverage-gap monthly missing-usage; do
  guardian --directory "$WALKTHROUGH/$scenario" start --scenario "$scenario"
done
guardian --directory "$WALKTHROUGH/forged" start
guardian --directory "$WALKTHROUGH/forged" resume --decision-id invented-decision
```

Expect BLOCKED for insufficient evidence and STALE for the invented decision,
with no action requests. Use another directory to repeat a closed case.

## 5. Real local-model evaluation

The installed laptop GGUF is already available. Install its runtime if needed:

```bash
uv sync --locked --inexact --extra verification --extra local-model
test -f /home/dionysus/models/Qwen2.5-7B-Instruct-Q4_K_M.gguf
```

For this laptop, the existing ignored profile is
`personal_docs/phase3-local-smoke.toml`. On another machine, copy
`config/dev-laptop.toml` to an ignored path and replace the absolute model path.
The checked-in model path is a placeholder.

```bash
REAL_RUN=$(mktemp -d "$PWD/personal_docs/real-evaluation-XXXXXXXX")
.venv/bin/python -m agents.guardian.evaluate \
  --directory "$REAL_RUN" --scenario complete \
  --profile personal_docs/phase3-local-smoke.toml
.venv/bin/python -m json.tool "$REAL_RUN/evaluation.json"
```

The current v4 prompt produced one useful development result with the real local
Qwen model: investigator and planner both validated, two model calls, zero lookup
calls, approximately 176.6 seconds total, and a proposed get-secrets removal while
retaining both Pod operations. No execution requests or cluster writes occurred.
Earlier invalid/budget-blocked/all-retain experiments remain preserved. This is
one synthetic development case, not reliability, held-out quality or lab evidence.
Runtime/model/config/source hashes and exact inputs/results allow inspection.

The evaluator exits nonzero if the development case abstains or misses its
expected useful result. Do not count schema validity alone as usefulness.
For all four development scenarios, omit `--scenario complete`; allow more CPU
time. Never relabel scripted responses as real inference.

## 6. Actual captured producer exports

The main pod-evidence API output is not itself an EvidenceBundle or UsageSummary.
The evidence owner must supply a valid sanitized captured EvidenceBundle. Then:

```bash
CAPTURE_RUN=$(mktemp -d "$PWD/personal_docs/captured-evaluation-XXXXXXXX")
.venv/bin/python -m agents.guardian.evaluate \
  --directory "$CAPTURE_RUN" \
  --evidence /absolute/path/to/captured-evidence.json \
  --profile personal_docs/phase3-local-smoke.toml
```

Optional context from main's selected-pod evidence endpoint can be supplied with
`--pod-context /absolute/path/pod-evidence.json --pod-name POD_NAME --pod-uid POD_UID`.
The adapter validates identity/SA/time and adds context only. Network events or
`health=following` cannot substitute for permission usage/coverage. Captured
exports stay unscored previews (`passed=null`), with no local execution authority.

## 7. Real backend and lab acceptance

See `HANDOFF.md` and decision 0004. Backend owners provide agreed real drivers,
VerificationPort, evidence, durable budgets/queue and checkpointer/session factory.
The current file CLI cannot enable governed execution. Use the backend's trusted
worker integration to deliver analyze/resume/reconcile items by stored IDs.

Before calling the integrated system verified, demonstrate authenticated
approval, no writes for stale/expired/paused cases, conditional patch, actual
access/functional verification, baseline transaction, durable receipt and exact
authorized recovery. Exercise crash/reconciliation against the real service and
disposable cluster. These results cannot be supplied by our recording tests.
Held-out A/B evaluation, deployment and archive/recovery acceptance also need the
appropriate component owners and lab access.

## 8. Existing application and teammate telemetry views

With the existing `.env`, Redis, Kubernetes/audit access and legacy model already
configured, start two terminals from the repository root:

```bash
.venv/bin/python -m uvicorn backend.app.main:app --reload --port 8000
```

```bash
.venv/bin/python -m streamlit run frontend/main.py
```

Visit `http://127.0.0.1:8000/docs` and `http://localhost:8501`. For read-only checks:

```bash
curl -fsS http://127.0.0.1:8000/telemetry/status
curl -fsS http://127.0.0.1:8000/telemetry/pods
curl -fsS 'http://127.0.0.1:8000/telemetry/events?limit=10'
```

Empty results are expected with disabled exporters/no inventory. Teammate setup
is in `docs/telemetry.md`. Those endpoints/views remain the existing telemetry
and legacy summary flow; they are not the new graph's authenticated review UI.
No Cilium/Tetragon deployment or real exporter collection is established by the
unit tests. Do not change workload RBAC to manufacture an event for this check.
