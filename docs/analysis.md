# Integrated analysis and report review (Phase 3)

Use the current `feat/guardian-project-completion` branch. The earlier five
LangGraph module phases are separate from the six whole-project phases in
`docs/implementation-phases.md`.

## What runs

1. An authenticated human requests an initial/manual analysis of a namespaced
   Role. No approved baseline is required. The API records intake immediately.
2. A backend task captures immutable UID/version-bound inventory and exact usage
   evidence, preserves authenticated context notes and pins archive provenance
   when configured. Missing/unsupported evidence stays explicitly failed/blocked.
3. A separate worker claims one job over the scoped API. It loads normalized
   evidence, uses server-owned persistent model/lookup budgets and executes the
   bounded investigator/planner graph. Inference never runs in audit ingestion.
4. The worker atomically publishes the exact report and optional blocked Role
   preview under its live lease. The API independently fences stale, expired or
   revoked workers. A terminal checkpoint replay reads the acknowledged report;
   lost acknowledgements are idempotent and cannot replace immutable output.
5. The dashboard shows actual coverage intervals, protected/candidate facts,
   uncertainty, readiness, exact diff, source/model identity and history. Humans
   acknowledge, reject or request context. Context decisions atomically queue a
   fresh capture/analysis revision; prior reports and context remain intact.

Report review is deliberately outside the execution interrupt. A blocked report
with no proposal is still reviewable. Review outcome is separate from the graph's
analysis status: acknowledging a BLOCKED report records NO_CHANGE, preserving the
original BLOCKED analysis. Neither this review nor a ready-looking model response
creates action authority. Positive approval/adoption remains HTTP 503; no execution
port is wired. Phase 4 will independently implement/revalidate that transaction.

This extends the same private governance database, scoped credentials, server
clocks and immutable audit trail. Original `/governance/reviews` records remain
separate proposal-oriented intake; blocked previews are stored with their analysis
run, not promoted into an execution review. No test ledger or recording executor
is used by the service worker. Its verification adapter returns unknown.

## Laptop setup and run

From the repository root, preserve your existing `.env` and working cluster.
These steps start services; they do not apply/recreate Kubernetes resources.

```bash
uv sync --locked --inexact --extra verification
```

The default install uses Ollama without compiling llama.cpp. See `docs/models.md`
for the optional GGUF/vLLM profiles. Keep the API/dashboard on loopback for a local
demo; use authenticated TLS for a remote deployment.

Set these in `.env` (use the same cluster ID in the collector declaration):

```dotenv
GUARDIAN_CLUSTER_ID=client-dev
GUARDIAN_GOVERNANCE_DB=data/guardian/governance.sqlite3
GUARDIAN_AUTH_FILE=/absolute/path/to/Guardian/data/guardian/reviewers.auth.json
GUARDIAN_MODEL_PROFILE=agents/guardian/config/dev-laptop.toml
POD_REVIEW_ENABLED=false
```

Use real absolute paths for private files. `POD_REVIEW_ENABLED=false` reserves the
laptop GPU for graph analysis; enable advisory monitoring separately if desired.
Do not label a namespace controlled unless the operator has actually established
that all consumers are known. `GUARDIAN_CONTROLLED_NAMESPACES=guardian-demo` is
only an isolated-pilot attestation, never a way to bypass missing workload tests.

Issue separate human and worker credentials; tokens print once into private files:

```bash
umask 077
mkdir -p data/guardian
.venv/bin/python -m scripts.guardian_auth --registry data/guardian/reviewers.auth.json issue \
  --actor reviewer --kind human --cluster client-dev --namespace guardian-demo \
  --permission read --permission review > data/guardian/reviewer.token
.venv/bin/python -m scripts.guardian_auth --registry data/guardian/reviewers.auth.json issue \
  --actor analysis-worker --kind service --cluster client-dev --namespace guardian-demo \
  --permission read --permission publish --permission deliver > data/guardian/worker.token
```

In separate terminals:

```bash
# Model process (if Ollama is not already running)
OLLAMA_MODELS="$PWD/data/ollama-models" OLLAMA_NUM_PARALLEL=1 OLLAMA_MAX_LOADED_MODELS=1 OLLAMA_MAX_QUEUE=4 ollama serve
ollama pull qwen3.5:4b
.venv/bin/python -m scripts.guardian_model_smoke

# Redis (use the existing local service, or a local demo container)
docker run --rm --name guardian-redis -p 127.0.0.1:6379:6379 redis:7-alpine

# Backend: requires readable kubeconfig and Redis; model stays in its own process
.venv/bin/uvicorn backend.app.main:app --host 127.0.0.1 --port 8000

# Dedicated worker: code uses HTTP ports, no Kubernetes client is wired
.venv/bin/python -m agents.guardian.service_worker \
  --backend http://127.0.0.1:8000 --token-file data/guardian/worker.token \
  --cluster client-dev --namespace guardian-demo --directory data/guardian/worker

# Dashboard
.venv/bin/streamlit run frontend/main.py --server.address 127.0.0.1
```

Run the independent collector with the actual operator-approved audit policy and
source declaration as described in `docs/evidence.md`. Without it, reports must
show unavailable coverage. Do not edit completeness/behavior fields to make a
demo pass. No live workload behavior checks have been supplied by Phase 3.

Open the dashboard's **Analysis and review** page, enter the human token from
`data/guardian/reviewer.token`, select its authorized namespace, tick **Start an
analysis**, choose a Role and queue it. The initial window explicitly ends at the
available collector watermark (or shows missing coverage); a week means seven
actual days. Historical report browsing does not require a live inventory request.
Refresh reports, inspect evidence and record a nonwriting review. Request context
to observe a new case revision with fresh evidence/model calls; the old report
remains available. Approval is visibly disabled. Use **Capture fresh evidence and
analyse again** after expiry; old credentials/decisions cannot renew authority.

Optional automatic analysis: set `GUARDIAN_ANALYSIS_NAMESPACES=guardian-demo` for
operator-approved namespaces. It watches previously requested cases, captures
material RBAC/UID/consumer/workload changes and schedules fresh revisions (hourly
periodic default). It compares against the pre-inference capture, not its first
poll; resourceVersion-only churn does not trigger a revision. The cursor is an
observation, never approved desired state. New namespaces/targets are not silently
added. Unsupported and failed captures remain explicit investigation cases.

## Verification

```bash
.venv/bin/python -m unittest discover -s tests -q
GUARDIAN_RUN=$(mktemp -d)
.venv/bin/python -m agents.guardian.demo --directory "$GUARDIAN_RUN" --skip-tests
.venv/bin/python -m scripts.guardian_model_smoke
```

The first command covers the real HTTP ports/graph/SQLite producer and consumer
contracts, credential scope, queue limits, fencing/restart/deadlines, lookup and
repair budgets, exact preview publication, lost completion acknowledgements,
immutable report/revision history, atomic context intake, review races/expiry,
material-change scheduling and actual Streamlit review controls. Kubernetes reads
and model answers are fixture boundaries in the deterministic test suite.
The second remains the explicitly synthetic module/recording-backend demo; it does
not establish deployment or action acceptance. The third uses the actual model.

On 29 October 2026, real local `qwen3.5:4b` also traversed the HTTP ports with
synthetic inventory/audit evidence: the incomplete case returned a validated
investigation and no removal; the candidate case returned a validated investigator,
planner and exact blocked preview (two model calls). An earlier unconstrained
output attempted an ineligible removal and was rejected. Decoding now mirrors the
existing ID/eligibility validator while retaining abstention choices; independent
schema/domain validation still runs. These are functional smoke checks, not the
held-out benchmark or live-cluster acceptance.

The initial durable deployment supports one host/local SQLite persistent disk,
not multiple writers over a network filesystem. Worker mounts/OS identities,
measured capacity/latency, pinned model digest, external encrypted copies and key
backup/restore, clean Helm deployment and live end-to-end acceptance remain
Phases 4–6. Report archive pins explicitly disclose external-copy verification as
pending. No Kubernetes writes have been performed for this phase.
