# Guardian LangGraph orchestration

This module supplies the bounded evidence-to-report graph used by the integrated
Guardian analysis worker. It includes deterministic facts/policy checks,
investigator/planner stages, scoped read-only evidence tools, structured model
adapters, durable budgets/checkpoints and revision/receipt-consumer contracts.

The merged backend now supplies real evidence/jobs, scoped authentication,
governed action preparation and conditional execution. Start with the
[project overview](../../README.md), [analysis guide](../../docs/analysis.md) or
[complete demo runbook](../../docs/demo-runbook.md). This module's development
CLI and recording demo are separate from the deployed execution workflow.

## Deployed service boundary

`service_worker.py` claims jobs through scoped HTTP APIs, uses a server-pinned
model configuration and backend-owned budgets, saves per-run checkpoints and
publishes immutable reports under a live lease. It has no Kubernetes actuator.
The configured default model is Ollama `qwen3.5:4b`.

The backend independently prepares exact actions from source reports, obtains a
scoped human decision and executes/verifies the conditional patch. A saved preview
can remain `BLOCKED/readiness_incomplete` because the inference worker deliberately
has no real execution-verification port. Its proposed candidate may still be
useful for separate backend preparation. See [execution.md](../../docs/execution.md).

## Graph and constraints

The ordinary path loads evidence, builds deterministic permission facts and risk,
runs an investigator, optionally obtains bounded context, selects a strategy,
runs a planner and deterministically renders/validates exact rules. Unknown or
protected grants cannot become eligible through model text. The model emits known
IDs, not executable YAML or commands.

The reusable graph also supports adoption, side-effect-free review interrupts,
validated governed-decision consumers and receipt reconciliation. The production
preview worker does not wire those routes as a direct executor. Baseline
activation and recovery authority remain backend-owned.

Defaults bound model calls to six, tool lookups to two rounds/four calls and
repairs to one per stage. Calls are durably reserved before dispatch; crashes do
not reset budgets. Checkpoints require compatible graph/state/validator/policy
versions and the same model configuration fingerprint. Do not edit stamps to
resume an incompatible review.

## Install and verify

From the repository root:

```bash
uv sync --locked --extra verification
.venv/bin/python -m unittest discover -s tests/orchestrator -v
GUARDIAN_RUN=$(mktemp -d)
.venv/bin/python -m agents.guardian.demo --directory "$GUARDIAN_RUN" --skip-tests
```

The demo uses synthetic evidence, scripted responses and recording boundaries.
It performs no cluster writes and cannot activate a real approved baseline.
`EXECUTION_REQUESTED` in that demo is not verified live remediation. Use a fresh
output directory to preserve earlier evidence/results.

For a real-model development case, with Ollama running and the model downloaded:

```bash
REAL_RUN=$(mktemp -d)
.venv/bin/python -m agents.guardian.evaluate --directory "$REAL_RUN" \
  --scenario complete --profile agents/guardian/config/dev-laptop.toml
```

This uses real inference over synthetic development evidence, not a live cluster
or held-out benchmark. A nonzero result can represent an honest invalid/blocked
or unhelpful model result. Do not replace it with scripted success.

[Models](../../docs/models.md) documents the default and optional llama.cpp/vLLM
profiles. The `local-model` extra installs llama.cpp only when deliberately
selected. There is no hard-coded personal GGUF path in the supported workflow.

## Developer interfaces

```bash
.venv/bin/python -m agents.guardian.runner --help
.venv/bin/python -m agents.guardian.runner schema
.venv/bin/python -m agents.guardian.service_worker --help
```

The file runner's `start/status/decide/resume/renew/next` commands exercise local
simulation and compatible revisions. Its test decisions cannot authorise real
captured evidence or enable production execution. Actual action decisions use
the dashboard or `scripts.guardian_review` against the governed backend.

`contracts.py`, `schemas.py` and `contracts/compatibility.json` define the strict
wire contracts. `ports.py` describes interfaces; `adapters/backend.py` supplies
the service HTTP implementation. Supplemental pod evidence validates scope,
identity and time; network/runtime context never substitutes for API usage
coverage. [HANDOFF.md](HANDOFF.md) records current component responsibilities and
[VERIFY.md](VERIFY.md) has focused commands.

## Evaluation and limits

The development evaluator and `eval/guardian` frozen comparison keep expected
labels outside model inputs/runtime images. The wider validator-v2 development
run exposed unsafe accepted advice; the retained results and shared validator-v3
correction are in [evaluation.md](../../docs/evaluation.md). Neither schema-valid
output nor the local live pilot demonstrates LLM superiority or universal safety.
Independent lab reproduction, reviewed held-out evaluation and live recovery
remain separate acceptance gates; see [project-report.md](../../docs/project-report.md).
