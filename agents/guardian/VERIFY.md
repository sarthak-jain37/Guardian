# Verify the LangGraph component and integrated workflow

Run commands from the repository root with Python 3.11+. Use merged source from
`main`; preserve existing `.env`, credentials, checkpoints and cluster state.

## Install and run the automated tests

```bash
uv sync --locked --extra verification
.venv/bin/python -m unittest discover -s tests -q
```

The latest complete local run on 30 October 2026 passed 378 tests. The current
count can grow; check the actual run output and `OK`. The suite uses explicit
model/cluster recording boundaries and is not a live safety proof. Some HTTP and
subprocess tests need normal local socket/process access; a restricted execution
sandbox can stall them before producing results.

Focused groups:

```bash
.venv/bin/python -m unittest discover -s tests/orchestrator -v
.venv/bin/python -m unittest tests.test_analysis tests.test_review_workspace -v
.venv/bin/python -m unittest tests.test_execution tests.test_execution_ports tests.test_execution_workspace -v
.venv/bin/python -m unittest tests.test_acceptance_cli -v
```

These cover contracts, schema/domain validation, scoped tools, durable budgets,
checkpoint/revision replay, HTTP worker fencing, actual Streamlit control logic,
exact authority, conditional apply/recovery protocol and terminal parity. No live
cluster writes are needed for these deterministic checks.

## Synthetic recording demo

```bash
GUARDIAN_RUN=$(mktemp -d)
.venv/bin/python -m agents.guardian.demo --directory "$GUARDIAN_RUN" --skip-tests
.venv/bin/python -m json.tool "$GUARDIAN_RUN/demo-summary.json"
```

Expect `passed: true`, twenty validated schemas, explicitly synthetic scope and
`cluster_writes_performed: false`. `--skip-tests` records `tests_run=false`; it
must not be described as another full test run. Omit that flag if the demo should
run the tests itself. Preserve the output directory for provenance/history.

The demo exercises reject, recording approval, acknowledgement, adoption, context
revisions, blocked evidence, forged decisions and duplicate worker delivery.
Recording approval ends at `EXECUTION_REQUESTED`; adoption does not activate a real
baseline. Those labels are intentional, not incomplete live remediation.

For individual file-runner commands:

```bash
.venv/bin/python -m agents.guardian.runner --help
CASE_DIR=$(mktemp -d)
.venv/bin/python -m agents.guardian.runner --directory "$CASE_DIR" start
.venv/bin/python -m agents.guardian.runner --directory "$CASE_DIR" status
```

Use a genuinely fresh directory to preserve earlier runs.
`decide/resume/renew/next` remain local simulation
commands. They cannot authorise a real captured-evidence mutation.

## Real model development check

With the intended Ollama endpoint running:

```bash
ollama pull qwen3.5:4b
.venv/bin/python -m scripts.guardian_model_smoke
REAL_RUN=$(mktemp -d)
.venv/bin/python -m agents.guardian.evaluate --directory "$REAL_RUN" \
  --scenario complete --profile agents/guardian/config/dev-laptop.toml
```

This checks real inference with synthetic evidence. Inspect provider/digest,
stage validation, selected operations, latency and failures. Do not replace
invalid/blocked outputs with a scripted response. Optional GGUF/vLLM profiles are
documented in [models.md](../../docs/models.md); no personal downloaded model path
is assumed. Use [evaluation.md](../../docs/evaluation.md) for the distinct frozen
A/B protocol and held-out label-review requirements.

## Captured evidence and the real pilot

The selected-pod telemetry response is not itself a complete EvidenceBundle or
UsageSummary. Only a valid scoped captured export can enter the development
preview path. Optional pod context adds validated context without manufacturing
usage/coverage or authority. See [README.md](README.md) and [HANDOFF.md](HANDOFF.md).

For actual collection, authenticated report review and model jobs, follow
[analysis.md](../../docs/analysis.md). For the packaged live demo and terminal/UI
exact action approval, follow [demo-runbook.md](../../docs/demo-runbook.md).

Inspect the exact run/proposal and actual receipt. A completed live narrowing must
show confirmed apply, passed verification and baseline activation, with independent
effective access checks. The current pilot has achieved that initial result;
[project-report.md](../../docs/project-report.md) records its dated identifiers.
Fresh analysis after narrowing can correctly return `NO_CHANGE`.

Stale/manual outcomes are not successes; preserve their reasons. Live recovery,
independent lab reproduction and reviewed held-out evaluation remain separate
acceptance gates. Do not alter a known-used grant or install a fake harness to
manufacture a passing demonstration.
