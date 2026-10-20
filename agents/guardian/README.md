# Guardian LangGraph module demo

## Plan v4 foundation update

The next implementation is divided into contracts/compatibility, graph review
routes, model/tool integration, backend governance adapters, then real-model/lab
validation. Phase 1 implements the contract and checkpoint foundation. The
personal phase plan remains in Git-ignored `personal_docs/langgraph-part2-phases.md`.

Requests now use `guardian.analysis-request.v2` and bind the optional baseline and
policy version as well as snapshot/cluster/target UID. Reports use
`guardian.report.v2` with typed permission facts, readiness and runtime versions.
The three lifecycle vocabularies are separate; defining their values does not
implement backend lifecycle persistence. The graph independently validates exports
from every evidence adapter before analysis.

`schema` exports all ten boundary/model schemas from the runtime definitions.
See `contracts/compatibility.json` and
`contracts/decisions/0001-orchestration-foundations.md` for producer/consumer review
status and wire versions. Shared component acceptance is pending. Production
decision/verification/recovery/receipt integration belongs to subsequent phases;
the exported test-decision contract remains simulation-only.

Checkpoints require compatible graph/state/validator/canonicalization/policy
versions. Earlier unstamped reviews can be inspected with `status`, which reports
`compatible=false`; `decide` and `resume` refuse them. Preserve old directories,
reconcile any already-requested real backend action, and use a fresh reviewed
revision. There is no automatic checkpoint migration or authority renewal.

This implements the first orchestration slice of the v3 design. It demonstrates useful initial analysis without an approved baseline, separate investigator/planner stages, deterministic policy rendering, and a restartable review flow. It does not implement collector storage, backend authentication, the production decision ledger, a Kubernetes executor, baseline activation, recovery, or deployment.

All built-in evidence is **synthetic fixture data**. Scripted model responses are explicitly labeled `scripted-test`. The optional llama.cpp adapter runs real inference over the same fixture, without hidden required/unnecessary labels. Every review/decision/execution record is a **local simulation**. The recording executor performs no cluster writes and cannot activate a baseline. Captured evidence accepts preview mode only; missing backend verification prevents execution review.

## Setup

From the repository root, install the locked module dependencies:

```bash
uv sync --inexact
```

CPU tests need no model or GPU:

```bash
uv run --no-sync python -m unittest discover -s tests/orchestrator -v
```

For real local inference, install the optional runtime and configure a GGUF file:

```bash
uv sync --inexact --extra local-model
export MODEL_PATH=/absolute/path/to/model.gguf
```

The adapter initializes lazily in a separate process with a per-request deadline. It uses CPU inference, recorded decoding settings, a bounded context, and schema-constrained JSON followed by independent Pydantic/reference/eligibility validation. Runtime string bounds are omitted from the llama.cpp grammar to avoid its grammar-expansion limit; they remain enforced by the independent validator. The grammar requires one assessment per supplied permission ID without choosing its action. Runtime failure never becomes a scripted success.

## Demo commands

Choose a new directory for each case so prior evidence and results are preserved. Default output is under the existing Git-ignored `personal_docs/` folder. Check ignore rules if you choose another path; checkpoints and actual evidence exports are local artifacts.

```bash
uv run --no-sync python -m agents.guardian.runner --directory personal_docs/demo-initial start
uv run --no-sync python -m agents.guardian.runner --directory personal_docs/demo-initial status
```

These are separate processes. The second command retrieves the same pending review without another model call. Inspect `result.json`, `role-preview.yaml`, and `binding-preview.json`. The patch changes only Role rules, with UID/resourceVersion tests; the binding preview is unchanged.

Record a local test rejection, then copy the returned decision ID into resume:

```bash
uv run --no-sync python -m agents.guardian.runner --directory personal_docs/demo-initial decide reject
uv run --no-sync python -m agents.guardian.runner --directory personal_docs/demo-initial resume --decision-id RETURNED_ID
```

On a separate case, use `decide approve_remediation` and resume its returned ID to demonstrate **one recording-fake request**. The receipt explicitly says `cluster_write_performed=false`, `verification_performed=false`, and `baseline_activated=false`. Duplicate delivery cannot create another recorded action. A resume boolean or forged decision ID cannot authorize even this simulated request.

Demonstrate blocked evidence:

```bash
uv run --no-sync python -m agents.guardian.runner --directory personal_docs/demo-gap start --scenario coverage-gap
uv run --no-sync python -m agents.guardian.runner --directory personal_docs/demo-monthly start --scenario monthly
uv run --no-sync python -m agents.guardian.runner --directory personal_docs/demo-missing start --scenario missing-usage
```

Run actual inference instead of scripted responses:

```bash
uv run --no-sync python -m agents.guardian.runner --directory personal_docs/demo-model start --model llama-cpp --threads 4 --timeout 180
```

The default schema uses separate investigator/planner outputs. Reports retain model outputs, validation failures, producer, stage latency, token usage where available, and model/prompt metadata. A useful run should contain a nonempty proposal; a valid but unhelpful all-retain output is reported honestly. Built-in frozen fixtures explicitly configure a 600-second source-lag allowance for slow CPU smoke tests; the shared policy default is 60 seconds. Neither value proves production safety.

## Team integration boundary

Generate the schemas for a teammate's export:

```bash
uv run --no-sync python -m agents.guardian.runner schema
```

`contracts/usage_summary_v1.py` is the shared collector boundary, including exact clipped UTC hourly buckets, coverage partitioning, effective identity, outcome distinctions, carried authorizations, bounds and unknown values. It validates an export; it does not aggregate or deduplicate audit logs. The collector owner supplies the actual summary and its source/health references.

`EvidenceBundle` requires a target identity/version envelope, subject, optional binding/context/usage, nullable approved baseline, policy and source references. For the pilot, include separate keys for `get pods`, `list pods` and `get secrets`, using `any_name` projections for unrestricted get grants. The supported input is bounded to 128 permission combinations. Unsupported wildcards, name restrictions, shared/unknown consumers, alternate grants and missing candidate evidence block narrowing.

Load an actual sanitized export labeled `source_mode="captured"`:

```bash
uv run --no-sync python -m agents.guardian.runner --directory personal_docs/demo-capture start --evidence /absolute/path/to/evidence.json --model llama-cpp
```

Captured evidence produces a draft/blocked preview unless the later real governance/verification integration exists. It cannot acquire authority from the local test decision store. The external component interfaces are in `ports.py`; current adapters are confined to this module. The existing ingestion processor, API, dashboard, audit policy and Kubernetes service are unchanged.

## Implemented checks and limits

- No baseline or permission answer sheet is required for the fixture's useful initial proposal.
- Observed authorization use, including authorized errors and carried requests, protects a capability. Unknown/denied attempts, missing coverage, stale sources and relevant unexercised cycles prevent its removal.
- Risk severity comes from the existing pure scanner; the model cannot erase its findings. Severity is separate from evidence completeness and change risk.
- Rendering preserves original rule associations and their cross-product semantics. Exact selected removals form a subset; no model YAML is executed.
- The review interrupt contains no side effects. SQLite checkpoints and separate local test records survive process restart.
- Decisions bind revision, hashes, target, policy, kind and independent review/execution deadlines. Current evidence/readiness is checked again before recording a request.
- Durable model-call reservations are committed before inference, so a crashed call consumes the budget. Lookup rounds/calls and one repair per stage are bounded; the longest supported route fits the recursion backstop.
- Material evidence refreshes are conservatively rejected using an exact snapshot hash. Fine-grained non-material refresh handling is deferred.
- `request_context` closes the old run as stale; the caller must start a fresh revision/run. Automatic renewal/revision scheduling and expired-review cleanup are backend integration work.
- Simulated approval ends at `EXECUTION_REQUESTED`, never a claimed verified `COMPLETED` deployment. No recovery authority is granted.

See the personal scope document for the meeting sequence and teammate messages. It intentionally remains in Git-ignored personal documentation.
