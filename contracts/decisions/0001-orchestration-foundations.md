# 0001: Orchestration foundation compatibility

Status: proposed for component review; module implementation only.

Plan v4.0 sections 2.11, 5, 8 and 9 require versioned boundaries, generated schemas
and explicit resume compatibility. The existing demo has UsageSummary semantic
validation and durable review, but no persisted compatibility stamp or strict
report/readiness envelope.

The phase-1 release adds request v2 (binding optional baseline and policy), report
v2, readiness v1, separate lifecycle vocabularies and required run-version stamps.
Schemas come from the same Pydantic definitions used at runtime:

```bash
.venv/bin/python -m agents.guardian.runner schema
```

`contracts/compatibility.json` lists producer/consumer review status. Its base
commit identifies the preceding demo. `release_commit` remains null until this
release is committed and collectively accepted; it does not invent sign-off or
declare team-wide M1 complete. Production decision, verification, recovery and
receipt schemas still need agreement with their accountable owners. The exported
test-decision contract is explicitly local simulation authority only.

Missing UsageSummary series are errors; missing usage/context stays null. Explicit
zero requires the existing exact-window, coverage, identity and progress semantic
checks. Empty optional documents and a null baseline are valid. Schema shape
alone cannot establish coverage or readiness; Python consumers must run semantic
validators and non-Python adapters must pass the same semantic fixtures.

The graph validates adapter outputs itself and binds request snapshot, cluster,
target UID, baseline and policy. Runtime compatibility binds graph/state,
validator, canonicalization and policy versions. Checkpoints without a supported
stamp cannot resume or create new local decisions. Preserve their historical
files, reconcile any already-requested backend action, and request a fresh review
revision. There is no automatic migration, new approval, baseline activation or
recovery authority in this change. Backend revision/expiry/reconciliation service
implementation belongs to its owner.

Canonicalization remains the existing sorted compact UTF-8 JSON SHA-256 encoding
with `sha256-v1:` prefixes. The stamp names this algorithm; it does not change
ordering semantics or claim RFC 8785 compliance. Approval hashes now bind the
runtime version stamp. Model/prompt metadata remains in model-stage trace output;
profile/prompt version expansion belongs to the next model integration phase.

LangGraph resumes an interrupted node from its beginning, so compatibility checks
are pure validation and the review interrupt still performs no external writes.
See [interrupt behavior](https://docs.langchain.com/oss/python/langgraph/interrupts)
and [graph migrations](https://docs.langchain.com/oss/python/langgraph/graph-api#graph-migrations).
No collector, backend, dashboard, executor, deployment or shared scanner
implementation is changed by this foundation release.
