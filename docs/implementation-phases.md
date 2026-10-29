# Guardian project completion

Baseline: Guardian Final Team Implementation Plan v4.0, 19 October 2026.
The September drift blueprint supplies historical context; the final plan governs
approval, evidence, execution and recovery. Branch: `feat/guardian-project-completion`.

These six phases complete the integrated project. They follow the earlier five
LangGraph module phases, which supplied tested consumers and development adapters.
Completion of a module or a phase is not a claim of live lab acceptance.

| Phase | Work | Exit checks | Status |
| --- | --- | --- | --- |
| 1. Governance foundation | Retire unsafe mutation paths; stop automatic adoption; scoped authentication; immutable review/decision/history storage; atomic resume outbox; pause/incident records | Unauthorized/self-approved/stale/conflicting requests blocked; crash/race/replay/lease tests; no cluster writes | Implemented; see governance guide |
| 2. Evidence and history | Correct inventory/hash semantics, effective grants and consumers; real hourly UsageSummary; stages/outcomes/dedup/coverage; context freshness; raw archive/catalog/retrieval and retention | Complete/gap/quiet/watch/late/recreated-identity fixtures; exact window queries and archive round-trip | Implemented locally; live collection/backup acceptance remains Phase 5 |
| 3. Integrated analysis and review | Shared producer/consumer contracts; real EvidencePort; dedicated LangGraph worker, durable budgets/queue, scheduling and revisions; backend report projection; authenticated dashboard; Ollama native structured-output adapter and Qwen3.5 4B laptop profile, shared with advisory monitoring, retaining optional llama.cpp/vLLM | Actual evidence traverses analysis, exact proposal and durable human review; restart/expiry/duplicate deliveries preserve meaning; ingestion remains responsive; Ollama schema/deadline/error tests and an explicitly labeled available-model smoke test | Implemented locally; live deployment/benchmark acceptance remains Phases 5–6 |
| 4. Governed action and recovery | Independent preflight; forced dry-run; exact conditional one-Role rules update; SAR/application checks; scoped baseline activation/adoption; explicit consented exact recovery and notifications | Successful initial hardening and later drift; stale/expired/revoked/paused/incident cases cause zero writes; uncertain responses reconciled; recovery verified | Pending |
| 5. Deployment and lab pilot | Images, Helm, model endpoint, scoped identities, persistent storage, disabled-execution defaults, capacity/encryption/backup/restore, pinned demo workload/reset | Clean install/restart/upgrade; live real-model pilot; recovery/manual fallback; archive and backup restore with measured results | Pending |
| 6. Evaluation and release | Frozen development/held-out scenario families; competent deterministic/LLM comparison; attack catalog, measured results, report, slides, runbook and tagged release | Label isolation; useful narrowing and safety/grounding/latency results; independent deployment reproduction; rehearsed demo/reset | Pending |

## Delivery rules

- Make focused commits after meaningful passing checks; retain failures and limits.
- Preserve existing observation/history data. Never infer authority from an old
  baseline, model response, userAgent, graph resume or severity score.
- Keep current, approved and proposed state distinct. Activate desired state only
  after verified execution or separately authenticated and revalidated adoption.
- Forward scope is one existing dedicated namespaced Role with supported rules;
  bindings remain unchanged. Analysis can explain unsupported wider patterns.
- Recovery restores this action's captured rules under separate explicit consent,
  a bounded trigger/deadline and current conditions. General baseline reversion
  and cluster-wide/multi-object execution remain outside the final release.
- Runtime evidence never receives evaluation labels or expected patches.
- Test doubles, synthetic demos, real model smoke tests and live-cluster results
  are recorded separately. External lab allocation and acceptance remain measured
  deployment gates, not facts that local tests can establish.

## Phase 1 boundary

The new backend ledger accepts scoped non-simulated report/proposal publications
as immutable review intake. Humans can reject, acknowledge or request context;
each accepted decision atomically creates a durable resume record. Phase 3 now supplies separate analysis jobs and nonwriting report review
(including report-only blocked cases); see `docs/analysis.md`. Positive approvals and baseline
adoption return `503 governed_executor_unavailable`; there is no enable flag.
The phase 4 executor must independently establish readiness/current authority.

The ledger uses private local SQLite with WAL/full synchronization and separate
connections/transactions, distinct from Redis and graph checkpoints. It supports
one host with local persistent disk. Shared/multi-host DB deployment is not yet
claimed; choose the tested lab topology or implement a shared database adapter in
phase 5. Read-only legacy Redis history does not become ledger authority.

Phase 1 tests cover the retired entrypoints, automatic-adoption regressions,
credential expiry/revocation/scope, immutable publications, decision races and
idempotency, atomic failure rollback, bounded queues, restart, delivery fencing,
and operator-owned holds. Local tests perform no Kubernetes writes.
