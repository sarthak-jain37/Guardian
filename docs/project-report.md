# Guardian project report and acceptance record

Release candidate: 0.2.0rc1. Scope follows the October final plan; the September
Redis blueprint remains historical context. This is an implementation/evidence
report, updated 30 October 2026. University deployment, independent sign-off and
final model selection are not asserted to have happened.

## Problem and design

Audit-observed access alone cannot establish every future need. Guardian combines
actual usage/coverage, identity-bound RBAC inventory, deterministic protections,
bounded model interpretation, exact human review and backend-owned conditional
execution. The supported actuator changes only `/rules` on one existing dedicated
namespaced Role, with unchanged bindings. Shared/cluster-wide patterns remain
analysis cases. No baseline is silently adopted, no model response grants write
authority and no old approval is renewed by a retry.

The investigator and planner run in a separate LangGraph worker with durable
budgets/checkpoints and a scoped HTTP evidence interface. Ollama Qwen3.5 is lazy
and configurable. The backend owns the independent readiness/authority ledger,
conditional UID/resourceVersion patch, post-change SAR/application checks, scoped
baseline activation, separately consented exact recovery and durable receipts.
SQLite and local locking deliberately constrain this release to one storage host.

Actual audit stages/outcomes are deduplicated into exact half-open usage windows.
Missing telemetry never becomes covered zero. Encrypted archives, case pins and
coordinated backups retain evidence; restore invalidates authority and disables
execution until reconciliation. Backend, collector, inference and dashboard have
separate deployment identities. Inference has no Kubernetes token or raw archive
credentials. See `deployment.md`, `execution.md` and the chart for exact privileges.

## Research and scope

Kubernetes recommends least-privilege RBAC and highlights escalation risks; the
backend therefore has a deliberately bounded named-Role write/escalate grant.
Audit-based policy generation already exists in audit2rbac, whose usage guidance
also depends on exercising applications and reviewing policies. Guardian makes no
novelty claim for mining audit logs. Its research question is whether bounded
contextual interpretation adds useful grounded recommendations or reduces human
review effort over a competent deterministic baseline with common evidence/gates.
LangGraph persistence supports durable stage orchestration; it does not itself
provide authenticated human authority or a globally atomic Kubernetes transaction.

Sources: [Kubernetes RBAC guidance](https://kubernetes.io/docs/concepts/security/rbac-good-practices/),
[audit2rbac](https://github.com/liggitt/audit2rbac),
[LangGraph interrupts and persistence](https://docs.langchain.com/oss/python/langgraph/interrupts),
[Kind auditing](https://kind.sigs.k8s.io/docs/user/auditing/),
[Helm chart guidance](https://docs.helm.sh/docs/chart_best_practices/).

## Implementation and measured local checks

The repository includes versioned contracts, real HTTP adapters, bounded model
providers, immutable review/decision/history, execution/recovery state machines,
real reader/harness, images/chart, archive/backup tools, optional coordinated daily
backup, frozen A/B evaluation and this report/demo package. The latest full suite
passed 378 tests on 30 October 2026, including the later live-workflow regressions.
The earlier frozen release snapshot records its original 368 tests. Component
tests use explicit recording boundaries; they are not live-cluster safety proofs.

A separate local `guardian-release` Kind cluster was created without changing the
existing `guardian-test` cluster/default kubeconfig. Kubernetes 1.30.0, Docker
29.9.0, Helm 3.19.0, Ollama 0.40.3 and a 6 GB RTX 3050 laptop GPU were observed.
This old Kubernetes pin is a local reproducibility environment, not an endorsement
for current production. The university run must use its approved maintained
version. Guardian's six optional/live components and reader were installed with
persistent state and separate identities. Model digest:
`d8b0f5e9760cd1682034f292d7ef72ec46f432149be0df7574bf2d6e92e38c04`.

Integration uncovered and fixed real issues not proven by mocks: SDK 36's
response-map signature and header override, legitimate repeated watch stages,
scoping of unrelated audit conflicts, required harness discovery variables,
large citation menus and Kubernetes-projected backup keys. Failed attempts remain
in the local evidence/history. The actual harness verified ServiceAccount Pod
reads, initialization, normal operation and a new reader process after restart.
This is a process-restart check, not a claim of pod/node disaster recovery.

The earlier image/model route, pre-approval readiness and backup/restore results
are preserved in `release/local-verification.json`. That dated snapshot is not
the current action state. Frozen measurements are retained rather than rewritten.

### Follow-up live workflow verification on 30 October 2026

The local pilot completed the exact initial Role narrowing after an explicit
user instruction to complete the previously approved change. The decision was
submitted through the scoped governed-review API; model output did not grant
authority. The resulting receipt recorded:

| Check | Recorded result |
| --- | --- |
| Target | `guardian-release / guardian-demo / pod-reader` |
| Source run | `run-ea472d505325402685f85ac3c77bfd5d` |
| Action | `proposal-prepare-d57e04861f584042bdb0dec50b3ab986` |
| Receipt | `receipt-9a9648812ee940bfb588bbdc21a1b18b` |
| Outcome / apply / verification | `completed / confirmed / passed` |
| Baseline activation | `true` |
| Confirmed post-change resourceVersion | `60664` |
| Independently checked Secret read / Pod read | `no / yes` |
| Live API audit | 39 checks passed |
| Repository tests | 378 passed; latest complete run took 42.805 seconds |

Actual Streamlit checks covered report acknowledgement/rejection, fresh analysis,
context revisions, governed rejection and outcome acknowledgement. The final
governed context request queued revision 4; opening it displayed a real Ollama
analysis that finished `NO_CHANGE` after the successful narrowing. The terminal
resume/watch paths read the same saved outcome instead of generating new authority.
All six pilot deployments were healthy at the final check.

This audit found and fixed long-window coverage lock contention, concurrent
functional-check collisions, stale execution evidence, windows beyond the source
watermark and misleading approval/outcome displays. The earlier stopped action
remains recorded as stale. Current success does not rewrite that failure.

Raw pilot evidence/credentials remain private under ignored `data/pilot/`.
Results above describe the observed local run, not a guarantee about a future
cluster state. The isolated RBAC pilot did not install Hubble/Tetragon, and does
not establish live eBPF coverage. Later drift execution, live recovery and
independent university acceptance remain separate gates.

## Development comparison: failures included

The frozen synthetic set has 60 families: 20 development and 40 held-out. Labels
are provisional pending two independent human reviews. Exact labels and expected
removals are outside runtime evidence/images. Predictions are frozen before the
evaluator reads labels. See `evaluation.md` for reproduction and definitions.

The **original validator-v2** 20-family development measurement was:

| Metric | Deterministic A | Qwen3.5 4B B |
| --- | ---: | ---: |
| Families / runs | 20 / 20 | 20 / 20 |
| Correct accepted removals | 10 | 8 |
| All accepted removals | 10 | 10 |
| Accepted known-required removals | 0 | 2 |
| Useful proposal coverage | 10/10 | 8/10 |
| Appropriate deferral | 10/10 | 8/10 |
| Model calls | N/A | 35 |

B failed the frozen safety criterion on two documentation-only rare workflows.
Its schema/domain-valid stage count was 26/30 first pass and 28/30 final; four
repair calls occurred, with zero invalid permission IDs among 79 emitted IDs.
These are syntax/domain checks, not semantic grounding scores. Its active-path
p50/p95 was approximately 24.74/400.23 seconds; the tail includes real resource/
provider failures during an overloaded laptop run. Those failures are retained.
A's active implementation is rule/report construction; B includes graph,
checkpoint and inference overhead. Neither is pure decoder latency.

An earlier matched three-family smoke repeated three times produced 6/6 correct
removals, 0 accepted required removals, 3/3 appropriate rare-path deferrals, 15
calls, zero repairs and p50/p95 21.85/25.69 seconds. Its family-level upper 95%
Wilson bound for zero unsafe families out of three is about 56%, illustrating why
that small successful sample cannot establish safety or superiority.

The wider negative result takes precedence over the earlier smoke. Validator v3
now conservatively blocks executable removal when ordinary documentation signals
an unresolved rare/periodic workflow. Both arms and the backend share that gate;
it is not delegated to model interpretation. Source/version fencing requires fresh
analysis rather than silently upgrading old proposals. Regression tests cover the
finding. This development correction is not a held-out pass. The English cue rule
is limited; unseen language/phrasing still needs contextual/human validation.

No held-out results, independently reviewed grounding, human review-time study,
actual university allocation or same-family model-size comparison have been
fabricated. Qwen3.5 4B is a laptop candidate, not a measured winning lab model.
The current evidence does not show an LLM advantage over A. A remains viable.

## Remaining human acceptance steps

1. Inspect/reproduce the completed initial action from the runbook, retaining the
   exact receipt and access/application checks. A new owned scenario needs a new
   explicit review; the existing successful Role is already narrowed. Do not reset
   it merely to repeat a verification check.
2. Introduce only the owned scenario drift, review its distinct proposal, and
   verify the second outcome. Rehearse stale/pause/incident/manual cases; a real
   recovery drill needs a controlled meaningful failure and explicit consent.
3. Have another teammate reproduce the tagged candidate from the runbook. Obtain
   actual university audit/storage/model/network authorization, measured capacity,
   a separate durable backup/archive copy and separate key recovery. A same-host
   restore drill is not disaster-recovery sign-off.
4. Have two humans independently review/reconcile the synthetic labels and freeze
   their hash. Run A and each approved same-family model setting on held-out
   families at least three times, without tuning to held-out outputs. Add a small
   live subset and blinded grounding/question/review-effort measurements.
5. Add the actual signed results, environment versions, screenshots/recording and
   conclusions to this report/slides. Tag/publish a final release only after those
   gates pass. The current tag/bundle is a local candidate; registry publication
   and university acceptance are not implied.

## Limits

Finite collection/behavior checks do not prove every future dependency; UID/RV
conditions do not freeze all bindings/workloads. Identity/source ambiguity, stale
context, unknown apply or unhealthy verification stop new writes or require
manual intervention. Recovery restores only captured rules under a separate exact
contract, never arbitrary baseline rollback. Multi-object remediation, additive
bindings, ClusterRole mutation, autonomous approvals, a universal NLP dependency
proof and multi-host SQLite execution are outside this release. Storage/RPO and
365-day retention remain measured provisioning targets rather than past history.
