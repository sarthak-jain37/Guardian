# 0002: Explicit adoption and review revision routes

Status: module implementation; producer/consumer acceptance pending.

Plan v4 sections 3, 8–10 require explicit baseline adoption without a removal
candidate and immutable review renewal. Phase 2 introduces request v4 with an
explicit intent, proposal v2 with an action discriminator, and local test
decision v2 with an adoption kind. Reports use v4 and checkpoint graph/state
versions advance to v4. The intermediate adoption-only commit used v3; those
saved reviews also require a fresh revision. Historical files remain preserved.

Adoption skips investigator/planner calls, binds the exact snapshot and scoped
identity to review, and contains no patch or permission removal. It does not
require zero-use evidence. Known scope/consumers, fresh snapshot context and
backend preconditions must pass. Captured previews cannot obtain test authority.
The BaselinePort receives only stored proposal/decision IDs and a stable action
key. Its recording adapter records a simulated request and never activates a
baseline or reports COMPLETED. The backend owner supplies the actual conditional
adoption transaction and authentication in a later integration phase.

The interrupt remains free of side effects. Model unavailability cannot prevent
an explicit adoption review when its deterministic prerequisites pass. Local
decision-kind validation prevents remediation and adoption authority from being
interchanged. Every proposal still needs its own human decision.

`RevisionRequest` v1 binds source run/proposal/revision/hash, reason and a new
case-linked run at revision +1. Context requests persist the intent before graph
completion and always run fresh analysis. Their snapshot reference is the intake
snapshot; the worker subsequently loads scoped current evidence and binds its
actual snapshot ID before analysis, allowing a later answer to be incorporated.
Renewal instead fixes the refreshed evidence hash. A changed renewal snapshot
blocks consumption; it is never silently substituted into reused analysis.

The review port atomically accepts one successor, projects EXPIRED/SUPERSEDED and
retains immutable decisions and append-only transitions. A crash after that commit
retrieves the same successor before accessing evidence again. The worker closes
the old checkpoint only after acceptance; replay cannot reopen a terminal
proposal. Backend authentication, leases, scheduler/outbox and production database
transactions remain outside this module. The local SQLite adapter exercises the
single-worker test contract only.

Reuse requires unchanged target/version, subject, binding, baseline, policy,
material context and collector/request-key semantics; retained history/citations;
no new candidate use, lost coverage, new unknown/denied requests or decreasing
counts; and successful independent investigation/plan validation. Reuse retains
the original producer and records the source run in the trace. Fresh gates,
verification, publication and human approval still apply. Changed evidence uses
fresh model stages. Already-started actions require reconciliation, never renewal.

The demo persists provider settings outside checkpoints for follow-up inference,
refuses missing real-model settings and preserves per-run evidence/results.
No model, collector, dashboard, Kubernetes service, baseline database, production
executor or Helm implementation is introduced by these review routes.
