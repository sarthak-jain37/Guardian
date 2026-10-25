# 0005: Development evaluation and producer handoff

Status: module tooling implemented; real team/lab acceptance pending.

The versioned bounded-stage prompt advances to v4. It separates exposure severity
from operational necessity, reads each permission's own usage/eligibility and
discourages redundant lookups. Generic decision examples contain no case IDs,
resources or expected fixture patch. Independent eligibility/citation/plan checks
remain authoritative; the model may still abstain. ModelConfig/ModelResult advance
to v2 to coordinate the changed prompt contract. Older prompt checkpoints/configs
remain incompatible. Exact inputs and hashes preserve unsuccessful experiments.

`evaluate` runs visibly synthetic development scenarios or actual sanitized
captured exports. Development expectations are applied only after the graph and
never enter model messages/evidence. An always-abstaining result fails usefulness.
Captured exports have no invented ground truth and remain unscored previews.
Failures, provider identity, config/source/evidence hashes, dirty state, duration
and token metadata are retained. This is not the held-out team benchmark or a
deterministic-versus-LLM comparison result.

The bounded pod-context adapter consumes main's current read-only pod-evidence
export and validates explicit identity/SA/time/scope. Only supplemental context
and references are added. It cannot turn network/runtime records, health flags
or missing series into zero usage, complete coverage or a required permission.
Tests invoke the actual producer helpers without altering those implementations.

`demo` runs the current repository tests, validates exported schemas, and exercises
separate-process analysis/review/restart/worker routes plus development scoring.
Its artifacts explicitly state synthetic scope, no cluster writes and no lab
acceptance. Backend receipt/recovery scenarios are recording-port contract tests.
The file CLI still has no production queue or reviewer authentication.

Worker configuration, permissions, persistence, driver semantics, capability
scope and remaining lab gates are in `agents/guardian/HANDOFF.md`. Verification
commands are in `agents/guardian/VERIFY.md`. No backend, telemetry, frontend,
Kubernetes executor or Helm implementation is changed by this slice.
