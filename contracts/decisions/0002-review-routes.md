# 0002: Explicit adoption and review revision routes

Status: module implementation; producer/consumer acceptance pending.

Plan v4 sections 3, 8–10 require explicit baseline adoption without a removal
candidate and immutable review renewal. Phase 2 introduces request v3 with an
explicit intent, proposal v2 with an action discriminator, and local test
decision v2 with an adoption kind. Reports use v3 and checkpoint graph/state
versions advance to v3. Older saved reviews remain incompatible and preserved.

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
