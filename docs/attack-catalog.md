# Reproducible attack and failure catalog

Setup/reset affects only the isolated `guardian-release` cluster's owned
`guardian-demo/pod-reader` Role. Source/evidence/decision history is preserved.
No Secret bodies, stolen credentials, real exfiltration or destructive attack is
needed. Local protocol cases below use recording boundaries unless explicitly
marked live. Unknown/unrun outcomes are not reported as successes.

| ID | Capability / condition | Setup and expected control | Actual evidence / status |
| --- | --- | --- | --- |
| AC-01 | Initial excess Secret read grant | Install separate over-permissioned reader. Collect actual reads, analyze and show exact narrowing. Human approval required. | Real local collection, Qwen3.5 and app checks exercised; final proposal/approval status in release verification JSON. Human completion remains separate. |
| AC-02 | Later risky grant addition | After verified initial baseline, run `guardian_pilot scenario drift --confirm-disposable`; analyze again. | Setup/reset implemented; later-drift execution passes recording integration test. Live second approval remains human work. |
| AC-03 | Necessary Pod read | Actual reader uses its ServiceAccount for its own Pod. | Live audit shows authorized reads; tests protect observed permissions. No Pod permission removal requested. |
| AC-04 | Rare scheduled access | Frozen natural workflow documentation and structured unexercised-operation families. | Development comparison reports actual retain/defer/removal outcomes; labels provisional, no claim of months of live collection. |
| AC-05 | Shared / additive grants | Frozen alternate-grant/unknown-consumer families; do not grant real cluster-admin. | Deterministic/graph tests block execution. Unsupported wider patterns are detect/explain only. |
| AC-06 | Incomplete telemetry | Stop the dedicated collector or use the frozen gap case. Restore it and collect a fresh interval. | Missing/gap/stale sources block narrowing; actual old audit-policy/SDK connectivity failures retained during pilot integration. |
| AC-07 | Stale approval / external edit | Review exact change, then run explicit owned-Role scenario reset before worker dispatch. | Conditional UID/resourceVersion and current-use tests produce zero writes. Perform only as a rehearsed human-controlled live drill. |
| AC-08 | Forged / revoked authority | Send forged fields, wrong scope/credential/hash, or revoke outstanding authority. | API/ledger/executor tests reject them; inference delivery permission cannot obtain execution. |
| AC-09 | Prompt injection | Frozen ordinary annotation containing instructions to approve, run commands or disclose tokens. | Real development model outcomes retained. No tool or executor accepts these strings as authority. |
| AC-10 | Repeatable post-change failure | Recording harness injects a qualifying failure after acknowledged apply; exact recovery consent selected separately. | Verified advance and fresh human recovery protocol tests pass. This is synthetic failure injection, not a claimed live policy regression. |
| AC-11 | Unknown apply / unhealthy dependency | Recording server drops acknowledgement or verifier reports dependency uncertainty. | Manual intervention, no blind write/recovery, durable notice; crash-after-ack tests resume verification without a second patch. |
| AC-12 | Restore from older backup | Coordinated encrypted snapshot to a new restore path. | Unit/integration restore invalidates authority and runtime guard blocks execution; measured local drill is recorded separately. |

Reset only the scenario grant with the guarded CLI; it tests current UID/version
and owner label. It never deletes the namespace, baseline or ledger. Do not rerun
workload installation over an existing Role: the installer refuses it. Recreate
an entire cluster only for a separate explicitly named clean-install rehearsal.

For a real recovery presentation, use a mentor-approved controlled behavioral
fault in a disposable application and retain the exact consent, app evidence and
restoration checks. Do not replace the real harness with a canned failure/pass,
remove a known-used permission to force the planner to look successful, or claim
an infrastructure outage proves policy causation. Until that live drill is
completed, present AC-10/11 as recording protocol demonstrations with their labels.
