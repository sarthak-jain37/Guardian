# guardian_audit

Collects Kubernetes API-server audit logs and answers one question for the orchestrator:

> Which permissions has this ServiceAccount actually **exercised**, when, how often, and **how sure are we** (coverage)?

Example: `get pods` used 50 times, `get secrets` used 0 times, *and* the interval was confirmed fully covered, so the zero is trustworthy.

## How it fits together

```
kube-apiserver audit.log
        |
     tailer.py        rotation / truncation / partial-line safe reader + checkpoint
        |
   normalize.py       raw JSON entry -> usage events + RBAC-change events
        |
   collector.py       main loop: parse -> commit batch + checkpoint -> coverage heartbeat
      /     \
 store.py   coverage.py      hourly counters (Redis)   |   "what time ranges did we really see"
      \     /
      Redis
        |
     query.py         builds guardian.usage-summary.v1 (validated by schema.py)
        |
   orchestrator
```

## Files

| File | Role |
|---|---|
| `schema.py` | The Pydantic 2 contract (`UsageSummary` and friends), copied verbatim from the spec. Extra fields are rejected. |
| `config.py` | All settings, read from environment variables (see below). |
| `normalize.py` | Pure functions (no I/O). Identifies the ServiceAccount, builds the canonical request key, classifies the outcome, extracts RBAC-change events, handles impersonation, and computes `key_id()` / `family_id()`. |
| `tailer.py` | Reads `audit.log` by byte offset. Drains a renamed file before switching to the new one, detects truncation, buffers partial lines, and can resume from a rotated file after a restart. |
| `store.py` | Redis write path. One atomic Lua script per event handles dedupe, counters, indexes and evidence refs. A second script appends RBAC changes to a stream. Also saves and loads the checkpoint. |
| `coverage.py` | The coverage ledger. Records observed time ranges per apiserver, marks gaps and defects, lints the audit policy, and merges coverage across apiservers at query time. |
| `collector.py` | The process you run. Reads a batch, commits it (retrying the same batch if Redis is down), then updates coverage. |
| `query.py` | `build_usage_summary()`. Assembles buckets, coverage slices and carried requests into a validated `UsageSummary`. |
| `audit-policy.yaml` | Sample apiserver audit policy: Metadata level only, `RequestReceived` omitted. |
| `tests/test_smoke.py` | End-to-end tests against fakeredis. |
| `__init__.py` | Collector and aggregation version strings embedded in every summary. |

## Quick start

```bash
pip install redis pydantic pyyaml
export CLUSTER_ID=prod-1
export SOURCE_ID=apiserver-0                      # unique per apiserver
export EXPECTED_SOURCES=apiserver-0,apiserver-1   # every apiserver that must be covered (HA)
export AUDIT_LOG_PATH=/var/log/kubernetes/audit/audit.log
export AUDIT_POLICY_PATH=/etc/kubernetes/audit-policy.yaml   # mounted read-only
export REDIS_HOST=guardian-redis
python -m guardian_audit.collector
```

Run one collector per apiserver, each with its own `SOURCE_ID`.

### Configuration

| Variable | Default | Meaning |
|---|---|---|
| `CLUSTER_ID` | `default` | Namespaces all Redis keys. |
| `SOURCE_ID` | hostname | Identifies this apiserver's audit file. |
| `EXPECTED_SOURCES` | this source | Comma-separated. Coverage is complete only if all of these are complete. |
| `AUDIT_LOG_PATH` | `/var/log/kubernetes/audit/audit.log` | File to tail. |
| `AUDIT_POLICY_PATH` | unset | Policy file to verify. If unset, coverage is capped at `partial`. |
| `REDIS_HOST` / `REDIS_PORT` | `guardian-redis` / `6379` | Redis location. |
| `DEDUPE_TTL_S` | 86400 | Must exceed the longest possible replay window. |
| `AGG_TTL_S` | 120 days | Retention of hourly aggregates. |
| `SAFETY_LAG_S` | 90 | Coverage watermark is `now - lag`. Must exceed the apiserver request timeout. |

### Querying

```python
from guardian_audit.query import build_usage_summary
summary = build_usage_summary(r, cfg, "system:serviceaccount:default:app",
                              window_start_us, window_end_us, requested_keys)
print(summary.model_dump_json())
```

- `requested_keys` is a list of `RequestKey` objects. Their ids come from `normalize.key_id()`.
- The window must be hour-aligned UTC (`boundary_mode: exact`).
- A key with no activity still gets a series with empty `buckets`. Whether that means "zero use" depends on the `coverage` slices.

## Concepts

**Outcomes** (the `Counts` fields):
- `successful_completed`: allowed, 2xx or 3xx response.
- `authorized_error`: allowed, but the request failed (4xx or 5xx, including admission denials).
- `authorized_incomplete`: `ResponseStarted` seen (watch, exec) with no completion yet. It moves to its final outcome when the completion arrives and is counted once.
- `denied`: authorization said forbid.
- `unknown`: decision or status missing.

**Coverage statuses:**
- `complete_for_declared_scope`: every expected apiserver was observed, with a verified policy.
- `partial`: observed, but something weakens the guarantee (policy unverified or hiding ServiceAccounts, malformed line, truncated log, or only some apiservers covered).
- `unavailable`: no reliable observation (unrecoverable gap, not yet processed, future, or older than retention).

Reason codes explain every non-complete slice, for example `audit_policy_unverified`, `collector_gap_unrecoverable`, `not_yet_processed:<source>`, `beyond_aggregate_retention`.

**RBAC changes vs usage.** RBAC mutations (create, update, patch, delete on roles, rolebindings, clusterroles, clusterrolebindings) go to the Redis stream `rbac_events:{cluster}` for any actor. Usage aggregates track ServiceAccounts only.

**Carried requests.** A long-running request that began before the query window and may still be running appears in `carried_authorized_requests`.

**Bucketing.** Counts are bucketed by request start time (`requestReceivedTimestamp`), one hour per bucket.

**Evidence refs.** Buckets cite `rawlog:{source}:{inode}:{fingerprint}`, identifying the raw log file segment. Your archival tooling should be able to resolve these.

## Redis keys (for debugging)

| Key | Contents |
|---|---|
| `ub:{cluster}:{user}:{keyid}:{bucket_us}` | Hash of counts plus first/last request time for one hour |
| `ubi:...` / `ubr:...` | Bucket index (zset) / evidence refs (set) |
| `uki:` / `ukf:` / `kd:` | Observed key ids per user / per name-family / key definitions |
| `sj:` / `sju:` / `sv:` | Subject info / observed UIDs / data version |
| `cy:` / `cyi:` | Carried (in-flight) requests / index |
| `dd:...` | Dedupe markers (TTL) |
| `ckpt:{cluster}:{source}` | Tailer checkpoint |
| `covopen:` / `cov:` / `cv:` | Open coverage segment / closed segments / coverage version |
| `rbac_events:{cluster}` | Stream of RBAC change events |

## Tests

```bash
pip install pytest fakeredis lupa pyyaml
python -m pytest guardian_audit/tests -q
```

Covers duplicates, a watch moving from incomplete to complete, authorized errors and denials, the RBAC stream, no bodies stored, log rotation, restart without double counting, an unrecoverable gap, and complete coverage with a verified policy.

## Known limitations

- Resource scope: audit events do not say whether a resource is namespaced. Unknown cluster-wide lists are labelled `scope='unknown'`. Replace `is_namespaced()` in `normalize.py` with a discovery-backed function for exact scope.
- Events dropped by the apiserver itself are invisible unless you also scrape its audit metrics. `known_lost_events` counts only losses the collector can see.
- Intermediate rotated files deleted while the collector was down are undetectable. Compressed `.gz` rotations are not read.
- Memory: dedupe uses about one Redis key per event (24h TTL), and the observed-key set per ServiceAccount is unbounded.
- Coverage assumes the collector host's clock is close to the apiserver's.
- Impersonation is approximate: the real caller is credited with `impersonate`, the impersonated ServiceAccount with the request itself, both using the one recorded decision and status.
- Tests ran against fakeredis, not a live cluster.
