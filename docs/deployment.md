# Deploy and operate Guardian

Use the release's exact source, `uv.lock`, model digest and image/chart pins. The
chart supports one backend, one collector and one inference worker on one host
with local persistent disk. SQLite WAL and the executor lock do not support
multi-host or network-filesystem execution. The collector shares the backend PVC
and is colocated with it. Select the same storage host for all persistent
components in a larger cluster. Never scale the backend or worker above one.

## What is packaged

`Dockerfile` builds the shared nonroot runtime. The chart at
`deploy/helm/guardian` deploys backend, inference worker, collector, dashboard and
Redis with private persistent volumes, separate identities, bounded resources,
health checks, existing Secret references and default-disabled execution. No
Helm dependencies or hidden database services are downloaded by the chart.
The demo workload is installed separately and survives Guardian upgrades.

Inference/dashboard pods mount no Kubernetes token, auth registry or archive key.
The backend reads RBAC/consumer inventory and creates SubjectAccessReviews. Only
an explicitly enabled pilot grants `get,patch,escalate` on the **named pod-reader
Role in guardian-demo**. `escalate` is necessary for exact restoration of grants
the backend itself does not hold; it is not cluster-admin or arbitrary Role
mutation. The real workload harness also needs scoped Pod proxy access. The
collector has only the nonresource `/version` probe grant; its volume grants
local evidence append access, never human approval authority.

Services are ClusterIP. Use loopback port-forwards on laptops. A shared lab needs
an approved TLS/authentication gateway and protected model endpoint; do not expose
the legacy monitoring API or Redis publicly. The chart's ingress NetworkPolicy
requires an enforcing CNI; Kind's default networking may not enforce it. It is not
a claim of tenant isolation. Existing monitoring endpoints are intended for the
trusted local/lab boundary.

## Build and install

Prerequisites: Docker, Kind or an approved cluster, kubectl, Helm 3.19.0, Python
3.11+ and uv. See `demo-runbook.md` for the tested isolated Kind commands. For an
existing lab cluster obtain its authorization, audit export, scope, encrypted
storage and protected model endpoint first. Creating an application chart does
not enable API-server audit collection or provide encrypted persistent storage.

```bash
uv sync --locked --extra verification
.venv/bin/python -m unittest discover -s tests -q
docker build -t guardian:0.2.0-rc.1 .
helm lint deploy/helm/guardian
helm template guardian deploy/helm/guardian --namespace guardian-system
```

Push a versioned image to the team's approved registry when ready, obtain its
registry digest and use `image.repository`/`image.digest`. The local pilot uses
Kind-loaded content digests and no public push. Never use `latest` for Guardian.
The base/runtime/Redis versions are explicit; the release evidence records the
actual resolved image IDs. Registry publication requires your registry access.

Create existing Secrets `guardian-auth` (`registry.json`), `guardian-worker`
(`worker.token`), `guardian-archive` (`archive-keys.json`) and
`guardian-collection` (`source.json`, `audit-policy.yaml`). Generate unique scoped
credentials using `scripts.guardian_auth`; keep token values out of values files
and shell history. The collector declaration must hash the actual mounted audit
policy and honestly attest its scope; a provided export cannot be declared
complete merely to pass a demo.

```bash
helm upgrade --install guardian deploy/helm/guardian \
  --namespace guardian-system --create-namespace \
  -f deploy/helm/guardian/values-lab.yaml \
  --set image.repository=YOUR_REGISTRY/guardian \
  --set image.digest=sha256:YOUR_RESOLVED_DIGEST \
  --set model.endpoint=YOUR_PROTECTED_OLLAMA_ENDPOINT \
  --set model.revision=YOUR_ACTUAL_OLLAMA_DIGEST \
  --wait --timeout 180s
```

The example lab endpoint/registry are placeholders, not functioning credentials.
Set its node selector to the approved storage host, size/storageClass to actual
encrypted volumes and collector.auditHostPath to an approved **readable export**
on that host. The collector UID/GID is 10001; directory traversal and file read
access must include it after log rotation too. Do not truncate active logs. The
Kind setup adjusts only its new disposable audit directory to group 10001; other
clusters require their own approved adapter/ACL/rotation arrangement. Lost access
stops the watermark and blocks narrowing.

## Health, restart and compatible upgrade

`/` is process liveness. `/ready` checks governance DB and Redis connectivity;
collector coverage, model connectivity and functional readiness are separate
surfaces. Inspect `/evidence/status`, a real analysis result and action checks.
A healthy HTTP server alone is not permission to execute.

Use `kubectl rollout restart deployment/guardian-backend` for a normal restart;
PVCs preserve reports, decisions, baselines and archive catalogs. Worker
checkpoints have their own PVC. Compare saved run/decision IDs and hashes before
and after. Compatible `helm upgrade` uses Recreate for stateful singletons. Take
a backup first for an incompatible change, pause/hold action intake and reconcile
in-flight requests. Never delete checkpoints or edit state versions to force a
resume. Helm rollback changes installation resources, not DB schema, retained
evidence or target Role rules.

`helm uninstall` preserves PVCs through the keep annotation. Their physical
survival also depends on the storage class/reclaim policy. Reinstall must reattach
the same compatible volumes and Secret/key versions. Do not delete demo namespace,
PVCs or keys as a routine scenario reset.

## Backup, restore, encryption and capacity

Custodian responsibilities are in `release-responsibilities.md`. Stop backend,
collector and worker before a coordinated backup; preserve their previous replica
counts. Keep collecting the external audit spool, with sufficient outage capacity.
Mount both state/checkpoint volumes into an approved temporary custodian pod, or
use your host's stopped service directories. Copy archive key recovery material
into that custodian's protected input. Do not mount these in inference pods.

```bash
.venv/bin/python -m scripts.guardian_backup keygen --key-file /PRIVATE/backup.key
.venv/bin/python -m scripts.guardian_backup create --quiesced \
  --root state=/QUIESCED/guardian-state --root worker=/QUIESCED/checkpoints \
  --root keys=/PRIVATE/archive-key-recovery \
  --destination /SEPARATE_DURABLE_COPY/guardian.fernet --key-file /PRIVATE/backup.key
.venv/bin/python -m scripts.guardian_backup restore \
  --source /SEPARATE_DURABLE_COPY/guardian.fernet \
  --destination /NEW_EMPTY_PATH/restore --key-file /SEPARATE_KEY_COPY/backup.key
```

The pilot backup authenticates/encrypts a checksummed bundle, takes SQLite backup
snapshots including WAL state, rejects symlinks/unsafe archive members and verifies
readback. It is bounded to 256 MiB; use approved encrypted volume/object-store
backup for larger retention datasets. A copy on the same disk is only a local
restore drill, not disaster recovery. Maintain a separate durable archive/backup
copy and separate protected key custody. Never promise 90/365 days of history or
RPO without provisioning and measurement.

Restore requires a new path. It invalidates pending decisions/deliveries and adds
`restore-required` beside governed ledgers, which disables execution even if the
operator policy says enabled. Preserve that marker while comparing every action
since the snapshot against surviving receipts, live UID/version/rules and audit
records. Uncertain actions require manual intervention and fresh review. Reissue
credentials and fresh analyses; only the custodian removes the marker after a
recorded reconciliation. An old backup is never a license to replay a patch.

Daily backups with 30 rolling days and <=24-hour RPO/one-working-day recovery are
**lab targets**, not measured service guarantees. Record actual backup age, missing
events, recovery duration, archive readback, DB integrity and authority invalidation
in each drill. Configure the approved scheduler rather than assuming a chart
implements a functioning external backup service. Fail/notify on missed jobs.

```bash
.venv/bin/python -m scripts.guardian_capacity \
  --directory /STATE --database /STATE/guardian/governance.sqlite3
```

The report records actual bytes, interval and 80% filesystem alert. Before a full
day of representative data it returns insufficient measurement. Longer estimates
are explicitly linear estimates with 30% headroom and disclosed excluded overhead;
measure archive compression, indices, replicas, retained cases and rolling backups
before choosing capacity. Archive pruning remains explicitly authorized via the
collector's `--prune`; it never deletes the control-plane log.

Sources: [Helm chart practices](https://docs.helm.sh/docs/chart_best_practices/),
[Helm resource retention](https://helm.sh/docs/v3/howto/charts_tips_and_tricks/),
[Kind auditing](https://kind.sigs.k8s.io/docs/user/auditing/),
[Ollama Qwen3.5 catalog](https://ollama.com/library/qwen3.5).
