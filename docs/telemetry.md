# Cilium system telemetry

Guardian consumes Cilium Hubble network events and Cilium Tetragon runtime events;
it does not load eBPF programs itself. Cilium must be the supported CNI for the
customer cluster. Do not replace an existing CNI without a migration plan.

## Cluster setup

Merge `k8s/cilium-observability-values.yaml` into the **existing** Cilium Helm
release values using that cluster's pinned compatible Cilium chart version.
Enable Hubble Relay. Install Tetragon with the compatible pinned chart and
`k8s/tetragon-observability-values.yaml`. Review kernel compatibility and privileged
DaemonSet requirements. These files are configuration inputs, not an automatic
installation or a blanket authorization to change customer networking.

L3/L4 flow visibility includes pod endpoints, TCP/UDP ports, verdicts, drops and
cross-namespace communications. HTTP and DNS metadata require L7 policies.
`k8s/http-visibility-example.yaml` is an opt-in test example for labeled workloads
on ports 80/8080 and kube-dns. It restricts selected pods' other egress: merge
visibility rules into reviewed workload policies instead of applying it blindly.
HTTPS bodies/paths cannot be recovered from ordinary encrypted flows. Configure
TLS inspection separately where appropriate. This implementation never captures
HTTP bodies, headers or query strings. Paths and DNS names may still be sensitive.

## Connect exports to Guardian

For a development connection using an authorized kubeconfig and Hubble CLI:

```bash
mkdir -p /tmp/guardian-telemetry
# In a separate terminal, keep the relay port forward running:
cilium hubble port-forward
# In another terminal (use TLS flags instead for a directly exposed relay):
hubble observe --server localhost:4245 --follow --output json >> /tmp/guardian-telemetry/hubble.jsonl
# In another terminal, follow Tetragon exporters across the current nodes:
kubectl logs -n kube-system -l app.kubernetes.io/name=tetragon -c export-stdout --follow --tail=0 --max-log-requests=100 >> /tmp/guardian-telemetry/tetragon.jsonl
```

Set the paths and unique `GUARDIAN_CLUSTER_ID` in `.env` and start the existing
backend. Relay includes flows from all connected Cilium nodes. Restart the
Tetragon log command when its selected pod set changes. These CLI bridges are
for development, not durable transport: disconnects can lose events.

In production, use a supervised per-node log shipper reading Hubble and Tetragon
export files and forwarding JSONL to the corresponding trusted Guardian files.
Hubble exporter records may be bare Flow objects; Guardian also accepts Relay
`{"flow": ...}` wrappers. Preserve source timestamps; mount exports read-only to
Guardian. Do not concatenate partial lines. Secure shipper transport with mTLS,
isolate customer credentials, and monitor lag/rotation on each node. The current
file follower handles inode replacement and truncation but cannot recover unread
records from rotated-away files. Collector status reports following/errors and
last event time, not proof that every node is connected. No full-cluster coverage
or lossless-delivery guarantee is implied.

Use dedicated Redis credentials/database per customer and enable Redis AOF or
RDB persistence and backups: Redis without persistence loses history on restart.
Data is limited to the latest `TELEMETRY_MAX_EVENTS` (default 50,000) and API
visibility to `TELEMETRY_RETENTION_SECONDS` (default 7 days). Idle keys expire;
list entries older than the window are filtered on reads. This is bounded recent
history, not an archival database. Export to a durable analytics store for
long-term compliance. A restarted importer can resume using Redis byte cursors;
source event hashes deduplicate replay during the retention window.

## Runtime coverage and boundaries

Tetragon supplies process exec/exit by default. Kprobe, tracepoint and uprobe
records include policy/function identifiers when additional tracing policies are
installed. File access, syscall argument values and all kernel operations are
not automatically collected. Guardian excludes process arguments/environment to
avoid retaining credentials; currently it retains binary, UID, PID, parent binary,
exit status, signal and tracing function/policy. Root execution is an observation,
not sufficient evidence of compromise.

Set `TELEMETRY_BOUNDARIES_FILE` to reviewed JSON rules shaped like
`k8s/telemetry-boundaries.example.json`. Namespace rules optionally target an exact
pod name. Explicit allowed destination namespaces and executable paths produce
evidence flags. Unresolved external destinations are a heuristic, not reliable
service identity. Without boundary configuration the LLM cannot infer a customer's
authorized behavior. Detected flags do not automatically block or remediate.

## API and frontend

- `GET /telemetry/status`: collector state, last observed event, retention, limitations.
- `GET /telemetry/events?namespace=client-app&limit=100&kind=network`: recent records including HTTP/DNS and findings.
- `GET /telemetry/graph`: nodes and directed edges with flow record, HTTP request and drop counts.
- `GET /telemetry/llm-context`: bounded evidence plus boundaries and coverage.
- `POST /telemetry/evaluate?limit=50`: invokes the configured local model and returns evidence IDs and analysis.

Streamlit displays status, the communication graph, event records and an explicit
local evaluation button. Graph counts are flow observations, not distinct TCP
connections; ingress/egress observation points can report the same traffic.
Evaluation is on demand; it does not automatically scan every event. Model output
is advisory and never executed. Keep the existing API behind authenticated private
access; these endpoints inherit the project's lack of built-in authentication.

References: [Hubble exports](https://docs.cilium.io/en/stable/observability/hubble/configuration/export/),
[L7 visibility](https://docs.cilium.io/en/stable/observability/visibility/),
[Tetragon Helm](https://tetragon.io/docs/reference/helm-chart/).

## Pod evidence expansion (no scores or permission removal)

Guardian now refreshes a read-only pod inventory every `POD_INVENTORY_INTERVAL`
seconds. `/telemetry/pods` exposes this snapshot and
`/telemetry/pods/{namespace}/{pod}/evidence` combines it with bounded event evidence.
Use `namespace` and `pod` on `/telemetry/llm-context` or `/telemetry/evaluate` to
include a selected pod's evidence in local model input. No numeric risk score or
automatic permission modification has been added.

Collected evidence:

- Pod UID, service account, node, owner references and container/image IDs.
- Security contexts: privileged mode, Linux capabilities, escalation controls,
  seccomp, run-as identity, host PID/network/IPC, resource limits and mounts.
- Secret/config/projected-volume **references**, host paths, restart counts,
  termination state and image changes; never secret values or environment values.
- RBAC rules resolved through RoleBindings and ClusterRoleBindings, including
  explicit users and the service-account/authenticated groups. Every grant retains
  binding/role provenance, destination namespace scope, API groups and resourceNames.
- Pod/workload create/delete/deletecollection/update/patch, pod exec/attach,
  ephemeral-container, secret/token, bind/escalate/impersonate permission signals.
  These are permissions, not proof of misuse. Rules are a current RBAC snapshot,
  not a historical authorization decision or admission-policy evaluation.
- API requests by service accounts, including failed requests, target resource,
  target pod, verb, response code, source IP and authentication pod UID when present.
- Runtime parent IDs, container identity, capabilities, namespaces, sensitive file
  paths, numeric syscall arguments and return values. Shells, execution from temp
  directories, powerful capabilities and namespace/mount/ptrace/BPF operations are
  evidence flags, not compromise verdicts.
- Changes between successive inventories, including permission/configuration/image
  and container-status changes, persisted as `pod_configuration_change` events.
  Short-lived changes between polls can be missed. Initial inventory is a baseline.

Configure `POD_AUDIT_EXPORT_PATH` to an API-server JSONL audit export. It has its
own durable cursor, independent of the existing RBAC worker. Merge
`k8s/pod-evidence-audit-policy.yaml` into the cluster audit policy before deny-all
rules; it records all service-account requests at Metadata level. Managed clusters
may require a provider audit-log export bridge. Audit logs are control-plane
proof; eBPF alone cannot recover Kubernetes authorization decisions from TLS.

The Guardian identity needs the read-only ClusterRole in
`k8s/guardian-evidence-reader.yaml` bound to its dedicated ServiceAccount. This
role grants no access to secret contents and no mutation privileges. Granting
Guardian this role does not grant monitored client pods any permissions.

Review and install `k8s/tetragon-evidence-policy.yaml` for sensitive file permission
checks and namespace/mount/ptrace/BPF syscall attempts. Enable process credential
and namespace export using the provided Tetragon values. Hook availability and
architecture vary; verify loaded policies and emit test events on every supported
node. Policies observe only and do not kill or deny. File permission hook success
means the check passed, not proof that a read/write completed. Some I/O paths and
newer syscalls require additional hooks. No file contents are retained.

Shared service-account events are listed separately unless a matching token pod
UID is available. A bound token UID identifies the credential's pod binding; a
stolen token can be used elsewhere. Name-only runtime/network identity is weaker
and can span recreated pods. Do not revoke a shared role based solely on an LLM
claim: modifying one binding can affect many workloads. This version deliberately
retains evidence and provenance without implementing revocation.

Evidence is bounded by the existing retention and event limits. Historical
permissions at the exact request time, full syscall coverage, complete CPU/memory
usage and lossless ingestion are not claimed. RBAC collection errors appear in
collector status; previous snapshots can remain visible with their timestamps.


## Pod workspaces and interactive connections

The frontend now separates Overview, Connections, Pod workspace, Permissions,
Evidence and LLM review. Pod capabilities are explained in plain language with
binding provenance, rather than presenting a severity per RBAC rule. The graph
supports drag, zoom, an inspector and observation replay; it does not animate
individual live packets. The vendored vis-network build and its license are
included under frontend/assets.

Selected-pod review uses GET /telemetry/pods/{namespace}/{pod}/review-context
and POST /telemetry/pods/{namespace}/{pod}/review. The POST body contains
question and event_limit. Distinct evidence channels are sampled, shared service
account events stay separate, and context overflow returns a 413 response.
Model answers are advisory; missing evidence citations and output truncation
are surfaced. The model uses its GGUF chat template and serialized inference.
LLM_CONTEXT_SIZE, LLM_MAX_TOKENS and LLM_THREADS configure local resource use.

Minikube testing uses a dedicated guardian-e2e Docker profile and audit mount.
The API server must mount its audit file directory onto the node for export.
The Kubernetes client explicitly honors KUBECONFIG set through dotenv. The
frontend requires Streamlit 1.63 or newer. llama-cpp-python is now declared as
an application dependency; CPU wheels may be installed from the upstream
project's wheel index when a local source build is unsuitable.

### Continuous severity assessments and dashboard alerts

The backend reviews each current pod serially, checks again 60 seconds after each
cycle, and skips successful reviews whose sampled evidence, permissions, pod UID,
boundaries and collector states are unchanged. A slow CPU model can make a full
cycle take longer than 60 seconds. `POD_REVIEW_ENABLED`, `POD_REVIEW_INTERVAL`,
`POD_REVIEW_EVENT_LIMIT`, `POD_ALERT_THRESHOLD` and `LLM_GRADE_MAX_TOKENS` configure it.
Manual reviews use the same model lock and grading path.

Grades are advisory model assessments from 0–10: 0–2 low concern in the sample,
3–4 needs checking, 5–6 concerning, 7–8 dangerous, 9–10 critical. Missing evidence
produces a null score; invalid/truncated output, unknown evidence IDs and grades
based only on shared identity produce visible review errors, never a fabricated
score. Exact supplied evidence IDs are required, but citation validation cannot
verify the truth of the model's interpretation. The small test model is not a
validated security analyst. Review its reasons against the actual evidence.

GET `/telemetry/reviews` exposes assessments and worker state. GET
`/telemetry/alerts` exposes persistent alerts and the unread count. At severity 7
or above a per-pod-UID alert appears on every dashboard page (10-second polling)
and in the Alerts page. Optional namespace filters affect the page list, while
the global banner includes every namespace. POST
`/telemetry/alerts/{uid}/acknowledge` requires the displayed alert `version` and
returns 409 if it changed. Acknowledgement does not clear the condition. Worsening
severity or a new flagged action signature reopens an acknowledged alert. Repeated
observations update it without resetting acknowledgement. A later valid grade
below threshold marks it inactive; errors or insufficient evidence do not resolve
an existing alert. Pod replacement uses a new UID, preserving the old alert as
history. Redis persistence depends on the configured Redis deployment; this local
Redis container uses AOF. Records expire after the telemetry retention period.

No email, desktop or Slack notifications are sent. The dashboard must be open for
the human to see notifications; background reviews continue while it is closed.
Neither the model nor the alert service modifies RBAC or deletes pods.


### Continuous local monitoring

The `guardian-monitor.service` user service runs `scripts/dev_services.py`, which
supervises the API, dashboard, audit export, Hubble relay forwarding/export, and
Tetragon export. Failed child processes retry with bounded backoff. Backend
collectors and the pod grading worker run independently of browser requests.
Inventory polls every 10 seconds; each pod is due for model review every 120 seconds, including unchanged evidence.
Inference is serial; queued and overdue counts disclose CPU capacity limits.
Model input combines aggregate counts across retained history with concrete examples
and the previous assessment. Retention bounds apply; this is not lifetime history.
Alerts publish immediately after a valid assessment reaches the configured threshold
(default 7/10). Model errors never clear an existing alert.
The dashboard refreshes automatically every 10 seconds while open.

Service template: `scripts/guardian-monitor.service`. On this machine it is
installed in the user's systemd directory, enabled, and user lingering is enabled.
Use `systemctl --user status guardian-monitor` to inspect it,
`systemctl --user restart guardian-monitor` to restart, and
`systemctl --user stop guardian-monitor` to stop all supervised children.
Logs are in `output/testing/continuous` under the chat workspace.
The machine, Docker, Redis and Kubernetes must be available; sleep/power loss
interrupts collection. Model failures remain errors, not successful assessments.


### Critical alerts and permission decisions

Only confirmed scores of 9–10 appear as red critical alerts. Both model passes
must cite corroborating observations from different collectors; root status,
ordinary token reads, permissions, and denied requests alone cannot qualify.
Critical reviews automatically queue a model-generated permission proposal.
The model selects removal IDs from existing rules; it cannot create grants or
execute commands. Proposed manifests are built and validated by the server.

The Alerts page shows the exact before/after Role and RoleBinding objects and
all pods sharing the service account. Only Roles exclusively bound to that
service account in the pod's namespace can be reduced. Shared/cluster-wide
roles require manually scoped remediation. Other grants may still authorize
the same actions. RoleBinding subjects and role references are preserved;
an annotation records the accepted proposal.

Accept and Reject are explicit client decisions. Acceptance rechecks the
critical assessment, pod UID, service account, affected pods, RBAC snapshot,
and resource versions before writing. Changed proposals are blocked. Partial
execution is recorded rather than reported as success. Repeated decisions do
not repeat writes. Redis stores proposal manifests and an append-only decision
stream without expiry, including actor name supplied by the local operator,
notes, timestamps and execution receipts. This local application does not
provide authenticated operator identity; do not expose its write API publicly.
After a restart, interrupted applications are marked unknown for reconciliation.
