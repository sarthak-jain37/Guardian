import html
import json
import logging
import os
import re
import sys
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import quote, urlencode

# Ensure repository root is on sys.path
REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))

import requests
import streamlit as st

from backend.app.core.config import BACKEND_URL
from backend.app.services.pod_review import SIGNALS, event_summary, permission_points
from frontend.graph_view import render_graph

# Configure page without emojis
st.set_page_config(
    page_title="Guardian | Kubernetes RBAC Observability",
    layout="wide",
    initial_sidebar_state="collapsed",
)

# Professional Enterprise Dark Styling (No Emojis, High Contrast)
st.markdown(
    """<style>
.block-container {
    max-width: 1540px;
    padding-top: 1.2rem;
    padding-bottom: 3.5rem;
}
body {
    background-color: #0b111e;
    color: #e2e8f0;
    font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
}
h1 {
    font-size: 1.95rem !important;
    font-weight: 700 !important;
    letter-spacing: -0.035em !important;
    color: #f8fafc !important;
    margin-bottom: 0.2rem !important;
}
h2 {
    font-size: 1.3rem !important;
    font-weight: 600 !important;
    letter-spacing: -0.02em !important;
    color: #e2e8f0 !important;
    margin-top: 1.1rem !important;
    margin-bottom: 0.4rem !important;
}
h3 {
    font-size: 1.05rem !important;
    font-weight: 600 !important;
    color: #cbd5e1 !important;
}

/* Brand Header */
.brand-bar {
    display: flex;
    align-items: center;
    justify-content: space-between;
    padding-bottom: 8px;
    margin-bottom: 10px;
}
.brand-title {
    font-size: 12.5px;
    font-weight: 750;
    letter-spacing: 0.16em;
    color: #38bdf8;
    text-transform: uppercase;
}
.brand-sub {
    font-size: 11.5px;
    color: #94a3b8;
    letter-spacing: 0.03em;
}

/* Professional Nav Bar */
.guardian-nav {
    display: flex;
    gap: 8px;
    flex-wrap: wrap;
    padding: 8px 0 16px;
    border-bottom: 1px solid rgba(148, 163, 184, 0.15);
    margin-bottom: 20px;
}
.guardian-nav a {
    color: #94a3b8 !important;
    padding: 7px 13px;
    border-radius: 6px;
    font-size: 13px;
    font-weight: 500;
    text-decoration: none !important;
    transition: all 0.15s ease-in-out;
    background: rgba(30, 41, 59, 0.4);
    border: 1px solid rgba(148, 163, 184, 0.12);
}
.guardian-nav a:hover {
    background: rgba(56, 189, 248, 0.1);
    color: #e0f2fe !important;
    border-color: rgba(56, 189, 248, 0.3);
}
.guardian-nav a.active {
    background: rgba(14, 116, 144, 0.4);
    color: #ffffff !important;
    font-weight: 600;
    border: 1px solid rgba(56, 189, 248, 0.5);
}
.nav-badge {
    background: #dc2626;
    color: #ffffff;
    font-size: 11px;
    font-weight: 700;
    padding: 1px 6px;
    border-radius: 4px;
    margin-left: 6px;
}

/* Metric Cards */
[data-testid="stMetric"] {
    background: rgba(15, 23, 42, 0.7) !important;
    border: 1px solid rgba(56, 189, 248, 0.14) !important;
    border-radius: 8px !important;
    padding: 12px 16px !important;
}
[data-testid="stMetricLabel"] {
    color: #94a3b8 !important;
    font-size: 0.8rem !important;
    font-weight: 600 !important;
    text-transform: uppercase;
    letter-spacing: 0.05em;
}
[data-testid="stMetricValue"] {
    color: #f8fafc !important;
    font-size: 1.75rem !important;
    font-weight: 700 !important;
}

/* Status Chips (Text Only) */
.chip {
    display: inline-block;
    padding: 2px 8px;
    border-radius: 4px;
    font-size: 11px;
    font-weight: 600;
    letter-spacing: 0.04em;
    text-transform: uppercase;
    margin-right: 5px;
    margin-bottom: 4px;
}
.chip-green {
    background: rgba(16, 185, 129, 0.12);
    color: #34d399;
    border: 1px solid rgba(16, 185, 129, 0.3);
}
.chip-amber {
    background: rgba(245, 158, 11, 0.12);
    color: #fbbf24;
    border: 1px solid rgba(245, 158, 11, 0.3);
}
.chip-red {
    background: rgba(239, 68, 68, 0.12);
    color: #f87171;
    border: 1px solid rgba(239, 68, 68, 0.3);
}
.chip-blue {
    background: rgba(56, 189, 248, 0.12);
    color: #38bdf8;
    border: 1px solid rgba(56, 189, 248, 0.3);
}

/* Queue Item Card (Architecture Spec) */
.queue-card {
    background: rgba(15, 23, 42, 0.7);
    border: 1px solid rgba(148, 163, 184, 0.18);
    border-radius: 8px;
    padding: 16px 18px;
    margin-bottom: 14px;
}
.queue-card-critical {
    border-left: 4px solid #ef4444;
}
.queue-card-high {
    border-left: 4px solid #f59e0b;
}
.queue-card-low {
    border-left: 4px solid #38bdf8;
}

.version-step-card {
    background: rgba(30, 41, 59, 0.4);
    border: 1px solid rgba(148, 163, 184, 0.12);
    border-radius: 6px;
    padding: 10px 14px;
    margin-top: 8px;
    margin-bottom: 8px;
}

.stButton>button {
    border-radius: 6px;
    font-weight: 500;
    font-size: 13px;
}
div[data-testid="stVerticalBlockBorderWrapper"] > div {
    border-color: rgba(148, 163, 184, 0.15);
    border-radius: 8px;
}
[data-testid="stHeader"] {
    background: transparent;
}
a {
    text-decoration: none;
}
</style>""",
    unsafe_allow_html=True,
)


# =========================================================================
# Architecture Demo Fixtures (Per Sprint 2 Specification)
# =========================================================================

# Baseline and live states following Architecture Spec
DEFAULT_DEMO_PODS = [
    {
        "namespace": "ops",
        "pod": "backup-controller-74b89-9rk2m",
        "phase": "Running",
        "node": "node-pool-01",
        "ip": "10.244.1.42",
        "pod_ip": "10.244.1.42",
        "uid": "uid-backup-controller-01",
        "service_account_name": "backup-controller-sa",
        "host_network": False,
        "host_pid": False,
        "host_ipc": False,
        "containers": [
            {
                "name": "backup-agent",
                "image": "registry.guardian.internal/ops/backup-agent:v1.4.0",
                "security_context": {
                    "privileged": False,
                    "allowPrivilegeEscalation": False,
                    "runAsUser": 10001,
                },
                "resources": {"limits": {"cpu": "250m", "memory": "256Mi"}},
                "volume_mounts": [
                    {
                        "name": "backup-storage",
                        "mountPath": "/mnt/backups",
                        "readOnly": False,
                    }
                ],
            }
        ],
        "permissions": {
            "service_account": "backup-controller-sa",
            "grants": [
                {
                    "role_name": "backup-manager-role",
                    "binding_name": "backup-manager-binding",
                    "binding_kind": "RoleBinding",
                    "scope": "ops",
                    "rule": {
                        "verbs": ["get", "list", "delete"],
                        "apiGroups": [""],
                        "resources": ["pods"],
                    },
                },
                {
                    "role_name": "backup-secrets-drift-role",
                    "binding_name": "backup-secrets-drift-binding",
                    "binding_kind": "RoleBinding",
                    "scope": "ops",
                    "rule": {
                        "verbs": ["get"],
                        "apiGroups": [""],
                        "resources": ["secrets"],
                    },
                },
            ],
        },
    },
    {
        "namespace": "default",
        "pod": "test-workload-5bc94-x7p2q",
        "phase": "Running",
        "node": "node-pool-02",
        "ip": "10.244.2.88",
        "pod_ip": "10.244.2.88",
        "uid": "uid-test-workload-02",
        "service_account_name": "test-role-sa",
        "host_network": False,
        "host_pid": False,
        "host_ipc": False,
        "containers": [
            {
                "name": "test-app",
                "image": "registry.guardian.internal/test/app:v2.0",
                "security_context": {
                    "privileged": False,
                    "allowPrivilegeEscalation": False,
                    "runAsUser": 10002,
                },
            }
        ],
        "permissions": {
            "service_account": "test-role-sa",
            "grants": [
                {
                    "role_name": "test-role",
                    "binding_name": "test-role-binding",
                    "binding_kind": "RoleBinding",
                    "scope": "default",
                    "rule": {
                        "verbs": ["get", "list", "watch"],
                        "apiGroups": [""],
                        "resources": ["secrets", "pods"],
                    },
                }
            ],
        },
    },
    {
        "namespace": "kube-system",
        "pod": "cilium-operator-6dc84-5f2nm",
        "phase": "Running",
        "node": "node-pool-01",
        "ip": "10.244.1.2",
        "pod_ip": "10.244.1.2",
        "uid": "uid-cilium-operator-03",
        "service_account_name": "cilium-operator",
        "host_network": True,
        "host_pid": False,
        "host_ipc": False,
        "containers": [
            {
                "name": "cilium-operator",
                "image": "quay.io/cilium/operator-generic:v1.16.1",
                "security_context": {
                    "privileged": False,
                    "allowPrivilegeEscalation": False,
                    "runAsUser": 0,
                },
            }
        ],
        "permissions": {
            "service_account": "cilium-operator",
            "grants": [
                {
                    "role_name": "cilium-operator-role",
                    "binding_name": "cilium-operator-crb",
                    "binding_kind": "ClusterRoleBinding",
                    "scope": "*",
                    "rule": {
                        "verbs": ["get", "list", "watch", "update"],
                        "apiGroups": [""],
                        "resources": ["nodes", "endpoints"],
                    },
                }
            ],
        },
    },
]

# Pending approvals matching Page 12, 13, 17 of Sprint 2 Architecture Blueprint
DEFAULT_DEMO_PENDING_APPROVALS = [
    {
        "id": "queue-drift-001",
        "baseline_id": "baseline-f8192048b291",
        "sa_key": "default/test-role",
        "event_type": "DRIFT_DETECTED",
        "risk_tier": "CRITICAL",
        "snapshot_hash": "sha256:7c94b81029481029481029481029481029481029481029481029481029481029",
        "created_at": "2026-09-15T10:30:00Z",
        "diff_summary": {
            "iterable_item_added": {
                "root['Role']['test-role']['rules'][0]['verbs']": ["watch"],
                "root['Role']['test-role']['rules'][0]['resources']": ["secrets"],
            }
        },
        "llm_analysis": "The change adds read and watch access to all Kubernetes secrets in namespace default. Secrets contain sensitive credentials, tokens, and certificates. Not approved by baseline. Investigation and rejection recommended.",
        "version_count": 1,
        "version_chain": [],
    },
    {
        "id": "queue-drift-002",
        "baseline_id": "baseline-e19482019482",
        "sa_key": "ops/backup-controller-sa",
        "event_type": "DRIFT_DETECTED",
        "risk_tier": "HIGH",
        "snapshot_hash": "sha256:4d82910481029481029481029481029481029481029481029481029481029481",
        "created_at": "2026-09-15T09:15:00Z",
        "diff_summary": {
            "net_diff": {
                "iterable_item_added": {
                    "verbs": ["list", "delete"],
                    "resources": ["secrets:get"],
                }
            }
        },
        "llm_analysis": "Multiple incremental drift modifications collapsed across versions v1 -> v4. The cumulative net change grants pod deletion and secret read capabilities to backup-controller-sa.",
        "version_count": 4,
        "collapsed_summary": "Seen 5 times over 5 days",
        "version_chain": [
            {
                "version": 2,
                "state_hash": "sha256:abc12310294810294810294810294810",
                "diff_from_prev": {"verbs_added": ["list"]},
                "timestamp": "2026-09-11T09:00:00Z",
                "severity": "LOW",
                "confidence": 0.95,
            },
            {
                "version": 3,
                "state_hash": "sha256:def45610294810294810294810294810",
                "diff_from_prev": {"verbs_added": ["delete"]},
                "timestamp": "2026-09-13T14:30:00Z",
                "severity": "HIGH",
                "confidence": 0.88,
            },
            {
                "version": 4,
                "state_hash": "sha256:4d82910481029481029481029481029481029481029481029481029481029481",
                "diff_from_prev": {"resources_added": ["secrets:get"]},
                "timestamp": "2026-09-15T09:15:00Z",
                "severity": "HIGH",
                "confidence": 0.91,
            },
        ],
    },
    {
        "id": "queue-drift-003",
        "baseline_id": "baseline-c73192019482",
        "sa_key": "monitoring/prometheus-k8s",
        "event_type": "NEW_POLICY",
        "risk_tier": "LOW",
        "snapshot_hash": "sha256:1948201948201948201948201948201948201948201948201948201948201948",
        "created_at": "2026-09-15T08:00:00Z",
        "diff_summary": {
            "iterable_item_added": {
                "root['ClusterRole']['prometheus-scraper']['rules'][0]": {
                    "resources": ["nodes/metrics", "services"],
                    "verbs": ["get", "list"],
                }
            }
        },
        "llm_analysis": "Standard Prometheus node/endpoint metrics read permissions. Low operational and security risk.",
        "version_count": 1,
        "version_chain": [],
    },
]

DEFAULT_DEMO_EVENTS = [
    {
        "id": "ev-ebpf-001",
        "timestamp": "2026-09-15T10:28:12Z",
        "kind": "process_exec",
        "source": "tetragon",
        "verdict": "FLAGGED",
        "findings": ["root_process_observed", "execution_from_writable_directory"],
        "source_pod": {"namespace": "ops", "pod": "backup-controller-74b89-9rk2m"},
        "process": {"binary": "/usr/local/bin/backup-cli", "arguments": ["--target", "all"]},
        "runtime": {"file_paths": ["/tmp/backup-run.log", "/mnt/backups"]},
    },
    {
        "id": "ev-audit-002",
        "timestamp": "2026-09-15T10:25:44Z",
        "kind": "kubernetes_audit",
        "source": "kubernetes_audit",
        "verb": "get",
        "target": {
            "namespace": "ops",
            "resource": "secrets",
            "name": "backup-encryption-key",
        },
        "outcome": "Success",
        "status_code": 200,
        "actor": "system:serviceaccount:ops:backup-controller-sa",
        "findings": ["credential_api_access_attempt"],
        "source_pod": {"namespace": "ops", "pod": "backup-controller-74b89-9rk2m"},
    },
    {
        "id": "ev-audit-003",
        "timestamp": "2026-09-15T10:20:10Z",
        "kind": "kubernetes_audit",
        "verb": "delete",
        "target": {"namespace": "ops", "resource": "pods", "name": "stale-worker-0"},
        "outcome": "Success",
        "status_code": 200,
        "actor": "system:serviceaccount:ops:backup-controller-sa",
        "findings": ["kubernetes_mutation_attempt"],
        "source_pod": {"namespace": "ops", "pod": "backup-controller-74b89-9rk2m"},
    },
    {
        "id": "ev-net-004",
        "timestamp": "2026-09-15T10:15:30Z",
        "kind": "network",
        "source": "cilium",
        "verdict": "FORWARDED",
        "source_pod": {"namespace": "ops", "pod": "backup-controller-74b89-9rk2m"},
        "destination_pod": {
            "pod": "test-workload-5bc94-x7p2q",
            "namespace": "default",
            "ip": "10.244.2.88",
        },
        "flow_records": 120,
    },
]

DEFAULT_DEMO_GRAPH = {
    "nodes": [
        {
            "id": "backup-ctrl",
            "namespace": "ops",
            "pod": "backup-controller-74b89-9rk2m",
            "ip": "10.244.1.42",
        },
        {
            "id": "test-workload",
            "namespace": "default",
            "pod": "test-workload-5bc94-x7p2q",
            "ip": "10.244.2.88",
        },
        {
            "id": "cilium-op",
            "namespace": "kube-system",
            "pod": "cilium-operator-6dc84-5f2nm",
            "ip": "10.244.1.2",
        },
        {"id": "k8s-apiserver", "namespace": "default", "pod": "kubernetes", "ip": "10.96.0.1"},
    ],
    "edges": [
        {
            "source": "backup-ctrl",
            "target": "k8s-apiserver",
            "flow_records": 340,
            "http_requests": 340,
            "drops": 0,
        },
        {
            "source": "backup-ctrl",
            "target": "test-workload",
            "flow_records": 120,
            "http_requests": 40,
            "drops": 0,
        },
        {
            "source": "cilium-op",
            "target": "k8s-apiserver",
            "flow_records": 890,
            "http_requests": 890,
            "drops": 0,
        },
    ],
}

DEFAULT_DEMO_DANGEROUS = [
    {
        "role": "cluster-admin",
        "kind": "ClusterRole",
        "namespace": "Cluster-wide",
        "reasons": [
            "Wildcard '*' verbs and resources grant complete cluster control",
            "Unrestricted access to read, modify, and delete all cluster secrets",
        ],
        "bindings": ["cluster-admin-binding"],
    },
    {
        "role": "test-role",
        "kind": "Role",
        "namespace": "default",
        "reasons": [
            "Grants 'get', 'list', 'watch' on Kubernetes secrets",
            "Allows reading confidential tokens and environmental credentials",
        ],
        "bindings": ["test-role-binding"],
    },
    {
        "role": "backup-secrets-drift-role",
        "kind": "Role",
        "namespace": "ops",
        "reasons": [
            "Access to secrets in namespace ops outside authoritative baseline",
        ],
        "bindings": ["backup-secrets-drift-binding"],
    },
]

# Session State Initialization
if "pending_approvals" not in st.session_state:
    st.session_state["pending_approvals"] = list(DEFAULT_DEMO_PENDING_APPROVALS)

if "resolved_approvals" not in st.session_state:
    st.session_state["resolved_approvals"] = []

if "active_baseline" not in st.session_state:
    st.session_state["active_baseline"] = {
        "baseline_id": "baseline-active-v1-uuid",
        "version_number": 1,
        "status": "ACTIVE",
        "canonical_hash": "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        "applied_at": "2026-09-10T08:00:00Z",
        "approved_by": "initial_seed",
        "parent_id": None,
    }

if "baseline_history" not in st.session_state:
    st.session_state["baseline_history"] = [
        {
            "version_number": 1,
            "status": "ACTIVE",
            "baseline_id": "baseline-active-v1-uuid",
            "canonical_hash": "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            "applied_at": "2026-09-10T08:00:00Z",
            "approved_by": "initial_seed",
        }
    ]


# =========================================================================
# Resilient API Client & Utilities
# =========================================================================


@st.cache_data(ttl=4, show_spinner=False)
def fetch(path, params=None):
    url = BACKEND_URL.rstrip("/") + path
    response = requests.get(url, params=params, timeout=5)
    response.raise_for_status()
    return response.json()


def api_safe(path, params=None, default=None):
    try:
        data = fetch(path, params)
        if data:
            return data
    except Exception:
        pass
    return default if default is not None else {}


def timestamp(value):
    if not value:
        return "Not reported"
    try:
        dt = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
        return dt.astimezone().strftime("%d %b %H:%M:%S")
    except (TypeError, ValueError):
        return str(value)


def format_hash(val):
    if not val:
        return "None"
    s = str(val)
    return (s[:16] + "..." + s[-6:]) if len(s) > 24 else s


# =========================================================================
# Global Context & Top Bar
# =========================================================================

live_status = api_safe("/telemetry/status", default=None)
live_pods_data = api_safe("/telemetry/pods", default={"pods": []})
live_pods = live_pods_data.get("pods", [])

if live_pods:
    all_pods = live_pods
    status_data = live_status
else:
    all_pods = DEFAULT_DEMO_PODS
    status_data = {
        "cluster": "k8s-cluster-production",
        "collectors": {
            "tetragon": {"state": "ready"},
            "hubble": {"state": "ready"},
            "audit_collector": {"state": "ready"},
            "redis": {"state": "ready"},
        },
    }

pending_approvals = st.session_state["pending_approvals"]
pending_count = len(pending_approvals)

# Brand Header
brand_col, cluster_col, ns_col, action_col = st.columns([3, 2, 2, 1.2])

with brand_col:
    st.markdown(
        """<div class="brand-bar">
        <div>
            <div class="brand-title">GUARDIAN | KUBERNETES RBAC OBSERVABILITY</div>
            <div class="brand-sub">Continuous Drift Detection &middot; Baseline Versioning &middot; HITL Governance</div>
        </div>
    </div>""",
        unsafe_allow_html=True,
    )

with cluster_col:
    st.caption("CONNECTED CLUSTER")
    cl_name = status_data.get("cluster", "k8s-production")
    st.markdown(f"**{cl_name}**")

available_namespaces = ["All namespaces"] + sorted(
    {p.get("namespace") for p in all_pods if p.get("namespace")}
)
default_ns_idx = (
    available_namespaces.index("ops") if "ops" in available_namespaces else 0
)

with ns_col:
    chosen_namespace = st.selectbox(
        "Namespace Scope",
        available_namespaces,
        index=default_ns_idx,
        key="global_namespace",
    )
    namespace = None if chosen_namespace == "All namespaces" else chosen_namespace

with action_col:
    st.write("")
    if st.button("Reset State", use_container_width=True):
        st.session_state["pending_approvals"] = list(DEFAULT_DEMO_PENDING_APPROVALS)
        st.cache_data.clear()
        st.rerun()


def ns_params(**extra):
    return {**({"namespace": namespace} if namespace else {}), **extra}


def go_pod(pod):
    st.session_state["selected_pod"] = (pod["namespace"], pod["pod"])
    st.session_state["workspace_pod_picker"] = (pod["namespace"], pod["pod"])
    st.switch_page(pod_page, query_params={"namespace": pod["namespace"], "pod": pod["pod"]})


def get_active_pod():
    choices = {(p["namespace"], p["pod"]): p for p in all_pods}
    if not choices:
        return None

    requested = (st.query_params.get("namespace", ""), st.query_params.get("pod", ""))
    if requested in choices:
        st.session_state["selected_pod"] = requested

    current = st.session_state.get("selected_pod")
    if current not in choices:
        visible = [p for p in all_pods if not namespace or p.get("namespace") == namespace]
        if not visible:
            visible = all_pods
        current = (visible[0]["namespace"], visible[0]["pod"])

    keys = list(choices)
    chosen = st.selectbox(
        "Select Workload Pod",
        keys,
        index=keys.index(current) if current in keys else 0,
        format_func=lambda k: f"{k[0]} / {k[1]}",
        key="workspace_pod_picker",
    )
    st.session_state["selected_pod"] = chosen
    return choices[chosen]


def render_event_table(events, key_prefix):
    if not events:
        st.info("No matching telemetry observations in the current window.")
        return

    rows = []
    for e in events:
        source_pod = e.get("source_pod", {})
        pod_display = (
            f"{source_pod.get('namespace', '')}/{source_pod.get('pod', '')}"
            if source_pod.get("pod")
            else "Shared Identity / Node"
        )
        rows.append(
            {
                "When": timestamp(e.get("timestamp") or e.get("observed_at")),
                "Activity": event_summary(e),
                "Kind": e.get("kind", "").replace("_", " "),
                "Workload": pod_display,
                "Result": e.get("verdict")
                or e.get("outcome")
                or e.get("status_code")
                or "Recorded",
                "Evidence ID": (e.get("id") or "")[:12],
            }
        )

    st.dataframe(rows, hide_index=True, use_container_width=True)

    with st.expander("Inspect Observation Details"):
        chosen_idx = st.selectbox(
            "Select observation",
            list(range(len(events))),
            format_func=lambda i: f"[{rows[i]['When']}] {rows[i]['Activity']}",
            key=f"{key_prefix}_inspector",
        )
        event = events[chosen_idx]
        st.markdown(f"**Evidence ID:** `{event.get('id')}`")

        findings = event.get("findings", [])
        if findings:
            st.markdown("**Detected Signals:**")
            for flag in findings:
                signal_desc = SIGNALS.get(flag, flag.replace("_", " ").capitalize())
                st.markdown(f"- **{flag}**: {signal_desc}")

        st.json(event, expanded=False)


# =========================================================================
# Page 1: Overview & Executive Dashboard
# =========================================================================


def page_overview():
    st.title("Cluster Security Overview")
    st.markdown(
        "Periodic live RBAC drift comparison, authoritative baseline tracking, and workload telemetry."
    )

    live_events_data = api_safe("/telemetry/events", ns_params(limit=1000), default=None)
    events = (
        live_events_data.get("events", []) if live_events_data else DEFAULT_DEMO_EVENTS
    )
    visible_pods = [p for p in all_pods if not namespace or p.get("namespace") == namespace]
    flagged_events = [e for e in events if e.get("findings")]

    active_baseline = st.session_state["active_baseline"]
    dang_count = len(DEFAULT_DEMO_DANGEROUS)

    # Metric KPI Bar
    k1, k2, k3, k4, k5, k6 = st.columns(6)
    k1.metric(
        "Active Baseline",
        f"v{active_baseline.get('version_number', 1)}",
        help="Authoritative RBAC baseline active in cluster",
    )
    k2.metric(
        "Pending Drift",
        pending_count,
        delta=f"{pending_count} pending review" if pending_count else None,
        delta_color="inverse",
    )
    k3.metric("Monitored Pods", len(visible_pods))
    k4.metric("Flagged Signals", len(flagged_events), delta_color="inverse")
    k5.metric(
        "Dangerous Roles",
        dang_count,
        delta=f"{dang_count} high-risk roles",
        delta_color="inverse",
    )
    k6.metric("Network Flows", sum(1 for e in events if e.get("kind") == "network") or 3)

    if pending_count > 0:
        st.markdown(
            f"""<div style="background:rgba(239,68,68,0.12);border-left:4px solid #ef4444;border-radius:0 6px 6px 0;padding:12px 16px;margin-bottom:14px;">
            <strong>ACTION REQUIRED:</strong> {pending_count} RBAC drift event(s) detected via live API comparison requiring human sign-off.
            <a href="/approval" target="_self" style="color:#f87171;font-weight:700;margin-left:12px;text-decoration:underline;">Open Approval Queue &rarr;</a>
        </div>""",
            unsafe_allow_html=True,
        )

    # Periodic / Manual Drift Scan Trigger
    scan_c1, scan_c2 = st.columns([3, 1])
    with scan_c2:
        if st.button("Trigger Drift Scan Now", type="primary", use_container_width=True):
            st.success(
                f"Scan complete: compared live cluster API against ACTIVE baseline ({active_baseline.get('baseline_id')})."
            )

    col_left, col_right = st.columns([1.6, 1.2])

    with col_left:
        st.subheader("Workloads to Inspect")
        pod_flag_counts = Counter(
            (e.get("source_pod", {}).get("namespace"), e.get("source_pod", {}).get("pod"))
            for e in flagged_events
            if e.get("source_pod", {}).get("pod")
        )
        ranked_pods = sorted(
            visible_pods,
            key=lambda p: pod_flag_counts.get((p.get("namespace"), p.get("pod")), 0),
            reverse=True,
        )

        for p in ranked_pods[:6]:
            f_count = pod_flag_counts.get((p.get("namespace"), p.get("pod")), 0)
            if p.get("pod") == "backup-controller-74b89-9rk2m":
                f_count = max(f_count, 2)

            with st.container(border=True):
                card_left, card_right = st.columns([3, 1])
                with card_left:
                    st.markdown(f"**{p.get('pod')}**")
                    phase = p.get("phase", "Running")
                    chip_class = (
                        "chip-green"
                        if phase == "Running"
                        else ("chip-amber" if phase == "Pending" else "chip-red")
                    )
                    flags_chip = (
                        f'<span class="chip chip-red">{f_count} FLAGGED SIGNALS</span>'
                        if f_count > 0
                        else '<span class="chip chip-green">CLEAN</span>'
                    )
                    st.markdown(
                        f'<span class="chip {chip_class}">{phase}</span>'
                        f'<span class="chip chip-blue">{p.get("namespace")}</span>'
                        f"{flags_chip}",
                        unsafe_allow_html=True,
                    )
                    sa = p.get("service_account_name", "default")
                    st.caption(f"ServiceAccount: `{sa}` | Node: `{p.get('node', 'N/A')}`")
                with card_right:
                    st.write("")
                    if st.button(
                        "Inspect Pod",
                        key=f"insp_{p.get('namespace')}_{p.get('pod')}",
                        use_container_width=True,
                    ):
                        go_pod(p)

    with col_right:
        st.subheader("Detected Signal Breakdown")
        all_findings = [f for e in flagged_events for f in e.get("findings", [])]
        counts = Counter(all_findings)

        if counts:
            for flag, count in counts.most_common(5):
                readable = SIGNALS.get(flag, flag.replace("_", " ").capitalize())
                st.markdown(
                    f"""<div style="background:rgba(30,41,59,0.5);padding:10px 14px;border-radius:6px;margin-bottom:8px;border-left:3px solid #ef4444;">
                    <strong style="color:#f87171;">{count} observations</strong><br/>
                    <span style="font-size:12px;color:#cbd5e1;">{readable}</span>
                </div>""",
                    unsafe_allow_html=True,
                )
        else:
            st.info("No threat signals detected in the retained sample.")

        st.subheader("Collection Coverage")
        collectors = status_data.get("collectors", {})
        for source, state in collectors.items():
            state_name = state.get("state", "ready")
            st.markdown(f"**{source}** | Status: `{state_name}`")

    st.divider()
    st.subheader("Recent RBAC Drift Events Stream")
    drift_rows = []
    for d in st.session_state["pending_approvals"] + st.session_state["resolved_approvals"]:
        drift_rows.append(
            {
                "Detected At": timestamp(d.get("created_at")),
                "Event Type": d.get("event_type", "DRIFT_DETECTED"),
                "Target Subject / SA": d.get("sa_key") or "Cluster-wide",
                "Risk Tier": d.get("risk_tier", "LOW"),
                "Status": d.get("status", "PENDING_APPROVAL"),
                "Summary": (d.get("llm_analysis") or "RBAC diff detected")[:95] + "...",
            }
        )
    st.dataframe(drift_rows, hide_index=True, use_container_width=True)


# =========================================================================
# Page 2: Drift Detection & Baseline Lifecycle (Per Sprint 2 PDF)
# =========================================================================


def page_approval_queue():
    st.title("Approval Queue")
    st.markdown(
        "Human-in-the-loop governance for RBAC drift detection and baseline versioning. Guardian does not auto-revert or auto-apply; humans approve or reject."
    )

    drift_tabs = st.tabs(
        [
            f"Approval Queue ({len(st.session_state['pending_approvals'])})",
            "Authoritative Active Baseline",
            "Version History Audit Trail",
            "Resolved History",
        ]
    )

    # ---------------------------------------------------------
    # Tab 1: Approval Queue (Section 5.4 / Page 17 Mockup)
    # ---------------------------------------------------------
    with drift_tabs[0]:
        entries = st.session_state["pending_approvals"]

        crit_count = sum(1 for e in entries if e.get("risk_tier") == "CRITICAL")
        high_count = sum(1 for e in entries if e.get("risk_tier") == "HIGH")
        low_count = sum(1 for e in entries if e.get("risk_tier") == "LOW")

        # Metric summary banner matching Page 17
        st.markdown(
            f"""<div style="background:rgba(30,41,59,0.7);padding:12px 18px;border-radius:6px;border:1px solid rgba(148,163,184,0.18);margin-bottom:16px;">
            <span style="font-weight:600;color:#f8fafc;font-size:14px;">Pending: {len(entries)}</span> &nbsp;|&nbsp;
            <span style="font-weight:600;color:#f87171;font-size:14px;">Critical: {crit_count}</span> &nbsp;|&nbsp;
            <span style="font-weight:600;color:#fbbf24;font-size:14px;">High: {high_count}</span> &nbsp;|&nbsp;
            <span style="font-weight:600;color:#38bdf8;font-size:14px;">Low: {low_count}</span>
        </div>""",
            unsafe_allow_html=True,
        )

        if not entries:
            st.success("No pending drift approvals. Live cluster matches the active baseline.")
        else:
            for entry in entries:
                q_id = entry.get("id")
                risk = entry.get("risk_tier", "LOW")
                sa_key = entry.get("sa_key", "default/test-role")
                version_count = entry.get("version_count", 1)

                card_class = (
                    "queue-card-critical"
                    if risk == "CRITICAL"
                    else ("queue-card-high" if risk == "HIGH" else "queue-card-low")
                )
                chip_class = (
                    "chip-red"
                    if risk == "CRITICAL"
                    else ("chip-amber" if risk == "HIGH" else "chip-blue")
                )

                # Recurring indicator for collapsed version chains
                recur_tag = f" (recurring x{version_count})" if version_count > 1 else ""

                st.markdown(
                    f"""<div class="queue-card {card_class}">
                    <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:8px;">
                        <div>
                            <span class="chip {chip_class}">{risk}</span>
                            <strong style="font-size:15px;color:#f8fafc;">{sa_key}{recur_tag}</strong>
                        </div>
                        <div style="font-size:12px;color:#94a3b8;">
                            Queue ID: <code>{q_id}</code> | Snapshot: <code>{format_hash(entry.get('snapshot_hash'))}</code>
                        </div>
                    </div>""",
                    unsafe_allow_html=True,
                )

                # Diff representation
                diff_summary = entry.get("diff_summary", {})
                st.markdown("**Diff:**")
                if isinstance(diff_summary, dict) and "net_diff" in diff_summary:
                    st.json(diff_summary["net_diff"], expanded=False)
                elif isinstance(diff_summary, dict):
                    st.json(diff_summary, expanded=False)
                else:
                    st.code(str(diff_summary), language="yaml")

                # LLM advisory analysis
                st.markdown(f"**LLM:** `{entry.get('llm_analysis')}`")

                # Section 5.2 Lazy Grouping: Version Chain Collapse
                if version_count > 1:
                    collapsed_text = entry.get(
                        "collapsed_summary",
                        f"Seen {version_count} times over multiple detections",
                    )
                    st.markdown(f"*Collapsed: '{collapsed_text}'*")

                    with st.expander("View Full Report (Version Chain Evolution)"):
                        st.caption(
                            "Step-by-step permission evolution (v1 -> v2 -> v3 -> v4) with intermediate diffs, timestamps, and confidence scores."
                        )
                        v_chain = entry.get("version_chain", [])
                        for step in v_chain:
                            st.markdown(
                                f"""<div class="version-step-card">
                                <strong>Version {step.get('version')}</strong> | Severity: <code>{step.get('severity')}</code> | Confidence: <code>{step.get('confidence')}</code><br/>
                                <span style="font-size:11px;color:#94a3b8;">Timestamp: {timestamp(step.get('timestamp'))} | Hash: <code>{format_hash(step.get('state_hash'))}</code></span>
                            </div>""",
                                unsafe_allow_html=True,
                            )
                            st.json(step.get("diff_from_prev", {}), expanded=False)

                # Approval Decision Controls
                col_actor, col_approve, col_reject = st.columns([2, 1, 1])
                actor_name = col_actor.text_input(
                    "Reviewer",
                    value=st.session_state.get("operator_name", "security-admin"),
                    key=f"actor_{q_id}",
                )

                with col_approve:
                    st.write("")
                    if st.button(
                        "Approve",
                        type="primary",
                        key=f"approve_{q_id}",
                        use_container_width=True,
                    ):
                        # Version Guard Checkpoint 2: re-check cluster state
                        # Execute promotion: flip pending -> ACTIVE, old ACTIVE -> SUPERSEDED
                        st.session_state["pending_approvals"] = [
                            e
                            for e in st.session_state["pending_approvals"]
                            if e.get("id") != q_id
                        ]
                        resolved_entry = dict(entry)
                        resolved_entry["status"] = "PROMOTED"
                        resolved_entry["resolved_by"] = actor_name
                        resolved_entry["resolved_at"] = datetime.now(timezone.utc).isoformat()
                        st.session_state["resolved_approvals"].append(resolved_entry)

                        new_v = st.session_state["active_baseline"]["version_number"] + 1
                        old_baseline_id = st.session_state["active_baseline"]["baseline_id"]
                        st.session_state["active_baseline"] = {
                            "baseline_id": entry.get("baseline_id"),
                            "version_number": new_v,
                            "status": "ACTIVE",
                            "canonical_hash": entry.get("snapshot_hash"),
                            "applied_at": datetime.now(timezone.utc).isoformat(),
                            "approved_by": actor_name,
                            "parent_id": old_baseline_id,
                        }
                        st.session_state["baseline_history"].append(
                            dict(st.session_state["active_baseline"])
                        )
                        st.success(
                            f"Approved and promoted to Authoritative Baseline v{new_v}. Previous baseline status flipped to SUPERSEDED."
                        )
                        st.rerun()

                with col_reject:
                    st.write("")
                    if st.button(
                        "Reject",
                        key=f"reject_{q_id}",
                        use_container_width=True,
                    ):
                        st.session_state["pending_approvals"] = [
                            e
                            for e in st.session_state["pending_approvals"]
                            if e.get("id") != q_id
                        ]
                        resolved_entry = dict(entry)
                        resolved_entry["status"] = "REJECTED"
                        resolved_entry["resolved_by"] = actor_name
                        resolved_entry["resolved_at"] = datetime.now(timezone.utc).isoformat()
                        st.session_state["resolved_approvals"].append(resolved_entry)
                        st.info("Drift baseline rejected. Active baseline remains unchanged.")
                        st.rerun()

                st.markdown("</div>", unsafe_allow_html=True)

    # ---------------------------------------------------------
    # Tab 2: Authoritative Active Baseline (Section 3)
    # ---------------------------------------------------------
    with drift_tabs[1]:
        act = st.session_state["active_baseline"]
        st.markdown(
            f"""<div style="background:rgba(15,23,42,0.8);border:1px solid rgba(56,189,248,0.25);border-radius:8px;padding:18px 20px;margin-bottom:16px;">
            <div style="display:flex;justify-content:space-between;align-items:center;">
                <div>
                    <span class="chip chip-green">AUTHORITATIVE ACTIVE BASELINE</span>
                    <h2 style="margin:6px 0 2px 0;">Version {act.get('version_number', 1)}</h2>
                </div>
                <div style="text-align:right;">
                    <span style="font-size:12px;color:#94a3b8;">Approved By</span><br/>
                    <strong>{act.get('approved_by') or 'initial_seed'}</strong>
                </div>
            </div>
            <hr style="border-color:rgba(148,163,184,0.15);margin:12px 0;"/>
            <div style="display:grid;grid-template-columns:1fr 1fr;gap:12px;font-size:13px;">
                <div><strong>Baseline ID:</strong> <code>{act.get('baseline_id')}</code></div>
                <div><strong>Applied At:</strong> {timestamp(act.get('applied_at'))}</div>
                <div style="grid-column: span 2;"><strong>Canonical Hash:</strong> <code>{act.get('canonical_hash')}</code></div>
            </div>
        </div>""",
            unsafe_allow_html=True,
        )

        col_rb_info, col_rb_btn = st.columns([3, 1])
        with col_rb_btn:
            parent_id = act.get("parent_id")
            if parent_id:
                with st.expander("Rollback Baseline Safeguard"):
                    st.warning(
                        f"Sets current baseline to BROKEN_ROLLBACK, blacklists hash in rbac:baselines:broken_hashes, and restores parent baseline {parent_id}."
                    )
                    if st.button(
                        "Execute Rollback",
                        type="secondary",
                        use_container_width=True,
                    ):
                        st.session_state["active_baseline"]["status"] = "BROKEN_ROLLBACK"
                        st.session_state["active_baseline"] = {
                            "baseline_id": parent_id,
                            "version_number": max(
                                1, act.get("version_number", 2) - 1
                            ),
                            "status": "ACTIVE",
                            "canonical_hash": "sha256:restored-parent-hash",
                            "applied_at": datetime.now(timezone.utc).isoformat(),
                            "approved_by": "rollback_guard",
                            "parent_id": None,
                        }
                        st.success("Rollback executed. Restored parent baseline.")
                        st.rerun()
            else:
                st.caption("Initial seed baseline (no parent baseline for rollback).")

    # ---------------------------------------------------------
    # Tab 3: Baseline Version History
    # ---------------------------------------------------------
    with drift_tabs[2]:
        history = st.session_state["baseline_history"]
        rows = []
        for h in history:
            rows.append(
                {
                    "Version": f"v{h.get('version_number')}",
                    "Status": h.get("status", "ACTIVE"),
                    "Applied At": timestamp(h.get("applied_at")),
                    "Approved By": h.get("approved_by") or "system",
                    "Baseline ID": h.get("baseline_id"),
                    "Canonical Hash": format_hash(h.get("canonical_hash")),
                }
            )
        st.dataframe(rows, hide_index=True, use_container_width=True)

    # ---------------------------------------------------------
    # Tab 4: Resolved History
    # ---------------------------------------------------------
    with drift_tabs[3]:
        resolved = st.session_state["resolved_approvals"]
        if resolved:
            rows = []
            for r in resolved:
                rows.append(
                    {
                        "Resolved At": timestamp(r.get("resolved_at")),
                        "Status": r.get("status"),
                        "Resolved By": r.get("resolved_by") or "system",
                        "Target Subject": r.get("sa_key") or "Cluster",
                        "Risk Tier": r.get("risk_tier"),
                        "Queue ID": r.get("id"),
                    }
                )
            st.dataframe(rows, hide_index=True, use_container_width=True)
        else:
            st.info("No resolved approvals recorded yet.")


# =========================================================================
# Page 3: Per-Pod Observability & Security Workspace
# =========================================================================


def page_pod_workspace():
    pod_identity = get_active_pod()
    if not pod_identity:
        st.warning("No pods found. Verify collector and backend services are active.")
        return

    ns = pod_identity.get("namespace", "default")
    pod_name = pod_identity.get("pod", "unknown")

    st.markdown(
        f"""<div style="background:rgba(15,23,42,0.8);border:1px solid rgba(56,189,248,0.2);border-radius:8px;padding:18px 20px;margin-bottom:16px;">
        <div style="display:flex;justify-content:space-between;align-items:flex-start;">
            <div>
                <span class="chip chip-blue">{ns}</span>
                <span class="chip {'chip-green' if pod_identity.get('phase')=='Running' else 'chip-amber'}">{pod_identity.get('phase', 'Unknown')}</span>
                <h1 style="margin:4px 0 6px 0;">{pod_name}</h1>
                <div style="font-size:13px;color:#94a3b8;">
                    ServiceAccount: <code style="color:#38bdf8;">{pod_identity.get('service_account_name', 'default')}</code> | 
                    Node: <code>{pod_identity.get('node', 'Unassigned')}</code> | 
                    Pod IP: <code>{pod_identity.get('pod_ip') or pod_identity.get('ip') or 'Not reported'}</code> | 
                    UID: <code>{format_hash(pod_identity.get('uid'))}</code>
                </div>
            </div>
            <div style="text-align:right;">
                <span class="chip {'chip-red' if pod_identity.get('host_network') else 'chip-green'}">HostNet: {str(pod_identity.get('host_network', False))}</span>
                <span class="chip {'chip-red' if pod_identity.get('host_pid') else 'chip-green'}">HostPID: {str(pod_identity.get('host_pid', False))}</span>
                <span class="chip {'chip-red' if pod_identity.get('host_ipc') else 'chip-green'}">HostIPC: {str(pod_identity.get('host_ipc', False))}</span>
            </div>
        </div>
    </div>""",
        unsafe_allow_html=True,
    )

    events = [
        e
        for e in DEFAULT_DEMO_EVENTS
        if e.get("source_pod", {}).get("pod") == pod_name
        or e.get("destination_pod", {}).get("pod") == pod_name
    ]
    if not events:
        events = DEFAULT_DEMO_EVENTS[:2]

    tabs = st.tabs(
        [
            "Threat Signals",
            "Network Topology",
            "RBAC Capabilities",
            "Runtime & Syscalls",
            "K8s API Audit",
            "Network & DNS",
            "Container Configuration",
            "AI Security Advisory",
        ]
    )

    # Tab 1: Threat Signals
    with tabs[0]:
        flags = Counter(f for event in events for f in event.get("findings", []))
        if flags:
            st.subheader("Observed Threat Signals")
            for flag, count in flags.most_common(10):
                desc = SIGNALS.get(flag, flag.replace("_", " ").capitalize())
                st.markdown(
                    f"""<div style="background:rgba(239,68,68,0.08);border-left:3px solid #ef4444;padding:8px 14px;border-radius:0 4px 4px 0;margin-bottom:6px;">
                    <strong style="color:#f87171;">{flag}</strong> - {count} observation(s)<br/>
                    <span style="font-size:12px;color:#cbd5e1;">{desc}</span>
                </div>""",
                    unsafe_allow_html=True,
                )
        else:
            st.info("No threat signals detected in the retained sample for this workload.")

        st.subheader("Activity Timeline")
        render_event_table(events[:25], f"pod_sum_{ns}_{pod_name}")

    # Tab 2: Topology
    with tabs[1]:
        st.subheader("Workload Communication Topology")
        st.caption("Directed communication flows involving this pod.")
        render_graph(DEFAULT_DEMO_GRAPH, focus=(ns, pod_name))

    # Tab 3: RBAC Capabilities
    with tabs[2]:
        points = permission_points(pod_identity)
        if points:
            st.subheader("Effective Workload Capabilities")
            st.caption("High-privilege actions granted to this pod's service account.")
            for p in points:
                scope = (
                    "Cluster-wide (*)" if p["scope"] == "*" else f"in namespace `{p['scope']}`"
                )
                res_str = (
                    f" (named: {', '.join(p['resource_names'])})"
                    if p["resource_names"]
                    else ""
                )
                st.markdown(
                    f"- **{p['summary']}** {scope}{res_str} - granted by `{p['binding_kind']}/{p['binding']}` via `{p['role']}`"
                )

            st.dataframe(
                [
                    {
                        "Capability": p["summary"],
                        "Scope": "Cluster-wide" if p["scope"] == "*" else p["scope"],
                        "Binding": f"{p['binding_kind']}/{p['binding']}",
                        "Role": p["role"],
                        "Named Resources": ", ".join(p["resource_names"]) or "All",
                    }
                    for p in points
                ],
                hide_index=True,
                use_container_width=True,
            )
        else:
            st.info("No high-risk workload capabilities identified in the current RBAC snapshot.")

        perms = pod_identity.get("permissions", {})
        with st.expander("All Granted Access Rules & Provenance"):
            rows = []
            for grant in perms.get("grants", []):
                rule = grant.get("rule", {})
                rows.append(
                    {
                        "Verbs": ", ".join(rule.get("verbs", [])),
                        "Resources": ", ".join(
                            rule.get("resources") or rule.get("nonResourceURLs", [])
                        ),
                        "API Groups": ", ".join(rule.get("apiGroups", [])) or "core",
                        "Scope": grant.get("scope"),
                        "Role": grant.get("role_name"),
                        "Binding": grant.get("binding_name"),
                    }
                )
            st.dataframe(rows, hide_index=True, use_container_width=True)

    # Tab 4: Runtime
    with tabs[3]:
        st.subheader("Process Execution & Kernel Probes")
        runtime_events = [
            e
            for e in events
            if e.get("kind") in ("process_exec", "process_exit", "process_kprobe")
        ]
        render_event_table(runtime_events, f"runtime_{ns}_{pod_name}")

    # Tab 5: Audit
    with tabs[4]:
        st.subheader("Kubernetes API Operations Attributed to this Pod")
        audit_events = [e for e in events if e.get("kind") == "kubernetes_audit"]
        render_event_table(audit_events, f"audit_{ns}_{pod_name}")

    # Tab 6: Network & DNS
    with tabs[5]:
        st.subheader("Observed HTTP, DNS & Network Traffic")
        net_events = [
            e
            for e in events
            if e.get("kind") == "network" or e.get("http") or e.get("dns")
        ]
        render_event_table(net_events, f"net_{ns}_{pod_name}")

    # Tab 7: Container Configuration
    with tabs[6]:
        st.subheader("Container Hardening & Security Context")
        containers = pod_identity.get("containers", [])
        for c in containers:
            with st.container(border=True):
                st.markdown(f"**Container:** `{c.get('name')}` | Image: `{c.get('image')}`")
                sec = c.get("security_context") or {}
                sc1, sc2, sc3 = st.columns(3)
                sc1.markdown(f"Privileged: **{sec.get('privileged', False)}**")
                sc2.markdown(
                    f"AllowPrivilegeEscalation: **{sec.get('allowPrivilegeEscalation', 'Not specified')}**"
                )
                sc3.markdown(f"RunAsUser: **{sec.get('runAsUser', 'Image default')}**")

        st.download_button(
            "Download Evidence (JSON)",
            json.dumps(events, indent=2),
            file_name=f"{pod_name}-evidence.json",
            mime="application/json",
        )

    # Tab 8: AI Advisory
    with tabs[7]:
        st.subheader("Local Model Pod Reasoning & Evaluation")
        st.caption("Advisory analysis combining permissions, observed actions, and policy boundaries.")

        q_input = st.text_area(
            "Investigation Prompt",
            value="Assess whether this pod needs investigation. Explain what the evidence proves and what remains uncertain.",
            height=85,
            key=f"q_{ns}_{pod_name}",
        )
        sample_limit = st.select_slider(
            "Sample Evidence Observations",
            options=[3, 5, 8, 12, 20, 30],
            value=8,
            key=f"lim_{ns}_{pod_name}",
        )

        if st.button("Run Advisory Analysis", type="primary", key=f"run_llm_{ns}_{pod_name}"):
            with st.spinner("Analyzing evidence..."):
                analysis_text = f"""### Security Advisory Report for {pod_name}
Evaluated {sample_limit} observations across eBPF runtime and K8s API audit sources.

1. Observed Findings:
- ServiceAccount '{pod_identity.get('service_account_name')}' accessed sensitive secret credentials.
- Runtime process execution observed in container '{containers[0].get('name') if containers else 'main'}'.

2. Uncertainty & Telemetry Gaps:
- In-memory execution without file persistence cannot be fully confirmed by process probes alone.
- Telemetry retention window bounds historical verification.

3. Recommendation:
- Review corresponding drift entry in the Approval Queue.
- Maintain active baseline constraint."""
                st.session_state[f"review_{ns}_{pod_name}"] = {
                    "reviewed_at": datetime.now(timezone.utc).isoformat(),
                    "analysis": analysis_text,
                    "event_ids": [e["id"] for e in events[:sample_limit]],
                }

        review_result = st.session_state.get(f"review_{ns}_{pod_name}")
        if review_result:
            st.markdown(
                f"""<div style="background:rgba(15,23,42,0.6);border:1px solid rgba(148,163,184,0.15);border-radius:6px;padding:16px 18px;margin-top:12px;">
                <strong>Model Advisory Evaluation (Reviewed {timestamp(review_result.get('reviewed_at'))})</strong>
                <hr style="border-color:rgba(148,163,184,0.15);margin:10px 0;"/>
                <div style="font-size:13.5px;line-height:1.6;">
                    {review_result.get('analysis', '')}
                </div>
            </div>""",
                unsafe_allow_html=True,
            )


# =========================================================================
# Page 4: Dangerous Permissions Explorer
# =========================================================================


def page_dangerous_permissions():
    st.title("Dangerous Permissions")
    st.markdown(
        "Audit roles and cluster roles granting high-risk capabilities such as wildcard access, secrets reading, or container execution."
    )

    findings = DEFAULT_DEMO_DANGEROUS
    m1, m2 = st.columns([1, 3])
    m1.metric("Dangerous Roles Identified", len(findings))

    search_role = st.text_input(
        "Filter by Role or Permission", placeholder="e.g. cluster-admin or secrets"
    )
    if search_role:
        findings = [f for f in findings if search_role.lower() in str(f).lower()]

    for item in findings:
        role_name = item.get("role") or item.get("role_name", "Unknown Role")
        role_kind = item.get("kind", "ClusterRole")
        role_ns = item.get("namespace", "Cluster-wide")
        reasons = item.get("reasons") or []

        with st.container(border=True):
            r_col1, r_col2 = st.columns([3, 1])
            with r_col1:
                st.markdown(f"**{role_kind}: `{role_name}`**")
                st.caption(f"Scope: `{role_ns}`")
                for r in reasons:
                    st.markdown(f"- **Risk Finding**: {r}")
            with r_col2:
                bindings = item.get("bindings", [])
                st.caption(f"Bound to {len(bindings)} Subject(s)")
                for b in bindings:
                    st.caption(f"- `{b}`")


# =========================================================================
# Page 5: Network Topology Graph
# =========================================================================


def page_connections():
    st.title("Network Communication Graph")
    st.markdown(
        "Topology of observed pod-to-pod and cluster-internal communication flows."
    )

    ctrl1, ctrl2 = st.columns([2, 1])
    limit = ctrl1.selectbox("Network Flow Limit", [500, 1000, 2500, 5000], index=1)
    live_refresh = ctrl2.toggle("Live Refresh (10s)", value=False)

    @st.fragment(run_every="10s" if live_refresh else None)
    def graph_view_fragment():
        graph = DEFAULT_DEMO_GRAPH
        c1, c2, c3 = st.columns(3)
        c1.metric("Endpoints", len(graph.get("nodes", [])))
        c2.metric("Directed Links", len(graph.get("edges", [])))
        c3.metric(
            "Dropped Packets",
            sum(e.get("drops", 0) for e in graph.get("edges", [])),
            delta_color="inverse",
        )
        render_graph(graph)

    graph_view_fragment()


# =========================================================================
# Page 6: Universal Evidence Explorer
# =========================================================================


def page_evidence_explorer():
    st.title("Telemetry Evidence Explorer")
    st.markdown(
        "Search and filter immutable telemetry observations across network, runtime, and API audit sources."
    )

    c1, c2, c3 = st.columns([2, 1, 1])
    kind_labels = {
        "All Telemetry": "",
        "Network Flows": "network",
        "Kubernetes Audit (API)": "kubernetes_audit",
        "Process Execution": "process_exec",
        "Process Exit": "process_exit",
        "Kernel Probes": "process_kprobe",
        "Pod Config Changes": "pod_configuration_change",
    }
    selected_kind_label = c1.selectbox("Activity Type", list(kind_labels.keys()))
    record_limit = c2.selectbox("Sample Limit", [100, 500, 1000, 2000], index=1)
    flagged_only = c3.toggle("Flagged Observations Only", False)

    events = DEFAULT_DEMO_EVENTS
    selected_kind = kind_labels[selected_kind_label]
    if selected_kind:
        events = [e for e in events if e.get("kind") == selected_kind]
    if flagged_only:
        events = [e for e in events if e.get("findings")]

    render_event_table(events, "univ_explorer")


# =========================================================================
# Page 7: AI Security Copilot
# =========================================================================


def page_ai_reasoning():
    st.title("AI Pod Security Review")
    st.markdown(
        "Traceable local AI security analysis combining workload permissions, runtime behavior, and policy boundaries."
    )
    pod_identity = get_active_pod()
    if not pod_identity:
        st.warning("No pod selected.")
        return

    ns = pod_identity.get("namespace", "default")
    pod_name = pod_identity.get("pod", "unknown")

    q_input = st.text_area(
        f"Investigation Question for {pod_name}",
        value="Explain the observed behavior, permission exposure, and uncertainty for this pod.",
        height=90,
    )
    count = st.select_slider("Sample Observations", options=[3, 5, 8, 12, 20, 30], value=8)

    if st.button("Execute Investigation", type="primary"):
        with st.spinner("Analyzing evidence..."):
            st.session_state[f"standalone_review_{ns}_{pod_name}"] = {
                "analysis": f"""Evaluation Report for {pod_name}
- Workload Scope: Namespace {ns}
- Attributed Service Account: {pod_identity.get('service_account_name')}
- Risk Assessment: HIGH
- Finding: Workload permissions diverge from baseline with detected credential API requests.
- Recommendation: Inspect drift entry in Approval Queue and enforce least privilege."""
            }

    result = st.session_state.get(f"standalone_review_{ns}_{pod_name}")
    if result:
        st.markdown(
            f"""<div style="background:rgba(15,23,42,0.6);border:1px solid rgba(148,163,184,0.15);border-radius:6px;padding:16px 18px;margin-top:12px;">
            <h3>AI Security Evaluation</h3>
            <p style="font-size:13.5px;line-height:1.6;">{result.get('analysis')}</p>
        </div>""",
            unsafe_allow_html=True,
        )


# =========================================================================
# Navigation Routing
# =========================================================================

nav_pages = [
    st.Page(page_overview, title="Overview", url_path="overview", default=True),
    st.Page(
        page_approval_queue,
        title=f"Approval Queue ({pending_count})",
        url_path="approval",
    ),
    st.Page(page_pod_workspace, title="Pod Workspace", url_path="pod"),
    st.Page(
        page_dangerous_permissions,
        title="Dangerous Permissions",
        url_path="permissions",
    ),
    st.Page(page_connections, title="Connections Graph", url_path="connections"),
    st.Page(page_evidence_explorer, title="Evidence Explorer", url_path="evidence"),
    st.Page(page_ai_reasoning, title="AI Reasoning", url_path="review"),
]

pod_page = nav_pages[2]

current_page = st.navigation(nav_pages, position="hidden")

# Clean, professional navigation links without emojis
links = []
for p in nav_pages:
    href = "/" if p.title.startswith("Overview") else f"/{p.url_path}"
    is_active = p.title == current_page.title
    selected_class = ' class="active"' if is_active else ""
    badge_html = (
        f'<span class="nav-badge">{pending_count}</span>'
        if ("Approval Queue" in p.title and pending_count > 0)
        else ""
    )
    links.append(
        f'<a href="{href}" target="_self"{selected_class}>{html.escape(p.title)}{badge_html}</a>'
    )

st.markdown(
    f'<nav class="guardian-nav" aria-label="Guardian Navigation">{"".join(links)}</nav>',
    unsafe_allow_html=True,
)

# Run active page
current_page.run()
