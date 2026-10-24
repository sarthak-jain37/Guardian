import sys
from pathlib import Path

# Ensure project root is in sys.path so 'backend' imports work seamlessly
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import streamlit as st
import requests
from backend.app.core.config import BACKEND_URL


st.set_page_config(
    page_title="RBAC Drift Guardian",
    page_icon="🛡️",
    layout="wide",
)

st.title("Kubernetes RBAC Drift Guardian")


def get_dangerous_permissions():
    try:
        response = requests.get(
            f"{BACKEND_URL}/dangerous-permissions",
            timeout=5,
        )
        response.raise_for_status()
        return response.json().get("findings", [])
    except requests.RequestException as error:
        st.error(f"Failed to fetch dangerous permissions from backend: {error}")
        return []


def get_events():
    try:
        response = requests.get(
            f"{BACKEND_URL}/outputs",
            timeout=5,
        )
        response.raise_for_status()
        return response.json().get("events", [])
    except requests.RequestException as error:
        st.error(f"Backend connection failed: {error}")
        return []


def render_diff(diff):
    for category, changes in diff.items():
        if not changes:
            continue

        is_added = "added" in category
        is_removed = "removed" in category
        title = category.replace("_", " ").title()

        if is_added:
            st.success(f"🟢 {title}")
        elif is_removed:
            st.error(f"🔴 {title}")
        else:
            st.warning(title)

        st.json(changes)


st.header("⚠️ Dangerous Permissions Detection")
st.caption(
    "Live cluster audit of Roles & ClusterRoles for privilege escalation risks "
    "(dangerous verbs like bind/impersonate/escalate, wildcards, and sensitive resources)."
)

dangerous_perms = get_dangerous_permissions()

if not dangerous_perms:
    st.success("✅ No dangerous permissions detected in the cluster.")
else:
    crit_count = sum(1 for r in dangerous_perms if r.get("severity") == "CRITICAL")
    high_count = sum(1 for r in dangerous_perms if r.get("severity") == "HIGH")
    med_count = sum(1 for r in dangerous_perms if r.get("severity") == "MEDIUM")

    metric_col1, metric_col2, metric_col3, metric_col4 = st.columns(4)
    metric_col1.metric("Flagged Roles", len(dangerous_perms))
    metric_col2.metric("Critical Risks", crit_count)
    metric_col3.metric("High Risks", high_count)
    metric_col4.metric("Medium Risks", med_count)

    st.write("")

    for role in dangerous_perms:
        sev = role.get("severity", "LOW")
        icon = "🚨" if sev == "CRITICAL" else ("⚠️" if sev == "HIGH" else "ℹ️")
        expander_label = (
            f"{icon} [{sev}] {role.get('role_kind')}: {role.get('role_name')} "
            f"(Namespace: {role.get('namespace')})"
        )

        with st.expander(expander_label, expanded=(sev == "CRITICAL")):
            flags_tags = " ".join([f"`{flag}`" for flag in role.get("flags", [])])
            st.markdown(f"**Identified Risks:** {flags_tags}")

            for rule in role.get("rules", []):
                rule_num = rule.get("rule_index", 0) + 1
                st.markdown(f"**Rule #{rule_num}** (Severity: `{rule.get('severity')}`)")

                c1, c2, c3 = st.columns(3)
                with c1:
                    st.markdown(f"**Verbs:** `{rule.get('verbs')}`")
                with c2:
                    st.markdown(f"**Resources:** `{rule.get('resources')}`")
                with c3:
                    st.markdown(f"**API Groups:** `{rule.get('api_groups')}`")

                for finding in rule.get("findings", []):
                    if rule.get("severity") == "CRITICAL":
                        st.error(f"• {finding}")
                    else:
                        st.warning(f"• {finding}")

                st.markdown("---")


st.divider()


st.header("🔄 RBAC Drift Events")

events = get_events()

if not events:
    st.info("No RBAC drift events detected yet.")
else:
    if "current_index" not in st.session_state:
        st.session_state.current_index = 0

    # Ensure index remains within bounds
    if st.session_state.current_index >= len(events):
        st.session_state.current_index = len(events) - 1

    left, middle, right = st.columns([1, 2, 1])

    with left:
        if st.button(
            "⬅ Previous",
            disabled=(st.session_state.current_index == 0),
            use_container_width=True,
        ):
            st.session_state.current_index -= 1
            st.rerun()

    with middle:
        st.markdown(
            f"""
            <div style="text-align:center;">
                <h4>
                    Drift Event
                    {st.session_state.current_index + 1}
                    of
                    {len(events)}
                </h4>
            </div>
            """,
            unsafe_allow_html=True,
        )

    with right:
        if st.button(
            "Next ➡",
            disabled=(st.session_state.current_index == len(events) - 1),
            use_container_width=True,
        ):
            st.session_state.current_index += 1
            st.rerun()

    current_event = events[st.session_state.current_index]

    st.caption(f"Detected: {current_event.get('timestamp', 'Unknown')}")

    diff_col, llm_col = st.columns(2)

    with diff_col:
        st.subheader("🔐 RBAC Diff")
        render_diff(current_event.get("diff", {}))

    with llm_col:
        st.subheader("LLM Analysis")
        st.markdown(
            current_event.get("llm_response", "No LLM analysis available.")
        )
st.divider()
st.header("Pod activity and runtime monitoring")
try:
    telemetry_status = requests.get(f"{BACKEND_URL}/telemetry/status", timeout=5)
    telemetry_status.raise_for_status()
    st.json(telemetry_status.json())
    selected_namespace = st.text_input("Telemetry namespace (empty for all)")
    params = {"limit": 500}
    if selected_namespace:
        params["namespace"] = selected_namespace
    graph_response = requests.get(f"{BACKEND_URL}/telemetry/graph", params=params, timeout=10)
    graph_response.raise_for_status()
    graph = graph_response.json()
    import json
    dot = ["digraph pods {"]
    for node in graph["nodes"]:
        dot.append(f'{json.dumps(node["id"])} [label={json.dumps(node.get("namespace", "") + "/" + (node.get("pod") or node.get("ip", "unknown")))}];')
    for edge in graph["edges"]:
        label = f'{edge["flow_records"]} flows / {edge["http_requests"]} HTTP / {edge["drops"]} drops'
        dot.append(f'{json.dumps(edge["source"])} -> {json.dumps(edge["target"])} [label={json.dumps(label)}];')
    st.graphviz_chart("\n".join(dot + ["}"]))
    records_response = requests.get(f"{BACKEND_URL}/telemetry/events", params=params, timeout=10)
    records_response.raise_for_status()
    records = records_response.json()["events"]
    st.caption("Recent observed events; collection gaps and encrypted traffic limit coverage.")
    st.dataframe(records, use_container_width=True)
    if st.button("Evaluate recent activity with local LLM"):
        with st.spinner("Evaluating activity against configured boundaries..."):
            evaluation = requests.post(f"{BACKEND_URL}/telemetry/evaluate", params={**params, "limit": 50}, timeout=180)
            evaluation.raise_for_status()
            st.write(evaluation.json()["analysis"])
except requests.RequestException as error:
    st.warning(f"Telemetry backend unavailable: {error}")

st.subheader("Pod evidence and permissions")
try:
    inventory_response = requests.get(f"{BACKEND_URL}/telemetry/pods", timeout=10)
    inventory_response.raise_for_status()
    inventory = inventory_response.json()
    identities = {(p["namespace"], p["pod"]): p for p in inventory.get("pods", [])}
    st.caption(f'Inventory observed at: {inventory.get("observed_at") or "not collected"}')
    if identities:
        selected = st.selectbox("Inspect a pod", list(identities), format_func=lambda p: "/".join(p))
        with st.expander("Pod configuration and service-account grants"):
            st.json(identities[selected])
        evidence_response = requests.get(f"{BACKEND_URL}/telemetry/pods/{selected[0]}/{selected[1]}/evidence", timeout=15)
        evidence_response.raise_for_status()
        st.json(evidence_response.json())
    else:
        st.info("No pod inventory available. Check inventory collector status and read permissions.")
except requests.RequestException as error:
    st.warning(f"Pod evidence unavailable: {error}")
