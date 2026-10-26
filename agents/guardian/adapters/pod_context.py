"""Bounded supplemental context from main's read-only pod-evidence export.

Inventory health is not UsageSummary coverage. This adapter never manufactures
zero request counts, complete consumer discovery or authority from telemetry.
"""

import json
from datetime import datetime

from contracts.usage_summary_v1 import utc

from ..contracts import EvidenceBundle
from ..policy import canonical_hash


def attach_pod_context(evidence, payload, *, cluster_id, pod_name, pod_uid, now):
    evidence = EvidenceBundle.model_validate(evidence)
    if evidence.context is None or evidence.target.cluster_id != cluster_id:
        raise ValueError("pod_context_requires_existing_scoped_context")
    if len(json.dumps(payload).encode()) > 131072:
        raise ValueError("pod_context_export_too_large")
    if not isinstance(payload, dict) or not isinstance(payload.get("pods"), list) or len(payload["pods"]) > 128:
        raise ValueError("invalid_pod_context_export")
    observed = payload.get("inventory_observed_at")
    try:
        observed = utc(datetime.fromisoformat(observed))
    except (ValueError, TypeError):
        raise ValueError("pod_inventory_time_unavailable") from None
    if not 0 <= (now - observed).total_seconds() <= evidence.policy.maximum_source_lag_seconds:
        raise ValueError("pod_inventory_stale")
    matching = [p for p in payload["pods"] if isinstance(p, dict) and
                p.get("identity", {}).get("namespace") == evidence.target.namespace and
                p.get("identity", {}).get("pod") == pod_name and p.get("identity", {}).get("uid") == pod_uid]
    if len(matching) != 1:
        raise ValueError("pod_context_identity_mismatch")
    selected = matching[0]
    identity = selected["identity"]
    if identity.get("permissions", {}).get("service_account") != evidence.subject.username:
        raise ValueError("pod_context_subject_mismatch")
    events = selected.get("events", [])
    shared = selected.get("shared_identity_audit_events", [])
    if not isinstance(events, list) or not isinstance(shared, list):
        raise ValueError("invalid_pod_context_events")
    projection = {"cluster_id": cluster_id, "namespace": evidence.target.namespace, "pod": pod_name,
                  "pod_uid": pod_uid, "inventory_observed_at": observed.isoformat(),
                  "events": [{key: event[key] for key in ("id", "kind", "timestamp", "signals") if key in event}
                             for event in events[:8] if isinstance(event, dict)],
                  "shared_identity_event_ids": [event.get("id") for event in shared[:8] if isinstance(event, dict)],
                  "additional_records_omitted": max(0, len(events) - 8) + max(0, len(shared) - 8),
                  "coverage": "unknown_for_permission_removal", "attribution": "context_only_not_proof_of_physical_caller"}
    source_id = "pod-context-" + canonical_hash(projection).split(":")[1][:24]
    document = ("Supplemental untrusted telemetry, not request counts, complete coverage, dependency proof or approval. "
                + json.dumps(projection, sort_keys=True))
    if len(document) > 4000:
        raise ValueError("pod_context_projection_too_large")
    result = evidence.model_copy(deep=True)
    if len(result.context.optional_documents) >= 8 or len(result.context.evidence_refs) >= 32:
        raise ValueError("pod_context_capacity_exhausted")
    result.context.optional_documents.append(document)
    result.context.evidence_refs.append(source_id)
    return EvidenceBundle.model_validate(result.model_dump(mode="json"))
