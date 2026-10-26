"""Synthetic inputs, visibly labeled. Expected removals exist only in test assertions."""

from copy import deepcopy
from datetime import timedelta

from .contracts import EvidenceBundle, utc_now


def demo_evidence(scenario="complete", now=None) -> EvidenceBundle:
    now = now or utc_now()
    end = (now - timedelta(seconds=10)).replace(microsecond=0)
    start = end - timedelta(minutes=5)
    subject = {"username": "system:serviceaccount:guardian-demo:guardian-demo-reader",
               "kind": "service_account", "namespace": "guardian-demo", "name": "guardian-demo-reader",
               "uid": "fixture-sa-uid", "uid_status": "verified",
               "groups": ["system:serviceaccounts", "system:serviceaccounts:guardian-demo", "system:authenticated"],
               "identity_evidence_refs": ["fixture-identity"]}
    series = []
    for resource, verb, count in [("pods", "get", 5), ("pods", "list", 30), ("secrets", "get", 0)]:
        buckets = []
        cursor = start
        while cursor < end:
            hour = cursor.replace(minute=0, second=0)
            stop = min(hour + timedelta(hours=1), end)
            # These are fixture counts, never claimed as measured traffic.
            buckets.append({"bucket_start": hour.isoformat(), "interval": {"start": cursor.isoformat(), "end": stop.isoformat()},
                            "counts": {"successful_completed": count, "authorized_error": 0, "authorized_incomplete": 0,
                                       "denied": 0, "unknown": 0},
                            "first_request_at": cursor.isoformat() if count else None,
                            "last_request_at": (stop - timedelta(microseconds=1)).isoformat() if count else None,
                            "evidence_refs": [f"fixture-audit-{verb}-{resource}"] if count else []})
            cursor = stop
        series.append({"request_key_id": f"fixture-key-{verb}-{resource}",
                       "request_key": {"kind": "resource", "verb": verb, "api_group": "", "resource": resource,
                                       "subresource": None, "scope": "namespaced", "namespace": "guardian-demo",
                                       "resource_name": None, "name_resolution": "collection" if verb == "list" else "any_name",
                                       "name_field_selector": None, "non_resource_path": None},
                       "buckets": buckets,
                       "coverage": [{"interval": {"start": start.isoformat(), "end": end.isoformat()},
                                     "status": "complete_for_declared_scope", "reason_codes": [],
                                     "source_ids": ["fixture-audit-source"], "audit_policy_refs": ["fixture-policy"],
                                     "health_evidence_refs": ["fixture-coverage"], "known_lost_events": 0}],
                       "carried_authorized_requests": []})
    data = {"snapshot_id": f"fixture-{scenario}", "revision": 1, "source_mode": "fixture",
            "target": {"cluster_id": "guardian-fixture", "kind": "Role", "namespace": "guardian-demo",
                       "name": "guardian-demo-reader-role", "uid": "fixture-role-uid", "resource_version": "42",
                       "controller_managed": False,
                       "rules": [{"apiGroups": [""], "resources": ["pods"], "verbs": ["get", "list"]},
                                 {"apiGroups": [""], "resources": ["secrets"], "verbs": ["get"]}]},
            "subject": subject,
            "binding": {"binding_id": "fixture-binding", "uid": "fixture-binding-uid", "resource_version": "41",
                        "namespace": "guardian-demo", "role_name": "guardian-demo-reader-role", "role_kind": "Role",
                        "subjects": [deepcopy(subject)], "evidence_refs": ["fixture-binding-evidence"]},
            "context": {"context_id": "fixture-context", "workload_uid": "fixture-workload-uid",
                        "image_digest": "sha256:fixture-image", "subject_uid": subject["uid"],
                        "known_consumers": ["fixture-pod-reader"], "consumer_inventory_complete": True,
                        "alternate_grants": [], "collected_at": end.isoformat(), "provenance": "fixture",
                        "evidence_refs": ["fixture-workload-behavior"], "exercised_behaviors": ["startup", "normal", "restart"],
                        "known_dependencies": [], "unexercised_operations": [], "optional_documents": [], "conflicts": []},
            "usage": {"schema_version": "guardian.usage-summary.v1", "summary_id": "fixture-usage", "revision": 1,
                      "cluster_id": "guardian-fixture", "subject": deepcopy(subject),
                      "query_window": {"start": start.isoformat(), "end": end.isoformat()}, "generated_at": now.isoformat(),
                      "processed_through": end.isoformat(), "bucket_resolution": "PT1H", "boundary_mode": "exact",
                      "collector_version": "fixture-collector-v1", "aggregation_version": "fixture-aggregation-v1",
                      "source_cursor_refs": ["fixture-cursor"],
                      "requested_key_ids": [s["request_key_id"] for s in series], "series": series,
                      "truncated": False, "warnings": []},
            # A frozen synthetic source uses a recorded longer lag allowance for slow CPU
            # inference. The production contract default remains 60 seconds.
            "baseline_id": None, "policy": {"maximum_source_lag_seconds": 600},
            "evidence_refs": ["fixture-snapshot"], "source_errors": []}
    if scenario == "coverage-gap":
        data["usage"]["series"][-1]["coverage"][0].update(
            status="unavailable", reason_codes=["source_outage"], known_lost_events=None)
    elif scenario == "monthly":
        data["context"]["unexercised_operations"] = [{
            "operation": {"api_group": "", "resource": "secrets", "verb": "get", "namespace": "guardian-demo"},
            "reason": "Monthly recovery operation has not been exercised in this interval.",
            "evidence_refs": ["fixture-monthly-workflow"]}]
        data["context"]["optional_documents"] = ["A monthly recovery workflow fetches credentials through the Kubernetes API."]
    elif scenario == "missing-usage":
        data["usage"] = None
    elif scenario != "complete":
        raise ValueError("unknown fixture scenario")
    return EvidenceBundle.model_validate(data)
