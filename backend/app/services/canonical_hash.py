import hashlib
import json
from typing import Any


def canonical_hash(rbac_state: dict[str, Any] | None) -> str:
    """
    Compute a SHA-256 hash of the canonicalized RBAC state.

    Steps:
    1. Extract all permission rules from all roles in the state
    2. Normalize each rule to {resource, verb, apiGroup} lowercase
    3. Sort rules deterministically (so order doesn't matter)
    4. Serialize with sorted keys, compact separators
    5. SHA-256 the resulting string
    """
    if not rbac_state or not isinstance(rbac_state, dict):
        canonical_str = "[]"
        return f"sha256:{hashlib.sha256(canonical_str.encode()).hexdigest()}"

    permission_set: list[dict[str, Any]] = []

    for key, obj in rbac_state.items():
        if not isinstance(obj, dict):
            continue
        kind = obj.get("kind", "")
        if kind not in ("Role", "ClusterRole"):
            continue

        rules = obj.get("rules") or []
        metadata = obj.get("metadata") or {}
        name = metadata.get("name", "")
        namespace = metadata.get("namespace", "cluster" if kind == "ClusterRole" else "default")

        for rule in rules:
            if not isinstance(rule, dict):
                continue
            verbs = sorted([str(v).lower() for v in (rule.get("verbs") or []) if v is not None])
            resources = sorted([str(r).lower() for r in (rule.get("resources") or []) if r is not None])
            api_groups = sorted([str(g).lower() for g in (rule.get("apiGroups") or []) if g is not None])

            permission_set.append({
                "apiGroups": api_groups,
                "name": name,
                "namespace": namespace,
                "resources": resources,
                "verbs": verbs,
            })

    # Sort the list of dicts for deterministic ordering
    permission_set.sort(key=lambda x: json.dumps(x, sort_keys=True))

    canonical_str = json.dumps(permission_set, sort_keys=True, separators=(",", ":"))
    return f"sha256:{hashlib.sha256(canonical_str.encode()).hexdigest()}"
