"""
Permission Scanner Service for Kubernetes RBAC.

Detects dangerous verbs (bind, impersonate, escalate), wildcards (*),
and sensitive resources (secrets, serviceaccounts, roles, etc.) in Roles
and ClusterRoles.
"""

from typing import Any

DANGEROUS_VERBS = {
    "bind": "Allows binding roles/clusterroles to grant elevated privileges",
    "impersonate": "Allows impersonating other users, groups, or service accounts",
    "escalate": "Allows creating or updating roles with permissions exceeding caller's own permissions",
}

# Sensitive resources that are prime targets for privilege escalation or credential theft
# Note for Phase 1: Technically, core resources like 'secrets' belong only to the core API group ("").
# In Phase 0, we flag them regardless of apiGroup to ensure no malicious permissions go unnoticed.
SENSITIVE_RESOURCES = {
    "secrets": "Provides access to sensitive credentials, tokens, and keys",
    "serviceaccounts": "Enables token manipulation and identity assumption",
    "roles": "Enables modifying namespace-scoped RBAC definitions",
    "clusterroles": "Enables modifying cluster-wide RBAC definitions",
    "rolebindings": "Enables attaching identities to namespace roles",
    "clusterrolebindings": "Enables attaching identities to cluster-wide roles",
}

WILDCARD = "*"

SEVERITY_ORDER = {
    "CRITICAL": 3,
    "HIGH": 2,
    "MEDIUM": 1,
    "LOW": 0,
}


def _max_severity(sev1: str, sev2: str) -> str:
    return sev1 if SEVERITY_ORDER.get(sev1, 0) >= SEVERITY_ORDER.get(sev2, 0) else sev2


def scan_dangerous_permissions(rbac_state: dict[str, Any]) -> list[dict[str, Any]]:
    """
    Stateless pure function that inspects all Roles and ClusterRoles in the given
    RBAC state dictionary and returns a list of dangerous permission findings
    grouped per role.

    :param rbac_state: Dictionary of sanitized K8s objects keyed by {Kind}_{Namespace}_{Name}
    :return: List of findings grouped by Role/ClusterRole, ordered by severity (CRITICAL first).
    """
    findings: list[dict[str, Any]] = []

    if not rbac_state or not isinstance(rbac_state, dict):
        return findings

    for key, obj in rbac_state.items():
        if not isinstance(obj, dict):
            continue

        kind = str(obj.get("kind", ""))
        if kind.lower() not in ("role", "clusterrole"):
            continue

        metadata = obj.get("metadata", {})
        name = metadata.get("name", "unknown")
        namespace = metadata.get(
            "namespace",
            "cluster" if kind.lower() == "clusterrole" else "default"
        )
        rules = obj.get("rules", [])

        if not isinstance(rules, list):
            continue

        role_findings_rules: list[dict[str, Any]] = []
        role_all_flags: set[str] = set()
        role_severity = "LOW"

        for idx, rule in enumerate(rules):
            if not isinstance(rule, dict):
                continue

            raw_verbs = rule.get("verbs") or []
            raw_resources = rule.get("resources") or []
            raw_api_groups = rule.get("apiGroups") or []

            verbs = [str(v).strip().lower() for v in raw_verbs if v is not None]
            resources = [str(r).strip().lower() for r in raw_resources if r is not None]
            api_groups = [str(g).strip().lower() for g in raw_api_groups if g is not None]

            rule_flags: list[str] = []
            rule_finding_texts: list[str] = []
            rule_severity = "LOW"

            has_wildcard_verbs = WILDCARD in verbs
            has_wildcard_resources = WILDCARD in resources
            has_wildcard_api_groups = WILDCARD in api_groups

            dangerous_verbs_found = [v for v in verbs if v in DANGEROUS_VERBS]

            sensitive_resources_found = [
                r for r in resources
                if r in SENSITIVE_RESOURCES or any(r.startswith(sr + "/") for sr in SENSITIVE_RESOURCES)
            ]

            if has_wildcard_verbs and has_wildcard_resources:
                rule_flags.append("FULL_ADMIN_WILDCARD")
                rule_finding_texts.append("Full wildcard access (* on *): grants all actions on all resources")
                rule_severity = _max_severity(rule_severity, "CRITICAL")
            else:
                if has_wildcard_verbs:
                    rule_flags.append("WILDCARD_VERBS")
                    rule_finding_texts.append("Wildcard verb '*' allows all actions (create, delete, patch, etc.)")
                    rule_severity = _max_severity(rule_severity, "HIGH")

                if has_wildcard_resources:
                    rule_flags.append("WILDCARD_RESOURCES")
                    rule_finding_texts.append("Wildcard resource '*' allows access to all resources")
                    rule_severity = _max_severity(rule_severity, "HIGH")

            for dv in dangerous_verbs_found:
                flag = f"DANGEROUS_VERB_{dv.upper()}"
                rule_flags.append(flag)
                rule_finding_texts.append(f"Dangerous verb '{dv}' detected: {DANGEROUS_VERBS[dv]}")
                rule_severity = _max_severity(rule_severity, "CRITICAL")

            for sr in sensitive_resources_found:
                base_sr = sr.split("/")[0]
                flag = f"SENSITIVE_RESOURCE_{base_sr.upper()}"
                if flag not in rule_flags:
                    rule_flags.append(flag)
                desc = SENSITIVE_RESOURCES.get(base_sr, "Privileged resource")
                rule_finding_texts.append(f"Targeting sensitive resource '{sr}': {desc}")
                
                if has_wildcard_verbs or dangerous_verbs_found:
                    rule_severity = _max_severity(rule_severity, "CRITICAL")
                else:
                    rule_severity = _max_severity(rule_severity, "HIGH")

            if has_wildcard_api_groups:
                rule_flags.append("WILDCARD_API_GROUPS")
                rule_finding_texts.append("Wildcard apiGroups '*' allows targeting all API groups")
                rule_severity = _max_severity(rule_severity, "MEDIUM")

            if rule_flags:
                role_all_flags.update(rule_flags)
                role_severity = _max_severity(role_severity, rule_severity)
                role_findings_rules.append({
                    "rule_index": idx,
                    "verbs": raw_verbs,
                    "resources": raw_resources,
                    "api_groups": raw_api_groups,
                    "severity": rule_severity,
                    "flags": rule_flags,
                    "findings": rule_finding_texts,
                })

        if role_findings_rules:
            findings.append({
                "role_name": name,
                "role_kind": kind,
                "namespace": namespace,
                "severity": role_severity,
                "flags": sorted(list(role_all_flags)),
                "rules": role_findings_rules,
            })

    findings.sort(
        key=lambda item: (-SEVERITY_ORDER.get(item["severity"], 0), item["role_kind"], item["role_name"])
    )

    return findings
