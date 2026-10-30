"""Deterministic eligibility and rendering for one dedicated namespaced Role."""

import difflib
import hashlib
import itertools
import json
from datetime import datetime

import yaml

from backend.app.services.permission_scanner import scan_dangerous_permissions

from .contracts import EvidenceBundle, Gate, Investigation, ChangePlan, Target


def canonical_hash(value) -> str:
    """Versioned sorted JSON, deliberately not advertised as RFC 8785."""
    encoded = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return "sha256-v1:" + hashlib.sha256(encoded.encode()).hexdigest()


def operation_id(group: str, resource: str, verb: str, namespace: str) -> str:
    return "perm-" + canonical_hash([group, resource, verb, namespace]).split(":")[1][:20]


def operations(rules: list[dict]) -> set[tuple[str, str, str]]:
    result = set()
    for rule in rules:
        result.update(itertools.product(rule["apiGroups"], rule["resources"], rule["verbs"]))
    return result


def rule_dicts(target: Target) -> list[dict]:
    return [r.model_dump(exclude_defaults=True) for r in target.rules]


def unresolved_documented_workflow(context):
    """Conservative English workflow cues, shared by both arms and the backend.

Ordinary documentation is not an authority grant. A potentially relevant rare
cycle needs corroborated behavior/structured evidence before executable removal.
This rule is intentionally not a general natural-language dependency proof.
"""
    if context is None:return False
    for document in context.optional_documents:
        text=document.lower()
        periodic=any(word in text for word in ('monthly','quarterly','annual','infrequent','overnight','year-end','rotation','recovery','restore','emergency','scheduled'))
        workflow=any(word in text for word in ('workflow','routine','fetches','requests','exercise','backup','job'))
        if periodic and workflow:return True
    return False


def global_gates(e: EvidenceBundle, now: datetime) -> list[Gate]:
    def gate(name, reasons):
        return Gate(gate_id=name, result="fail" if reasons else "pass", reasons=sorted(set(reasons)))

    reasons = []
    if e.target.kind != "Role" or e.target.namespace not in e.policy.allowed_namespaces:
        reasons.append("unsupported_target")
    if e.target.controller_managed:
        reasons.append("controller_managed_role")
    for rule in e.target.rules:
        tokens = rule.apiGroups + rule.resources + rule.verbs
        if rule.resourceNames or rule.nonResourceURLs or not rule.resources or any("*" in t for t in tokens):
            reasons.append("unsupported_rule")
    supported = gate("supported_target", reasons)
    reasons = []
    b, c = e.binding, e.context
    if not b or b.namespace != e.target.namespace or b.role_kind != "Role" or b.role_name != e.target.name:
        reasons.append("unknown_consumer")
    elif b.subjects != [e.subject] or e.subject.kind != "service_account" or e.subject.uid_status != "verified":
        reasons.append("shared_or_unknown_subject")
    if not c or not c.consumer_inventory_complete or len(c.known_consumers) != 1:
        reasons.append("unknown_consumer")
    if c and c.alternate_grants:
        reasons.append("alternate_grant")
    consumers = gate("consumer_inventory", reasons)
    reasons = []
    if not e.usage:
        reasons.append("usage_unavailable")
    else:
        interval = e.usage.query_window.end - e.usage.query_window.start
        if interval.total_seconds() < e.policy.minimum_observation_seconds:
            reasons.append("observation_too_short")
    if e.policy.profile == "controlled-lab":
        if not c or set(c.exercised_behaviors) != {"startup", "normal", "restart"}:
            reasons.append("unexercised_behavior")
    profile = gate("observation_profile", reasons)
    reasons = []
    if not e.usage or not e.usage.processed_through:
        reasons.append("stale_source")
    elif not 0 <= (now - e.usage.processed_through).total_seconds() <= e.policy.maximum_source_lag_seconds:
        reasons.append("stale_source")
    if unresolved_documented_workflow(c):
        reasons.append("documented_rare_workflow_requires_validation")
    if c and c.collected_at > now:
        reasons.append("future_context")
    freshness = gate("source_freshness", reasons)
    integrity = gate("context_integrity", ["context_conflict"] if c and c.conflicts else [])
    errors = gate("source_and_failure_status", e.source_errors)
    return [supported, consumers, profile, freshness, integrity, errors]


def build_facts(e: EvidenceBundle, now: datetime) -> tuple[list[dict], list[Gate]]:
    gates = global_gates(e, now)
    shared_reasons = sorted({r for g in gates for r in g.reasons})
    c, usage = e.context, e.usage
    facts = []
    for group, resource, verb in sorted(operations(rule_dicts(e.target))):
        pid = operation_id(group, resource, verb, e.target.namespace or "cluster")
        refs = set(e.evidence_refs)
        reasons = list(shared_reasons)
        protected = False
        observed = None
        base_resource, _, subresource = resource.partition("/")
        matches = []
        if usage:
            refs.add(usage.summary_id)
            for s in usage.series:
                k = s.request_key
                if (k.kind == "resource" and k.api_group == group and k.resource == base_resource
                        and k.subresource == (subresource or None) and k.verb == verb
                        and k.scope == "namespaced" and k.namespace == e.target.namespace
                        and (k.name_resolution == "any_name" or (verb in ("list", "watch") and k.name_resolution == "collection"))):
                    matches.append(s)
        # An ambiguous projection cannot be summed into an invented unique-request count.
        if len(matches) != 1:
            reasons.append("usage_unavailable" if not matches else "ambiguous_usage_projection")
        else:
            s = matches[0]
            refs.add(s.request_key_id)
            refs.update(ref for b in s.buckets for ref in b.evidence_refs)
            refs.update(ref for cov in s.coverage for ref in cov.health_evidence_refs + cov.audit_policy_refs)
            observed = sum(b.counts.authorized() for b in s.buckets)
            if observed or s.carried_authorized_requests:
                protected = True
                reasons.append("observed_use")
            if not s.buckets or any(cov.status != "complete_for_declared_scope" for cov in s.coverage):
                reasons.append("coverage_gap")
            if any(b.counts.unknown or b.counts.denied for b in s.buckets):
                reasons.append("unknown_usage")
            if usage.truncated:
                reasons.append("truncated_evidence")
        if c:
            refs.update(c.evidence_refs)
            for dependencies, reason in [(c.known_dependencies, "known_dependency"),
                                         (c.unexercised_operations, "unexercised_relevant_cycle")]:
                for dependency in dependencies:
                    op = dependency.operation
                    if (op.api_group, op.resource, op.verb, op.namespace) == (group, resource, verb, e.target.namespace):
                        protected = True
                        reasons.append(reason)
                        refs.update(dependency.evidence_refs)
        reasons = sorted(set(reasons))
        facts.append({"permission_id": pid, "api_group": group, "resource": resource, "verb": verb,
                      "namespace": e.target.namespace, "authorized_use": observed,
                      "protected": protected, "eligible": not reasons,
                      "reason_codes": reasons, "evidence_ids": sorted(refs)})
    return facts, gates


def risk_findings(e: EvidenceBundle) -> list[dict]:
    obj = {"kind": e.target.kind, "metadata": {"name": e.target.name, "namespace": e.target.namespace},
           "rules": rule_dicts(e.target)}
    return scan_dangerous_permissions({"target": obj})


def validate_investigation(result: Investigation, facts: list[dict], e: EvidenceBundle) -> None:
    known = {f["permission_id"]: f for f in facts}
    returned = [a.permission_id for a in result.permission_assessments]
    if len(set(returned)) != len(returned) or set(returned) != set(known):
        raise ValueError("investigator must assess each known permission exactly once")
    for assessment in result.permission_assessments:
        fact = known[assessment.permission_id]
        if not set(assessment.evidence_ids) <= set(fact["evidence_ids"]):
            raise ValueError("investigator cited unknown or out-of-scope evidence")
        if assessment.recommendation == "propose_remove" and not fact["eligible"]:
            raise ValueError("investigator cannot remove a protected/unresolved permission")
    for request in result.context_requests:
        if request.subject_id != e.subject.username:
            raise ValueError("lookup outside case subject")


def validate_plan(result: ChangePlan, facts: list[dict], investigation: Investigation, e: EvidenceBundle) -> None:
    if result.target_id != e.target.uid:
        raise ValueError("planner target outside allowlist")
    known = {f["permission_id"]: f for f in facts}
    returned = [d.permission_id for d in result.decisions]
    if len(set(returned)) != len(returned) or set(returned) != set(known):
        raise ValueError("planner must decide every known permission exactly once")
    suggested = {a.permission_id for a in investigation.permission_assessments if a.recommendation == "propose_remove"}
    for decision in result.decisions:
        fact = known[decision.permission_id]
        if not set(decision.evidence_ids) <= set(fact["evidence_ids"]):
            raise ValueError("planner cited unknown or out-of-scope evidence")
        if decision.action == "remove" and (not fact["eligible"] or decision.permission_id not in suggested):
            raise ValueError("planner cannot manufacture removal eligibility")


def render(e: EvidenceBundle, removed_ids: set[str]) -> dict:
    original = rule_dicts(e.target)
    result = []
    for rule in original:
        # Preserve each original rule's associations; split only that rule when narrowing.
        ids = {operation_id(g, r, v, e.target.namespace or "cluster") for g, r, v in operations([rule])}
        if not ids & removed_ids:
            result.append(rule)
            continue
        for group, resource in itertools.product(rule["apiGroups"], rule["resources"]):
            verbs = [v for v in rule["verbs"] if operation_id(group, resource, v, e.target.namespace or "cluster") not in removed_ids]
            if verbs:
                result.append({"apiGroups": [group], "resources": [resource], "verbs": verbs})
    before, after = operations(original), operations(result)
    expected = {op for op in before if operation_id(*op, e.target.namespace or "cluster") not in removed_ids}
    if after != expected or not after <= before:
        raise ValueError("renderer changed unapproved permission semantics")
    manifest = {"apiVersion": "rbac.authorization.k8s.io/v1", "kind": "Role",
                "metadata": {"name": e.target.name, "namespace": e.target.namespace}, "rules": result}
    preview = yaml.safe_dump(manifest, sort_keys=False)
    if operations(yaml.safe_load(preview)["rules"]) != after:
        raise ValueError("preview round trip disagrees with patch")
    patch = [{"op": "test", "path": "/metadata/uid", "value": e.target.uid},
             {"op": "test", "path": "/metadata/resourceVersion", "value": e.target.resource_version},
             {"op": "replace", "path": "/rules", "value": result}]
    diff = "".join(difflib.unified_diff(yaml.safe_dump({"rules": original}, sort_keys=False).splitlines(True),
                                       yaml.safe_dump({"rules": result}, sort_keys=False).splitlines(True),
                                       fromfile="current", tofile="proposed"))
    return {"result_rules": result, "role_yaml": preview, "patch": patch, "diff": diff}
