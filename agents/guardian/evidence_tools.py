"""Typed read-only evidence tools. Call arguments never contain URLs or paths."""

from typing import Literal

from pydantic import Field, model_validator

from contracts.usage_summary_v1 import Contract, ID
from .contracts import ContextLookup, EvidenceBundle, EvidenceToolName


class FailureRecord(Contract):
    target_uid: ID
    candidate_hash: ID
    workload_uid: ID
    image_digest: ID
    policy_version: ID
    blocks_candidate: bool = Field(strict=True)
    evidence_refs: list[ID] = Field(min_length=1, max_length=16)


class AccessResult(Contract):
    permission_id: ID
    allowed: bool | None = Field(strict=True)
    denied: bool | None = Field(strict=True)
    evaluation_error: ID | None


class ToolResult(Contract):
    schema_version: Literal["guardian.evidence-tool-result.v1"] = "guardian.evidence-tool-result.v1"
    tool: EvidenceToolName
    case_id: ID
    subject_id: ID
    target_uid: ID
    status: Literal["available", "unavailable"]
    evidence: EvidenceBundle | None = None
    failures: list[FailureRecord] = Field(default_factory=list, max_length=64)
    access: AccessResult | None = None
    evidence_refs: list[ID] = Field(max_length=32)
    reasons: list[ID] = Field(max_length=16)

    @model_validator(mode="after")
    def shape(self):
        if self.status == "unavailable":
            if not self.reasons or self.evidence is not None or self.access is not None or self.failures:
                raise ValueError("unavailable tool result needs reasons and no invented evidence")
        else:
            if not self.evidence_refs:
                raise ValueError("available result needs provenance")
            if self.tool == "get_failure_history":
                if self.evidence is not None or self.access is not None:
                    raise ValueError("failure history cannot replace evidence")
            elif self.tool == "check_access":
                if self.access is None or self.evidence is not None or self.failures:
                    raise ValueError("access result cannot replace observed usage")
            elif self.evidence is None or self.failures or self.access is not None:
                raise ValueError("evidence tool requires exactly an evidence bundle")
        return self


def validate_lookup(lookup, request, evidence, facts):
    if lookup.subject_id != evidence.subject.username or (lookup.case_id is not None and lookup.case_id != request.case_id):
        raise ValueError("lookup_outside_case_subject")
    if lookup.target_uid is not None and lookup.target_uid != evidence.target.uid:
        raise ValueError("lookup_outside_target")
    permitted = {"tool", "subject_id", "case_id"}
    if lookup.tool in ("get_case_snapshot", "get_binding_consumers", "get_failure_history"):
        if lookup.target_uid != evidence.target.uid:
            raise ValueError("lookup_requires_known_target")
        permitted.add("target_uid")
    elif lookup.tool == "get_usage_summary":
        if (evidence.usage is None or lookup.usage_summary_id != evidence.usage.summary_id
                or not lookup.request_key_ids or not set(lookup.request_key_ids) <= set(evidence.usage.requested_key_ids)):
            raise ValueError("lookup_outside_usage_query")
        permitted.update(("usage_summary_id", "request_key_ids"))
    elif lookup.tool == "check_access":
        if lookup.permission_id not in {f["permission_id"] for f in facts}:
            raise ValueError("lookup_outside_permission")
        permitted.add("permission_id")
    supplied = {key for key, value in lookup.model_dump().items() if value is not None and value != []}
    if not supplied <= permitted:
        raise ValueError("lookup_has_unrelated_arguments")


def validate_result(raw, lookup, request, evidence):
    result = ToolResult.model_validate(raw.model_dump(mode="json") if isinstance(raw, ToolResult) else raw)
    if (result.tool, result.case_id, result.subject_id, result.target_uid) != (
            lookup.tool, request.case_id, evidence.subject.username, evidence.target.uid):
        raise ValueError("tool_result_scope_mismatch")
    if result.access and result.access.permission_id != lookup.permission_id:
        raise ValueError("access_result_scope_mismatch")
    if any(f.target_uid != evidence.target.uid for f in result.failures):
        raise ValueError("failure_history_scope_mismatch")
    refreshed = result.evidence
    if refreshed is not None:
        allowed = {"evidence_refs"}
        if lookup.tool == "get_workload_context":
            allowed.add("context")
        elif lookup.tool == "get_usage_summary":
            allowed.add("usage")
            if (refreshed.usage is None or refreshed.usage.query_window != evidence.usage.query_window
                    or refreshed.usage.requested_key_ids != evidence.usage.requested_key_ids):
                raise ValueError("usage_lookup_changed_query_scope")
        elif lookup.tool == "get_binding_consumers":
            # Consumer details are authoritative context, never grants or policy.
            allowed.add("context")
            if evidence.context is None or refreshed.context is None:
                raise ValueError("consumer_context_unavailable")
            fields = {"known_consumers", "consumer_inventory_complete", "alternate_grants", "collected_at", "evidence_refs"}
            if evidence.context.model_dump(exclude=fields) != refreshed.context.model_dump(exclude=fields):
                raise ValueError("consumer_lookup_changed_other_context")
        for field in EvidenceBundle.model_fields:
            if field not in allowed and getattr(refreshed, field) != getattr(evidence, field):
                raise ValueError("lookup_changed_unrelated_evidence")
        if not set(evidence.evidence_refs) <= set(refreshed.evidence_refs):
            raise ValueError("lookup_discarded_existing_evidence")
    return result


def allowed_lookups(request, evidence, facts):
    base = {"subject_id": evidence.subject.username, "case_id": request.case_id}
    result = [{"tool": "get_workload_context", **base}]
    result.extend({"tool": tool, "target_uid": evidence.target.uid, **base}
                  for tool in ("get_case_snapshot", "get_binding_consumers", "get_failure_history"))
    if evidence.usage:
        result.append({"tool": "get_usage_summary", "usage_summary_id": evidence.usage.summary_id,
                       "request_key_ids": evidence.usage.requested_key_ids[:16], **base})
    result.extend({"tool": "check_access", "permission_id": fact["permission_id"], **base} for fact in facts)
    return result
