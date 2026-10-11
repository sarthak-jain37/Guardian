"""Strict orchestration contracts. Review/execution here is a local simulation."""

from datetime import datetime
from typing import Annotated, Literal

from pydantic import AwareDatetime, Field, model_validator

from contracts.usage_summary_v1 import Contract, ID, Subject, UsageSummary, utc

Text = Annotated[str, Field(min_length=1, max_length=4000)]


class RoleRule(Contract):
    apiGroups: list[Annotated[str, Field(max_length=256)]] = Field(min_length=1, max_length=16)
    resources: list[ID] = Field(default_factory=list, max_length=64)
    verbs: list[ID] = Field(min_length=1, max_length=32)
    resourceNames: list[ID] = Field(default_factory=list, max_length=64)
    nonResourceURLs: list[ID] = Field(default_factory=list, max_length=64)


class Target(Contract):
    cluster_id: ID
    kind: Literal["Role", "ClusterRole"]
    namespace: ID | None
    name: ID
    uid: ID
    resource_version: ID
    rules: list[RoleRule] = Field(min_length=1, max_length=64)
    controller_managed: bool = Field(strict=True)

    @model_validator(mode="after")
    def bounded_rule_expansion(self):
        if sum(len(r.apiGroups) * len(r.resources) * len(r.verbs) for r in self.rules) > 128:
            raise ValueError("pilot input supports at most 128 permission combinations")
        return self


class Binding(Contract):
    binding_id: ID
    uid: ID
    resource_version: ID
    namespace: ID
    role_name: ID
    role_kind: Literal["Role", "ClusterRole"]
    subjects: list[Subject] = Field(min_length=1, max_length=32)
    evidence_refs: list[ID] = Field(min_length=1, max_length=32)


class Operation(Contract):
    api_group: str = Field(max_length=256)
    resource: ID
    verb: ID
    namespace: ID


class Dependency(Contract):
    operation: Operation
    reason: Text
    evidence_refs: list[ID] = Field(min_length=1, max_length=32)


class WorkloadContext(Contract):
    context_id: ID
    workload_uid: ID
    image_digest: ID
    subject_uid: ID
    known_consumers: list[ID] = Field(max_length=64)
    consumer_inventory_complete: bool = Field(strict=True)
    alternate_grants: list[ID] = Field(max_length=64)
    collected_at: AwareDatetime
    provenance: Literal["cluster_metadata", "owner_assertion", "fixture"]
    evidence_refs: list[ID] = Field(min_length=1, max_length=32)
    exercised_behaviors: list[Literal["startup", "normal", "restart"]] = Field(max_length=3)
    known_dependencies: list[Dependency] = Field(max_length=64)
    unexercised_operations: list[Dependency] = Field(max_length=64)
    optional_documents: list[Text] = Field(max_length=8)
    conflicts: list[ID] = Field(max_length=32)


class EvidencePolicy(Contract):
    policy_version: ID = "guardian.demo-policy.v1"
    allowed_namespaces: list[ID] = Field(default_factory=lambda: ["guardian-demo"], max_length=16)
    profile: Literal["controlled-lab", "operational"] = "controlled-lab"
    minimum_observation_seconds: int = Field(default=300, strict=True, ge=300)
    maximum_source_lag_seconds: int = Field(default=60, strict=True, ge=0, le=3600)
    review_window_seconds: int = Field(default=86400, strict=True, ge=1)
    execution_window_seconds: int = Field(default=300, strict=True, ge=1)
    lookup_rounds: int = Field(default=2, strict=True, ge=0, le=2)
    lookup_calls: int = Field(default=4, strict=True, ge=0, le=4)
    model_calls: int = Field(default=6, strict=True, ge=0, le=6)
    active_run_timeout_seconds: int = Field(default=600, strict=True, ge=1, le=3600)

    @model_validator(mode="after")
    def observation(self):
        if self.profile == "operational" and self.minimum_observation_seconds < 7 * 86400:
            raise ValueError("operational profile requires at least seven actual days")
        if self.profile == "controlled-lab" and self.allowed_namespaces != ["guardian-demo"]:
            raise ValueError("controlled-lab profile is restricted to guardian-demo")
        return self


class EvidenceBundle(Contract):
    schema_version: Literal["guardian.evidence.v1"] = "guardian.evidence.v1"
    snapshot_id: ID
    revision: int = Field(strict=True, ge=1)
    source_mode: Literal["fixture", "captured"]
    target: Target
    subject: Subject
    binding: Binding | None
    context: WorkloadContext | None
    usage: UsageSummary | None
    baseline_id: ID | None
    policy: EvidencePolicy
    evidence_refs: list[ID] = Field(min_length=1, max_length=128)
    source_errors: list[ID] = Field(max_length=32)

    @model_validator(mode="after")
    def agreement(self):
        if self.usage is not None:
            if self.usage.cluster_id != self.target.cluster_id or self.usage.subject != self.subject:
                raise ValueError("usage scope/identity differs from snapshot")
        if self.context is not None:
            utc(self.context.collected_at)
            if self.context.subject_uid != self.subject.uid:
                raise ValueError("workload subject UID differs")
        return self


class AnalysisRequest(Contract):
    schema_version: Literal["guardian.analysis-request.v1"] = "guardian.analysis-request.v1"
    case_id: ID
    run_id: ID
    revision: int = Field(default=1, strict=True, ge=1)
    trigger: Literal["initial", "manual", "drift", "periodic"] = "initial"
    snapshot_id: ID
    cluster_id: ID
    target_uid: ID
    mode: Literal["simulation", "preview"] = "simulation"


class ContextLookup(Contract):
    tool: Literal["get_workload_context"]
    subject_id: ID


class PermissionAssessment(Contract):
    permission_id: ID
    recommendation: Literal["retain", "propose_remove", "request_context", "human_investigation"]
    evidence_ids: list[ID] = Field(min_length=1, max_length=16)
    reason: Text


class Investigation(Contract):
    summary: Text
    permission_assessments: list[PermissionAssessment] = Field(min_length=1, max_length=128)
    uncertainty: list[Text] = Field(max_length=8)
    questions: list[Text] = Field(max_length=3)
    context_requests: list[ContextLookup] = Field(max_length=2)


class PlanDecision(Contract):
    permission_id: ID
    action: Literal["retain", "remove"]
    evidence_ids: list[ID] = Field(min_length=1, max_length=16)
    reason: Text


class ChangePlan(Contract):
    strategy_id: Literal["narrow_dedicated_role"]
    target_id: ID
    decisions: list[PlanDecision] = Field(min_length=1, max_length=128)
    rationale: Text
    verification_profile_id: Literal["pod-reader-behavior.v1"]


class Gate(Contract):
    gate_id: ID
    result: Literal["pass", "fail", "unknown"]
    reasons: list[ID] = Field(max_length=32)


class Proposal(Contract):
    schema_version: Literal["guardian.proposal.v1"] = "guardian.proposal.v1"
    proposal_id: ID
    case_id: ID
    run_id: ID
    revision: int = Field(strict=True, ge=1)
    simulation: bool = Field(strict=True)
    status: Literal["DRAFT", "BLOCKED", "PENDING_APPROVAL", "APPROVED", "REJECTED", "EXPIRED", "SUPERSEDED"]
    target: Target
    unchanged_binding: Binding | None
    evidence_hash: ID
    candidate_hash: ID
    approval_hash: ID
    policy_version: ID
    removed_permission_ids: list[ID] = Field(max_length=128)
    result_rules: list[RoleRule] = Field(max_length=64)
    patch: list[dict] = Field(max_length=3)
    role_yaml: Text
    diff: Text
    gates: list[Gate] = Field(max_length=16)
    uncertainty: list[Text] = Field(max_length=8)
    published_at: AwareDatetime
    review_expires_at: AwareDatetime
    execution_window_seconds: int = Field(strict=True, ge=1)
    verification_profile_id: Literal["pod-reader-behavior.v1"]
    recovery_authorized: Literal[False] = False


class ApprovalDecision(Contract):
    schema_version: Literal["guardian.test-decision.v1"] = "guardian.test-decision.v1"
    decision_id: ID
    proposal_id: ID
    revision: int = Field(strict=True, ge=1)
    kind: Literal["approve_remediation", "reject", "acknowledge", "request_context"]
    authority: Literal["human"]
    actor: Literal["local-demo-reviewer"]
    simulation: Literal[True]
    approval_hash: ID
    policy_version: ID
    target_uid: ID
    approved_at: AwareDatetime
    execution_expires_at: AwareDatetime | None
    revoked: bool = Field(default=False, strict=True)

    @model_validator(mode="after")
    def timestamps(self):
        utc(self.approved_at)
        if self.kind == "approve_remediation":
            if self.execution_expires_at is None or utc(self.execution_expires_at) <= self.approved_at:
                raise ValueError("remediation decision needs execution deadline")
        elif self.execution_expires_at is not None:
            raise ValueError("non-writing decision cannot authorize execution")
        return self


def utc_now() -> datetime:
    from datetime import timezone
    return datetime.now(timezone.utc)
