"""Strict orchestration contracts. Review/execution here is a local simulation."""

from datetime import datetime
from typing import Annotated, Literal

from pydantic import AwareDatetime, Field, JsonValue, model_validator

from contracts.usage_summary_v1 import Contract, ID, Subject, UsageSummary, utc

from .lifecycle import ProposalStatus, RunStatus
from .versions import RunVersions

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
        if (self.kind == "Role") != (self.namespace is not None):
            raise ValueError("Role requires namespace; ClusterRole forbids namespace")
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
    schema_version: Literal["guardian.analysis-request.v4"] = "guardian.analysis-request.v4"
    case_id: ID
    run_id: ID
    revision: int = Field(default=1, strict=True, ge=1)
    trigger: Literal["initial", "manual", "drift", "periodic"] = "initial"
    snapshot_id: ID
    cluster_id: ID
    target_uid: ID
    baseline_id: ID | None = None
    policy_version: ID = "guardian.demo-policy.v1"
    mode: Literal["simulation", "preview"] = "simulation"
    intent: Literal["analyze", "adopt_baseline"] = "analyze"
    revision_request_id: ID | None = None


def validate_request_evidence(request: AnalysisRequest, evidence: EvidenceBundle) -> None:
    """Consumer-side checks apply to every adapter, including future real ports."""
    expected = (request.snapshot_id, request.cluster_id, request.target_uid,
                request.baseline_id, request.policy_version)
    actual = (evidence.snapshot_id, evidence.target.cluster_id, evidence.target.uid,
              evidence.baseline_id, evidence.policy.policy_version)
    if expected != actual:
        raise ValueError("request_evidence_mismatch: snapshot, scope, baseline or policy differs")
    if request.mode == "simulation" and evidence.source_mode != "fixture":
        raise ValueError("captured evidence cannot enter simulation review")


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


class PermissionFact(Contract):
    permission_id: ID
    api_group: str = Field(max_length=256)
    resource: ID
    verb: ID
    namespace: ID | None
    authorized_use: Annotated[int, Field(strict=True, ge=0)] | None
    protected: bool = Field(strict=True)
    eligible: bool = Field(strict=True)
    reason_codes: list[ID] = Field(max_length=64)
    evidence_ids: list[ID] = Field(min_length=1, max_length=1024)

    @model_validator(mode="after")
    def protections(self):
        if self.eligible and (self.protected or self.reason_codes or self.authorized_use != 0):
            raise ValueError("eligible removal requires unprotected, known covered non-use")
        return self


class ReadinessAssessment(Contract):
    """Projection of deterministic gates, never model-issued execution authority."""

    schema_version: Literal["guardian.readiness.v1"] = "guardian.readiness.v1"
    policy_version: ID
    evidence_revision: int = Field(strict=True, ge=1)
    gates: list[Gate] = Field(min_length=1, max_length=32)
    allowed_removal_ids: list[ID] = Field(max_length=128)
    protected_permission_ids: list[ID] = Field(max_length=128)
    residual_uncertainties: list[Text] = Field(max_length=8)
    execution_ready: bool = Field(strict=True)

    @model_validator(mode="after")
    def consistency(self):
        for ids in ([g.gate_id for g in self.gates], self.allowed_removal_ids, self.protected_permission_ids):
            if len(ids) != len(set(ids)):
                raise ValueError("duplicate readiness ID")
        if set(self.allowed_removal_ids) & set(self.protected_permission_ids):
            raise ValueError("protected permission cannot be allowed for removal")
        if self.execution_ready and (not self.allowed_removal_ids or any(g.result != "pass" for g in self.gates)):
            raise ValueError("execution readiness requires nonempty removals and all gates passing")
        return self


class Proposal(Contract):
    schema_version: Literal["guardian.proposal.v2"] = "guardian.proposal.v2"
    action: Literal["remediate", "adopt_baseline"] = "remediate"
    proposal_id: ID
    case_id: ID
    run_id: ID
    revision: int = Field(strict=True, ge=1)
    simulation: bool = Field(strict=True)
    status: ProposalStatus
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
    diff: str = Field(max_length=4000)
    gates: list[Gate] = Field(max_length=16)
    uncertainty: list[Text] = Field(max_length=8)
    published_at: AwareDatetime
    review_expires_at: AwareDatetime
    execution_window_seconds: int = Field(strict=True, ge=1)
    verification_profile_id: Literal["pod-reader-behavior.v1"] | None
    recovery_authorized: Literal[False] = False

    @model_validator(mode="after")
    def action_scope(self):
        utc(self.published_at)
        utc(self.review_expires_at)
        if self.review_expires_at <= self.published_at:
            raise ValueError("review deadline must follow publication")
        if self.action == "adopt_baseline":
            if self.patch or self.removed_permission_ids or self.result_rules != self.target.rules:
                raise ValueError("baseline adoption must preserve the exact snapshot without a patch")
            if self.verification_profile_id is not None:
                raise ValueError("adoption does not authorize mutation verification")
        elif not self.verification_profile_id:
            raise ValueError("remediation requires a verification profile")
        return self


class ApprovalDecision(Contract):
    schema_version: Literal["guardian.test-decision.v2"] = "guardian.test-decision.v2"
    decision_id: ID
    proposal_id: ID
    revision: int = Field(strict=True, ge=1)
    kind: Literal["approve_remediation", "adopt_baseline", "reject", "acknowledge", "request_context"]
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
        if self.kind in ("approve_remediation", "adopt_baseline"):
            if self.execution_expires_at is not None:
                utc(self.execution_expires_at)
            if self.execution_expires_at is None or utc(self.execution_expires_at) <= self.approved_at:
                raise ValueError("governed change decision needs execution deadline")
        elif self.execution_expires_at is not None:
            raise ValueError("non-writing decision cannot authorize execution")
        return self


class AnalysisReport(Contract):
    schema_version: Literal["guardian.report.v5"] = "guardian.report.v5"
    graph_version: Literal["guardian.graph.v5"]
    versions: RunVersions
    case_id: ID
    run_id: ID
    mode: Literal["simulation", "preview"]
    producer: ID
    status: RunStatus
    reason: Text | None
    facts: list[PermissionFact] = Field(max_length=128)
    # The scanner owns its finding schema; retain its JSON output without a
    # competing risk implementation or inference object in the checkpoint.
    security_risk: list[dict[str, JsonValue]] = Field(max_length=1024)
    investigation: Investigation | None
    plan: ChangePlan | None
    readiness: ReadinessAssessment | None
    model_status: ID
    model_calls: int = Field(strict=True, ge=0, le=6)
    lookup_calls: int = Field(strict=True, ge=0, le=4)
    trace: list[dict[str, JsonValue]] = Field(max_length=128)


class RevisionRequest(Contract):
    schema_version: Literal["guardian.revision-request.v1"] = "guardian.revision-request.v1"
    revision_request_id: ID
    source_proposal_id: ID
    source_run_id: ID
    source_revision: int = Field(strict=True, ge=1)
    source_approval_hash: ID
    reason: Literal["revision_requested", "review_window_expired", "execution_window_expired"]
    request: AnalysisRequest
    evidence_hash: ID
    reuse_analysis: bool = Field(strict=True)
    created_at: AwareDatetime

    @model_validator(mode="after")
    def lineage(self):
        utc(self.created_at)
        if (self.request.run_id == self.source_run_id or self.request.revision != self.source_revision + 1
                or self.request.revision_request_id != self.revision_request_id):
            raise ValueError("revision requires a new run, next revision and matching request ID")
        if self.reason == "revision_requested" and self.reuse_analysis:
            raise ValueError("context requests require fresh analysis")
        return self


def utc_now() -> datetime:
    from datetime import timezone
    return datetime.now(timezone.utc)
