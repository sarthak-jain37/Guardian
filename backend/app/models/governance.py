"""Backend review requests. Actor, authority, clocks and scope are server-owned."""
from typing import Annotated, Literal

from pydantic import Field, model_validator

from agents.guardian.contracts import AnalysisReport, Proposal
from contracts.usage_summary_v1 import Contract, ID


class ReviewPublication(Contract):
    schema_version: Literal["guardian.review-publication.v1"] = "guardian.review-publication.v1"
    proposal: Proposal
    report: AnalysisReport

    @model_validator(mode="after")
    def matching_records(self):
        p, r = self.proposal, self.report
        if p.simulation or r.mode not in ("preview", "governed"):
            raise ValueError("simulation_cannot_become_governed_review")
        if (p.case_id, p.run_id, p.policy_version) != (r.case_id, r.run_id, r.versions.policy_version):
            raise ValueError("proposal_report_scope_mismatch")
        if p.status not in ("DRAFT", "BLOCKED", "PENDING_APPROVAL"):
            raise ValueError("publication_cannot_claim_a_decision_or_execution")
        if r.execution_outcome is not None or r.status not in ("BLOCKED", "PENDING_REVIEW"):
            raise ValueError("publication_cannot_claim_an_execution_outcome")
        if p.target.kind != "Role" or p.target.namespace is None:
            raise ValueError("review_intake_requires_namespaced_role")
        return self


class DecisionInput(Contract):
    kind: Literal["approve_remediation", "adopt_baseline", "reject", "acknowledge", "request_context"]
    expected_revision: int = Field(strict=True, ge=1)
    expected_approval_hash: ID
    idempotency_key: Annotated[str, Field(min_length=8, max_length=128)]
    note: str = Field(default="", max_length=2000)
    accept_residual_risk: bool = Field(default=False, strict=True)


class DeliveryClaim(Contract):
    cluster_id: ID
    namespace: ID
    limit: int = Field(default=1, strict=True, ge=1, le=32)
    lease_seconds: int = Field(default=30, strict=True, ge=1, le=300)


class DeliveryAck(Contract):
    lease_token: ID


class HoldInput(Contract):
    cluster_id: ID
    namespace: ID
    kind: Literal["pause", "incident"]
    active: bool = Field(strict=True)
    reason: str = Field(min_length=1, max_length=2000)

    @model_validator(mode="after")
    def explained(self):
        if not self.reason.strip():
            raise ValueError("hold_change_requires_reason")
        return self
