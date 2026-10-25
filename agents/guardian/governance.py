"""Consumer contracts for trusted backend governance; no authentication or writes.

These proposed contracts require backend/executor acceptance. A validated record
is meaningful only when loaded from the configured authoritative service.
"""

from typing import Literal, Protocol

from pydantic import AwareDatetime, Field, model_validator

from contracts.usage_summary_v1 import Contract, ID, utc


class GovernedDecision(Contract):
    schema_version: Literal["guardian.governed-decision.v1"] = "guardian.governed-decision.v1"
    decision_id: ID
    proposal_id: ID
    revision: int = Field(strict=True, ge=1)
    kind: Literal["approve_remediation", "adopt_baseline", "reject", "acknowledge", "request_context"]
    authority: Literal["human"]
    actor: ID
    simulation: Literal[False] = False
    approval_hash: ID
    policy_version: ID
    target_uid: ID
    approved_at: AwareDatetime
    execution_expires_at: AwareDatetime | None
    revoked: bool = Field(default=False, strict=True)
    recovery_authority_id: ID | None = None

    @model_validator(mode="after")
    def scope(self):
        utc(self.approved_at)
        writing = self.kind in ("approve_remediation", "adopt_baseline")
        if writing:
            if self.execution_expires_at is None or utc(self.execution_expires_at) <= self.approved_at:
                raise ValueError("change_requires_execution_deadline")
        elif self.execution_expires_at is not None or self.recovery_authority_id is not None:
            raise ValueError("nonwriting_decision_has_no_write_authority")
        if self.kind != "approve_remediation" and self.recovery_authority_id is not None:
            raise ValueError("recovery_requires_separate_remediation_consent")
        return self


PREFLIGHT_CHECKS = frozenset({"authorization", "pause", "incident", "snapshot", "consumers",
                              "baseline", "policy", "verification", "dry_run"})


class PreflightResult(Contract):
    schema_version: Literal["guardian.preflight.v1"] = "guardian.preflight.v1"
    proposal_id: ID
    decision_id: ID
    action_key: ID
    approval_hash: ID
    evidence_hash: ID
    candidate_hash: ID
    target_uid: ID
    resource_version: ID
    checked_at: AwareDatetime
    expires_at: AwareDatetime
    checks: dict[str, Literal["pass", "fail", "unknown"]] = Field(max_length=9)

    @model_validator(mode="after")
    def bounded(self):
        if set(self.checks) != PREFLIGHT_CHECKS:
            raise ValueError("preflight_requires_every_named_check")
        if utc(self.expires_at) <= utc(self.checked_at):
            raise ValueError("invalid_preflight_deadline")
        return self


class ExecutionReceipt(Contract):
    schema_version: Literal["guardian.execution-receipt.v1"] = "guardian.execution-receipt.v1"
    receipt_id: ID
    sequence: int = Field(strict=True, ge=1)
    action_key: ID
    proposal_id: ID
    decision_id: ID
    action: Literal["remediate", "adopt_baseline"]
    cluster_id: ID
    target_uid: ID
    approval_hash: ID
    candidate_hash: ID
    phase: Literal["requested", "applying", "verifying", "completed", "rolled_back", "manual", "stale", "failed"]
    apply_status: Literal["not_started", "confirmed", "unknown"]
    verification_status: Literal["pending", "passed", "failed", "inconclusive", "not_required"]
    recovery_status: Literal["not_requested", "pending", "verified", "blocked", "inconclusive"]
    baseline_activated: bool = Field(strict=True)
    post_resource_version: ID | None = None
    recovery_authority_id: ID | None = None
    restored_rules_hash: ID | None = None
    restored_resource_version: ID | None = None
    check_refs: list[ID] = Field(default_factory=list, max_length=64)
    notification_intent_id: ID | None = None
    recorded_at: AwareDatetime

    @model_validator(mode="after")
    def claims(self):
        utc(self.recorded_at)
        if self.baseline_activated != (self.phase == "completed"):
            raise ValueError("baseline_activation_requires_confirmed_completion")
        if self.apply_status == "unknown" and self.phase != "manual":
            raise ValueError("uncertain_apply_requires_manual_intervention")
        if self.apply_status == "confirmed" and self.post_resource_version is None:
            raise ValueError("confirmed_apply_requires_version")
        if self.action == "adopt_baseline" and (self.apply_status != "not_started" or
                self.recovery_status != "not_requested" or self.verification_status != "not_required"):
            raise ValueError("adoption_does_not_apply_or_restore_rules")
        if self.phase == "completed":
            if not self.check_refs or self.recovery_status != "not_requested":
                raise ValueError("completion_requires_verification_evidence")
            if self.action == "remediate" and (self.apply_status != "confirmed" or self.verification_status != "passed"):
                raise ValueError("remediation_completion_requires_confirmed_verified_apply")
        if self.phase == "verifying" and (self.action != "remediate" or self.apply_status != "confirmed"):
            raise ValueError("verification_requires_confirmed_apply")
        if self.phase == "rolled_back":
            if (self.apply_status != "confirmed" or self.verification_status != "failed" or
                    self.recovery_status != "verified" or not self.recovery_authority_id or
                    not self.restored_rules_hash or not self.restored_resource_version or
                    self.restored_resource_version == self.post_resource_version or
                    not self.check_refs or not self.notification_intent_id):
                raise ValueError("restoration_requires_exact_authority_verified_receipt_and_notification")
        elif (self.recovery_status == "verified" or self.restored_rules_hash is not None
              or self.restored_resource_version is not None):
            raise ValueError("restoration_claim_requires_rolled_back_phase")
        if self.phase in ("requested", "stale") and self.apply_status != "not_started":
            raise ValueError("unstarted_phase_cannot_claim_apply")
        if self.phase == "manual" and not self.notification_intent_id:
            raise ValueError("manual_intervention_requires_notification_intent")
        return self


class GovernancePort(Protocol):
    simulation_only: bool
    def preflight(self, proposal_id: str, decision_id: str, action_key: str) -> PreflightResult: ...
    def request(self, proposal_id: str, decision_id: str, action_key: str, action: str) -> ExecutionReceipt: ...
    def get_receipt(self, action_key: str) -> ExecutionReceipt | None: ...
    def record_outcome(self, run_id: str, receipt: ExecutionReceipt) -> None: ...


def action_key(proposal, decision_id):
    from .policy import canonical_hash
    return canonical_hash([proposal.proposal_id, decision_id, proposal.approval_hash])


def validate_preflight(raw, proposal, decision, now):
    result = PreflightResult.model_validate(raw)
    expected = (proposal.proposal_id, decision.decision_id, action_key(proposal, decision.decision_id),
                proposal.approval_hash, proposal.evidence_hash, proposal.candidate_hash,
                proposal.target.uid, proposal.target.resource_version)
    actual = tuple(getattr(result, k) for k in ("proposal_id", "decision_id", "action_key", "approval_hash",
                                                "evidence_hash", "candidate_hash", "target_uid", "resource_version"))
    if actual != expected:
        raise ValueError("preflight_scope_mismatch")
    if not result.checked_at <= now < result.expires_at <= decision.execution_expires_at:
        raise ValueError("preflight_expired_or_future")
    if any(value != "pass" for value in result.checks.values()):
        raise ValueError("backend_preflight_blocked")
    return result


def validate_receipt(raw, proposal, decision_id, now, previous=None, recovery_authority_id=None):
    from .policy import canonical_hash
    receipt = ExecutionReceipt.model_validate(raw)
    if (receipt.proposal_id, receipt.decision_id, receipt.action_key, receipt.action,
            receipt.cluster_id, receipt.target_uid, receipt.approval_hash, receipt.candidate_hash) != (
            proposal.proposal_id, decision_id, action_key(proposal, decision_id), proposal.action,
            proposal.target.cluster_id, proposal.target.uid, proposal.approval_hash, proposal.candidate_hash):
        raise ValueError("receipt_scope_mismatch")
    if receipt.recorded_at > now:
        raise ValueError("receipt_from_future")
    if receipt.phase == "rolled_back" and (receipt.recovery_authority_id != recovery_authority_id or
            receipt.restored_rules_hash != canonical_hash([r.model_dump(mode="json") for r in proposal.target.rules])):
        raise ValueError("restoration_scope_mismatch")
    if previous is not None:
        old = ExecutionReceipt.model_validate(previous)
        if receipt.sequence < old.sequence or receipt.recorded_at < old.recorded_at:
            raise ValueError("receipt_regression")
        if receipt.sequence == old.sequence and receipt != old:
            raise ValueError("conflicting_receipt_sequence")
        if old.phase in ("completed", "rolled_back", "manual", "stale", "failed") and receipt != old:
            raise ValueError("terminal_outcome_requires_separate_reconciliation")
        if old.apply_status == "confirmed" and receipt.apply_status != "confirmed":
            raise ValueError("confirmed_apply_cannot_regress")
        if old.apply_status == "confirmed" and receipt.post_resource_version != old.post_resource_version:
            raise ValueError("forward_receipt_version_cannot_change")
        if (old.phase == "verifying" and receipt.phase in ("requested", "applying")
                or old.phase == "applying" and receipt.phase == "requested"):
            raise ValueError("receipt_phase_regression")
    return receipt


def receipt_status(receipt):
    return {"requested": "EXECUTION_REQUESTED", "applying": "EXECUTION_REQUESTED", "verifying": "VERIFYING",
            "completed": "COMPLETED", "rolled_back": "ROLLED_BACK", "manual": "NEEDS_MANUAL_INTERVENTION",
            "stale": "STALE", "failed": "FAILED"}[receipt.phase]
