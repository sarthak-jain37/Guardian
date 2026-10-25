"""Strict, bounded client bridge to backend-owned operations; no invented URLs.

The backend owner implements the driver against its agreed transport and must
honor timeout_seconds, authorize scope and atomically persist action intent.
This module neither retries requests nor receives actor/approval from a delivery.
"""

import json

from ..governance import ExecutionReceipt, GovernedDecision, PreflightResult


class BackendGovernanceAdapter:
    simulation_only = False
    max_response_bytes = 262144

    def __init__(self, driver, timeout_seconds=10):
        if type(timeout_seconds) is not int or not 1 <= timeout_seconds <= 30:
            raise ValueError("invalid_governance_timeout")
        self.driver = driver
        self.timeout = timeout_seconds

    def _call(self, operation, **ids):
        try:
            value = getattr(self.driver, operation)(**ids, timeout_seconds=self.timeout)
            if value is not None and len(json.dumps(value).encode()) > self.max_response_bytes:
                raise ValueError("oversized_backend_result")
            return value
        except Exception:
            raise ValueError("governance_operation_unavailable") from None

    def get_decision(self, decision_id):
        return self._validated(GovernedDecision, self._call("get_decision", decision_id=decision_id))

    @staticmethod
    def _validated(model, value):
        try:
            return model.model_validate(value)
        except Exception:
            raise ValueError("invalid_governance_record") from None

    def preflight(self, proposal_id, decision_id, action_key):
        return self._validated(PreflightResult, self._call("validate_preconditions", proposal_id=proposal_id,
                                                        decision_id=decision_id, action_key=action_key))

    def request(self, proposal_id, decision_id, action_key, action):
        if action not in ("remediate", "adopt_baseline"):
            raise ValueError("unsupported_backend_action")
        operation = "execute_approved" if action == "remediate" else "adopt_approved_snapshot"
        return self._validated(ExecutionReceipt, self._call(operation, proposal_id=proposal_id,
                                                          decision_id=decision_id, action_key=action_key))

    def get_receipt(self, action_key):
        value = self._call("get_execution_receipt", action_key=action_key)
        return self._validated(ExecutionReceipt, value) if value is not None else None

    def record_outcome(self, run_id, receipt):
        # Send the durable receipt ID, never a caller's proposed terminal status.
        self._call("project_execution_outcome", run_id=run_id, receipt_id=receipt.receipt_id,
                   sequence=receipt.sequence)


class BackendReviewAdapter(BackendGovernanceAdapter):
    """ReviewPort bridge; the driver owns its DB, sessions, outbox and scheduling."""
    authoritative = True
    max_response_bytes = 2097152

    def publish(self, proposal, report):
        from ..contracts import Proposal
        return self._validated(Proposal, self._call("publish_review", proposal=proposal.model_dump(mode="json"), report=report))

    def get_proposal(self, proposal_id):
        from ..contracts import Proposal
        return self._validated(Proposal, self._call("get_proposal", proposal_id=proposal_id))

    def publish_report(self, run_id, report):
        return self._call("publish_report", run_id=run_id, report=report)

    def get_report(self, run_id):
        from ..contracts import AnalysisReport
        return self._validated(AnalysisReport, self._call("get_report", run_id=run_id)).model_dump(mode="json")

    def finalize_run(self, run_id, result):
        return self._call("finalize_run", run_id=run_id, result=result)

    def get_proposal_status(self, proposal_id):
        from ..lifecycle import ProposalStatus
        try:
            return ProposalStatus(self._call("get_proposal_status", proposal_id=proposal_id)).value
        except Exception:
            raise ValueError("invalid_proposal_status") from None

    def project_proposal(self, proposal_id, status, reason):
        from ..lifecycle import ProposalStatus
        value = self._call("project_proposal", proposal_id=proposal_id, status=ProposalStatus(status).value, reason=reason)
        if not isinstance(value, dict) or value.get("proposal_id") != proposal_id:
            raise ValueError("invalid_proposal_projection")
        return {"proposal_id": proposal_id, "status": ProposalStatus(value.get("status")).value, "reason": value.get("reason")}

    def get_proposal_decision(self, proposal_id):
        value = self._call("get_proposal_decision", proposal_id=proposal_id)
        return self._validated(GovernedDecision, value) if value is not None else None

    def request_revision(self, request):
        from ..contracts import RevisionRequest
        return self._validated(RevisionRequest, self._call("request_revision", request=request.model_dump(mode="json")))

    def get_revision(self, revision_request_id):
        from ..contracts import RevisionRequest
        return self._validated(RevisionRequest, self._call("get_revision", revision_request_id=revision_request_id))

    def get_successor(self, proposal_id):
        from ..contracts import RevisionRequest
        value = self._call("get_successor", proposal_id=proposal_id)
        return self._validated(RevisionRequest, value) if value is not None else None
