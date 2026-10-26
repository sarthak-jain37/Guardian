"""Authoritative-port consumer tests. Every backend here is a recording fake."""

import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from unittest.mock import Mock

from langgraph.types import Command
from pydantic import ValidationError

from agents.guardian.adapters.governance import BackendGovernanceAdapter
from agents.guardian.contracts import AnalysisReport, AnalysisRequest, Proposal
from agents.guardian.fixtures import demo_evidence
from agents.guardian.governance import (ExecutionReceipt, GovernedDecision, PREFLIGHT_CHECKS, PreflightResult,
                                       action_key, validate_receipt)
from agents.guardian.policy import canonical_hash
from agents.guardian.reconciliation import reconcile_run
from agents.guardian.runner import config, open_runner
from agents.guardian.work import WorkItem
from agents.guardian.worker import process_work

NOW = datetime(2026, 10, 25, 0, 0, 20, tzinfo=timezone.utc)


class FixtureVerification:
    """Emulates the trusted port in contract tests, never real verification."""
    simulation_only = False

    def check(self, evidence, rules):
        return [{"gate_id": "failure_history", "result": "pass", "reasons": []},
                {"gate_id": "contract_fixture_verification", "result": "pass", "reasons": []}]

    def check_adoption(self, evidence):
        return [{"gate_id": "contract_fixture_adoption", "result": "pass", "reasons": []}]


class GovernanceTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.now = NOW
        self.evidence = demo_evidence(now=NOW).model_copy(update={"source_mode": "captured"})
        self.request = AnalysisRequest(case_id="governance-test", run_id="governance-run",
                                      snapshot_id=self.evidence.snapshot_id, cluster_id=self.evidence.target.cluster_id,
                                      target_uid=self.evidence.target.uid, mode="governed")
        self.cfg = config(self.request.run_id)
        self.session = open_runner(self.temp.name, evidence=self.evidence, clock=lambda: self.now)
        self.graph, self.runtime, self.store = self.session.__enter__()
        self.backend = Mock(simulation_only=False)
        self.backend.get_receipt.return_value = None
        self.runtime.governance = self.backend
        self.store.authoritative = True
        self.runtime.verification = FixtureVerification()

    def tearDown(self):
        self.session.__exit__(None, None, None)
        self.temp.cleanup()

    def start(self, intent="analyze"):
        self.request = self.request.model_copy(update={"intent": intent})
        self.state = self.graph.invoke({"request": self.request.model_dump(mode="json")}, self.cfg)
        self.assertEqual(self.state["status"], "PENDING_REVIEW", self.state.get("reason"))
        self.proposal = Proposal.model_validate(self.state["proposal"])
        self.decision = GovernedDecision(decision_id="backend-decision", proposal_id=self.proposal.proposal_id,
                                        revision=1, kind="adopt_baseline" if intent == "adopt_baseline" else "approve_remediation",
                                        authority="human", actor="authenticated-reviewer",
                                        approval_hash=self.proposal.approval_hash, policy_version=self.proposal.policy_version,
                                        target_uid=self.proposal.target.uid, approved_at=self.now,
                                        execution_expires_at=self.now + timedelta(seconds=300))
        self.store.get_decision = lambda _: self.decision
        self.preflight = PreflightResult(proposal_id=self.proposal.proposal_id, decision_id=self.decision.decision_id,
                                         action_key=action_key(self.proposal, self.decision.decision_id),
                                         approval_hash=self.proposal.approval_hash, evidence_hash=self.proposal.evidence_hash,
                                         candidate_hash=self.proposal.candidate_hash, target_uid=self.proposal.target.uid,
                                         resource_version=self.proposal.target.resource_version, checked_at=self.now,
                                         expires_at=self.now + timedelta(seconds=10),
                                         checks={k: "pass" for k in PREFLIGHT_CHECKS})
        self.backend.preflight.return_value = self.preflight
        self.backend.request.return_value = self.receipt()

    def receipt(self, **changes):
        data = dict(receipt_id="receipt-1", sequence=1,
                    action_key=action_key(self.proposal, self.decision.decision_id),
                    proposal_id=self.proposal.proposal_id, decision_id=self.decision.decision_id,
                    action=self.proposal.action, cluster_id=self.proposal.target.cluster_id,
                    target_uid=self.proposal.target.uid, approval_hash=self.proposal.approval_hash,
                    candidate_hash=self.proposal.candidate_hash, phase="requested", apply_status="not_started",
                    verification_status="not_required" if self.proposal.action == "adopt_baseline" else "pending",
                    recovery_status="not_requested", baseline_activated=False, recorded_at=self.now)
        data.update(changes)
        return ExecutionReceipt(**data)

    def resume(self):
        return self.graph.invoke(Command(resume=self.decision.decision_id), self.cfg)

    def test_governed_approval_requests_only_stored_ids_and_records_outcome(self):
        self.start()
        result = self.resume()
        self.assertEqual(result["status"], "EXECUTION_REQUESTED")
        self.backend.request.assert_called_once_with(self.proposal.proposal_id, self.decision.decision_id,
                                                     action_key(self.proposal, self.decision.decision_id), "remediate")
        self.assertEqual(self.store.count("action"), 0)
        self.assertEqual(self.store.count("action_dispatch"), 1)
        self.assertEqual(result["execution_outcome"]["phase"], "requested")

    def test_paused_unknown_and_wrong_snapshot_preflight_cause_zero_requests(self):
        self.start()
        for changes in [{"checks": {k: "fail" if k == "pause" else "pass" for k in PREFLIGHT_CHECKS}},
                        {"checks": {k: "unknown" if k == "authorization" else "pass" for k in PREFLIGHT_CHECKS}},
                        {"resource_version": "edited"}, {"decision_id": "other-decision"}]:
            with self.subTest(changes=changes):
                from agents.guardian.governance import validate_preflight
                with self.assertRaises(ValueError):
                    validate_preflight(self.preflight.model_copy(update=changes), self.proposal, self.decision, self.now)
        self.backend.preflight.return_value = self.preflight.model_copy(update={"resource_version": "edited"})
        self.assertEqual(self.resume()["status"], "STALE")
        self.backend.request.assert_not_called()

    def test_revoked_or_expired_authority_never_dispatches(self):
        self.start()
        self.decision = self.decision.model_copy(update={"revoked": True})
        self.assertEqual(self.resume()["status"], "STALE")
        self.backend.request.assert_not_called()

    def test_backend_cannot_extend_the_approved_execution_window(self):
        self.start()
        self.decision = self.decision.model_copy(update={"execution_expires_at": self.now + timedelta(hours=1)})
        result = self.resume()
        self.assertEqual(result["reason"], "execution_window_does_not_match_proposal")
        self.backend.request.assert_not_called()

    def test_raw_authority_provider_failure_is_redacted_and_blocks_dispatch(self):
        self.start()
        def unavailable(_):
            raise RuntimeError("credential=must-not-leak")
        self.store.get_decision = unavailable
        result = self.resume()
        self.assertEqual(result["reason"], "governance_revalidation_failed")
        self.assertNotIn("must-not-leak", str(result))
        self.backend.request.assert_not_called()

    def test_expired_forward_authority_prevents_new_dispatch(self):
        self.start()
        self.now += timedelta(seconds=301)
        result = self.resume()
        self.assertEqual(result["reason"], "execution_window_expired")
        self.backend.request.assert_not_called()

    def test_report_cannot_claim_verified_success_without_receipt(self):
        from agents.guardian.graph import report
        self.start()
        output = report(self.state, self.runtime)
        output["status"] = "COMPLETED"
        with self.assertRaises(ValidationError):
            AnalysisReport.model_validate(output)

    def test_local_test_decision_cannot_authorize_governed_run(self):
        self.start()
        data = self.decision.model_dump(mode="json")
        data.update(schema_version="guardian.test-decision.v2", simulation=True, actor="local-demo-reviewer")
        data.pop("recovery_authority_id")
        self.store.get_decision = lambda _: data
        self.assertEqual(self.resume()["status"], "STALE")
        self.backend.request.assert_not_called()

    def test_missing_authoritative_ports_cannot_publish_executable_review(self):
        self.store.authoritative = False
        state = self.graph.invoke({"request": self.request.model_dump(mode="json")}, self.cfg)
        self.assertEqual(state["status"], "BLOCKED")
        self.assertFalse(state["readiness"]["execution_ready"])
        self.backend.request.assert_not_called()

    def test_receipt_reconciliation_after_deadline_never_repeats_action_or_model(self):
        self.start()
        self.resume()
        self.now += timedelta(seconds=400)
        self.backend.get_receipt.return_value = self.receipt(receipt_id="receipt-2", sequence=2, phase="completed",
                                                            apply_status="confirmed", post_resource_version="43",
                                                            verification_status="passed", baseline_activated=True,
                                                            check_refs=["required-operation", "candidate-denial", "functional"])
        item = WorkItem(work_id="receipt-work", run_id=self.request.run_id, kind="reconcile")
        outcome = process_work(self.graph, self.runtime, item)
        self.assertEqual(outcome.status, "COMPLETED")
        self.assertEqual(outcome.model_calls, 2)
        self.assertEqual(process_work(self.graph, self.runtime, item), outcome)
        self.backend.request.assert_called_once()

    def test_crash_after_dispatch_reservation_requires_reconciliation_not_retry(self):
        self.start()
        self.backend.request.side_effect = KeyboardInterrupt("crash after send")
        with self.assertRaises(KeyboardInterrupt):
            self.resume()
        state = self.graph.invoke(None, self.cfg)
        self.assertEqual(state["status"], "NEEDS_MANUAL_INTERVENTION")
        self.backend.request.assert_called_once()

    def test_crash_with_durable_receipt_replays_without_dispatch(self):
        self.start()
        def crash(*args):
            self.backend.get_receipt.return_value = self.receipt()
            raise KeyboardInterrupt("response lost")
        self.backend.request.side_effect = crash
        with self.assertRaises(KeyboardInterrupt):
            self.resume()
        self.assertEqual(self.graph.invoke(None, self.cfg)["status"], "EXECUTION_REQUESTED")
        self.backend.request.assert_called_once()

    def test_uncertain_apply_and_inconclusive_verification_cannot_complete(self):
        self.start()
        self.backend.request.return_value = self.receipt(phase="manual", apply_status="unknown",
                                                        notification_intent_id="notify-operator")
        result = self.resume()
        self.assertEqual(result["status"], "NEEDS_MANUAL_INTERVENTION")
        self.assertFalse(result["execution_outcome"]["baseline_activated"])
        with self.assertRaises(ValidationError):
            self.receipt(phase="completed", apply_status="confirmed", post_resource_version="43",
                         verification_status="inconclusive", baseline_activated=True, check_refs=["probe"])

    def test_recovery_projection_requires_exact_original_rules_and_consent(self):
        self.start()
        self.decision = self.decision.model_copy(update={"recovery_authority_id": "explicit-recovery-consent"})
        self.resume()
        receipt = self.receipt(sequence=2, receipt_id="restoration-receipt", phase="rolled_back",
                               apply_status="confirmed", post_resource_version="43", verification_status="failed",
                               recovery_status="verified", recovery_authority_id="explicit-recovery-consent",
                               restored_resource_version="44",
                               restored_rules_hash=canonical_hash([r.model_dump(mode="json") for r in self.proposal.target.rules]),
                               check_refs=["restore-verified"], notification_intent_id="notify-reviewer")
        self.backend.get_receipt.return_value = receipt.model_copy(update={"restored_rules_hash": "wrong"})
        with self.assertRaisesRegex(ValueError, "restoration_scope_mismatch"):
            reconcile_run(self.graph, self.runtime, self.cfg)
        self.backend.get_receipt.return_value = receipt
        self.assertEqual(reconcile_run(self.graph, self.runtime, self.cfg)["status"], "ROLLED_BACK")
        self.backend.request.assert_called_once()

    def test_governed_adoption_never_requests_a_role_mutation(self):
        self.start(intent="adopt_baseline")
        self.backend.request.return_value = self.receipt(phase="completed", baseline_activated=True,
                                                        check_refs=["conditional-baseline-transaction"])
        result = self.resume()
        self.assertEqual(result["status"], "COMPLETED")
        self.assertEqual(result["model_calls"], 0)
        self.assertEqual(self.backend.request.call_args.args[-1], "adopt_baseline")

    def test_forged_regressing_and_conflicting_receipts_are_rejected(self):
        self.start()
        original = self.receipt(sequence=2)
        for changed in [self.receipt(target_uid="recreated"), self.receipt(sequence=1),
                        self.receipt(sequence=2, receipt_id="contradictory")]:
            with self.subTest(receipt=changed), self.assertRaises(ValueError):
                validate_receipt(changed, self.proposal, self.decision.decision_id, self.now, previous=original)

    def test_adapter_bounds_handoff_and_hides_backend_exception_text(self):
        driver = Mock()
        driver.execute_approved.side_effect = RuntimeError("secret-token-do-not-store")
        adapter = BackendGovernanceAdapter(driver)
        with self.assertRaisesRegex(ValueError, "^governance_operation_unavailable$"):
            adapter.request("proposal", "decision", "action", "remediate")
        self.assertEqual(driver.execute_approved.call_args.kwargs,
                         dict(proposal_id="proposal", decision_id="decision", action_key="action", timeout_seconds=10))
        driver.get_execution_receipt.return_value = {"oversized": "x" * 262145}
        with self.assertRaisesRegex(ValueError, "governance_operation_unavailable"):
            adapter.get_receipt("action")


if __name__ == "__main__":
    unittest.main()
