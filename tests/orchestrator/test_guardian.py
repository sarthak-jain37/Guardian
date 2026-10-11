"""CPU-only orchestration behavior, including actual process restarts."""

import json
import subprocess
import sys
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

from langgraph.types import Command
from pydantic import ValidationError

from agents.guardian.adapters.models import ScriptedModelClient
from agents.guardian.contracts import AnalysisRequest, ChangePlan, EvidenceBundle, Investigation
from agents.guardian.fixtures import demo_evidence
from agents.guardian.policy import build_facts, operation_id, operations, render, rule_dicts, validate_investigation, validate_plan
from agents.guardian.runner import config, open_runner
from contracts.usage_summary_v1 import UsageSummary

NOW = datetime(2026, 10, 11, 12, 0, 20, tzinfo=timezone.utc)


def request(evidence, run="test-run", mode="simulation"):
    return AnalysisRequest(case_id="test-case", run_id=run, snapshot_id=evidence.snapshot_id,
                           cluster_id=evidence.target.cluster_id, target_uid=evidence.target.uid, mode=mode)


class ModuleTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.directory = Path(self.temp.name)
        self.now = NOW
        self.evidence = demo_evidence(now=NOW)

    def tearDown(self):
        self.temp.cleanup()

    def open(self, evidence=None, model=None):
        return open_runner(self.directory, model=model, evidence=evidence or self.evidence, clock=lambda: self.now)

    def start(self, graph, evidence=None, mode="simulation"):
        req = request(evidence or self.evidence, mode=mode)
        return graph.invoke({"request": req.model_dump(mode="json")}, config(req.run_id))

    def test_useful_initial_proposal_without_baseline_or_answer_document(self):
        with self.open() as (graph, runtime, store):
            state = self.start(graph)
            self.assertEqual(state["status"], "PENDING_REVIEW")
            self.assertEqual(state["model_calls"], 2)
            self.assertEqual(store.count("action"), 0)
            self.assertIsNone(self.evidence.baseline_id)
            self.assertEqual(self.evidence.context.optional_documents, [])
            p = state["proposal"]
            self.assertEqual(operations(p["result_rules"]), {("", "pods", "get"), ("", "pods", "list")})
            self.assertEqual(p["patch"][0]["value"], self.evidence.target.uid)
            self.assertEqual(p["patch"][1]["value"], "42")
            self.assertTrue(p["simulation"])
            self.assertFalse(p["recovery_authorized"])
            self.assertEqual(p["unchanged_binding"], self.evidence.binding.model_dump(mode="json"))

    def test_restart_preserves_review_without_model_calls_or_duplicate_publication(self):
        with self.open() as (graph, runtime, store):
            state = self.start(graph)
            pid = state["proposal"]["proposal_id"]
        client = ScriptedModelClient([RuntimeError("must not be called")])
        with self.open(model=client) as (graph, runtime, store):
            self.assertEqual(graph.get_state(config("test-run")).values["status"], "PENDING_REVIEW")
            decision = store.record_test_decision(pid, "reject")
            resumed = graph.invoke(Command(resume=decision.decision_id), config("test-run"))
            self.assertEqual(resumed["status"], "REJECTED")
            self.assertEqual(store.count("proposal"), 1)
            self.assertEqual(store.count("action"), 0)
            self.assertEqual(client.calls, [])

    def test_approval_and_duplicate_delivery_record_one_simulated_request(self):
        with self.open() as (graph, runtime, store):
            state = self.start(graph)
            decision = store.record_test_decision(state["proposal"]["proposal_id"], "approve_remediation")
            result = graph.invoke(Command(resume=decision.decision_id), config("test-run"))
            self.assertEqual(result["status"], "EXECUTION_REQUESTED")
            self.assertFalse(result["receipt"]["cluster_write_performed"])
            self.assertFalse(result["receipt"]["baseline_activated"])
            runtime.execution.request(decision.proposal_id, decision.decision_id, result["receipt"]["action_key"])
            self.assertEqual(store.count("action"), 1)

    def test_forged_resume_cannot_authorize(self):
        with self.open() as (graph, runtime, store):
            self.start(graph)
            state = graph.invoke(Command(resume={"approved": True, "actor": "mentor"}), config("test-run"))
            self.assertEqual(state["status"], "STALE")
            self.assertEqual(store.count("action"), 0)

    def test_unknown_decision_cannot_authorize(self):
        with self.open() as (graph, runtime, store):
            self.start(graph)
            state = graph.invoke(Command(resume="invented-decision"), config("test-run"))
            self.assertEqual(state["status"], "STALE")
            self.assertEqual(store.count("action"), 0)

    def test_changed_version_invalidates_approval(self):
        with self.open() as (graph, runtime, store):
            state = self.start(graph)
            d = store.record_test_decision(state["proposal"]["proposal_id"], "approve_remediation")
            runtime.evidence.evidence.target.resource_version = "43"
            result = graph.invoke(Command(resume=d.decision_id), config("test-run"))
            self.assertEqual(result["status"], "STALE")
            self.assertEqual(result["reason"], "material_evidence_changed")
            self.assertEqual(store.count("action"), 0)

    def test_recreated_target_invalidates_approval(self):
        with self.open() as (graph, runtime, store):
            state = self.start(graph)
            d = store.record_test_decision(state["proposal"]["proposal_id"], "approve_remediation")
            runtime.evidence.evidence.target.uid = "recreated-role"
            result = graph.invoke(Command(resume=d.decision_id), config("test-run"))
            self.assertEqual(result["status"], "STALE")
            self.assertEqual(store.count("action"), 0)

    def test_execution_expiry_blocks_valid_decision(self):
        with self.open() as (graph, runtime, store):
            state = self.start(graph)
            d = store.record_test_decision(state["proposal"]["proposal_id"], "approve_remediation")
            self.now += timedelta(seconds=301)
            result = graph.invoke(Command(resume=d.decision_id), config("test-run"))
            self.assertEqual(result["reason"], "execution_window_expired")
            self.assertEqual(store.count("action"), 0)

    def test_review_expiry_and_independent_execution_clock(self):
        with self.open() as (graph, runtime, store):
            state = self.start(graph)
            pid = state["proposal"]["proposal_id"]
            self.now += timedelta(hours=23, minutes=59)
            d = store.record_test_decision(pid, "approve_remediation")
            self.assertEqual(d.execution_expires_at - d.approved_at, timedelta(minutes=5))
            self.assertGreater(d.execution_expires_at, store.get_proposal(pid).review_expires_at)
            self.now += timedelta(minutes=2)
            with self.assertRaisesRegex(ValueError, "review_window_expired"):
                store.record_test_decision(pid, "approve_remediation")

    def test_conflicting_decision_is_rejected(self):
        with self.open() as (graph, runtime, store):
            state = self.start(graph)
            pid = state["proposal"]["proposal_id"]
            store.record_test_decision(pid, "reject")
            with self.assertRaisesRegex(ValueError, "conflicting_decision"):
                store.record_test_decision(pid, "approve_remediation")

    def test_missing_gap_and_monthly_cases_do_not_enter_review(self):
        for scenario in ["coverage-gap", "monthly", "missing-usage"]:
            with self.subTest(scenario=scenario), tempfile.TemporaryDirectory() as directory:
                e = demo_evidence(scenario, now=NOW)
                with open_runner(directory, evidence=e, clock=lambda: NOW) as (graph, runtime, store):
                    state = self.start(graph, e)
                    self.assertEqual(state["status"], "BLOCKED")
                    self.assertEqual(store.count("action"), 0)
                    self.assertEqual(store.count("proposal"), 0)
                    self.assertFalse(graph.get_state(config("test-run")).next)

    def test_captured_preview_cannot_get_test_authority(self):
        data = self.evidence.model_dump(mode="json")
        data["source_mode"] = "captured"
        e = EvidenceBundle.model_validate(data)
        with self.open(e) as (graph, runtime, store):
            state = self.start(graph, e, mode="preview")
            self.assertEqual(state["status"], "BLOCKED")
            self.assertFalse(state["proposal"]["simulation"])
            self.assertTrue(state["proposal"]["removed_permission_ids"])
            with self.assertRaises(ValueError):
                store.record_test_decision(state["proposal"]["proposal_id"], "approve_remediation")

    def test_model_failure_preserves_findings_with_finite_repair(self):
        client = ScriptedModelClient([RuntimeError("offline"), RuntimeError("offline")])
        with self.open(model=client) as (graph, runtime, store):
            state = self.start(graph)
            self.assertEqual(state["status"], "BLOCKED")
            self.assertEqual(state["model_calls"], 2)
            self.assertEqual(state["model_status"], "investigator_failed")
            self.assertTrue(state["risk"])
            self.assertIsNone(state["investigation"])

    def test_crashed_inference_consumes_durable_budget_after_restart(self):
        class CrashingModel(ScriptedModelClient):
            def generate(self, stage, payload, schema):
                raise KeyboardInterrupt("simulated worker termination")
        with self.open(model=CrashingModel()) as (graph, runtime, store):
            with self.assertRaises(KeyboardInterrupt):
                self.start(graph)
            self.assertEqual(store.model_call_count("test-run"), 1)
        with self.open() as (graph, runtime, store):
            state = graph.invoke(None, config("test-run"))
            self.assertEqual(state["status"], "PENDING_REVIEW")
            self.assertEqual(state["model_calls"], 3)
            self.assertEqual(store.model_call_count("test-run"), 3)

    def test_invalid_planner_preserves_valid_investigation(self):
        class BrokenPlanner(ScriptedModelClient):
            def generate(self, stage, payload, schema):
                if stage == "planner":
                    return {"yaml": "arbitrary write"}
                return super().generate(stage, payload, schema)
        with self.open(model=BrokenPlanner()) as (graph, runtime, store):
            state = self.start(graph)
            self.assertEqual(state["status"], "BLOCKED")
            self.assertIsNotNone(state["investigation"])
            self.assertIsNone(state["plan"])
            self.assertEqual(state["model_calls"], 3)
            self.assertEqual(store.count("outcome"), 1)

    def test_revoked_and_mismatched_stored_decisions_are_blocked(self):
        for field, value in [("revoked", True), ("approval_hash", "different"), ("revision", 2),
                             ("target_uid", "different"), ("policy_version", "different")]:
            with self.subTest(field=field), tempfile.TemporaryDirectory() as directory:
                with open_runner(directory, evidence=self.evidence, clock=lambda: NOW) as (graph, runtime, store):
                    state = self.start(graph)
                    d = store.record_test_decision(state["proposal"]["proposal_id"], "approve_remediation")
                    payload = d.model_dump(mode="json")
                    payload[field] = value
                    with store.connection:
                        store.connection.execute("UPDATE records SET payload=? WHERE kind='decision' AND id=?",
                                                 (json.dumps(payload), d.decision_id))
                    state = graph.invoke(Command(resume=d.decision_id), config("test-run"))
                    self.assertEqual(state["status"], "STALE")
                    self.assertEqual(store.count("action"), 0)

    def test_lookup_budget_and_longest_route_fit_recursion_limit(self):
        class LookupModel(ScriptedModelClient):
            def generate(self, stage, payload, schema):
                output = super().generate(stage, payload, schema)
                if stage == "investigator":
                    output["context_requests"] = [payload["allowed_lookup"]]
                return output
        with self.open(model=LookupModel()) as (graph, runtime, store):
            state = self.start(graph)
            self.assertEqual(state["status"], "PENDING_REVIEW")
            self.assertEqual(state["lookup_rounds"], 2)
            self.assertEqual(state["lookup_calls"], 2)
            self.assertEqual(state["model_calls"], 4)

    def test_request_context_closes_old_run_without_execution(self):
        with self.open() as (graph, runtime, store):
            state = self.start(graph)
            d = store.record_test_decision(state["proposal"]["proposal_id"], "request_context")
            result = graph.invoke(Command(resume=d.decision_id), config("test-run"))
            self.assertEqual(result["status"], "STALE")
            self.assertEqual(result["reason"], "revision_requested")
            self.assertEqual(store.count("action"), 0)

    def test_six_call_repair_lookup_route_remains_bounded(self):
        class RepairLookupModel(ScriptedModelClient):
            def __init__(self):
                super().__init__()
                self.counts = {"investigator": 0, "planner": 0}
            def generate(self, stage, payload, schema):
                self.counts[stage] += 1
                if self.counts[stage] == 1:
                    return {"invalid": "output requiring one repair"}
                output = super().generate(stage, payload, schema)
                if stage == "investigator":
                    output["context_requests"] = [payload["allowed_lookup"], payload["allowed_lookup"]]
                return output
        with self.open(model=RepairLookupModel()) as (graph, runtime, store):
            state = self.start(graph)
            self.assertEqual(state["status"], "PENDING_REVIEW")
            self.assertEqual(state["model_calls"], 6)
            self.assertEqual(state["lookup_calls"], 4)
            self.assertEqual(store.model_call_count("test-run"), 6)

    def test_zero_model_budget_publishes_deterministic_findings(self):
        data = self.evidence.model_dump(mode="json")
        data["policy"]["model_calls"] = 0
        e = EvidenceBundle.model_validate(data)
        with self.open(e) as (graph, runtime, store):
            state = self.start(graph, e)
            self.assertEqual(state["status"], "BLOCKED")
            self.assertEqual(state["model_calls"], 0)
            self.assertEqual(state["model_status"], "budget_exhausted")
            self.assertTrue(state["risk"])
            self.assertEqual(store.count("outcome"), 1)


class PolicyAndContractTests(unittest.TestCase):
    def setUp(self):
        self.e = demo_evidence(now=NOW)

    def test_cross_product_removal_preserves_neighbors_and_adds_no_grants(self):
        data = self.e.model_dump(mode="json")
        data["target"]["rules"] = [{"apiGroups": ["", "example.org"], "resources": ["pods", "secrets"], "verbs": ["get", "list"]}]
        e = EvidenceBundle.model_validate(data)
        output = render(e, {operation_id("", "secrets", "get", "guardian-demo")})
        after = operations(output["result_rules"])
        self.assertEqual(len(after), 7)
        self.assertNotIn(("", "secrets", "get"), after)
        self.assertIn(("example.org", "secrets", "get"), after)
        self.assertLessEqual(after, operations(rule_dicts(e.target)))

    def test_authorized_errors_protect_operations(self):
        data = self.e.model_dump(mode="json")
        bucket = data["usage"]["series"][-1]["buckets"][0]
        bucket["counts"]["authorized_error"] = 1
        bucket["first_request_at"] = bucket["last_request_at"] = bucket["interval"]["start"]
        bucket["evidence_refs"] = ["fixture-authorized-404"]
        facts, _ = build_facts(EvidenceBundle.model_validate(data), NOW)
        self.assertTrue(next(f for f in facts if f["resource"] == "secrets")["protected"])

    def test_carried_authorization_protects_zero_new_request_count(self):
        data = self.e.model_dump(mode="json")
        start = self.e.usage.query_window.start
        data["usage"]["series"][-1]["carried_authorized_requests"] = [{
            "request_ref": "fixture-carried", "request_started_at": (start - timedelta(hours=1)).isoformat(),
            "authorized_at": (start - timedelta(hours=1)).isoformat(), "last_observed_at": start.isoformat(),
            "completed_at": None, "evidence_refs": ["fixture-carried-evidence"]}]
        facts, _ = build_facts(EvidenceBundle.model_validate(data), NOW)
        self.assertTrue(next(f for f in facts if f["resource"] == "secrets")["protected"])

    def test_stage_validators_reject_invented_ids_and_protected_removals(self):
        facts, _ = build_facts(self.e, NOW)
        client = ScriptedModelClient()
        payload = {"facts": facts, "target_uid": self.e.target.uid}
        output = client.generate("investigator", payload, {})
        output["permission_assessments"][0]["permission_id"] = "invented"
        with self.assertRaises(ValueError):
            validate_investigation(Investigation.model_validate(output), facts, self.e)
        investigation = Investigation.model_validate(client.generate("investigator", payload, {}))
        payload["investigation"] = investigation.model_dump()
        plan = client.generate("planner", payload, {})
        plan["decisions"][0]["action"] = "remove"
        with self.assertRaises(ValueError):
            validate_plan(ChangePlan.model_validate(plan), facts, investigation, self.e)

    def test_unknown_consumer_alternate_grant_wildcard_named_rules_block(self):
        mutations = [lambda d: d["context"].update(consumer_inventory_complete=False),
                     lambda d: d["context"].update(alternate_grants=["other-broad-grant"]),
                     lambda d: d["target"]["rules"][0].update(verbs=["*"]),
                     lambda d: d["target"]["rules"][0].update(resourceNames=["one-pod"])]
        for mutate in mutations:
            data = self.e.model_dump(mode="json")
            mutate(data)
            facts, _ = build_facts(EvidenceBundle.model_validate(data), NOW)
            self.assertFalse(any(f["eligible"] for f in facts))

    def test_summary_rejects_missing_duplicate_negative_and_false_coverage(self):
        mutations = [lambda d: d["series"].pop(),
                     lambda d: d["requested_key_ids"].append(d["requested_key_ids"][0]),
                     lambda d: d["series"][0]["buckets"][0]["counts"].update(successful_completed=-1),
                     lambda d: d["series"][0]["coverage"][0].update(known_lost_events=None),
                     lambda d: d.update(processed_through=None),
                     lambda d: d["series"][0]["coverage"][0].update(health_evidence_refs=[]),
                     lambda d: d["series"][0]["buckets"][0].update(bucket_start="2026-10-11T11:59:00Z")]
        for index, mutate in enumerate(mutations):
            with self.subTest(index=index):
                data = self.e.usage.model_dump(mode="json")
                mutate(data)
                with self.assertRaises(ValidationError):
                    UsageSummary.model_validate(data)

    def test_exact_partial_hours_and_utc_day_boundary(self):
        e = demo_evidence(now=datetime(2026, 10, 12, 0, 2, 10, tzinfo=timezone.utc))
        self.assertEqual(len(e.usage.series[0].buckets), 2)
        self.assertEqual(e.usage.series[0].buckets[0].interval.start, e.usage.query_window.start)
        self.assertEqual(e.usage.series[0].buckets[-1].interval.end, e.usage.query_window.end)


class ProcessRestartTest(unittest.TestCase):
    def test_cli_fresh_process_status_and_rejection(self):
        with tempfile.TemporaryDirectory() as directory:
            base = [sys.executable, "-m", "agents.guardian.runner", "--directory", directory]
            subprocess.run(base + ["start"], check=True, capture_output=True, text=True)
            status = json.loads(subprocess.run(base + ["status"], check=True, capture_output=True, text=True).stdout)
            self.assertEqual(status["status"], "PENDING_REVIEW")
            d = json.loads(subprocess.run(base + ["decide", "reject"], check=True, capture_output=True, text=True).stdout)
            result = json.loads(subprocess.run(base + ["resume", "--decision-id", d["decision_id"]], check=True, capture_output=True, text=True).stdout)
            self.assertEqual(result["status"], "REJECTED")
            self.assertEqual(result["execution_requests"], 0)


if __name__ == "__main__":
    unittest.main()
