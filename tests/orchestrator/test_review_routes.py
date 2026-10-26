"""Phase-2 adoption and review lifecycle tests with recording-only adapters."""

import tempfile
import unittest
from datetime import datetime, timedelta, timezone

from langgraph.types import Command
from pydantic import ValidationError

from agents.guardian.adapters.models import ScriptedModelClient
from agents.guardian.contracts import AnalysisRequest, Proposal
from agents.guardian.fixtures import demo_evidence
from agents.guardian.runner import config, open_runner

NOW = datetime(2026, 10, 21, 12, 0, 20, tzinfo=timezone.utc)


class AdoptionTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.now = NOW
        self.evidence = demo_evidence("missing-usage", now=NOW)
        self.req = AnalysisRequest(case_id="adoption-case", run_id="adoption-run", intent="adopt_baseline",
                                   snapshot_id=self.evidence.snapshot_id, cluster_id=self.evidence.target.cluster_id,
                                   target_uid=self.evidence.target.uid)
        self.cfg = config(self.req.run_id)

    def tearDown(self):
        self.temp.cleanup()

    def open(self, evidence=None):
        return open_runner(self.temp.name, evidence=evidence or self.evidence, clock=lambda: self.now)

    def start(self, graph, **changes):
        req = self.req.model_copy(update=changes)
        return graph.invoke({"request": req.model_dump(mode="json")}, self.cfg)

    def test_adoption_without_usage_baseline_or_removal_skips_models(self):
        with self.open() as (graph, runtime, store):
            state = self.start(graph)
            self.assertEqual(state["status"], "PENDING_REVIEW")
            self.assertEqual(state["model_calls"], 0)
            self.assertEqual(runtime.model.calls, [])
            self.assertEqual(state["proposal"]["action"], "adopt_baseline")
            self.assertEqual(state["proposal"]["patch"], [])
            self.assertEqual(state["proposal"]["removed_permission_ids"], [])
            self.assertEqual(state["proposal"]["result_rules"], state["proposal"]["target"]["rules"])
            self.assertEqual(store.count("adoption"), 0)
            self.assertEqual(store.count("action"), 0)

    def test_restart_and_approved_adoption_only_record_one_request(self):
        with self.open() as (graph, runtime, store):
            state = self.start(graph)
            pid = state["proposal"]["proposal_id"]
        with self.open() as (graph, runtime, store):
            d = store.record_test_decision(pid, "adopt_baseline")
            result = graph.invoke(Command(resume=d.decision_id), self.cfg)
            self.assertEqual(result["status"], "EXECUTION_REQUESTED")
            self.assertFalse(result["receipt"]["baseline_activated"])
            self.assertFalse(result["receipt"]["cluster_write_performed"])
            runtime.baseline.adopt_approved_snapshot(pid, d.decision_id, result["receipt"]["action_key"])
            self.assertEqual(store.count("adoption"), 1)
            self.assertEqual(store.count("action"), 0)
            self.assertEqual(runtime.model.calls, [])

    def test_non_authorizing_routes_do_not_request_adoption(self):
        for kind in ("reject", "acknowledge", "request_context"):
            with self.subTest(kind=kind), tempfile.TemporaryDirectory() as directory:
                with open_runner(directory, evidence=self.evidence, clock=lambda: NOW) as (graph, runtime, store):
                    state = self.start(graph)
                    d = store.record_test_decision(state["proposal"]["proposal_id"], kind)
                    graph.invoke(Command(resume=d.decision_id), self.cfg)
                    self.assertEqual(store.count("adoption"), 0)
                    self.assertEqual(store.count("action"), 0)

    def test_changed_snapshot_and_expired_adoption_fail_closed(self):
        for change in ("uid", "rules", "deadline"):
            with self.subTest(change=change), tempfile.TemporaryDirectory() as directory:
                with open_runner(directory, evidence=self.evidence.model_copy(deep=True), clock=lambda: self.now) as (graph, runtime, store):
                    self.now = NOW
                    state = self.start(graph)
                    d = store.record_test_decision(state["proposal"]["proposal_id"], "adopt_baseline")
                    if change == "uid":
                        runtime.evidence.evidence.target.uid = "new-role"
                    elif change == "rules":
                        runtime.evidence.evidence.target.rules[0].verbs = ["get"]
                    else:
                        self.now += timedelta(minutes=6)
                    result = graph.invoke(Command(resume=d.decision_id), self.cfg)
                    self.assertEqual(result["status"], "STALE")
                    self.assertEqual(store.count("adoption"), 0)
                    self.assertEqual(store.count("action"), 0)

    def test_adoption_decision_cannot_authorize_a_remediation_patch(self):
        with self.open(demo_evidence(now=NOW)) as (graph, runtime, store):
            req = self.req.model_copy(update={"intent": "analyze", "snapshot_id": "fixture-complete"})
            state = graph.invoke({"request": req.model_dump(mode="json")}, self.cfg)
            with self.assertRaisesRegex(ValueError, "decision_kind_does_not_match_proposal"):
                store.record_test_decision(state["proposal"]["proposal_id"], "adopt_baseline")

    def test_remediation_decision_cannot_authorize_adoption(self):
        with self.open() as (graph, runtime, store):
            state = self.start(graph)
            with self.assertRaisesRegex(ValueError, "decision_kind_does_not_match_proposal"):
                store.record_test_decision(state["proposal"]["proposal_id"], "approve_remediation")
            bad = dict(state["proposal"], patch=[{"op": "replace", "path": "/rules", "value": []}])
            with self.assertRaises(ValidationError):
                Proposal.model_validate(bad)

    def test_missing_adoption_port_or_captured_evidence_cannot_enter_review(self):
        with self.open() as (graph, runtime, store):
            runtime.baseline = None
            state = self.start(graph)
            self.assertEqual(state["status"], "BLOCKED")
            self.assertFalse(graph.get_state(self.cfg).next)
        captured = self.evidence.model_copy(update={"source_mode": "captured"})
        with tempfile.TemporaryDirectory() as directory:
            with open_runner(directory, evidence=captured, clock=lambda: NOW) as (graph, runtime, store):
                state = self.start(graph, mode="preview")
                self.assertEqual(state["status"], "BLOCKED")
                self.assertEqual(store.count("adoption"), 0)


if __name__ == "__main__":
    unittest.main()
