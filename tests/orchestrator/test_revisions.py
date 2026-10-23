"""Durable revision lineage, analysis reuse and no-authority-carryover tests."""

import json
import subprocess
import sys
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

from langgraph.types import Command

from agents.guardian.contracts import AnalysisRequest, EvidenceBundle
from agents.guardian.adapters.models import ScriptedModelClient
from agents.guardian.fixtures import demo_evidence
from agents.guardian.revisions import renew_review
from agents.guardian.runner import config, open_runner, start_successor

NOW = datetime(2026, 10, 21, 12, 0, 20, tzinfo=timezone.utc)


class RevisionTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.now = NOW
        data = demo_evidence(now=NOW).model_dump(mode="json")
        data["policy"].update(review_window_seconds=2, execution_window_seconds=3)
        self.evidence = EvidenceBundle.model_validate(data)
        self.req = AnalysisRequest(case_id="revision-case", run_id="revision-run",
                                   snapshot_id=self.evidence.snapshot_id, cluster_id=self.evidence.target.cluster_id,
                                   target_uid=self.evidence.target.uid)
        self.cfg = config(self.req.run_id)

    def tearDown(self):
        self.temp.cleanup()

    def open(self):
        return open_runner(self.temp.name, evidence=self.evidence, clock=lambda: self.now)

    def start(self, graph):
        return graph.invoke({"request": self.req.model_dump(mode="json")}, self.cfg)

    def successor(self, graph, ticket):
        return graph.invoke({"request": ticket.request.model_dump(mode="json")}, config(ticket.request.run_id))

    def test_expired_review_reuses_analysis_with_new_human_review(self):
        with self.open() as (graph, runtime, store):
            original = self.start(graph)
            self.now += timedelta(seconds=3)
            ticket = renew_review(graph, runtime, self.cfg)
            renewed = self.successor(graph, ticket)
            self.assertTrue(ticket.reuse_analysis)
            self.assertEqual(ticket.request.case_id, self.req.case_id)
            self.assertEqual(ticket.request.revision, 2)
            self.assertNotEqual(ticket.request.run_id, self.req.run_id)
            self.assertEqual(renewed["status"], "PENDING_REVIEW")
            self.assertEqual(renewed["model_calls"], 0)
            self.assertEqual(renewed["model_status"], "analysis_reused")
            self.assertEqual(original["proposal"]["candidate_hash"], renewed["proposal"]["candidate_hash"])
            self.assertFalse(graph.get_state(self.cfg).next)
            self.assertEqual(store.get_proposal_status(original["proposal"]["proposal_id"]), "EXPIRED")
            self.assertEqual(store.count("decision"), 0)
            self.assertEqual(store.count("action"), 0)
            d = store.record_test_decision(renewed["proposal"]["proposal_id"], "reject")
            result = graph.invoke(Command(resume=d.decision_id), config(ticket.request.run_id))
            self.assertEqual(result["status"], "REJECTED")

    def test_unused_approval_expiry_preserves_decision_and_needs_new_authority(self):
        with self.open() as (graph, runtime, store):
            state = self.start(graph)
            old = store.record_test_decision(state["proposal"]["proposal_id"], "approve_remediation")
            self.now += timedelta(seconds=4)
            ticket = renew_review(graph, runtime, self.cfg)
            self.assertEqual(store.get_decision(old.decision_id), old)
            renewed = self.successor(graph, ticket)
            rejected = graph.invoke(Command(resume=old.decision_id), config(ticket.request.run_id))
            self.assertEqual(rejected["status"], "STALE")
            self.assertEqual(store.count("action"), 0)
            self.assertEqual(store.count("decision"), 1)

    def test_context_request_creates_one_successor_and_reanalyzes(self):
        with self.open() as (graph, runtime, store):
            state = self.start(graph)
            pid = state["proposal"]["proposal_id"]
            d = store.record_test_decision(pid, "request_context")
            result = graph.invoke(Command(resume=d.decision_id), self.cfg)
            self.assertEqual(result["status"], "STALE")
            ticket = store.get_revision(result["revision_request"]["revision_request_id"])
            self.assertFalse(ticket.reuse_analysis)
            self.assertEqual(store.get_proposal_status(pid), "SUPERSEDED")
            self.assertEqual(store.count("revision"), 1)
            self.assertEqual(store.request_revision(ticket), ticket)
            renewed = self.successor(graph, ticket)
            self.assertEqual(renewed["model_calls"], 2)
            self.assertEqual(renewed["status"], "PENDING_REVIEW")
            self.assertEqual(store.count("action"), 0)

    def test_material_context_change_uses_fresh_model_stages(self):
        with self.open() as (graph, runtime, store):
            self.start(graph)
            self.now += timedelta(seconds=3)
            runtime.evidence.evidence.context.optional_documents = ["The workload was reviewed after an operational change."]
            ticket = renew_review(graph, runtime, self.cfg)
            self.assertFalse(ticket.reuse_analysis)
            renewed = self.successor(graph, ticket)
            self.assertEqual(renewed["model_calls"], 2)
            self.assertEqual(renewed["status"], "PENDING_REVIEW")

    def test_context_answer_can_arrive_after_revision_is_recorded(self):
        with self.open() as (graph, runtime, store):
            state = self.start(graph)
            d = store.record_test_decision(state["proposal"]["proposal_id"], "request_context")
            original_current = runtime.evidence.current

            def unavailable(req):
                raise RuntimeError("the requested context is not available yet")

            runtime.evidence.current = unavailable
            closed = graph.invoke(Command(resume=d.decision_id), self.cfg)
            ticket = store.get_revision(closed["revision_request"]["revision_request_id"])
            runtime.evidence.current = original_current
            runtime.evidence.evidence.snapshot_id = "snapshot-with-context-answer"
            runtime.evidence.evidence.context.optional_documents = ["An owner answered the requested operational question."]
            successor = self.successor(graph, ticket)
            self.assertEqual(successor["status"], "PENDING_REVIEW")
            self.assertEqual(successor["request"]["snapshot_id"], "snapshot-with-context-answer")
            self.assertEqual(successor["model_calls"], 2)
            self.assertEqual(store.count("action"), 0)
            self.assertEqual(store.get_revision(ticket.revision_request_id), ticket)

    def test_new_candidate_use_prevents_reusing_the_old_removal(self):
        with self.open() as (graph, runtime, store):
            self.start(graph)
            self.now += timedelta(seconds=3)
            data = runtime.evidence.evidence.model_dump(mode="json")
            bucket = data["usage"]["series"][-1]["buckets"][0]
            bucket["counts"]["successful_completed"] = 1
            bucket["first_request_at"] = bucket["last_request_at"] = bucket["interval"]["start"]
            bucket["evidence_refs"] = ["new-secret-use"]
            runtime.evidence.evidence = EvidenceBundle.model_validate(data)
            ticket = renew_review(graph, runtime, self.cfg)
            self.assertFalse(ticket.reuse_analysis)
            renewed = self.successor(graph, ticket)
            self.assertEqual(renewed["status"], "NO_CHANGE")
            self.assertIsNone(renewed["proposal"])
            self.assertEqual(store.count("action"), 0)

    def test_fresh_summary_for_retained_use_can_reuse_supported_analysis(self):
        with self.open() as (graph, runtime, store):
            state = self.start(graph)
            self.now += timedelta(seconds=3)
            data = runtime.evidence.evidence.model_dump(mode="json")
            data["snapshot_id"] = "refreshed-snapshot"
            data["revision"] += 1
            data["context"]["collected_at"] = self.now.isoformat()
            data["usage"]["generated_at"] = self.now.isoformat()
            data["usage"]["revision"] += 1
            data["usage"]["series"][0]["buckets"][0]["counts"]["successful_completed"] += 5
            runtime.evidence.evidence = EvidenceBundle.model_validate(data)
            ticket = renew_review(graph, runtime, self.cfg)
            self.assertTrue(ticket.reuse_analysis)
            renewed = self.successor(graph, ticket)
            self.assertEqual(renewed["model_calls"], 0)
            self.assertEqual(renewed["proposal"]["candidate_hash"], state["proposal"]["candidate_hash"])
            self.assertNotEqual(renewed["proposal"]["evidence_hash"], state["proposal"]["evidence_hash"])
            self.assertNotEqual(renewed["proposal"]["approval_hash"], state["proposal"]["approval_hash"])

    def test_renewal_is_idempotent_across_restart(self):
        with self.open() as (graph, runtime, store):
            self.start(graph)
            self.now += timedelta(seconds=3)
            ticket = renew_review(graph, runtime, self.cfg)
        with self.open() as (graph, runtime, store):
            repeated = renew_review(graph, runtime, self.cfg)
            self.assertEqual(repeated, ticket)
            self.assertEqual(store.count("revision"), 1)
            self.assertEqual(store.count("proposal"), 1)
            renewed = self.successor(graph, ticket)
            self.assertEqual(renewed["model_calls"], 0)

    def test_valid_review_and_already_started_action_cannot_be_renewed(self):
        with self.open() as (graph, runtime, store):
            state = self.start(graph)
            with self.assertRaisesRegex(ValueError, "review_has_not_expired"):
                renew_review(graph, runtime, self.cfg)
            d = store.record_test_decision(state["proposal"]["proposal_id"], "approve_remediation")
            self.now += timedelta(seconds=2)
            with self.assertRaisesRegex(ValueError, "approval_has_not_expired"):
                renew_review(graph, runtime, self.cfg)
            graph.invoke(Command(resume=d.decision_id), self.cfg)
            self.now += timedelta(seconds=4)
            with self.assertRaisesRegex(ValueError, "run_is_not_an_unused_review"):
                renew_review(graph, runtime, self.cfg)
            self.assertEqual(store.count("revision"), 0)
            self.assertEqual(store.count("action"), 1)

    def test_successor_rejects_unrecorded_revision_or_changed_evidence(self):
        with self.open() as (graph, runtime, store):
            self.start(graph)
            self.now += timedelta(seconds=3)
            ticket = renew_review(graph, runtime, self.cfg)
            runtime.evidence.evidence.context.conflicts = ["new-context-conflict"]
            state = self.successor(graph, ticket)
            self.assertEqual(state["status"], "BLOCKED")
            self.assertEqual(state["model_calls"], 0)
            self.assertIsNone(state["proposal"])
            self.assertEqual(store.count("action"), 0)

    def test_gap_report_has_readiness_and_never_waits_for_execution_review(self):
        gap = demo_evidence("coverage-gap", now=NOW)
        with tempfile.TemporaryDirectory() as directory:
            with open_runner(directory, evidence=gap, clock=lambda: NOW) as (graph, runtime, store):
                req = self.req.model_copy(update={"snapshot_id": gap.snapshot_id})
                state = graph.invoke({"request": req.model_dump(mode="json")}, self.cfg)
                self.assertEqual(state["status"], "BLOCKED")
                self.assertFalse(state["readiness"]["execution_ready"])
                self.assertFalse(graph.get_state(self.cfg).next)
                self.assertEqual(store.get_report(req.run_id)["status"], "BLOCKED")
                self.assertEqual(store.count("proposal"), 0)
                self.assertEqual(store.count("action"), 0)

    def test_committed_context_revision_recovers_after_worker_crash(self):
        with self.open() as (graph, runtime, store):
            state = self.start(graph)
            d = store.record_test_decision(state["proposal"]["proposal_id"], "request_context")
            record = store.request_revision

            def crash_after_commit(ticket):
                record(ticket)
                raise KeyboardInterrupt("worker stopped after revision commit")

            store.request_revision = crash_after_commit
            with self.assertRaises(KeyboardInterrupt):
                graph.invoke(Command(resume=d.decision_id), self.cfg)
            ticket = store.get_successor(state["proposal"]["proposal_id"])
            self.assertIsNotNone(ticket)
        with self.open() as (graph, runtime, store):
            def unavailable(req):
                raise RuntimeError("must use the already committed revision")

            runtime.evidence.current = unavailable
            recovered = graph.invoke(None, self.cfg)
            self.assertEqual(recovered["status"], "STALE")
            self.assertEqual(recovered["revision_request"]["revision_request_id"], ticket.revision_request_id)
            self.assertEqual(store.count("revision"), 1)
            self.assertEqual(runtime.model.calls, [])
            self.assertEqual(store.count("action"), 0)

    def test_successor_driver_recovers_interrupted_inference_without_reinitializing(self):
        class CrashingModel(ScriptedModelClient):
            def generate(self, stage, payload, schema):
                raise KeyboardInterrupt("inference worker stopped")

        with self.open() as (graph, runtime, store):
            state = self.start(graph)
            d = store.record_test_decision(state["proposal"]["proposal_id"], "request_context")
            state = graph.invoke(Command(resume=d.decision_id), self.cfg)
            ticket = store.get_revision(state["revision_request"]["revision_request_id"])
        with open_runner(self.temp.name, evidence=self.evidence, model=CrashingModel(), clock=lambda: self.now) as (graph, runtime, store):
            with self.assertRaises(KeyboardInterrupt):
                start_successor(graph, ticket)
            self.assertEqual(store.model_call_count(ticket.request.run_id), 1)
        with self.open() as (graph, runtime, store):
            state = start_successor(graph, ticket)
            self.assertEqual(state["status"], "PENDING_REVIEW")
            self.assertEqual(state["model_calls"], 3)
            repeated = start_successor(graph, ticket)
            self.assertEqual(repeated["model_calls"], 3)
            self.assertEqual(len(runtime.model.calls), 2)
            self.assertEqual(store.count("action"), 0)

    def test_existing_compatible_run_cannot_be_reinitialized(self):
        with self.open() as (graph, runtime, store):
            self.start(graph)
            with self.assertRaisesRegex(ValueError, "run_already_started"):
                self.start(graph)
            self.assertEqual(store.model_call_count(self.req.run_id), 2)
            self.assertEqual(store.count("proposal"), 1)

    def test_expired_projection_cannot_be_reopened_by_replay(self):
        with self.open() as (graph, runtime, store):
            state = self.start(graph)
            pid = state["proposal"]["proposal_id"]
            self.now += timedelta(seconds=3)
            renew_review(graph, runtime, self.cfg)
            projected = store.project_proposal(pid, "APPROVED", None)
            self.assertEqual(projected["status"], "EXPIRED")
            with self.assertRaisesRegex(ValueError, "ready simulated proposal"):
                store.record_test_decision(pid, "approve_remediation")

    def test_late_count_corrections_require_fresh_analysis(self):
        with self.open() as (graph, runtime, store):
            self.start(graph)
            self.now += timedelta(seconds=3)
            data = runtime.evidence.evidence.model_dump(mode="json")
            data["usage"]["series"][0]["buckets"][0]["counts"]["successful_completed"] -= 1
            runtime.evidence.evidence = EvidenceBundle.model_validate(data)
            ticket = renew_review(graph, runtime, self.cfg)
            self.assertFalse(ticket.reuse_analysis)


class RevisionProcessTests(unittest.TestCase):
    def test_fresh_process_context_revision_preserves_history(self):
        with tempfile.TemporaryDirectory() as directory:
            base = [sys.executable, "-m", "agents.guardian.runner", "--directory", directory]
            subprocess.run(base + ["start"], check=True, capture_output=True, text=True)
            source = json.loads((Path(directory) / "run.json").read_text())
            d = json.loads(subprocess.run(base + ["decide", "request_context"], check=True, capture_output=True, text=True).stdout)
            resumed = json.loads(subprocess.run(base + ["resume", "--decision-id", d["decision_id"]], check=True, capture_output=True, text=True).stdout)
            self.assertEqual(resumed["status"], "STALE")
            successor = json.loads(subprocess.run(base + ["next"], check=True, capture_output=True, text=True).stdout)
            self.assertEqual(successor["status"], "PENDING_REVIEW")
            self.assertEqual(successor["revision"], 2)
            self.assertEqual(successor["model_calls"], 2)
            self.assertEqual(successor["execution_requests"], 0)
            current = json.loads((Path(directory) / "run.json").read_text())
            self.assertNotEqual(source["run_id"], current["run_id"])
            self.assertEqual(current["model_config"]["provider"], "scripted")
            histories = [json.loads(p.read_text()) for p in (Path(directory) / "runs").glob("*/result.json")]
            self.assertEqual({h["run_id"] for h in histories}, {source["run_id"], current["run_id"]})
            self.assertEqual({h["status"] for h in histories}, {"STALE", "PENDING_REVIEW"})

    def test_missing_real_provider_configuration_cannot_fall_back_to_scripted(self):
        with tempfile.TemporaryDirectory() as directory:
            base = [sys.executable, "-m", "agents.guardian.runner", "--directory", directory]
            subprocess.run(base + ["start"], check=True, capture_output=True, text=True)
            manifest = Path(directory) / "run.json"
            run = json.loads(manifest.read_text())
            run.update(producer="llama-cpp")
            run.pop("model_config")
            manifest.write_text(json.dumps(run))
            result = subprocess.run(base + ["next"], capture_output=True, text=True)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("cannot substitute scripted inference", result.stderr)


if __name__ == "__main__":
    unittest.main()
