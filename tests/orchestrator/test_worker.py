"""Worker delivery, backpressure, restart and process handoff checks."""

import json
import subprocess
import sys
import tempfile
import unittest
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from queue import Full

from agents.guardian.adapters.models import ScriptedModelClient
from agents.guardian.contracts import AnalysisRequest
from agents.guardian.fixtures import demo_evidence
from agents.guardian.runner import config, open_runner
from agents.guardian.work import WorkItem
from agents.guardian.worker import RecordingWorkQueue, local_session, process_work, run_worker

NOW = datetime(2026, 10, 23, 12, 0, 20, tzinfo=timezone.utc)


class WorkerTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.e = demo_evidence(now=NOW)
        self.req = AnalysisRequest(case_id="worker-case", run_id="worker-run", snapshot_id=self.e.snapshot_id,
                                   cluster_id=self.e.target.cluster_id, target_uid=self.e.target.uid)
        self.item = WorkItem(work_id="work-initial", run_id=self.req.run_id, kind="analyze", request=self.req)

    def tearDown(self):
        self.temp.cleanup()

    def open(self, model=None):
        return open_runner(self.temp.name, evidence=self.e, model=model, clock=lambda: NOW)

    def test_duplicate_analysis_and_resume_deliveries_do_not_repeat_inference(self):
        with self.open() as (graph, runtime, store):
            first = process_work(graph, runtime, self.item)
            duplicate = process_work(graph, runtime, self.item)
            self.assertTrue(first.waiting_for_review)
            self.assertEqual(duplicate.model_calls, 2)
            self.assertEqual(len(runtime.model.calls), 2)
            state = graph.get_state(config(self.req.run_id)).values
            d = store.record_test_decision(state["proposal"]["proposal_id"], "reject")
            item = WorkItem(work_id="work-decision", run_id=self.req.run_id, kind="resume", decision_id=d.decision_id)
            self.assertEqual(process_work(graph, runtime, item).status, "REJECTED")
            self.assertEqual(process_work(graph, runtime, item).status, "REJECTED")
            self.assertEqual(len(runtime.model.calls), 2)
            self.assertEqual(store.count("action"), 0)

    def test_queue_capacity_and_waiting_release_the_session(self):
        queue = RecordingWorkQueue(limit=1)
        queue.submit(self.item)
        with self.assertRaises(Full):
            queue.submit(self.item)
        lifecycle = []

        @contextmanager
        def factory(item):
            lifecycle.append("open")
            with self.open() as session:
                yield session
            lifecycle.append("closed")

        results = run_worker(queue, factory)
        self.assertEqual(lifecycle, ["open", "closed"])
        self.assertTrue(results[0].waiting_for_review)
        self.assertEqual(queue.pending.qsize(), 0)
        queue.submit(self.item)
        repeated = run_worker(queue, factory)
        self.assertEqual(repeated[0].model_calls, 2)

    def test_worker_consumes_only_the_recorded_successor_run(self):
        with self.open() as (graph, runtime, store):
            process_work(graph, runtime, self.item)
            state = graph.get_state(config(self.req.run_id)).values
            d = store.record_test_decision(state["proposal"]["proposal_id"], "request_context")
            process_work(graph, runtime, WorkItem(work_id="context", run_id=self.req.run_id,
                                                 kind="resume", decision_id=d.decision_id))
            ticket = store.get_successor(state["proposal"]["proposal_id"])
            wrong = WorkItem(work_id="wrong-run", run_id=self.req.run_id, kind="revision",
                             revision_request_id=ticket.revision_request_id)
            with self.assertRaisesRegex(ValueError, "revision_delivery_scope_mismatch"):
                process_work(graph, runtime, wrong)
            item = WorkItem(work_id="new-run", run_id=ticket.request.run_id, kind="revision",
                            revision_request_id=ticket.revision_request_id)
            outcome = process_work(graph, runtime, item)
            self.assertTrue(outcome.waiting_for_review)
            self.assertEqual(outcome.model_calls, 2)
            self.assertEqual(store.count("action"), 0)

    def test_worker_replays_a_crashed_analysis_from_its_checkpoint(self):
        class Crash(ScriptedModelClient):
            def generate(self, *args):
                raise KeyboardInterrupt("worker stopped")
        with self.open(Crash()) as (graph, runtime, store):
            with self.assertRaises(KeyboardInterrupt):
                process_work(graph, runtime, self.item)
        with self.open() as (graph, runtime, store):
            outcome = process_work(graph, runtime, self.item)
            self.assertEqual(outcome.status, "PENDING_REVIEW")
            self.assertEqual(outcome.model_calls, 3)
            self.assertEqual(store.count("action"), 0)

    def test_conflicting_intake_and_forged_resume_do_not_authorize(self):
        with self.open() as (graph, runtime, store):
            process_work(graph, runtime, self.item)
            bad = WorkItem(work_id="conflict", run_id=self.req.run_id, kind="analyze",
                           request=self.req.model_copy(update={"case_id": "different-case"}))
            with self.assertRaisesRegex(ValueError, "conflicting_analysis_delivery"):
                process_work(graph, runtime, bad)
            forged = WorkItem(work_id="forged", run_id=self.req.run_id, kind="resume", decision_id="invented")
            self.assertEqual(process_work(graph, runtime, forged).status, "STALE")
            self.assertEqual(store.count("action"), 0)

    def test_failed_delivery_records_only_stable_error_code(self):
        queue = RecordingWorkQueue()
        queue.submit(self.item)
        @contextmanager
        def unavailable(item):
            raise RuntimeError("credential=must-not-leak")
            yield
        self.assertEqual(run_worker(queue, unavailable), [])
        self.assertEqual(list(queue.failed), [{"work_id": self.item.work_id, "error_code": "RuntimeError"}])

    def test_local_worker_session_excludes_another_local_worker(self):
        directory = Path(self.temp.name)
        (directory / "evidence.json").write_text(self.e.model_dump_json())
        with local_session(directory, {"provider": "scripted"}):
            with self.assertRaisesRegex(ValueError, "worker_directory_busy"):
                with local_session(directory, {"provider": "scripted"}):
                    self.fail("a second session must not enter")

    def test_separate_worker_process_and_decision_process_share_review(self):
        directory = Path(self.temp.name)
        evidence = demo_evidence()
        req = self.req.model_copy(update={"snapshot_id": evidence.snapshot_id})
        item = self.item.model_copy(update={"request": req})
        (directory / "evidence.json").write_text(evidence.model_dump_json())
        work_file = directory / "work.json"
        work_file.write_text(item.model_dump_json())
        base = [sys.executable, "-m", "agents.guardian.worker", "--directory", str(directory), "--item", str(work_file)]
        first = json.loads(subprocess.run(base, check=True, capture_output=True, text=True).stdout)
        self.assertEqual(first["outcomes"][0]["status"], "PENDING_REVIEW")
        decide = [sys.executable, "-m", "agents.guardian.runner", "--directory", str(directory), "decide", "reject"]
        d = json.loads(subprocess.run(decide, check=True, capture_output=True, text=True).stdout)
        work_file.write_text(WorkItem(work_id="resume-work", run_id=self.req.run_id, kind="resume", decision_id=d["decision_id"]).model_dump_json())
        resumed = json.loads(subprocess.run(base, check=True, capture_output=True, text=True).stdout)
        self.assertEqual(resumed["outcomes"][0]["status"], "REJECTED")
        self.assertEqual(resumed["outcomes"][0]["model_calls"], 2)


if __name__ == "__main__":
    unittest.main()
