"""Scoped evidence, durable lookup reservations and stage-wide repair limits."""

import tempfile
import unittest
from datetime import datetime, timezone

from agents.guardian.adapters.models import ScriptedModelClient
from agents.guardian.contracts import AnalysisRequest, ContextLookup
from agents.guardian.evidence_tools import FailureRecord, ToolResult, allowed_lookups, validate_lookup
from agents.guardian.fixtures import demo_evidence
from agents.guardian.policy import build_facts, canonical_hash, operation_id, render
from agents.guardian.runner import config, open_runner

NOW = datetime(2026, 10, 23, 12, 0, 20, tzinfo=timezone.utc)


class LookupModel(ScriptedModelClient):
    def __init__(self, tool="get_workload_context", repeat=False):
        super().__init__()
        self.tool = tool
        self.repeat = repeat

    def generate(self, stage, payload, schema):
        output = super().generate(stage, payload, schema)
        if stage == "investigator" and (payload["remaining_lookup_rounds"] == 2 or self.repeat):
            output["context_requests"] = [next(r for r in payload["allowed_lookups"] if r["tool"] == self.tool)]
        return output


class EvidenceToolTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.e = demo_evidence(now=NOW)
        self.req = AnalysisRequest(case_id="tool-case", run_id="tool-run", snapshot_id=self.e.snapshot_id,
                                   cluster_id=self.e.target.cluster_id, target_uid=self.e.target.uid)
        self.cfg = config(self.req.run_id)

    def tearDown(self):
        self.temp.cleanup()

    def open(self, model=None):
        return open_runner(self.temp.name, evidence=self.e, model=model, clock=lambda: NOW)

    def start(self, graph):
        return graph.invoke({"request": self.req.model_dump(mode="json")}, self.cfg)

    def test_all_six_tools_are_scoped_and_do_not_become_mutation_tools(self):
        facts, _ = build_facts(self.e, NOW)
        lookups = allowed_lookups(self.req, self.e, facts)
        self.assertEqual({r["tool"] for r in lookups}, {"get_case_snapshot", "get_workload_context", "get_usage_summary",
                                                        "get_binding_consumers", "get_failure_history", "check_access"})
        for raw in lookups:
            validate_lookup(ContextLookup.model_validate(raw), self.req, self.e, facts)
            for field, value in (("subject_id", "other-subject"), ("case_id", "other-case")):
                with self.assertRaises(ValueError):
                    validate_lookup(ContextLookup.model_validate({**raw, field: value}), self.req, self.e, facts)
        with self.assertRaises(ValueError):
            ContextLookup(tool="shell", subject_id=self.e.subject.username, command="kubectl patch")

    def test_scoped_reads_produce_valid_followup_without_manufacturing_usage(self):
        for tool in ("get_case_snapshot", "get_usage_summary", "get_binding_consumers", "get_failure_history", "check_access"):
            with self.subTest(tool=tool), tempfile.TemporaryDirectory() as directory:
                with open_runner(directory, evidence=self.e, model=LookupModel(tool), clock=lambda: NOW) as (graph, runtime, store):
                    state = self.start(graph)
                    self.assertEqual(state["status"], "PENDING_REVIEW")
                    self.assertEqual(state["lookup_calls"], 1)
                    self.assertEqual(state["evidence"]["usage"], self.e.usage.model_dump(mode="json"))
                    self.assertEqual(store.count("action"), 0)

    def test_lookup_cannot_change_grants_or_policy(self):
        with self.open(LookupModel()) as (graph, runtime, store):
            lookup = runtime.evidence.lookup
            def forged(req, tool, **kwargs):
                result = lookup(req, tool, **kwargs)
                result.evidence.target.resource_version = "forged-version"
                return result
            runtime.evidence.lookup = forged
            result = self.start(graph)
            self.assertEqual(result["status"], "BLOCKED")
            self.assertIn("lookup_changed_unrelated_evidence", result["reason"])
            self.assertEqual(store.count("action"), 0)

    def test_crashed_lookup_consumes_budget_without_blind_repeat(self):
        with self.open(LookupModel()) as (graph, runtime, store):
            def crash(*args, **kwargs):
                raise KeyboardInterrupt("source response lost")
            runtime.evidence.lookup = crash
            with self.assertRaises(KeyboardInterrupt):
                self.start(graph)
        with self.open(LookupModel()) as (graph, runtime, store):
            result = graph.invoke(None, self.cfg)
            self.assertEqual(result["status"], "BLOCKED")
            self.assertIn("lookup_outcome_uncertain_after_restart", result["reason"])
            self.assertEqual(result["lookup_calls"], 1)
            self.assertEqual(runtime.evidence.context_fetches, 0)

    def test_committed_lookup_result_is_reused_after_checkpoint_crash(self):
        with self.open(LookupModel()) as (graph, runtime, store):
            complete = store.complete_lookup
            def crash(*args):
                complete(*args)
                raise KeyboardInterrupt("checkpoint not written")
            store.complete_lookup = crash
            with self.assertRaises(KeyboardInterrupt):
                self.start(graph)
        with self.open(LookupModel()) as (graph, runtime, store):
            result = graph.invoke(None, self.cfg)
            self.assertEqual(result["status"], "PENDING_REVIEW")
            self.assertEqual(result["lookup_calls"], 1)
            self.assertEqual(runtime.evidence.context_fetches, 0)

    def test_unresolved_lookups_at_budget_exhaustion_cannot_enter_review(self):
        with self.open(LookupModel(repeat=True)) as (graph, runtime, store):
            result = self.start(graph)
            self.assertEqual(result["status"], "BLOCKED")
            self.assertEqual(result["reason"], "lookup_budget_exhausted")
            self.assertEqual(result["lookup_rounds"], 2)
            self.assertEqual(store.count("proposal"), 0)

    def test_crashed_repair_does_not_receive_another_repair_after_restart(self):
        class CrashingRepair(ScriptedModelClient):
            def __init__(self):
                super().__init__()
                self.count = 0
            def generate(self, *args):
                self.count += 1
                if self.count == 1:
                    return {"invalid": "requires repair"}
                raise KeyboardInterrupt("repair response lost")
        with self.open(CrashingRepair()) as (graph, runtime, store):
            with self.assertRaises(KeyboardInterrupt):
                self.start(graph)
            self.assertEqual(store.model_repair_count(self.req.run_id, "investigator"), 1)
        with self.open() as (graph, runtime, store):
            result = graph.invoke(None, self.cfg)
            self.assertEqual(result["status"], "BLOCKED")
            self.assertEqual(result["model_calls"], 2)
            self.assertEqual(result["reason"], "stage_repair_budget_exhausted")
            self.assertEqual(runtime.model.calls, [])

    def test_backend_failure_record_blocks_only_its_exact_candidate_context(self):
        removed = {operation_id("", "secrets", "get", "guardian-demo")}
        rules = render(self.e, removed)["result_rules"]
        candidate = canonical_hash({"target_uid": self.e.target.uid, "namespace": self.e.target.namespace,
                                    "strategy": "narrow_dedicated_role", "rules": rules})
        with self.open(LookupModel("get_failure_history")) as (graph, runtime, store):
            original = runtime.evidence.lookup
            def failure(req, tool, **kwargs):
                result = original(req, tool, **kwargs)
                result.failures = [FailureRecord(target_uid=self.e.target.uid, candidate_hash=candidate,
                    workload_uid=self.e.context.workload_uid, image_digest=self.e.context.image_digest,
                    policy_version=self.e.policy.policy_version, blocks_candidate=True, evidence_refs=["failure-fixture"])]
                return result
            runtime.evidence.lookup = failure
            state = self.start(graph)
            self.assertEqual(state["status"], "BLOCKED")
            self.assertFalse(state["readiness"]["execution_ready"])
            self.assertIn("prior_candidate_failure", [r for g in state["proposal"]["gates"] for r in g["reasons"]])
            self.assertEqual(store.count("action"), 0)


if __name__ == "__main__":
    unittest.main()
