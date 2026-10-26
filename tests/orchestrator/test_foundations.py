"""Contract rejection and restart tests for the v4 phase-1 foundation slice."""

import json
import subprocess
import sys
import tempfile
import unittest
from copy import deepcopy
from datetime import datetime, timezone
from pathlib import Path

from langgraph.types import Command
from pydantic import ValidationError

from agents.guardian.adapters.models import ScriptedModelClient
from agents.guardian.contracts import (AnalysisReport, AnalysisRequest, EvidenceBundle,
                                      ReadinessAssessment, Target)
from agents.guardian.fixtures import demo_evidence
from agents.guardian.graph import report
from agents.guardian.lifecycle import BaselineStatus, ProposalStatus, RunStatus
from agents.guardian.runner import config, open_runner
from agents.guardian.schemas import SCHEMA_MODELS, export_schemas
from agents.guardian.versions import IncompatibleRunError, current_versions, require_compatible_state

NOW = datetime(2026, 10, 21, 12, 0, 20, tzinfo=timezone.utc)


def request(evidence):
    return AnalysisRequest(case_id="foundation-case", run_id="foundation-run",
                           snapshot_id=evidence.snapshot_id, cluster_id=evidence.target.cluster_id,
                           target_uid=evidence.target.uid, baseline_id=evidence.baseline_id,
                           policy_version=evidence.policy.policy_version)


class FoundationTests(unittest.TestCase):
    def setUp(self):
        self.evidence = demo_evidence(now=NOW)
        self.req = request(self.evidence)
        self.temp = tempfile.TemporaryDirectory()
        self.directory = Path(self.temp.name)
        self.cfg = config(self.req.run_id)

    def tearDown(self):
        self.temp.cleanup()

    def open(self, model=None):
        return open_runner(self.directory, evidence=self.evidence, model=model, clock=lambda: NOW)

    def start(self, graph):
        return graph.invoke({"request": self.req.model_dump(mode="json")}, self.cfg)

    def test_report_roundtrip_readiness_and_version_stamp(self):
        with self.open() as (graph, runtime, store):
            state = self.start(graph)
            expected = current_versions(self.evidence.policy.policy_version)
            self.assertEqual(require_compatible_state(state), expected)
            output = AnalysisReport.model_validate(report(state, runtime))
            self.assertEqual(AnalysisReport.model_validate_json(output.model_dump_json()), output)
            self.assertEqual(output.status, RunStatus.PENDING_REVIEW)
            self.assertTrue(output.readiness.execution_ready)
            self.assertTrue(set(state["proposal"]["removed_permission_ids"]) <= set(output.readiness.allowed_removal_ids))
            self.assertTrue(output.readiness.protected_permission_ids)
            self.assertEqual(store.get("report", state["proposal"]["proposal_id"])["versions"], expected.model_dump())
            self.assertEqual(store.count("action"), 0)

    def test_mismatched_adapter_evidence_blocks_before_model(self):
        # This adapter deliberately omits all producer-side scope checks. The
        # graph consumer must independently reject each changed binding field.
        for field in ["snapshot", "cluster", "uid", "baseline", "policy", "captured", "schema"]:
            with self.subTest(field=field), tempfile.TemporaryDirectory() as directory:
                data = self.evidence.model_dump(mode="json")
                if field == "snapshot":
                    data["snapshot_id"] = "other-snapshot"
                elif field == "cluster":
                    data["target"]["cluster_id"] = data["usage"]["cluster_id"] = "other-cluster"
                elif field == "uid":
                    data["target"]["uid"] = "recreated-role"
                elif field == "baseline":
                    data["baseline_id"] = "unrequested-baseline"
                elif field == "policy":
                    data["policy"]["policy_version"] = "other-policy"
                elif field == "captured":
                    data["source_mode"] = "captured"
                else:
                    data["schema_version"] = "guardian.evidence.v99"

                class UncheckedAdapter:
                    def load(self, req):
                        return data

                client = ScriptedModelClient()
                with open_runner(directory, evidence=self.evidence, model=client, clock=lambda: NOW) as (graph, runtime, store):
                    runtime.evidence = UncheckedAdapter()
                    state = self.start(graph)
                    self.assertEqual(state["status"], "BLOCKED")
                    self.assertIn("invalid_evidence", state["reason"])
                    self.assertEqual(client.calls, [])
                    self.assertEqual(store.count("proposal"), 0)
                    self.assertEqual(store.count("action"), 0)
                    self.assertEqual(store.count("outcome"), 1)

    def test_incompatible_checkpoint_cannot_resume_directly_after_restart(self):
        for field in [None, "graph_version", "state_version", "validator_version",
                      "canonicalization_version", "policy_version"]:
            with self.subTest(field=field), tempfile.TemporaryDirectory() as directory:
                with open_runner(directory, evidence=self.evidence, clock=lambda: NOW) as (graph, runtime, store):
                    state = self.start(graph)
                    decision = store.record_test_decision(state["proposal"]["proposal_id"], "approve_remediation")
                    bad = deepcopy(state["versions"])
                    if field is None:
                        bad = None  # A checkpoint from the old unstamped demo.
                    else:
                        bad[field] = "unsupported-version"
                    graph.update_state(self.cfg, {"versions": bad})
                client = ScriptedModelClient()
                with open_runner(directory, evidence=self.evidence, model=client, clock=lambda: NOW) as (graph, runtime, store):
                    with self.assertRaisesRegex(IncompatibleRunError, "incompatible_saved_run"):
                        graph.invoke(Command(resume=decision.decision_id), self.cfg)
                    self.assertEqual(client.calls, [])
                    self.assertEqual(store.count("action"), 0)
                    self.assertEqual(store.count("outcome"), 0)
                    self.assertEqual(store.count("proposal"), 1)

    def test_full_input_cannot_restamp_an_incompatible_saved_run(self):
        with self.open() as (graph, runtime, store):
            self.start(graph)
            graph.update_state(self.cfg, {"versions": None}, as_node="__start__")
            with self.assertRaises(IncompatibleRunError):
                self.start(graph)
            self.assertEqual(store.model_call_count(self.req.run_id), 2)
            self.assertEqual(store.count("action"), 0)

    def test_mismatched_checkpoint_thread_is_rejected(self):
        with self.open() as (graph, runtime, store):
            with self.assertRaisesRegex(ValueError, "run_id must equal checkpoint thread_id"):
                graph.invoke({"request": self.req.model_dump(mode="json")}, config("different-run"))
            self.assertEqual(store.model_call_count(self.req.run_id), 0)
            self.assertEqual(store.count("action"), 0)

    def test_crash_before_evidence_load_cannot_skip_compatibility(self):
        class CrashingAdapter:
            def load(self, req):
                raise KeyboardInterrupt("worker stopped before evidence was loaded")

        with self.open() as (graph, runtime, store):
            runtime.evidence = CrashingAdapter()
            with self.assertRaises(KeyboardInterrupt):
                self.start(graph)
            graph.update_state(self.cfg, {"versions": None}, as_node="accept_case")
        with self.open() as (graph, runtime, store):
            with self.assertRaises(IncompatibleRunError):
                graph.invoke(None, self.cfg)
            self.assertEqual(store.model_call_count(self.req.run_id), 0)
            self.assertEqual(store.count("proposal"), 0)

    def test_cli_preserves_legacy_review_and_refuses_a_new_decision(self):
        with self.open() as (graph, runtime, store):
            self.start(graph)
            graph.update_state(self.cfg, {"versions": None})
        (self.directory / "evidence.json").write_text(self.evidence.model_dump_json())
        (self.directory / "run.json").write_text(json.dumps({"run_id": self.req.run_id, "producer": "scripted-test"}))
        base = [sys.executable, "-m", "agents.guardian.runner", "--directory", str(self.directory)]
        status = subprocess.run(base + ["status"], capture_output=True, text=True, check=True)
        self.assertFalse(json.loads(status.stdout)["compatible"])
        decision = subprocess.run(base + ["decide", "approve_remediation"], capture_output=True, text=True)
        self.assertNotEqual(decision.returncode, 0)
        self.assertIn("incompatible_saved_run", decision.stderr)
        with self.open() as (graph, runtime, store):
            self.assertEqual(store.count("decision"), 0)
            self.assertEqual(store.count("action"), 0)
            self.assertEqual(store.count("proposal"), 1)

    def test_unknown_gate_or_protected_id_cannot_claim_readiness(self):
        valid = {"policy_version": "policy-v1", "evidence_revision": 1,
                 "gates": [{"gate_id": "coverage", "result": "pass", "reasons": []}],
                 "allowed_removal_ids": ["permission-1"], "protected_permission_ids": [],
                 "residual_uncertainties": [], "execution_ready": True}
        self.assertTrue(ReadinessAssessment.model_validate(valid).execution_ready)
        for mutation in [lambda d: d["gates"][0].update(result="unknown", reasons=["coverage_gap"]),
                         lambda d: d["gates"].append(deepcopy(d["gates"][0])),
                         lambda d: d.update(protected_permission_ids=["permission-1"]),
                         lambda d: d.update(allowed_removal_ids=[]),
                         lambda d: d.update(execution_ready="true"),
                         lambda d: d.update(proven_safe=True)]:
            data = deepcopy(valid)
            mutation(data)
            with self.assertRaises(ValidationError):
                ReadinessAssessment.model_validate(data)

    def test_target_scope_cannot_be_contradictory(self):
        for kind, namespace in [("Role", None), ("ClusterRole", "guardian-demo")]:
            data = self.evidence.target.model_dump()
            data.update(kind=kind, namespace=namespace)
            with self.assertRaises(ValidationError):
                Target.model_validate(data)

    def test_request_and_report_reject_unsupported_wire_versions(self):
        data = self.req.model_dump()
        data["schema_version"] = "guardian.analysis-request.v1"
        with self.assertRaises(ValidationError):
            AnalysisRequest.model_validate(data)
        with self.open() as (graph, runtime, store):
            state = self.start(graph)
            output = report(state, runtime)
            output["schema_version"] = "guardian.report.v1"
            with self.assertRaises(ValidationError):
                AnalysisReport.model_validate(output)

    def test_exported_contracts_match_manifest_and_lifecycle_boundaries(self):
        manifest = json.loads((Path(__file__).resolve().parents[2] / "contracts/compatibility.json").read_text())
        declared = {c["name"]: c["schema_id"] for c in manifest["contracts"]}
        self.assertEqual(declared, {name: schema_id for name, (schema_id, model) in SCHEMA_MODELS.items()})
        self.assertEqual(manifest["runtime_versions"], {k: v for k, v in current_versions("policy").model_dump().items()
                                                       if k != "policy_version"})
        schemas = export_schemas()
        self.assertEqual(set(schemas), set(declared))
        for name, schema in schemas.items():
            self.assertEqual(schema["$id"], f"urn:{declared[name]}")
            self.assertFalse(schema["additionalProperties"])
        self.assertIn("VALIDATED", ProposalStatus.__members__)
        self.assertNotIn("COMPLETED", ProposalStatus.__members__)
        self.assertNotIn("ACTIVE", RunStatus.__members__)
        self.assertEqual(set(BaselineStatus.__members__),
                         {"ACTIVE", "SUPERSEDED", "PENDING_APPROVAL", "REJECTED", "BROKEN_ROLLBACK"})


if __name__ == "__main__":
    unittest.main()
