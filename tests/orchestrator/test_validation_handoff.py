"""Development evaluation and read-only compatibility with main's pod producer."""

import json
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import AsyncMock

from agents.guardian.adapters.pod_context import attach_pod_context
from agents.guardian.evaluate import evaluate_case, score_development
from agents.guardian.fixtures import demo_evidence
from agents.guardian.modeling import ModelConfig
from backend.app.services.pod_evidence import inventory_pod, pod_evidence
from backend.app.services.telemetry import Telemetry

NOW = datetime(2026, 10, 25, 0, 0, 20, tzinfo=timezone.utc)


class ProducerCompatibilityTests(unittest.IsolatedAsyncioTestCase):
    async def export(self, scenario="complete"):
        self.evidence = demo_evidence(scenario, now=NOW)
        pod = {"metadata": {"namespace": self.evidence.target.namespace, "name": "reader", "uid": "pod-uid"},
               "spec": {"serviceAccountName": self.evidence.subject.name, "containers": [
                   {"name": "app", "image": "reader:v1", "env": [{"name": "SECRET", "value": "do-not-export"}]}]}}
        redis = AsyncMock()
        redis.get.return_value = json.dumps({"observed_at": NOW.isoformat(), "pods": [inventory_pod(pod, {})]})
        service = Telemetry(redis)
        service.events = AsyncMock(return_value=[])
        return await pod_evidence(service, self.evidence.target.namespace, "reader")

    def attach(self, payload, **kwargs):
        return attach_pod_context(self.evidence, payload, cluster_id=self.evidence.target.cluster_id,
                                  pod_name="reader", pod_uid="pod-uid", now=NOW, **kwargs)

    async def test_actual_main_producer_adds_context_without_manufacturing_coverage(self):
        payload = await self.export()
        enriched = self.attach(payload)
        self.assertEqual(enriched.usage, self.evidence.usage)
        self.assertEqual(enriched.context.collected_at, self.evidence.context.collected_at)
        self.assertEqual(enriched.context.known_dependencies, self.evidence.context.known_dependencies)
        self.assertEqual(enriched.context.consumer_inventory_complete, self.evidence.context.consumer_inventory_complete)
        self.assertIn('"coverage": "unknown_for_permission_removal"', enriched.context.optional_documents[-1])
        self.assertNotIn("do-not-export", enriched.model_dump_json())
        self.assertIsNone(enriched.baseline_id)

    async def test_missing_usage_remains_missing_after_telemetry_enrichment(self):
        payload = await self.export("missing-usage")
        self.assertIsNone(self.attach(payload).usage)

    async def test_wrong_pod_uid_service_account_and_stale_snapshot_are_rejected(self):
        payload = await self.export()
        for field in ("uid", "service_account", "time"):
            changed = json.loads(json.dumps(payload))
            if field == "uid":
                changed["pods"][0]["identity"]["uid"] = "recreated"
            elif field == "service_account":
                changed["pods"][0]["identity"]["permissions"]["service_account"] = "another-identity"
            else:
                changed["inventory_observed_at"] = (NOW - timedelta(hours=1)).isoformat()
            with self.subTest(field=field), self.assertRaises(ValueError):
                self.attach(changed)

    async def test_arbitrary_export_fields_never_enter_model_context(self):
        payload = await self.export()
        payload["pods"][0]["events"] = [{"id": "event-one", "kind": "network", "secret": "do-not-copy", "body": "do-not-copy"}]
        document = self.attach(payload).context.optional_documents[-1]
        self.assertIn("event-one", document)
        self.assertNotIn("do-not-copy", document)
        payload["extra"] = "x" * 131073
        with self.assertRaisesRegex(ValueError, "export_too_large"):
            self.attach(payload)


class EvaluationTests(unittest.TestCase):
    def test_always_abstaining_output_fails_usefulness(self):
        score = score_development("complete", {"status": "NO_CHANGE", "proposal": None})
        self.assertFalse(score["passed"])
        self.assertFalse(score["useful_narrowing"])

    def test_development_labels_are_scored_after_runtime_and_not_sent_to_model(self):
        with tempfile.TemporaryDirectory() as temp:
            result = evaluate_case(Path(temp) / "case", demo_evidence(), ModelConfig().model_dump(mode="json"), "complete")
            self.assertTrue(result["scoring"]["passed"])
            self.assertEqual(result["execution_requests"], 0)
            report = json.loads(Path(result["report"]).read_text())
            model_inputs = [t["model_input"] for t in report["trace"] if t.get("model_input")]
            self.assertNotIn("expected_operations", json.dumps(model_inputs))
            self.assertNotIn("scoring", json.dumps(model_inputs))
            self.assertEqual([r["stage"] for r in result["stages"]], ["investigator", "planner"])

    def test_captured_exports_are_unscored_previews_and_cannot_use_local_approval(self):
        with tempfile.TemporaryDirectory() as temp:
            evidence = demo_evidence().model_copy(update={"source_mode": "captured"})
            result = evaluate_case(Path(temp) / "case", evidence, ModelConfig().model_dump(mode="json"))
            self.assertIsNone(result["scoring"])
            self.assertEqual(result["status"], "BLOCKED")
            self.assertEqual(result["execution_requests"], 0)


if __name__ == "__main__":
    unittest.main()
