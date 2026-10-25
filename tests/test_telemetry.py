import asyncio
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import AsyncMock
from backend.app.services.telemetry import Telemetry, normalize


def flow():
    return {"flow": {"time": "2026-10-24T10:00:00Z", "source": {"namespace": "client", "pod_name": "web"},
                     "destination": {"namespace": "db", "pod_name": "api"}, "verdict": "DROPPED",
                     "l7": {"type": "REQUEST", "http": {"method": "GET", "url": "http://user:secret@api/items?token=secret", "headers": [{"key": "Authorization", "value": "secret"}]}}}}


class TelemetryTests(unittest.IsolatedAsyncioTestCase):
    async def test_redaction_and_bare_export(self):
        event = normalize(flow(), "hubble", "c1")
        self.assertNotIn("secret", json.dumps(event))
        self.assertEqual(event["http"]["path"], "/items")
        self.assertEqual(event["id"], normalize(flow(), "hubble", "c1")["id"])
        self.assertEqual(normalize(flow()["flow"], "hubble", "c1")["kind"], "network")
        self.assertNotEqual(event["id"], normalize(flow(), "hubble", "c2")["id"])

    async def test_runtime_and_boundaries(self):
        event = normalize({"process_exec": {"process": {"binary": "/bin/sh", "uid": 0, "arguments": "secret", "pod": {"namespace": "client", "name": "web"}}}}, "tetragon", "c1")
        self.assertNotIn("secret", json.dumps(event))
        service = Telemetry(AsyncMock())
        service.boundaries = [{"namespace": "client", "allowed_binaries": ["/app/server"], "allowed_destination_namespaces": ["client"]}]
        self.assertIn("binary_outside_boundary", service.findings(event))
        self.assertIn("root_process_observed", service.findings(event))
        self.assertIn("destination_namespace_outside_boundary", service.findings(normalize(flow(), "hubble", "c1")))

    async def test_graph_filters_and_counts(self):
        redis = AsyncMock()
        event = normalize(flow(), "hubble", "c1")
        redis.lrange.return_value = [json.dumps(event)]
        service = Telemetry(redis)
        graph = await service.graph(namespace="client")
        self.assertEqual(len(graph["nodes"]), 2)
        self.assertEqual(graph["edges"][0]["drops"], 1)
        self.assertEqual(graph["edges"][0]["http_requests"], 1)
        self.assertEqual(await service.events(namespace="other"), [])

    async def test_save_uses_atomic_dedup(self):
        redis = AsyncMock()
        service = Telemetry(redis)
        await service.save(normalize(flow(), "hubble", "c1"))
        redis.eval.assert_awaited_once()
        self.assertEqual(redis.eval.call_args.args[1], 2)

    async def test_follower_waits_for_complete_lines(self):
        redis = AsyncMock()
        redis.get.return_value = None
        service = Telemetry(redis)
        service.save = AsyncMock()
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "events.jsonl"
            path.write_text(json.dumps(flow()))
            task = asyncio.create_task(service.follow("hubble", str(path)))
            await asyncio.sleep(0.05)
            service.save.assert_not_awaited()
            path.write_text(json.dumps(flow()) + "\n")
            await asyncio.sleep(1.1)
            task.cancel()
            await asyncio.gather(task, return_exceptions=True)
            service.save.assert_awaited_once()


if __name__ == "__main__":
    unittest.main()
