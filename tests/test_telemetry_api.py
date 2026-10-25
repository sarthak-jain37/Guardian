import unittest
from unittest.mock import AsyncMock
from fastapi import FastAPI
from fastapi.testclient import TestClient
from backend.app.api.routes.telemetry import router
from backend.app.services.telemetry import Telemetry


class TelemetryAPITests(unittest.TestCase):
    def setUp(self):
        app = FastAPI()
        app.include_router(router)
        self.service = Telemetry(AsyncMock())
        self.service.redis.lrange.return_value = []
        self.service.redis.get.return_value = None
        app.state.telemetry = self.service
        self.client = TestClient(app)

    def test_status_and_empty_graph(self):
        self.assertEqual(self.client.get('/telemetry/status').status_code, 200)
        self.assertEqual(self.client.get('/telemetry/graph').json()['edges'], [])

    def test_limit_validation(self):
        for path in ('events', 'graph', 'llm-context'):
            self.assertEqual(self.client.get('/telemetry/' + path + '?limit=0').status_code, 422)
        self.assertEqual(self.client.post('/telemetry/evaluate?limit=101').status_code, 422)

    def test_context_contains_boundaries_and_coverage(self):
        result = self.client.get('/telemetry/llm-context').json()
        self.assertIn('boundaries', result)
        self.assertIn('coverage', result)
        self.assertEqual(result['events'], [])

    def test_pod_inventory_and_missing_evidence(self):
        response = self.client.get('/telemetry/pods')
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()['pods'], [])
        evidence = self.client.get('/telemetry/pods/app/web/evidence')
        self.assertEqual(evidence.status_code, 200)
        self.assertEqual(evidence.json()['pods'], [])
        self.assertFalse(evidence.json()['remediation_enabled'])

    def test_selected_pod_context(self):
        response = self.client.get('/telemetry/llm-context?namespace=app&pod=web')
        self.assertEqual(response.status_code, 200)
        self.assertFalse(response.json()['pod_evidence']['scoring_enabled'])

    def test_missing_pod_review_returns_not_found(self):
        response=self.client.get('/telemetry/pods/app/missing/review-context')
        self.assertEqual(response.status_code,404)

    def test_pod_review_input_limits(self):
        self.assertEqual(self.client.post('/telemetry/pods/app/web/review',json={'event_limit':0}).status_code,422)
        self.assertEqual(self.client.post('/telemetry/pods/app/web/review',json={'question':'x'*2001}).status_code,422)

    def test_counts_include_flows_beyond_recent_activity_sample(self):
        import json
        from datetime import datetime, timezone
        now = datetime.now(timezone.utc).isoformat()
        process = {'kind': 'process_exec', 'observed_at': now, 'source_pod': {'namespace': 'app'}}
        network = {'kind': 'network', 'observed_at': now, 'source_pod': {'namespace': 'app'}}
        other = {'kind': 'network', 'observed_at': now, 'source_pod': {'namespace': 'other'}}
        self.service.redis.lrange.return_value = [json.dumps(process)] * 1001 + [json.dumps(network), json.dumps(other)]
        recent = self.client.get('/telemetry/events?namespace=app&limit=1000').json()['events']
        self.assertFalse(any(e['kind'] == 'network' for e in recent))
        counts = self.client.get('/telemetry/counts?namespace=app').json()
        self.assertEqual(counts['by_kind']['network'], 1)
        self.assertEqual(counts['retained_events'], 1002)
        self.assertEqual(self.client.get('/telemetry/counts').json()['by_kind']['network'], 2)
