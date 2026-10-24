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
