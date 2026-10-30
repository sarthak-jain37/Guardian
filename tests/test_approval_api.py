"""Retired HTTP paths cannot mutate the cluster or legacy baseline history."""
import asyncio
import json
import unittest
from unittest.mock import MagicMock
from fastapi import FastAPI
from fastapi.testclient import TestClient
from backend.app.api.routes.approval import router
from backend.app.api.routes.telemetry import router as telemetry_router
from tests.test_baseline_service import FakeRedis


class LegacyApprovalTests(unittest.TestCase):
    def setUp(self):
        self.app = FastAPI()
        self.app.include_router(router)
        self.app.include_router(telemetry_router)
        self.redis = FakeRedis()
        self.k8s = MagicMock()
        self.app.state.redis = self.redis
        self.app.state.k8s = self.k8s
        self.app.state.permission_proposals = MagicMock()
        self.client = TestClient(self.app)

    def test_all_legacy_write_paths_are_retired_even_with_forged_actor_and_replay(self):
        before = json.dumps(vars(self.redis), sort_keys=True)
        paths = ['/approval/q/decision', '/approval/q/revert?actor=admin',
                 '/baselines/b/apply', '/baselines/b/rollback',
                 '/telemetry/permission-proposals/p/decision']
        for path in paths:
            for decision in ('promote', 'revert', 'reject', 'dismiss', 'accept'):
                with self.subTest(path=path, decision=decision):
                    for _ in range(2):
                        response = self.client.post(path, json={'decision': decision, 'actor': 'admin', 'apply_to_cluster': True})
                        self.assertEqual(response.status_code, 410)
                        self.assertEqual(response.json()['detail']['code'], 'legacy_execution_retired')
        self.assertEqual(json.dumps(vars(self.redis), sort_keys=True), before)
        self.assertEqual(self.k8s.mock_calls, [])
        self.assertEqual(self.app.state.permission_proposals.mock_calls, [])

    def test_legacy_history_is_readable_and_explicitly_unverified(self):
        from backend.app.services.baseline_service import create_baseline
        baseline = asyncio.run(create_baseline({'r': {'kind': 'Role', 'metadata': {'name': 'r'}, 'rules': []}},
            '__CLUSTER__', 'ACTIVE', 'system_startup', None, self.redis))
        response = self.client.get('/baselines/active')
        self.assertEqual(response.status_code, 200)
        self.assertFalse(response.json()['authority_verified'])
        self.assertEqual(response.json()['source'], 'legacy_redis')
        self.assertEqual(self.client.get('/baselines/history').json()['count'], 1)
        self.assertFalse(self.client.get('/baselines/'+baseline['baseline_id']).json()['authority_verified'])
        self.assertEqual(self.client.get('/approval/queue').json()['count'], 0)
        self.assertEqual(self.client.get('/approval/history').json()['count'], 0)
        self.assertEqual(self.client.get('/approval/stream?max_events=1').status_code, 200)
