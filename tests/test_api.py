import json
import unittest
from unittest.mock import AsyncMock, MagicMock
from fastapi.testclient import TestClient
from fastapi import FastAPI

from backend.app.api.routes.dangerous_permissions import router as dangerous_permissions_router
from backend.app.services.redis_service import DANGEROUS_PERMS_KEY


class TestDangerousPermissionsAPI(unittest.TestCase):

    def setUp(self):
        self.app = FastAPI()
        self.app.include_router(dangerous_permissions_router)
        self.mock_redis = MagicMock()
        self.app.state.redis = self.mock_redis
        self.client = TestClient(self.app)

    def test_get_dangerous_permissions_empty(self):
        self.mock_redis.get = AsyncMock(return_value=None)
        response = self.client.get("/dangerous-permissions")
        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertEqual(data["count"], 0)
        self.assertEqual(data["findings"], [])
        self.mock_redis.get.assert_called_once_with(DANGEROUS_PERMS_KEY)

    def test_get_dangerous_permissions_with_slash(self):
        self.mock_redis.get = AsyncMock(return_value=None)
        response = self.client.get("/dangerous-permissions/")
        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertEqual(data["count"], 0)
        self.assertEqual(data["findings"], [])

    def test_get_dangerous_permissions_populated(self):
        mock_findings = [
            {
                "role_name": "priv-escalate-role",
                "role_kind": "Role",
                "namespace": "default",
                "severity": "CRITICAL",
                "flags": ["DANGEROUS_VERB_BIND"],
                "rules": [
                    {
                        "rule_index": 0,
                        "verbs": ["bind"],
                        "resources": ["roles"],
                        "api_groups": ["rbac.authorization.k8s.io"],
                        "severity": "CRITICAL",
                        "flags": ["DANGEROUS_VERB_BIND"],
                        "findings": ["Dangerous verb 'bind' detected: Allows binding roles/clusterroles"],
                    }
                ],
            }
        ]
        self.mock_redis.get = AsyncMock(return_value=json.dumps(mock_findings))
        response = self.client.get("/dangerous-permissions")
        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertEqual(data["count"], 1)
        self.assertEqual(len(data["findings"]), 1)
        self.assertEqual(data["findings"][0]["role_name"], "priv-escalate-role")
        self.assertEqual(data["findings"][0]["severity"], "CRITICAL")


if __name__ == "__main__":
    unittest.main()
