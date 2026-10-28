import asyncio
import unittest
from unittest.mock import MagicMock
from deepdiff import DeepDiff

from backend.app.services.canonical_hash import canonical_hash
from backend.app.services.drift_detector import classify_drift_risk, run_drift_scan
from backend.app.services import baseline_service
from tests.test_baseline_service import FakeRedis


class TestDriftDetector(unittest.TestCase):
    def setUp(self):
        self.redis = FakeRedis()

    def test_no_drift_same_state(self):
        """Identical baseline and live state -> no drift found"""
        state = {
            "Role_default_viewer": {
                "kind": "Role",
                "metadata": {"name": "viewer", "namespace": "default"},
                "rules": [{"verbs": ["get"], "resources": ["pods"], "apiGroups": [""]}],
            }
        }
        mock_k8s = MagicMock()
        mock_k8s.get_rbac_state.return_value = state

        async def run():
            # Seed active baseline
            await baseline_service.create_baseline(
                rbac_state=state,
                sa_key="__CLUSTER__",
                status="ACTIVE",
                approved_by="admin",
                run_id=None,
                redis=self.redis,
            )

            findings = await run_drift_scan(self.redis, mock_k8s)
            self.assertEqual(findings, [])

        asyncio.run(run())

    def test_drift_detected_on_change(self):
        """Added permission -> drift finding returned"""
        baseline_state = {
            "Role_default_viewer": {
                "kind": "Role",
                "metadata": {"name": "viewer", "namespace": "default"},
                "rules": [{"verbs": ["get"], "resources": ["pods"], "apiGroups": [""]}],
            }
        }
        live_state = {
            "Role_default_viewer": {
                "kind": "Role",
                "metadata": {"name": "viewer", "namespace": "default"},
                "rules": [
                    {"verbs": ["get"], "resources": ["pods"], "apiGroups": [""]},
                    {"verbs": ["delete"], "resources": ["pods"], "apiGroups": [""]},
                ],
            }
        }
        mock_k8s = MagicMock()
        mock_k8s.get_rbac_state.return_value = live_state

        async def run():
            await baseline_service.create_baseline(
                rbac_state=baseline_state,
                sa_key="__CLUSTER__",
                status="ACTIVE",
                approved_by="admin",
                run_id=None,
                redis=self.redis,
            )

            findings = await run_drift_scan(self.redis, mock_k8s)
            self.assertEqual(len(findings), 1)
            self.assertIn("diff", findings[0])
            self.assertEqual(findings[0]["sa_key"], "__CLUSTER__")

        asyncio.run(run())

    def test_risk_tier_critical_on_wildcard(self):
        """Diff with * verb -> CRITICAL"""
        baseline_state = {
            "Role_default_r": {
                "kind": "Role",
                "metadata": {"name": "r", "namespace": "default"},
                "rules": [{"verbs": ["get"], "resources": ["pods"], "apiGroups": [""]}],
            }
        }
        live_state = {
            "Role_default_r": {
                "kind": "Role",
                "metadata": {"name": "r", "namespace": "default"},
                "rules": [{"verbs": ["*"], "resources": ["pods"], "apiGroups": [""]}],
            }
        }
        diff = DeepDiff(baseline_state, live_state, ignore_order=True).to_dict()
        tier = classify_drift_risk(diff, baseline_state, live_state)
        self.assertEqual(tier, "CRITICAL")

    def test_risk_tier_high_on_secrets(self):
        """Diff adding secrets -> HIGH"""
        baseline_state = {
            "Role_default_r": {
                "kind": "Role",
                "metadata": {"name": "r", "namespace": "default"},
                "rules": [{"verbs": ["get"], "resources": ["pods"], "apiGroups": [""]}],
            }
        }
        live_state = {
            "Role_default_r": {
                "kind": "Role",
                "metadata": {"name": "r", "namespace": "default"},
                "rules": [
                    {"verbs": ["get"], "resources": ["pods"], "apiGroups": [""]},
                    {"verbs": ["get"], "resources": ["secrets"], "apiGroups": [""]},
                ],
            }
        }
        diff = DeepDiff(baseline_state, live_state, ignore_order=True).to_dict()
        tier = classify_drift_risk(diff, baseline_state, live_state)
        self.assertEqual(tier, "HIGH")

    def test_risk_tier_low_on_pods(self):
        """Diff adding pods:list -> LOW"""
        baseline_state = {
            "Role_default_r": {
                "kind": "Role",
                "metadata": {"name": "r", "namespace": "default"},
                "rules": [{"verbs": ["get"], "resources": ["pods"], "apiGroups": [""]}],
            }
        }
        live_state = {
            "Role_default_r": {
                "kind": "Role",
                "metadata": {"name": "r", "namespace": "default"},
                "rules": [{"verbs": ["get", "list"], "resources": ["pods"], "apiGroups": [""]}],
            }
        }
        diff = DeepDiff(baseline_state, live_state, ignore_order=True).to_dict()
        tier = classify_drift_risk(diff, baseline_state, live_state)
        self.assertEqual(tier, "LOW")

    def test_lazy_grouping_increments(self):
        """Repeated same or progressive drift -> version_count increases"""
        baseline_state = {
            "Role_default_r": {
                "kind": "Role",
                "metadata": {"name": "r", "namespace": "default"},
                "rules": [{"verbs": ["get"], "resources": ["pods"], "apiGroups": [""]}],
            }
        }
        # First drift (v2)
        live_state_v2 = {
            "Role_default_r": {
                "kind": "Role",
                "metadata": {"name": "r", "namespace": "default"},
                "rules": [{"verbs": ["get", "list"], "resources": ["pods"], "apiGroups": [""]}],
            }
        }
        # Second drift before approval (v3)
        live_state_v3 = {
            "Role_default_r": {
                "kind": "Role",
                "metadata": {"name": "r", "namespace": "default"},
                "rules": [{"verbs": ["get", "list", "delete"], "resources": ["pods"], "apiGroups": [""]}],
            }
        }

        mock_k8s = MagicMock()

        async def run():
            await baseline_service.create_baseline(
                rbac_state=baseline_state,
                sa_key="__CLUSTER__",
                status="ACTIVE",
                approved_by="admin",
                run_id=None,
                redis=self.redis,
            )

            # First scan creates pending entry
            mock_k8s.get_rbac_state.return_value = live_state_v2
            findings1 = await run_drift_scan(self.redis, mock_k8s)
            self.assertEqual(len(findings1), 1)
            self.assertEqual(findings1[0]["version_count"], 1)

            # Second scan while queue entry is still pending increments version_count
            mock_k8s.get_rbac_state.return_value = live_state_v3
            findings2 = await run_drift_scan(self.redis, mock_k8s)
            self.assertEqual(len(findings2), 1)
            self.assertEqual(findings2[0]["version_count"], 2)
            self.assertTrue(findings2[0]["lazy_grouped"])

        asyncio.run(run())


if __name__ == "__main__":
    unittest.main()
