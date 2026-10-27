import asyncio
import unittest
from unittest.mock import MagicMock
from fastapi.testclient import TestClient
from fastapi import FastAPI

from backend.app.api.routes.approval import router as approval_router
from backend.app.services.canonical_hash import canonical_hash
from backend.app.services import baseline_service
from tests.test_baseline_service import FakeRedis


class TestApprovalApi(unittest.TestCase):
    def setUp(self):
        self.app = FastAPI()
        self.app.include_router(approval_router)
        self.redis = FakeRedis()
        self.k8s = MagicMock()
        self.app.state.redis = self.redis
        self.app.state.k8s = self.k8s
        self.client = TestClient(self.app)

    def test_list_and_get_approval_queue(self):
        state = {"Role_1": {"kind": "Role", "metadata": {"name": "r1"}, "rules": []}}
        queue_entry = {
            "id": "queue-entry-1",
            "baseline_id": "b-1",
            "risk_tier": "CRITICAL",
            "status": "PENDING",
            "diff_summary": {"values_changed": {}},
            "llm_analysis": "Dangerous permissions added",
            "sa_key": "__CLUSTER__",
            "snapshot_hash": canonical_hash(state),
            "original_state": state,
            "latest_state": state,
            "version_count": 1,
            "version_chain": [],
        }

        from backend.app.services.redis_service import save_approval_queue_entry
        asyncio.run(save_approval_queue_entry(queue_entry, self.redis))

        # Test GET /approval/queue
        res = self.client.get("/approval/queue")
        self.assertEqual(res.status_code, 200)
        data = res.json()
        self.assertEqual(data["count"], 1)
        self.assertEqual(data["entries"][0]["id"], "queue-entry-1")
        self.assertEqual(data["entries"][0]["risk_tier"], "CRITICAL")

        # Test GET /approval/{queue_id}
        res_detail = self.client.get("/approval/queue-entry-1")
        self.assertEqual(res_detail.status_code, 200)
        self.assertEqual(res_detail.json()["id"], "queue-entry-1")

    def test_submit_decision_promote_and_conflict(self):
        state_original = {"Role_1": {"kind": "Role", "metadata": {"name": "r1"}, "rules": []}}
        state_changed = {"Role_1": {"kind": "Role", "metadata": {"name": "r1"}, "rules": [{"verbs": ["*"], "resources": ["*"]}]}}

        # Seed baseline in redis
        b = asyncio.run(
            baseline_service.create_baseline(
                rbac_state=state_original,
                sa_key="__CLUSTER__",
                status="PENDING_APPROVAL",
                approved_by=None,
                run_id=None,
                redis=self.redis,
            )
        )

        from backend.app.services.redis_service import save_approval_queue_entry
        queue_entry = {
            "id": "q-decision",
            "baseline_id": b["baseline_id"],
            "risk_tier": "HIGH",
            "status": "PENDING",
            "diff_summary": {},
            "llm_analysis": "analysis",
            "sa_key": "__CLUSTER__",
            "snapshot_hash": canonical_hash(state_original),
            "original_state": state_original,
            "latest_state": state_original,
        }
        asyncio.run(save_approval_queue_entry(queue_entry, self.redis))

        # Test 1: Conflict when cluster changed
        self.k8s.get_rbac_state.return_value = state_changed
        res_conflict = self.client.post(
            "/approval/q-decision/decision",
            json={"decision": "promote", "actor": "admin"},
        )
        self.assertEqual(res_conflict.status_code, 200)
        self.assertEqual(res_conflict.json()["status"], "conflict")

        # Test 2: Clean promotion when cluster matches
        self.k8s.get_rbac_state.return_value = state_changed  # Updated state now matches snapshot_hash from conflict recheck
        res_promote = self.client.post(
            "/approval/q-decision/decision",
            json={"decision": "promote", "actor": "admin"},
        )
        self.assertEqual(res_promote.status_code, 200)
        self.assertEqual(res_promote.json()["status"], "promoted")

    def test_submit_decision_reject(self):
        state = {"Role_1": {"kind": "Role", "metadata": {"name": "r1"}, "rules": []}}
        b = asyncio.run(
            baseline_service.create_baseline(
                rbac_state=state,
                sa_key="__CLUSTER__",
                status="PENDING_APPROVAL",
                approved_by=None,
                run_id=None,
                redis=self.redis,
            )
        )

        from backend.app.services.redis_service import save_approval_queue_entry
        queue_entry = {
            "id": "q-reject",
            "baseline_id": b["baseline_id"],
            "risk_tier": "LOW",
            "status": "PENDING",
            "diff_summary": {},
            "llm_analysis": "analysis",
            "sa_key": "__CLUSTER__",
            "snapshot_hash": canonical_hash(state),
            "original_state": state,
            "latest_state": state,
        }
        asyncio.run(save_approval_queue_entry(queue_entry, self.redis))

        res_reject = self.client.post(
            "/approval/q-reject/decision",
            json={"decision": "reject", "actor": "admin"},
        )
        self.assertEqual(res_reject.status_code, 200)
        self.assertEqual(res_reject.json()["status"], "rejected")

        # Check baseline status is REJECTED
        updated_b = asyncio.run(baseline_service.get_baseline(b["baseline_id"], self.redis))
        self.assertEqual(updated_b["status"], "REJECTED")

    def test_baseline_active_history_and_rollback_api(self):
        state1 = {"Role_1": {"kind": "Role", "metadata": {"name": "r1"}, "rules": [{"verbs": ["get"], "resources": ["pods"]}]}}
        state2 = {"Role_1": {"kind": "Role", "metadata": {"name": "r1"}, "rules": [{"verbs": ["*"], "resources": ["*"]}]}}

        b1 = asyncio.run(
            baseline_service.create_baseline(
                rbac_state=state1,
                sa_key="__CLUSTER__",
                status="ACTIVE",
                approved_by="alice",
                run_id=None,
                redis=self.redis,
            )
        )
        b2 = asyncio.run(
            baseline_service.create_baseline(
                rbac_state=state2,
                sa_key="__CLUSTER__",
                status="ACTIVE",
                approved_by="bob",
                run_id=None,
                redis=self.redis,
                parent_id=b1["baseline_id"],
            )
        )

        # 1. Test GET /baselines/active
        res_act = self.client.get("/baselines/active")
        self.assertEqual(res_act.status_code, 200)
        self.assertEqual(res_act.json()["baseline_id"], b2["baseline_id"])
        self.assertEqual(res_act.json()["status"], "ACTIVE")

        # 2. Test GET /baselines/history
        res_hist = self.client.get("/baselines/history")
        self.assertEqual(res_hist.status_code, 200)
        self.assertEqual(res_hist.json()["count"], 2)

        # 3. Test GET /baselines/{id}
        res_detail = self.client.get(f"/baselines/{b1['baseline_id']}")
        self.assertEqual(res_detail.status_code, 200)
        self.assertEqual(res_detail.json()["baseline_id"], b1["baseline_id"])

        # 4. Test POST /baselines/{id}/rollback (transitions b2 to BROKEN_ROLLBACK, restores b1 to ACTIVE)
        res_rb = self.client.post(f"/baselines/{b2['baseline_id']}/rollback")
        self.assertEqual(res_rb.status_code, 200)
        self.assertEqual(res_rb.json()["status"], "rolled_back")
        self.assertEqual(res_rb.json()["restored_parent_id"], b1["baseline_id"])

        # Verify active baseline is now restored parent b1
        res_act_after = self.client.get("/baselines/active")
        self.assertEqual(res_act_after.json()["baseline_id"], b1["baseline_id"])
        self.assertEqual(res_act_after.json()["status"], "ACTIVE")

        # Verify b2 is now BROKEN_ROLLBACK
        res_b2 = self.client.get(f"/baselines/{b2['baseline_id']}")
        self.assertEqual(res_b2.json()["status"], "BROKEN_ROLLBACK")


if __name__ == "__main__":
    unittest.main()

