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

    def test_submit_decision_revert(self):
        state_active = {"Role_1": {"kind": "Role", "metadata": {"name": "r1"}, "rules": [{"verbs": ["get"], "resources": ["pods"]}]}}
        b = asyncio.run(
            baseline_service.create_baseline(
                rbac_state=state_active,
                sa_key="__CLUSTER__",
                status="ACTIVE",
                approved_by="admin",
                run_id=None,
                redis=self.redis,
            )
        )

        from backend.app.services.redis_service import save_approval_queue_entry
        queue_entry = {
            "id": "q-revert",
            "baseline_id": b["baseline_id"],
            "risk_tier": "CRITICAL",
            "status": "PENDING",
            "diff_summary": {"values_changed": {}},
            "llm_analysis": "Unauthorized role added",
            "sa_key": "__CLUSTER__",
            "snapshot_hash": "hash123",
            "original_state": state_active,
            "latest_state": state_active,
        }
        asyncio.run(save_approval_queue_entry(queue_entry, self.redis))

        fake_receipt = {
            "status": "success",
            "applied": ["Role_default_r1"],
            "deleted": ["Role_default_rogue"],
            "errors": [],
            "timestamp": "2026-10-28T10:00:00Z",
        }
        self.k8s.revert_to_baseline.return_value = fake_receipt

        res = self.client.post(
            "/approval/q-revert/decision",
            json={"decision": "revert", "actor": "sec-ops"},
        )
        self.assertEqual(res.status_code, 200)
        data = res.json()
        self.assertEqual(data["status"], "reverted")
        self.assertEqual(data["receipt"]["deleted"], ["Role_default_rogue"])
        self.k8s.revert_to_baseline.assert_called_once_with(state_active)

        # Check queue entry was updated to REVERTED
        detail = self.client.get("/approval/q-revert").json()
        self.assertEqual(detail["status"], "REVERTED")
        self.assertEqual(detail["resolved_by"], "sec-ops")

    def test_dedicated_revert_endpoint(self):
        state_active = {"Role_1": {"kind": "Role", "metadata": {"name": "r1"}, "rules": []}}
        b = asyncio.run(
            baseline_service.create_baseline(
                rbac_state=state_active,
                sa_key="__CLUSTER__",
                status="ACTIVE",
                approved_by="admin",
                run_id=None,
                redis=self.redis,
            )
        )

        from backend.app.services.redis_service import save_approval_queue_entry
        queue_entry = {
            "id": "q-ded-revert",
            "baseline_id": b["baseline_id"],
            "risk_tier": "HIGH",
            "status": "PENDING",
            "diff_summary": {},
            "llm_analysis": "test",
            "sa_key": "__CLUSTER__",
            "snapshot_hash": "h123",
            "original_state": state_active,
            "latest_state": state_active,
        }
        asyncio.run(save_approval_queue_entry(queue_entry, self.redis))

        fake_receipt = {"status": "success", "applied": [], "deleted": [], "errors": [], "timestamp": "t"}
        self.k8s.revert_to_baseline.return_value = fake_receipt

        res = self.client.post("/approval/q-ded-revert/revert?actor=lead-admin")
        self.assertEqual(res.status_code, 200)
        self.assertEqual(res.json()["status"], "reverted")
        self.assertEqual(res.json()["queue_id"], "q-ded-revert")

    def test_submit_decision_dismiss(self):
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
            "id": "q-dismiss",
            "baseline_id": b["baseline_id"],
            "risk_tier": "LOW",
            "status": "PENDING",
            "diff_summary": {},
            "llm_analysis": "benign change",
            "sa_key": "__CLUSTER__",
            "snapshot_hash": "h",
        }
        asyncio.run(save_approval_queue_entry(queue_entry, self.redis))

        res = self.client.post(
            "/approval/q-dismiss/decision",
            json={"decision": "dismiss", "actor": "admin", "note": "Acknowledged benign drift"},
        )
        self.assertEqual(res.status_code, 200)
        self.assertEqual(res.json()["status"], "dismissed")

        detail = self.client.get("/approval/q-dismiss").json()
        self.assertEqual(detail["status"], "DISMISSED")
        self.assertEqual(detail["note"], "Acknowledged benign drift")

    def test_approval_history_audit_trail(self):
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
            "id": "q-hist-1",
            "baseline_id": b["baseline_id"],
            "risk_tier": "LOW",
            "status": "PENDING",
            "diff_summary": {},
            "llm_analysis": "test",
            "sa_key": "__CLUSTER__",
            "snapshot_hash": "h",
        }
        asyncio.run(save_approval_queue_entry(queue_entry, self.redis))

        # Reject it so it gets resolved
        self.client.post("/approval/q-hist-1/decision", json={"decision": "reject", "actor": "auditor"})

        # Fetch history
        res_hist = self.client.get("/approval/history")
        self.assertEqual(res_hist.status_code, 200)
        data = res_hist.json()
        self.assertGreaterEqual(data["count"], 1)
        found = any(e["id"] == "q-hist-1" and e["status"] == "REJECTED" for e in data["history"])
        self.assertTrue(found)

    def test_apply_baseline_direct(self):
        state = {"Role_1": {"kind": "Role", "metadata": {"name": "r1"}, "rules": []}}
        b = asyncio.run(
            baseline_service.create_baseline(
                rbac_state=state,
                sa_key="__CLUSTER__",
                status="ACTIVE",
                approved_by="admin",
                run_id=None,
                redis=self.redis,
            )
        )
        self.k8s.revert_to_baseline.return_value = {"status": "success", "applied": ["Role_1"], "deleted": [], "errors": []}

        res = self.client.post(f"/baselines/{b['baseline_id']}/apply")
        self.assertEqual(res.status_code, 200)
        self.assertEqual(res.json()["status"], "applied")
        self.k8s.revert_to_baseline.assert_called_with(state)

    def test_rollback_root_baseline_error(self):
        state = {"Role_1": {"kind": "Role", "metadata": {"name": "r1"}, "rules": []}}
        b = asyncio.run(
            baseline_service.create_baseline(
                rbac_state=state,
                sa_key="__CLUSTER__",
                status="ACTIVE",
                approved_by="admin",
                run_id=None,
                redis=self.redis,
                parent_id=None,
            )
        )

        res = self.client.post(f"/baselines/{b['baseline_id']}/rollback")
        self.assertEqual(res.status_code, 400)
        self.assertIn("no parent baseline", res.json()["detail"])

    def test_approval_stream_endpoint(self):
        res = self.client.get("/approval/stream?max_events=1")
        self.assertEqual(res.status_code, 200)
        self.assertIn("text/event-stream", res.headers["content-type"])
        self.assertIn("CONNECTED", res.text)



if __name__ == "__main__":
    unittest.main()

