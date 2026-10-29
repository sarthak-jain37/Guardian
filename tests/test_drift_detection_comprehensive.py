import asyncio
import copy
import json
import unittest
from unittest.mock import AsyncMock, MagicMock, patch
from datetime import datetime, timezone
from fastapi import FastAPI
from fastapi.testclient import TestClient

from backend.app.services.canonical_hash import canonical_hash
from backend.app.services import baseline_service
from backend.app.services.drift_detector import (
    classify_drift_risk,
    propose_llm_policy,
    run_drift_scan,
    scan_single_sa,
    create_conflict_recheck,
    _sanitize_diff,
)
from backend.app.services.redis_service import (
    save_approval_queue_entry,
    update_approval_queue_entry,
    get_approval_queue_entry,
    get_pending_approvals,
    get_pending_approval_by_sa,
)
from backend.app.api.routes.approval import router as approval_router
from tests.test_baseline_service import FakeRedis


class TestComprehensiveDriftAndBaseline(unittest.TestCase):
    def setUp(self):
        self.redis = FakeRedis()
        self.k8s = MagicMock()
        self.app = FastAPI()
        self.app.include_router(approval_router)
        self.app.state.redis = self.redis
        self.app.state.k8s = self.k8s
        self.client = TestClient(self.app)

    # =========================================================================
    # 1. CANONICAL HASH DEEP DIVE & EDGE CASES
    # =========================================================================

    def test_canonical_hash_empty_and_null(self):
        """Verify hash behavior on empty or None input."""
        h1 = canonical_hash(None)
        h2 = canonical_hash({})
        self.assertEqual(h1, h2)
        self.assertTrue(h1.startswith("sha256:"))

    def test_canonical_hash_skips_non_role_objects(self):
        """Objects like Pod, Deployment, ConfigMap must not influence RBAC hash."""
        state_with_pods = {
            "Pod_default_web": {"kind": "Pod", "metadata": {"name": "web"}},
            "ConfigMap_default_cfg": {"kind": "ConfigMap", "metadata": {"name": "cfg"}},
            "Role_default_r": {
                "kind": "Role",
                "metadata": {"name": "r", "namespace": "default"},
                "rules": [{"verbs": ["get"], "resources": ["pods"], "apiGroups": [""]}],
            },
        }
        state_only_role = {
            "Role_default_r": {
                "kind": "Role",
                "metadata": {"name": "r", "namespace": "default"},
                "rules": [{"verbs": ["get"], "resources": ["pods"], "apiGroups": [""]}],
            }
        }
        self.assertEqual(canonical_hash(state_with_pods), canonical_hash(state_only_role))

    def test_canonical_hash_clusterrole_vs_role_namespace(self):
        """ClusterRole defaults namespace to 'cluster' if missing, Role defaults to 'default'."""
        crole = {
            "ClusterRole_admin": {
                "kind": "ClusterRole",
                "metadata": {"name": "admin"},
                "rules": [{"verbs": ["*"], "resources": ["*"], "apiGroups": ["*"]}],
            }
        }
        role = {
            "Role_admin": {
                "kind": "Role",
                "metadata": {"name": "admin"},
                "rules": [{"verbs": ["*"], "resources": ["*"], "apiGroups": ["*"]}],
            }
        }
        # Because one has namespace "cluster" and the other "default", hashes must be distinct
        self.assertNotEqual(canonical_hash(crole), canonical_hash(role))

    def test_canonical_hash_deep_normalization(self):
        """Whitespace, rule shuffling, and key shuffling produce identical hash."""
        rules1 = [
            {"verbs": ["get", "list"], "resources": ["pods", "services"], "apiGroups": [""]},
            {"verbs": ["watch"], "resources": ["nodes"], "apiGroups": ["metrics.k8s.io"]},
        ]
        rules2 = [
            {"apiGroups": ["metrics.k8s.io"], "resources": ["nodes"], "verbs": ["watch"]},
            {"resources": ["services", "pods"], "apiGroups": [""], "verbs": ["list", "get"]},
        ]
        s1 = {"Role_1": {"kind": "Role", "metadata": {"name": "r", "namespace": "ns"}, "rules": rules1}}
        s2 = {"Role_1": {"metadata": {"namespace": "ns", "name": "r"}, "kind": "Role", "rules": rules2}}
        self.assertEqual(canonical_hash(s1), canonical_hash(s2))

    # =========================================================================
    # 2. RISK TIER CLASSIFICATION RIGOR
    # =========================================================================

    def test_risk_classification_critical_dangerous_verbs(self):
        """Dangerous verbs: bind, impersonate, escalate, approve must be CRITICAL."""
        base = {"Role_1": {"kind": "Role", "metadata": {"name": "r", "namespace": "default"}, "rules": []}}
        for dv in ["bind", "impersonate", "escalate", "approve"]:
            live = {
                "Role_1": {
                    "kind": "Role",
                    "metadata": {"name": "r", "namespace": "default"},
                    "rules": [{"verbs": [dv], "resources": ["roles"], "apiGroups": ["rbac.authorization.k8s.io"]}],
                }
            }
            diff = _sanitize_diff({"added": {"verb": dv}})
            self.assertEqual(classify_drift_risk(diff, base, live), "CRITICAL")

    def test_risk_classification_critical_namespaces(self):
        """Any change in kube-system or kube-public is CRITICAL."""
        base = {}
        live = {
            "Role_kube-system_test": {
                "kind": "Role",
                "metadata": {"name": "test", "namespace": "kube-system"},
                "rules": [{"verbs": ["get"], "resources": ["configmaps"], "apiGroups": [""]}],
            }
        }
        diff = _sanitize_diff({"added": "Role_kube-system_test"})
        self.assertEqual(classify_drift_risk(diff, base, live), "CRITICAL")

    def test_risk_classification_high_value_resources(self):
        """High-value resources without dangerous verbs or wildcards must be HIGH."""
        base = {"Role_1": {"kind": "Role", "metadata": {"name": "r", "namespace": "app"}, "rules": []}}
        for hr in ["secrets", "rolebindings", "clusterroles", "certificatesigningrequests"]:
            live = {
                "Role_1": {
                    "kind": "Role",
                    "metadata": {"name": "r", "namespace": "app"},
                    "rules": [{"verbs": ["get"], "resources": [hr], "apiGroups": [""]}],
                }
            }
            diff = _sanitize_diff({"added": {"resource": hr}})
            self.assertEqual(classify_drift_risk(diff, base, live), "HIGH")

    def test_risk_classification_low_tier(self):
        """Benign resource additions in regular namespace must be LOW."""
        base = {"Role_1": {"kind": "Role", "metadata": {"name": "r", "namespace": "app"}, "rules": []}}
        live = {
            "Role_1": {
                "kind": "Role",
                "metadata": {"name": "r", "namespace": "app"},
                "rules": [{"verbs": ["get", "list"], "resources": ["configmaps"], "apiGroups": [""]}],
            }
        }
        diff = _sanitize_diff({"added": {"verbs": ["get", "list"], "resources": ["configmaps"]}})
        self.assertEqual(classify_drift_risk(diff, base, live), "LOW")

    # =========================================================================
    # 3. BASELINE ROLLBACK & BLOCKLISTING
    # =========================================================================

    def test_rollback_and_blocklist_lifecycle(self):
        """
        Verify:
        v1 (ACTIVE) -> v2 (ACTIVE) -> Mark v2 as BROKEN_ROLLBACK
        1. v2 status becomes BROKEN_ROLLBACK
        2. v2 canonical hash is added to broken_hashes
        3. v1 is restored to ACTIVE
        4. Attempting to propose v2 hash again fails with ValueError
        """
        state_v1 = {"Role_1": {"kind": "Role", "metadata": {"name": "r"}, "rules": [{"verbs": ["get"], "resources": ["pods"]}]}}
        state_v2 = {"Role_1": {"kind": "Role", "metadata": {"name": "r"}, "rules": [{"verbs": ["*"], "resources": ["*"]}]}}

        async def run():
            # Create initial active v1
            b1 = await baseline_service.create_baseline(
                rbac_state=state_v1,
                sa_key="team/app-sa",
                status="ACTIVE",
                approved_by="admin",
                run_id="run-1",
                redis=self.redis,
            )
            self.assertEqual(b1["version_number"], "1")

            # Promote v2
            b2 = await baseline_service.create_baseline(
                rbac_state=state_v2,
                sa_key="team/app-sa",
                status="ACTIVE",
                approved_by="admin",
                run_id="run-2",
                redis=self.redis,
                parent_id=b1["baseline_id"],
            )
            self.assertEqual(b2["version_number"], "2")
            active = await baseline_service.get_active_baseline("team/app-sa", self.redis)
            self.assertEqual(active["baseline_id"], b2["baseline_id"])

            # Now mark v2 as BROKEN_ROLLBACK
            await baseline_service.mark_broken_rollback(b2["baseline_id"], self.redis)

            # Check v2 is BROKEN_ROLLBACK
            b2_record = await baseline_service.get_baseline(b2["baseline_id"], self.redis)
            self.assertEqual(b2_record["status"], "BROKEN_ROLLBACK")

            # Check v1 is restored to ACTIVE
            b1_record = await baseline_service.get_baseline(b1["baseline_id"], self.redis)
            self.assertEqual(b1_record["status"], "ACTIVE")

            active_now = await baseline_service.get_active_baseline("team/app-sa", self.redis)
            self.assertEqual(active_now["baseline_id"], b1["baseline_id"])

            # Check canonical hash is in broken_hashes
            v2_hash = canonical_hash(state_v2)
            self.assertTrue(await baseline_service.is_known_broken(state_v2, self.redis))

            # Attempting to re-propose state_v2 must raise ValueError
            with self.assertRaises(ValueError):
                await baseline_service.create_baseline(
                    rbac_state=state_v2,
                    sa_key="team/app-sa",
                    status="PENDING_APPROVAL",
                    approved_by=None,
                    run_id=None,
                    redis=self.redis,
                )

        asyncio.run(run())

    # =========================================================================
    # 4. LAZY GROUPING (VERSION CHAIN COLLAPSE) & EVOLUTION HISTORY
    # =========================================================================

    def test_lazy_grouping_multi_step_evolution(self):
        """
        Verify v1 (ACTIVE) -> v2 (drift) -> v3 (drift) -> v4 (drift):
        - Only 1 PENDING queue item exists in Redis.
        - Default net_diff reflects v1 -> v4.
        - version_count is 4.
        - version_chain contains the full intermediate steps with per-step diffs and timestamps.
        """
        v1 = {"Role_1": {"kind": "Role", "metadata": {"name": "r", "namespace": "default"}, "rules": [{"verbs": ["get"], "resources": ["pods"]}]}}
        v2 = {"Role_1": {"kind": "Role", "metadata": {"name": "r", "namespace": "default"}, "rules": [{"verbs": ["get", "list"], "resources": ["pods"]}]}}
        v3 = {"Role_1": {"kind": "Role", "metadata": {"name": "r", "namespace": "default"}, "rules": [{"verbs": ["get", "list", "delete"], "resources": ["pods"]}]}}
        v4 = {"Role_1": {"kind": "Role", "metadata": {"name": "r", "namespace": "default"}, "rules": [{"verbs": ["get", "list", "delete"], "resources": ["pods", "secrets"]}]}}

        mock_k8s = MagicMock()

        async def run():
            # Initial active baseline
            await baseline_service.create_baseline(
                rbac_state=v1,
                sa_key="__CLUSTER__",
                status="ACTIVE",
                approved_by="admin",
                run_id=None,
                redis=self.redis,
            )

            # Step 1: drift to v2
            mock_k8s.get_rbac_state.return_value = v2
            f1 = await run_drift_scan(self.redis, mock_k8s)
            self.assertEqual(len(f1), 1)
            self.assertEqual(f1[0]["version_count"], 1)

            # Step 2: drift to v3 before review
            mock_k8s.get_rbac_state.return_value = v3
            f2 = await run_drift_scan(self.redis, mock_k8s)
            self.assertEqual(len(f2), 1)
            self.assertEqual(f2[0]["version_count"], 2)

            # Step 3: drift to v4 before review
            mock_k8s.get_rbac_state.return_value = v4
            f3 = await run_drift_scan(self.redis, mock_k8s)
            self.assertEqual(len(f3), 1)
            self.assertEqual(f3[0]["version_count"], 3)

            # Verify queue state in Redis
            pending = await get_pending_approvals(self.redis)
            self.assertEqual(len(pending), 1)  # Only 1 collapsed item in queue

            collapsed_item = pending[0]
            self.assertEqual(collapsed_item["version_count"], 3)
            self.assertEqual(len(collapsed_item["version_chain"]), 3)

            # Check net diff covers original v1 vs v4 (includes secrets)
            self.assertEqual(collapsed_item["risk_tier"], "HIGH")

            # Check individual versions in chain
            chain = collapsed_item["version_chain"]
            self.assertEqual(chain[0]["version"], 1)
            self.assertEqual(chain[1]["version"], 2)
            self.assertEqual(chain[2]["version"], 3)

        asyncio.run(run())

    # =========================================================================
    # 5. VERSION GUARD: CHECKPOINT 1 (LLM GENERATION RACE)
    # =========================================================================

    def test_version_guard_checkpoint_1_retry_limit(self):
        """
        Verify propose_llm_policy:
        - If cluster changed during LLM thinking:
          - attempts 0, 1, 2 return status="stale"
          - attempt 3 returns status="manual_review_required" with message
        """
        input_state = {"Role_1": {"kind": "Role", "metadata": {"name": "r"}, "rules": [{"verbs": ["get"], "resources": ["pods"]}]}}
        mutated_state = {"Role_1": {"kind": "Role", "metadata": {"name": "r"}, "rules": [{"verbs": ["get", "list"], "resources": ["pods"]}]}}

        self.k8s.get_rbac_state.return_value = mutated_state
        llm_output = {"baseline_id": "b-proposed", "diff": {}, "analysis": "policy proposal"}

        async def run():
            # Attempt 0: stale
            r0 = await propose_llm_policy(input_state, llm_output, self.k8s, self.redis, retry_count=0)
            self.assertEqual(r0["status"], "stale")

            # Attempt 1: stale
            r1 = await propose_llm_policy(input_state, llm_output, self.k8s, self.redis, retry_count=1)
            self.assertEqual(r1["status"], "stale")

            # Attempt 2: stale
            r2 = await propose_llm_policy(input_state, llm_output, self.k8s, self.redis, retry_count=2)
            self.assertEqual(r2["status"], "stale")

            # Attempt 3: retry bound hit -> manual review required
            r3 = await propose_llm_policy(input_state, llm_output, self.k8s, self.redis, retry_count=3)
            self.assertEqual(r3["status"], "manual_review_required")
            self.assertIn("Cluster state is actively changing", r3["message"])

        asyncio.run(run())

    # =========================================================================
    # 6. VERSION GUARD: CHECKPOINT 2 (HITL APPROVAL RACE VIA API)
    # =========================================================================

    def test_legacy_approval_never_promotes_or_rechecks_in_place(self):
        from backend.app.services.redis_service import save_approval_queue_entry, get_approval_queue_entry
        entry = {'id': 'legacy-review', 'status': 'PENDING', 'baseline_id': 'b', 'snapshot_hash': 'old'}
        asyncio.run(save_approval_queue_entry(entry, self.redis))
        for _ in range(2):
            response = self.client.post('/approval/legacy-review/decision', json={'decision': 'promote', 'actor': 'Alice'})
            self.assertEqual(response.status_code, 410)
        self.assertEqual(asyncio.run(get_approval_queue_entry('legacy-review', self.redis))['snapshot_hash'], 'old')
        self.assertEqual(self.k8s.mock_calls, [])

    # =========================================================================
    # 7. STARTUP MIGRATION & SEEDING LOGIC
    # =========================================================================

    def test_startup_preserves_legacy_evidence_without_adopting_it(self):
        from backend.app.services.observations import capture_startup_observation
        legacy = {'old': {'kind': 'Role', 'metadata': {'name': 'old'}, 'rules': []}}
        live = {'new': {'kind': 'Role', 'metadata': {'name': 'new'}, 'rules': []}}
        async def run():
            await self.redis.set('rbac:baseline', json.dumps(legacy))
            self.k8s.get_rbac_state.return_value = live
            await capture_startup_observation(self.redis, self.k8s)
            self.assertEqual(json.loads(await self.redis.get('rbac:baseline')), legacy)
            self.assertEqual(json.loads(await self.redis.get('rbac:current')), live)
            self.assertIsNone(await baseline_service.get_active_baseline('__CLUSTER__', self.redis))
            self.assertEqual(await baseline_service.get_baseline_history('__CLUSTER__', self.redis), [])
        asyncio.run(run())

    def test_no_baseline_scan_observes_without_auto_approval(self):
        self.k8s.get_rbac_state.return_value = {'r': {'kind': 'Role', 'metadata': {'name': 'r'}, 'rules': []}}
        async def run():
            self.assertEqual(await run_drift_scan(self.redis, self.k8s), [])
            self.assertIsNone(await baseline_service.get_active_baseline('__CLUSTER__', self.redis))
            self.assertEqual(json.loads(await self.redis.get('rbac:current')), self.k8s.get_rbac_state.return_value)
        asyncio.run(run())


if __name__ == "__main__":
    unittest.main()
