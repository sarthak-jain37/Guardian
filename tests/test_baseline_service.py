import asyncio
import unittest
from unittest.mock import MagicMock

from backend.app.services.canonical_hash import canonical_hash
from backend.app.services import baseline_service


class FakeRedis:
    def __init__(self):
        self.strings = {}
        self.hashes = {}
        self.zsets = {}  # key -> list of (member, score)
        self.sets = {}   # key -> set

    async def get(self, key):
        return self.strings.get(key)

    async def set(self, key, val):
        self.strings[key] = str(val)

    async def delete(self, key):
        self.strings.pop(key, None)
        self.hashes.pop(key, None)
        self.zsets.pop(key, None)
        self.sets.pop(key, None)

    async def hset(self, key, name=None, value=None, mapping=None, **kwargs):
        if key not in self.hashes:
            self.hashes[key] = {}
        if name is not None and value is not None:
            self.hashes[key][str(name)] = str(value)
        if mapping:
            for k, v in mapping.items():
                self.hashes[key][str(k)] = str(v)
        for k, v in kwargs.items():
            self.hashes[key][str(k)] = str(v)


    async def hgetall(self, key):
        return dict(self.hashes.get(key, {}))

    async def zadd(self, key, mapping):
        if key not in self.zsets:
            self.zsets[key] = []
        for member, score in mapping.items():
            self.zsets[key] = [(m, s) for m, s in self.zsets[key] if m != member]
            self.zsets[key].append((member, float(score)))
        self.zsets[key].sort(key=lambda x: x[1])

    async def zcard(self, key):
        return len(self.zsets.get(key, []))

    async def zrange(self, key, start, stop):
        items = [m for m, _ in self.zsets.get(key, [])]
        if stop == -1:
            return items[start:]
        return items[start:stop + 1]

    async def zrevrange(self, key, start, stop):
        items = [m for m, _ in reversed(self.zsets.get(key, []))]
        if stop == -1:
            return items[start:]
        return items[start:stop + 1]

    async def zrem(self, key, member):
        if key in self.zsets:
            self.zsets[key] = [(m, s) for m, s in self.zsets[key] if m != member]

    async def sadd(self, key, *members):
        if key not in self.sets:
            self.sets[key] = set()
        for m in members:
            self.sets[key].add(str(m))

    async def sismember(self, key, member):
        return str(member) in self.sets.get(key, set())


class TestBaselineService(unittest.TestCase):
    def setUp(self):
        self.redis = FakeRedis()

    def test_canonical_hash_order_independent(self):
        """Same permissions in different list/key order -> same hash"""
        state_1 = {
            "Role_default_viewer": {
                "kind": "Role",
                "metadata": {"name": "viewer", "namespace": "default"},
                "rules": [
                    {"verbs": ["get", "list"], "resources": ["pods", "services"], "apiGroups": [""]}
                ],
            }
        }
        state_2 = {
            "Role_default_viewer": {
                "metadata": {"namespace": "default", "name": "viewer"},
                "kind": "Role",
                "rules": [
                    {"resources": ["services", "pods"], "verbs": ["list", "get"], "apiGroups": [""]}
                ],
            }
        }
        hash1 = canonical_hash(state_1)
        hash2 = canonical_hash(state_2)
        self.assertEqual(hash1, hash2)

    def test_canonical_hash_case_insensitive(self):
        """Secrets vs secrets -> same hash"""
        state_1 = {
            "Role_default_secret_reader": {
                "kind": "Role",
                "metadata": {"name": "secret-reader", "namespace": "default"},
                "rules": [{"verbs": ["GET"], "resources": ["SECRETS"], "apiGroups": [""]}],
            }
        }
        state_2 = {
            "Role_default_secret_reader": {
                "kind": "Role",
                "metadata": {"name": "secret-reader", "namespace": "default"},
                "rules": [{"verbs": ["get"], "resources": ["secrets"], "apiGroups": [""]}],
            }
        }
        self.assertEqual(canonical_hash(state_1), canonical_hash(state_2))

    def test_canonical_hash_whitespace_irrelevant(self):
        """Different YAML/dict formatting -> same hash"""
        state_1 = {
            "Role_default_r1": {
                "kind": "Role",
                "metadata": {"name": "r1", "namespace": "default"},
                "rules": [{"verbs": ["get"], "resources": ["pods"], "apiGroups": [""]}],
            }
        }
        state_2 = {
            "Role_default_r1": {
                "metadata": {"name": "r1", "namespace": "default"},
                "rules": [{"verbs": ["get"], "resources": ["pods"], "apiGroups": [""]}],
                "kind": "Role",
            }
        }
        self.assertEqual(canonical_hash(state_1), canonical_hash(state_2))

    def test_broken_rollback_blocks_reproposal(self):
        """Hash in broken_hashes set -> is_known_broken() returns True"""
        state = {
            "Role_default_bad": {
                "kind": "Role",
                "metadata": {"name": "bad", "namespace": "default"},
                "rules": [{"verbs": ["*"], "resources": ["*"], "apiGroups": ["*"]}],
            }
        }

        async def run():
            chash = canonical_hash(state)
            await self.redis.sadd(baseline_service.BROKEN_HASHES_KEY, chash)

            self.assertTrue(await baseline_service.is_known_broken(state, self.redis))
            with self.assertRaises(ValueError):
                await baseline_service.create_baseline(
                    rbac_state=state,
                    sa_key="default/bad-sa",
                    status="PENDING_APPROVAL",
                    approved_by=None,
                    run_id=None,
                    redis=self.redis,
                )

        asyncio.run(run())

    def test_promote_flips_statuses(self):
        """Old ACTIVE -> SUPERSEDED, new PENDING -> ACTIVE"""
        state1 = {"Role_1": {"kind": "Role", "metadata": {"name": "r1"}, "rules": []}}
        state2 = {"Role_2": {"kind": "Role", "metadata": {"name": "r2"}, "rules": []}}

        async def run():
            b1 = await baseline_service.create_baseline(
                rbac_state=state1,
                sa_key="ops/backup-sa",
                status="ACTIVE",
                approved_by="alice",
                run_id=None,
                redis=self.redis,
            )
            b2 = await baseline_service.create_baseline(
                rbac_state=state2,
                sa_key="ops/backup-sa",
                status="PENDING_APPROVAL",
                approved_by=None,
                run_id=None,
                redis=self.redis,
                parent_id=b1["baseline_id"],
            )

            await baseline_service.promote_baseline(b2["baseline_id"], "bob", self.redis)

            updated_b1 = await baseline_service.get_baseline(b1["baseline_id"], self.redis)
            updated_b2 = await baseline_service.get_baseline(b2["baseline_id"], self.redis)

            self.assertEqual(updated_b1["status"], "SUPERSEDED")
            self.assertEqual(updated_b2["status"], "ACTIVE")
            self.assertEqual(updated_b2["approved_by"], "bob")

        asyncio.run(run())

    def test_only_one_active_per_sa(self):
        """After promotion, exactly one ACTIVE baseline exists"""
        state1 = {"Role_1": {"kind": "Role", "metadata": {"name": "r1"}, "rules": []}}
        state2 = {"Role_2": {"kind": "Role", "metadata": {"name": "r2"}, "rules": []}}

        async def run():
            b1 = await baseline_service.create_baseline(
                rbac_state=state1,
                sa_key="default/sa1",
                status="ACTIVE",
                approved_by="admin",
                run_id=None,
                redis=self.redis,
            )
            b2 = await baseline_service.create_baseline(
                rbac_state=state2,
                sa_key="default/sa1",
                status="PENDING_APPROVAL",
                approved_by=None,
                run_id=None,
                redis=self.redis,
            )
            await baseline_service.promote_baseline(b2["baseline_id"], "admin", self.redis)

            active = await baseline_service.get_active_baseline("default/sa1", self.redis)
            self.assertIsNotNone(active)
            self.assertEqual(active["baseline_id"], b2["baseline_id"])
            self.assertEqual(active["status"], "ACTIVE")

        asyncio.run(run())

    def test_version_guard_detects_conflict(self):
        """Modified cluster between detection and approval -> conflict"""
        from backend.app.services.drift_detector import create_conflict_recheck
        from backend.app.services.redis_service import save_approval_queue_entry, get_approval_queue_entry

        state_original = {"Role_1": {"kind": "Role", "metadata": {"name": "r1"}, "rules": []}}
        state_modified = {"Role_1": {"kind": "Role", "metadata": {"name": "r1"}, "rules": [{"verbs": ["*"], "resources": ["*"]}]}}

        async def run():
            queue_entry = {
                "id": "q-123",
                "baseline_id": "b-1",
                "status": "PENDING",
                "snapshot_hash": canonical_hash(state_original),
                "original_state": state_original,
                "latest_state": state_original,
                "diff_summary": {},
                "risk_tier": "LOW",
                "sa_key": "__CLUSTER__",
            }
            await save_approval_queue_entry(queue_entry, self.redis)

            # Checkpoint: detection hash != current cluster hash
            current_cluster_hash = canonical_hash(state_modified)
            entry = await get_approval_queue_entry("q-123", self.redis)
            self.assertNotEqual(entry["snapshot_hash"], current_cluster_hash)

            conflict_entry = await create_conflict_recheck("q-123", state_modified, self.redis)
            self.assertEqual(conflict_entry["id"], "q-123")
            self.assertEqual(conflict_entry["snapshot_hash"], current_cluster_hash)
            self.assertEqual(conflict_entry["risk_tier"], "CRITICAL")

        asyncio.run(run())

    def test_version_guard_passes_clean(self):
        """Unchanged cluster -> approval proceeds"""
        from backend.app.services.redis_service import save_approval_queue_entry, get_approval_queue_entry

        state_original = {"Role_1": {"kind": "Role", "metadata": {"name": "r1"}, "rules": []}}

        async def run():
            b = await baseline_service.create_baseline(
                rbac_state=state_original,
                sa_key="__CLUSTER__",
                status="PENDING_APPROVAL",
                approved_by=None,
                run_id=None,
                redis=self.redis,
            )
            queue_entry = {
                "id": "q-456",
                "baseline_id": b["baseline_id"],
                "status": "PENDING",
                "snapshot_hash": canonical_hash(state_original),
                "original_state": state_original,
                "latest_state": state_original,
                "sa_key": "__CLUSTER__",
            }
            await save_approval_queue_entry(queue_entry, self.redis)

            # Unchanged cluster
            current_hash = canonical_hash(state_original)
            entry = await get_approval_queue_entry("q-456", self.redis)
            self.assertEqual(entry["snapshot_hash"], current_hash)

            # Proceeds to promotion
            await baseline_service.promote_baseline(b["baseline_id"], "approver", self.redis)
            active = await baseline_service.get_active_baseline("__CLUSTER__", self.redis)
            self.assertEqual(active["baseline_id"], b["baseline_id"])

        asyncio.run(run())


if __name__ == "__main__":
    unittest.main()
