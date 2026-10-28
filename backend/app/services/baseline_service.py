import json
import time
import uuid
from datetime import datetime, timezone
from typing import Any
from redis.asyncio import Redis

from backend.app.services.canonical_hash import canonical_hash

BROKEN_HASHES_KEY = "rbac:baselines:broken_hashes"


def generate_baseline_id() -> str:
    """Simple UUID-based ID. Redis handles uniqueness."""
    return f"baseline-{uuid.uuid4().hex[:12]}"


def _parse_sa_key(sa_key: str) -> tuple[str, str]:
    if sa_key == "__CLUSTER__":
        return "__ALL__", "__CLUSTER__"
    if "/" in sa_key:
        ns, sa = sa_key.split("/", 1)
        return ns, sa
    return "default", sa_key


async def is_known_broken(rbac_state: dict[str, Any], redis: Redis) -> bool:
    """Check if canonical_hash(rbac_state) exists in broken_hashes set."""
    chash = canonical_hash(rbac_state)
    return bool(await redis.sismember(BROKEN_HASHES_KEY, chash))


async def create_baseline(
    rbac_state: dict[str, Any],
    sa_key: str,
    status: str,
    approved_by: str | None,
    run_id: str | None,
    redis: Redis,
    parent_id: str | None = None,
) -> dict[str, Any]:
    """
    1. Compute canonical_hash(rbac_state)
    2. Check hash against rbac:baselines:broken_hashes -> reject if match
    3. Generate baseline_id
    4. Get current version_number for sa_key (ZCARD of history set + 1)
    5. Store the baseline HASH in Redis
    6. Add to history sorted set
    7. If status == "ACTIVE":
       a. Fetch current active baseline_id for this sa_key
       b. Flip the old one's status to SUPERSEDED
       c. Update rbac:baselines:active:{sa_key} pointer
    8. Return the baseline dict
    """
    chash = canonical_hash(rbac_state)
    if await redis.sismember(BROKEN_HASHES_KEY, chash):
        raise ValueError(f"State matches a known broken baseline ({chash}) and cannot be proposed.")

    baseline_id = generate_baseline_id()
    now_dt = datetime.now(timezone.utc)
    applied_at_iso = now_dt.isoformat()
    applied_at_unix = now_dt.timestamp()

    history_key = f"rbac:baselines:history:{sa_key}"
    version_num = await redis.zcard(history_key) + 1

    namespace, service_account = _parse_sa_key(sa_key)

    baseline_record = {
        "baseline_id": baseline_id,
        "service_account": service_account,
        "namespace": namespace,
        "canonical_hash": chash,
        "status": status,
        "rbac_state": json.dumps(rbac_state),
        "applied_at": applied_at_iso,
        "approved_by": approved_by or "",
        "run_id": run_id or "",
        "parent_id": parent_id or "",
        "version_number": str(version_num),
        "sa_key": sa_key,
    }

    baseline_key = f"rbac:baselines:{baseline_id}"
    await redis.hset(baseline_key, mapping=baseline_record)
    await redis.zadd(history_key, {baseline_id: applied_at_unix})

    active_pointer_key = f"rbac:baselines:active:{sa_key}"
    if status == "ACTIVE":
        old_active_id = await redis.get(active_pointer_key)
        if old_active_id and old_active_id != baseline_id:
            await redis.hset(f"rbac:baselines:{old_active_id}", mapping={"status": "SUPERSEDED"})
        await redis.set(active_pointer_key, baseline_id)

    parsed_record = dict(baseline_record)
    parsed_record["rbac_state"] = rbac_state
    return parsed_record


async def get_baseline(baseline_id: str, redis: Redis) -> dict[str, Any] | None:
    """Fetch a baseline by its ID."""
    data = await redis.hgetall(f"rbac:baselines:{baseline_id}")
    if not data:
        return None
    res = dict(data)
    if "rbac_state" in res and isinstance(res["rbac_state"], str):
        try:
            res["rbac_state"] = json.loads(res["rbac_state"])
        except json.JSONDecodeError:
            pass
    return res


async def get_active_baseline(sa_key: str, redis: Redis) -> dict[str, Any] | None:
    """Fetch the current ACTIVE baseline for a service account or cluster."""
    active_pointer_key = f"rbac:baselines:active:{sa_key}"
    baseline_id = await redis.get(active_pointer_key)
    if not baseline_id:
        return None
    return await get_baseline(baseline_id, redis)


async def mark_broken_rollback(baseline_id: str, redis: Redis) -> None:
    """
    1. Set status to BROKEN_ROLLBACK
    2. Add canonical_hash to rbac:baselines:broken_hashes
    3. Restore the parent baseline (parent_id) to ACTIVE
    """
    baseline = await get_baseline(baseline_id, redis)
    if not baseline:
        return

    chash = baseline.get("canonical_hash")
    sa_key = baseline.get("sa_key") or (
        f"{baseline.get('namespace')}/{baseline.get('service_account')}"
        if baseline.get("service_account") != "__CLUSTER__"
        else "__CLUSTER__"
    )

    await redis.hset(f"rbac:baselines:{baseline_id}", mapping={"status": "BROKEN_ROLLBACK"})
    if chash:
        await redis.sadd(BROKEN_HASHES_KEY, chash)

    parent_id = baseline.get("parent_id")
    if parent_id:
        parent = await get_baseline(parent_id, redis)
        if parent:
            await redis.hset(f"rbac:baselines:{parent_id}", mapping={"status": "ACTIVE"})
            await redis.set(f"rbac:baselines:active:{sa_key}", parent_id)


async def get_baseline_history(sa_key: str, redis: Redis) -> list[dict[str, Any]]:
    """Return all baselines for an SA, newest first."""
    history_key = f"rbac:baselines:history:{sa_key}"
    baseline_ids = await redis.zrevrange(history_key, 0, -1)
    results = []
    for bid in baseline_ids:
        b = await get_baseline(bid, redis)
        if b:
            results.append(b)
    return results


async def promote_baseline(baseline_id: str, approved_by: str, redis: Redis) -> None:
    """
    1. Flip baseline status from PENDING_APPROVAL -> ACTIVE
    2. Flip the current ACTIVE -> SUPERSEDED
    3. Update the active pointer
    """
    baseline = await get_baseline(baseline_id, redis)
    if not baseline:
        raise ValueError(f"Baseline {baseline_id} not found.")

    sa_key = baseline.get("sa_key") or (
        f"{baseline.get('namespace')}/{baseline.get('service_account')}"
        if baseline.get("service_account") != "__CLUSTER__"
        else "__CLUSTER__"
    )

    active_pointer_key = f"rbac:baselines:active:{sa_key}"
    current_active_id = await redis.get(active_pointer_key)
    if current_active_id and current_active_id != baseline_id:
        await redis.hset(f"rbac:baselines:{current_active_id}", mapping={"status": "SUPERSEDED"})

    await redis.hset(
        f"rbac:baselines:{baseline_id}",
        mapping={
            "status": "ACTIVE",
            "approved_by": approved_by,
        },
    )
    await redis.set(active_pointer_key, baseline_id)


async def reject_baseline(baseline_id: str, redis: Redis) -> None:
    """Flip status from PENDING_APPROVAL -> REJECTED."""
    await redis.hset(f"rbac:baselines:{baseline_id}", mapping={"status": "REJECTED"})

