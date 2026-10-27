import json
import uuid
from datetime import datetime, timezone
from typing import Any
from redis.asyncio import Redis


LAST_APPLY_KEY = "rbac:last_processed:apply"
LAST_MODIFY_KEY = "rbac:last_processed:modify"

DRIFT_QUEUE_KEY = "rbac:drift:events"
DANGEROUS_PERMS_KEY = "rbac:dangerous_permissions"

async def get_last_processed_timestamp(event_type, redis: Redis):
    return await redis.get(f"rbac:last_processed:{event_type}")
            
async def set_last_processed_timestamp(event_type, timestamp, redis: Redis):
    await redis.set(f"rbac:last_processed:{event_type}", timestamp)
    
async def save_rbac_state(key: str, rbac_state: dict, redis: Redis) -> None:
    await redis.set(key, json.dumps(rbac_state))


async def get_rbac_state(key: str, redis: Redis) -> dict | None:
    state = await redis.get(key)

    if state is None:
        return None

    return json.loads(state)    


async def save_drift_event(diff: dict, llm_response: str, redis: Redis) -> dict:
    event = {
        "id": str(uuid.uuid4()),
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "diff": diff,
        "llm_response": llm_response,
    }

    await redis.rpush(DRIFT_QUEUE_KEY, json.dumps(event),)

    return event


async def get_all_drift_events(redis) -> list[dict]:
    events = await redis.lrange(DRIFT_QUEUE_KEY, 0, -1)

    return [
        json.loads(event)
        for event in events
    ]


async def get_drift_event(redis, index: int) -> dict | None:
    event = await redis.lindex(DRIFT_QUEUE_KEY, index)

    if event is None:
        return None

    return json.loads(event)


async def save_dangerous_permissions(findings: list[dict], redis: Redis) -> None:
    await redis.set(DANGEROUS_PERMS_KEY, json.dumps(findings))


async def get_dangerous_permissions(redis: Redis) -> list[dict]:
    data = await redis.get(DANGEROUS_PERMS_KEY)
    if data is None:
        return []
    return json.loads(data)


APPROVAL_PENDING_ZSET = "rbac:approval_queue:pending"
APPROVAL_RESOLVED_ZSET = "rbac:approval_queue:resolved"


def _deserialize_queue_entry(data: dict[str, Any]) -> dict[str, Any]:
    res = dict(data)
    json_fields = ["diff_summary", "original_state", "latest_state", "net_diff", "version_chain"]
    for field in json_fields:
        if field in res and isinstance(res[field], str) and res[field]:
            try:
                res[field] = json.loads(res[field])
            except Exception:
                pass
    if "version_count" in res:
        try:
            res["version_count"] = int(res["version_count"])
        except (ValueError, TypeError):
            res["version_count"] = 1
    return res


async def save_approval_queue_entry(entry: dict[str, Any], redis: Redis) -> str:
    """Save a new approval queue entry as a Redis HASH and add to pending ZSET."""
    queue_id = entry.get("id") or str(uuid.uuid4())
    entry["id"] = queue_id

    created_at = entry.get("created_at") or datetime.now(timezone.utc).isoformat()
    entry["created_at"] = created_at

    try:
        created_timestamp = datetime.fromisoformat(created_at.replace("Z", "+00:00")).timestamp()
    except Exception:
        created_timestamp = datetime.now(timezone.utc).timestamp()

    # Prepare string mapping for Redis HASH
    mapping = {}
    for k, v in entry.items():
        if isinstance(v, (dict, list)):
            mapping[k] = json.dumps(v)
        elif v is None:
            mapping[k] = ""
        else:
            mapping[k] = str(v)

    await redis.hset(f"rbac:approval_queue:{queue_id}", mapping=mapping)
    await redis.zadd(APPROVAL_PENDING_ZSET, {queue_id: created_timestamp})
    return queue_id


async def update_approval_queue_entry(queue_id: str, updates: dict[str, Any], redis: Redis) -> None:
    """Update fields on an existing approval queue entry."""
    mapping = {}
    for k, v in updates.items():
        if isinstance(v, (dict, list)):
            mapping[k] = json.dumps(v)
        elif v is None:
            mapping[k] = ""
        else:
            mapping[k] = str(v)

    if mapping:
        await redis.hset(f"rbac:approval_queue:{queue_id}", mapping=mapping)

    status = updates.get("status")
    if status in ("PROMOTED", "REJECTED"):
        resolved_at = updates.get("resolved_at") or datetime.now(timezone.utc).isoformat()
        try:
            resolved_timestamp = datetime.fromisoformat(resolved_at.replace("Z", "+00:00")).timestamp()
        except Exception:
            resolved_timestamp = datetime.now(timezone.utc).timestamp()

        await redis.zrem(APPROVAL_PENDING_ZSET, queue_id)
        await redis.zadd(APPROVAL_RESOLVED_ZSET, {queue_id: resolved_timestamp})


async def get_approval_queue_entry(queue_id: str, redis: Redis) -> dict[str, Any] | None:
    """Fetch an approval queue entry by queue_id."""
    data = await redis.hgetall(f"rbac:approval_queue:{queue_id}")
    if not data:
        return None
    return _deserialize_queue_entry(data)


async def get_pending_approvals(redis: Redis) -> list[dict[str, Any]]:
    """Return all PENDING approval queue entries, sorted newest created first."""
    queue_ids = await redis.zrevrange(APPROVAL_PENDING_ZSET, 0, -1)
    results = []
    for qid in queue_ids:
        entry = await get_approval_queue_entry(qid, redis)
        if entry and entry.get("status") == "PENDING":
            results.append(entry)
    return results


async def get_pending_approval_by_sa(sa_key: str, redis: Redis) -> dict[str, Any] | None:
    """Find an active PENDING queue entry for a given service account / cluster key."""
    queue_ids = await redis.zrange(APPROVAL_PENDING_ZSET, 0, -1)
    for qid in queue_ids:
        entry = await get_approval_queue_entry(qid, redis)
        if entry and entry.get("sa_key") == sa_key and entry.get("status") == "PENDING":
            return entry
    return None

