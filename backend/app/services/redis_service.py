import json
import uuid
from datetime import datetime, timezone
from redis.asyncio import Redis

LAST_APPLY_KEY = "rbac:last_processed:apply"
LAST_MODIFY_KEY = "rbac:last_processed:modify"

DRIFT_QUEUE_KEY = "rbac:drift:events"

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
    
