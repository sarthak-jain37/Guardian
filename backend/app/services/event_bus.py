import asyncio
import json
import logging
import uuid
from datetime import datetime, timezone
from typing import Any, AsyncGenerator
from redis.asyncio import Redis

logger = logging.getLogger(__name__)

REDIS_EVENT_CHANNEL = "guardian:events"


class EventBus:
    """
    In-memory and Redis-backed event bus for broadcasting cluster governance events
    (e.g., DRIFT_DETECTED, BASELINE_PROMOTED, DRIFT_REVERTED, BASELINE_ROLLED_BACK).
    """

    def __init__(self):
        self._subscribers: set[asyncio.Queue] = set()
        self._lock = asyncio.Lock()

    async def register(self) -> asyncio.Queue:
        """Register a new in-memory subscriber queue."""
        q: asyncio.Queue = asyncio.Queue(maxsize=100)
        async with self._lock:
            self._subscribers.add(q)
        return q

    async def unregister(self, q: asyncio.Queue) -> None:
        """Unregister a subscriber queue."""
        async with self._lock:
            self._subscribers.discard(q)

    async def publish(self, event_type: str, payload: dict[str, Any], redis: Redis | None = None) -> dict[str, Any]:
        """
        Broadcast an event to all in-memory subscribers and publish to Redis pub/sub if available.
        """
        event = {
            "id": str(uuid.uuid4()),
            "event": event_type,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "data": payload,
        }

        # 1. Distribute to in-memory queues
        async with self._lock:
            stale_queues = []
            for q in self._subscribers:
                try:
                    q.put_nowait(event)
                except asyncio.QueueFull:
                    stale_queues.append(q)
            for sq in stale_queues:
                self._subscribers.discard(sq)

        # 2. Publish to Redis channel if Redis instance provided
        if redis is not None:
            try:
                await redis.publish(REDIS_EVENT_CHANNEL, json.dumps(event))
            except Exception as e:
                logger.warning(f"Failed to publish event to Redis channel {REDIS_EVENT_CHANNEL}: {e}")

        return event


# Global event bus singleton
bus = EventBus()


async def publish_event(event_type: str, payload: dict[str, Any], redis: Redis | None = None) -> dict[str, Any]:
    """Helper to publish an event across the event bus."""
    return await bus.publish(event_type, payload, redis=redis)


async def sse_event_stream(
    redis: Redis | None = None,
    ping_interval: float = 15.0,
    max_events: int | None = None,
) -> AsyncGenerator[str, None]:
    """
    Async generator producing Server-Sent Events (SSE) from the event bus.
    Emits formatted `event: ...\ndata: ...\n\n` and periodic `: ping\n\n` keepalives.
    """
    queue = await bus.register()
    events_yielded = 0
    try:
        # Initial greeting event
        init_event = {
            "id": str(uuid.uuid4()),
            "event": "CONNECTED",
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "data": {"message": "Connected to Guardian real-time governance stream"},
        }
        yield f"id: {init_event['id']}\nevent: {init_event['event']}\ndata: {json.dumps(init_event)}\n\n"
        events_yielded += 1
        if max_events is not None and events_yielded >= max_events:
            return

        while True:
            try:
                # Wait for next event or heartbeat timeout
                event = await asyncio.wait_for(queue.get(), timeout=ping_interval)
                event_type = event.get("event", "message")
                event_id = event.get("id", "")
                data_str = json.dumps(event)
                yield f"id: {event_id}\nevent: {event_type}\ndata: {data_str}\n\n"
                events_yielded += 1
                if max_events is not None and events_yielded >= max_events:
                    return
            except asyncio.TimeoutError:
                # Emit SSE comment ping to keep connection alive
                yield ": ping\n\n"
    finally:
        await bus.unregister(queue)
