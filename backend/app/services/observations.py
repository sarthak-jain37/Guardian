"""Observation never grants baseline adoption authority."""
import asyncio

from backend.app.services.redis_service import save_rbac_state


async def capture_startup_observation(redis, k8s):
    state = await asyncio.to_thread(k8s.get_rbac_state)
    await save_rbac_state("rbac:current", state, redis)
    # Leave old baseline keys/history intact for accountability. They must not
    # become authenticated decisions merely because this version started.
    return state
