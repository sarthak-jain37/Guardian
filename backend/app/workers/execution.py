"""Deterministic governed action/recovery and notification-intent worker; no model."""
import asyncio
import logging

logger=logging.getLogger(__name__)


async def run_execution(store):
    while True:
        try:
            await asyncio.to_thread(store.recover_next)
            await asyncio.to_thread(store.execute_next)
            await asyncio.to_thread(store.prepare_next)
        except asyncio.CancelledError:raise
        except Exception:logger.error('Execution/recovery unavailable; durable intents retained for reconciliation')
        await asyncio.sleep(2)
