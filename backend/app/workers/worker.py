import asyncio
from backend.app.services.audit_collector import collect_audit_logs
from backend.app.services.event_processor import process_events
from backend.app.core.config import POLLING_INTERVAL

async def run_pipeline(redis):
    while True:
        try:
            print("Checking audit logs...")

            data = collect_audit_logs()
            await process_events(data, redis)

        except Exception as e:
            print(f"Worker error: {e}")
            
        await asyncio.sleep(POLLING_INTERVAL)