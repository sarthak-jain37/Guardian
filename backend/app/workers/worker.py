import asyncio
import logging
from backend.app.services.audit_collector import collect_audit_logs
from backend.app.services.event_processor import process_events
from backend.app.services.drift_detector import run_drift_scan
from backend.app.services.kubernetes_service import KubernetesService
from backend.app.core.config import POLLING_INTERVAL

logger = logging.getLogger(__name__)

async def run_pipeline(redis, k8s: KubernetesService):
    while True:
        try:
            logger.info("Checking audit logs")
            data = collect_audit_logs()
            logger.info("Processing events")
            await process_events(data, redis, k8s)

            # Periodic drift scan
            drift_findings = await run_drift_scan(redis, k8s)
            if drift_findings:
                logger.info("Drift detected: %d findings", len(drift_findings))

        except Exception:
            logger.exception("Worker error")
        await asyncio.sleep(int(POLLING_INTERVAL))