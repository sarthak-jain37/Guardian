import asyncio
import logging

from backend.app.services.grading import PodGrader
from backend.app.services.telemetry import Telemetry
from backend.app.services.pod_evidence import refresh_inventory
from backend.app.api.routes.telemetry import router as telemetry_router

from contextlib import asynccontextmanager
from fastapi import FastAPI
from redis.asyncio import Redis

from backend.app.services.kubernetes_service import KubernetesService
from backend.app.services.permission_scanner import scan_dangerous_permissions
from backend.app.services.redis_service import save_dangerous_permissions
import json

from backend.app.services.baseline_service import create_baseline, get_active_baseline
from backend.app.api.routes.approval import router as approval_router
from backend.app.api.routes.output import router as output_router
from backend.app.api.routes.dangerous_permissions import router as dangerous_permissions_router
from backend.app.workers.worker import run_pipeline
from backend.app.core.config import REDIS_URL

logging.basicConfig(
    level=logging.INFO,
    format="%(levelname)s: %(message)s - %(name)s - %(asctime)s ",
)

@asynccontextmanager
async def lifespan(app: FastAPI):
    redis = Redis.from_url(REDIS_URL, decode_responses=True)
    k8s = KubernetesService()
    
    app.state.redis = redis
    app.state.k8s = k8s
    app.state.telemetry = Telemetry(redis)
    app.state.pod_grader = PodGrader(app.state.telemetry)
    telemetry_tasks = app.state.telemetry.start()
    telemetry_tasks.append(asyncio.create_task(app.state.pod_grader.run()))
    telemetry_tasks.append(asyncio.create_task(refresh_inventory(app.state.telemetry, k8s)))

    # Seed dangerous permissions cache on application startup
    try:
        logging.info("Running initial RBAC dangerous permissions scan on startup...")
        current_state = k8s.get_rbac_state()
        findings = scan_dangerous_permissions(current_state)
        await save_dangerous_permissions(findings, redis)
        logging.info(
            "Initial scan completed: found %d roles with dangerous permissions",
            len(findings),
        )
    except Exception:
        logging.exception("Failed initial RBAC scan on startup (K8s cluster may be unavailable)")

    # Baseline Versioning Migration & Initialization
    try:
        active_cluster_baseline = await get_active_baseline("__CLUSTER__", redis)
        legacy_baseline_raw = await redis.get("rbac:baseline")

        if legacy_baseline_raw and not active_cluster_baseline:
            logging.info("Migrating legacy rbac:baseline key to new baseline versioning architecture...")
            legacy_baseline = json.loads(legacy_baseline_raw)
            await create_baseline(
                rbac_state=legacy_baseline,
                sa_key="__CLUSTER__",
                status="ACTIVE",
                approved_by="migration",
                run_id="startup-migration",
                redis=redis,
            )
            await redis.delete("rbac:baseline")
            logging.info("Migration of rbac:baseline completed successfully.")
        elif not active_cluster_baseline:
            logging.info("Seeding initial ACTIVE baseline from current cluster RBAC state...")
            current_state = k8s.get_rbac_state()
            await create_baseline(
                rbac_state=current_state,
                sa_key="__CLUSTER__",
                status="ACTIVE",
                approved_by="system_startup",
                run_id="startup-seed",
                redis=redis,
            )
            logging.info("Initial active baseline seeded.")
    except Exception:
        logging.exception("Failed baseline initialization / migration on startup")

    worker_task = asyncio.create_task(run_pipeline(redis, k8s))

    yield

    for task in telemetry_tasks:
        task.cancel()
    await asyncio.gather(*telemetry_tasks, return_exceptions=True)
    worker_task.cancel()

    try:
        await worker_task
    except asyncio.CancelledError:
        pass

    await redis.aclose()
    k8s.api_client.close()


app = FastAPI(lifespan=lifespan)
app.include_router(output_router)
app.include_router(telemetry_router)
app.include_router(dangerous_permissions_router)
app.include_router(approval_router)



@app.get("/")
def health_check():
    return {"health": "ok"}