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
from backend.app.services.observations import capture_startup_observation
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
    redis = Redis.from_url(REDIS_URL, decode_responses=True, socket_timeout=30, socket_connect_timeout=10)
    k8s = KubernetesService()
    
    app.state.redis = redis
    app.state.k8s = k8s
    app.state.telemetry = Telemetry(redis)
    from backend.app.services.permission_proposals import PermissionProposals
    app.state.permission_proposals = PermissionProposals(redis,k8s,app.state.telemetry.cluster)
    await app.state.permission_proposals.recover_interrupted()
    app.state.pod_grader = PodGrader(app.state.telemetry)
    app.state.pod_grader.proposals = app.state.permission_proposals
    telemetry_tasks = app.state.telemetry.start()
    telemetry_tasks.append(asyncio.create_task(app.state.pod_grader.run()))
    telemetry_tasks.append(asyncio.create_task(refresh_inventory(app.state.telemetry, k8s)))

    # Seed dangerous permissions cache on application startup
    try:
        logging.info("Running initial RBAC dangerous permissions scan on startup...")
        current_state = await capture_startup_observation(redis, k8s)
        findings = scan_dangerous_permissions(current_state)
        await save_dangerous_permissions(findings, redis)
        logging.info(
            "Initial scan completed: found %d roles with dangerous permissions",
            len(findings),
        )
    except Exception:
        logging.exception("Failed initial RBAC scan on startup (K8s cluster may be unavailable)")

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

    for task in list(app.state.permission_proposals.tasks):task.cancel()
    await asyncio.gather(*app.state.permission_proposals.tasks,return_exceptions=True)
    await redis.aclose()
    k8s.api_client.close()


app = FastAPI(lifespan=lifespan)
app.include_router(output_router)
app.include_router(telemetry_router)
app.include_router(dangerous_permissions_router)
app.include_router(approval_router)



@app.get("/")
def health_check():
    return {"health": "ok", "execution_enabled": False}
