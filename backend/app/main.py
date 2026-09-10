import asyncio
import logging

from contextlib import asynccontextmanager
from fastapi import FastAPI
from redis.asyncio import Redis

from backend.app.services.kubernetes_service import KubernetesService
from backend.app.services.permission_scanner import scan_dangerous_permissions
from backend.app.services.redis_service import save_dangerous_permissions
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

    worker_task = asyncio.create_task(run_pipeline(redis, k8s))

    yield

    worker_task.cancel()

    try:
        await worker_task
    except asyncio.CancelledError:
        pass

    await redis.aclose()
    k8s.api_client.close()


app = FastAPI(lifespan=lifespan)
app.include_router(output_router)
app.include_router(dangerous_permissions_router)


@app.get("/")
def health_check():
    return {"health": "ok"}