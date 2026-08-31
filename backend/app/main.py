import asyncio
import logging

from contextlib import asynccontextmanager
from fastapi import FastAPI
from redis.asyncio import Redis

from backend.app.services.kubernetes_service import KubernetesService
from backend.app.api.routes.output import router as output_router
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

@app.get("/")
def health_check():
    return {"health": "ok"}