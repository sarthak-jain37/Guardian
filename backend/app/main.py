import asyncio

from contextlib import asynccontextmanager
from fastapi import FastAPI
from redis.asyncio import Redis

from backend.app.api.routes.output import router as output_router
from backend.app.workers.worker import run_pipeline
from backend.app.core.config import REDIS_URL

@asynccontextmanager
async def lifespan(app: FastAPI):
    redis = Redis.from_url(REDIS_URL, decode_responses=True)
    
    app.state.redis = redis

    worker_task = asyncio.create_task(run_pipeline(redis))

    yield

    worker_task.cancel()

    try:
        await worker_task
    except asyncio.CancelledError:
        pass

    await redis.aclose()


app = FastAPI(lifespan=lifespan)
app.include_router(output_router)

@app.get("/")
def health_check():
    return {"health": "ok"}