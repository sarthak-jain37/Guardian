from fastapi import APIRouter, Request

from backend.app.services.redis_service import get_all_drift_events

router = APIRouter(
    prefix="/outputs",
    tags=["outputs"],
)

@router.get("/")
async def get_output(request: Request):
    redis = request.app.state.redis

    events = await get_all_drift_events(redis)
    
    return {
        "count": len(events),
        "events": events,
    }