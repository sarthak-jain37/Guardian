from fastapi import APIRouter, Request

from backend.app.services.redis_service import get_dangerous_permissions

router = APIRouter(
    prefix="/dangerous-permissions",
    tags=["dangerous-permissions"],
)


@router.get("")
@router.get("/")
async def get_permissions(request: Request):
    redis = request.app.state.redis
    findings = await get_dangerous_permissions(redis)

    return {
        "count": len(findings),
        "findings": findings,
    }
