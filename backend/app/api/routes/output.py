from fastapi import APIRouter

router = APIRouter()

@router.get("/output")
async def get_output():
    # Get latest result from Redis
    return