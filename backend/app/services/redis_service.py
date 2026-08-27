from redis.asyncio import Redis

async def get_last_processed_timestamp(event_type, redis: Redis):
    return await redis.get(event_type)
            
async def set_last_processed_timestamp(event_type, timestamp, redis: Redis):
    await redis.set(event_type, timestamp)
    
