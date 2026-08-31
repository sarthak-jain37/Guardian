from datetime import datetime

def parse_timestamp(timestamp) -> datetime:
        
    return datetime.fromisoformat(
        timestamp.replace("Z", "+00:00")
    )
    
def get_latest_event_timestamp(data, event_types) -> datetime | None:
    timestamps = []

    for event_type in event_types:
        if event_type in data:
            timestamps.extend(
                data[event_type].get("timestamps", [])
            )

    if not timestamps:
        return None

    return max(
        parse_timestamp(timestamp)
        for timestamp in timestamps
    )