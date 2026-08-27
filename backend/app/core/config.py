import os
from dotenv import load_dotenv

load_dotenv()

REDIS_URL = os.getenv("REDIS_URL")
POLLING_INTERVAL = os.getenv("POLLING_INTERVAL")