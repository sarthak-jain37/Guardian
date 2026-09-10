import os
from dotenv import load_dotenv

load_dotenv()

REDIS_URL = os.getenv("REDIS_URL", "redis://localhost:6379/0")
POLLING_INTERVAL = os.getenv("POLLING_INTERVAL", "10")
BACKEND_URL = os.getenv("BACKEND_URL", "http://127.0.0.1:8000")
MODEL_PATH = os.getenv("MODEL_PATH", "")
KUBERNETES_AUDIT_LOG_PATH = os.getenv(
    "KUBERNETES_AUDIT_LOG_PATH",
    "/tmp/guardian-audit/audit.log",
)