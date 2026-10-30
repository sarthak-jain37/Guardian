import logging
from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import StreamingResponse

from backend.app.services import baseline_service
from backend.app.services.drift_detector import run_drift_scan
from backend.app.services.event_bus import sse_event_stream
from backend.app.services.redis_service import (
    get_approval_queue_entry,
    get_pending_approvals,
    get_resolved_approvals,
)

logger = logging.getLogger(__name__)

router = APIRouter(
    tags=["approval"],
)

def legacy_write_disabled():
    raise HTTPException(410, detail={
        "code": "legacy_execution_retired",
        "message": "This legacy decision/apply/revert path is retired. Use governed review; cluster execution remains disabled until its safeguards are implemented.",
    })


SEVERITY_ORDER = {
    "CRITICAL": 3,
    "HIGH": 2,
    "LOW": 1,
}


@router.get("/approval/stream")
async def approval_stream(request: Request, max_events: int | None = None):
    """Real-time Server-Sent Events (SSE) notification stream for drift and approval events."""
    redis = getattr(request.app.state, "redis", None)
    return StreamingResponse(
        sse_event_stream(redis=redis, max_events=max_events),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "Connection": "keep-alive",
            "X-Accel-Buffering": "no",
        },
    )


@router.get("/approval/queue")
async def list_pending_approvals(request: Request):
    """Return all PENDING approval queue entries, sorted by risk (CRITICAL first)."""
    redis = request.app.state.redis
    entries = await get_pending_approvals(redis)

    entries.sort(
        key=lambda e: (-SEVERITY_ORDER.get(e.get("risk_tier", "LOW"), 0), e.get("created_at", "")),
    )

    return {
        "count": len(entries),
        "entries": entries,
    }


@router.get("/approval/history")
async def list_resolved_approvals(request: Request, limit: int = 50):
    """Return resolved approval entries (PROMOTED, REJECTED, REVERTED, DISMISSED) for audit history."""
    redis = request.app.state.redis
    resolved = await get_resolved_approvals(redis, limit=limit)
    return {
        "count": len(resolved),
        "history": resolved,
    }


@router.get("/approval/{queue_id}")
async def get_approval_detail(queue_id: str, request: Request):
    """Return full detail of one approval entry (diff, LLM analysis, history)."""
    redis = request.app.state.redis
    entry = await get_approval_queue_entry(queue_id, redis)
    if not entry:
        raise HTTPException(status_code=404, detail="Approval entry not found")
    return entry


@router.post("/approval/{queue_id}/decision")
async def submit_decision(queue_id: str):
    legacy_write_disabled()


@router.post("/approval/{queue_id}/revert")
async def revert_drift_endpoint(queue_id: str):
    legacy_write_disabled()


@router.post("/drift/scan-now")
async def trigger_manual_scan(request: Request):
    """Trigger an immediate drift scan (for demo/debugging)."""
    redis = request.app.state.redis
    k8s = request.app.state.k8s

    findings = await run_drift_scan(redis, k8s)
    return {
        "status": "completed",
        "findings_count": len(findings),
        "findings": findings,
    }


# =========================================================================
# Baseline Lifecycle & State Management Endpoints
# =========================================================================


@router.get("/baselines/active")
async def get_active_baseline_endpoint(request: Request, sa_key: str = "__CLUSTER__"):
    """Read legacy baseline history; this is not authenticated governance authority."""
    redis = request.app.state.redis
    baseline = await baseline_service.get_active_baseline(sa_key, redis)
    if not baseline:
        raise HTTPException(status_code=404, detail=f"No active baseline for '{sa_key}'")
    return {**baseline, "authority_verified": False, "source": "legacy_redis"}


@router.get("/baselines/history")
async def get_baseline_history_endpoint(request: Request, sa_key: str = "__CLUSTER__"):
    """Fetch complete baseline version history (ACTIVE, SUPERSEDED, BROKEN_ROLLBACK, REJECTED)."""
    redis = request.app.state.redis
    history = await baseline_service.get_baseline_history(sa_key, redis)
    return {
        "sa_key": sa_key,
        "count": len(history),
        "history": history,
        "authority_verified": False,
        "source": "legacy_redis",
    }


@router.get("/baselines/{baseline_id}")
async def get_baseline_detail_endpoint(baseline_id: str, request: Request):
    """Fetch detail of a specific baseline version."""
    redis = request.app.state.redis
    b = await baseline_service.get_baseline(baseline_id, redis)
    if not b:
        raise HTTPException(status_code=404, detail="Baseline not found")
    return {**b, "authority_verified": False, "source": "legacy_redis"}


@router.post("/baselines/{baseline_id}/rollback")
async def rollback_baseline_endpoint(baseline_id: str):
    legacy_write_disabled()


@router.post("/baselines/{baseline_id}/apply")
async def apply_baseline_endpoint(baseline_id: str):
    legacy_write_disabled()


