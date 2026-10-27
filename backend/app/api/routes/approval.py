from datetime import datetime, timezone
import logging
from fastapi import APIRouter, HTTPException, Request

from backend.app.models.approval import ApprovalDecision
from backend.app.services import baseline_service
from backend.app.services.canonical_hash import canonical_hash
from backend.app.services.drift_detector import create_conflict_recheck, run_drift_scan
from backend.app.services.redis_service import (
    get_approval_queue_entry,
    get_pending_approvals,
    update_approval_queue_entry,
)

logger = logging.getLogger(__name__)

router = APIRouter(
    tags=["approval"],
)

SEVERITY_ORDER = {
    "CRITICAL": 3,
    "HIGH": 2,
    "LOW": 1,
}


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


@router.get("/approval/{queue_id}")
async def get_approval_detail(queue_id: str, request: Request):
    """Return full detail of one approval entry (diff, LLM analysis, history)."""
    redis = request.app.state.redis
    entry = await get_approval_queue_entry(queue_id, redis)
    if not entry:
        raise HTTPException(status_code=404, detail="Approval entry not found")
    return entry


@router.post("/approval/{queue_id}/decision")
async def submit_decision(queue_id: str, body: ApprovalDecision, request: Request):
    """
    body: { "decision": "promote" | "reject", "actor": "username", "note": "..." }

    If promote:
    1. Checkpoint 2 (Version Guard): re-read cluster state and compare hashes.
    2. Call baseline_service.promote_baseline(baseline_id, actor)
    3. Update queue entry status to PROMOTED

    If reject:
    1. Call baseline_service.reject_baseline(baseline_id)
    2. Update queue entry status to REJECTED
    """
    redis = request.app.state.redis
    k8s = request.app.state.k8s

    queue_entry = await get_approval_queue_entry(queue_id, redis)
    if not queue_entry:
        raise HTTPException(status_code=404, detail="Approval entry not found")

    baseline_id = queue_entry.get("baseline_id")
    if not baseline_id:
        raise HTTPException(status_code=400, detail="Approval entry missing baseline_id")

    if body.decision == "promote":
        original_snapshot_hash = queue_entry.get("snapshot_hash")
        fresh_live_state = k8s.get_rbac_state()
        current_hash = canonical_hash(fresh_live_state)

        # Checkpoint 2: Re-check if cluster state mutated since detection
        if current_hash != original_snapshot_hash:
            logger.warning(
                "Version Guard Checkpoint 2 Conflict: detection hash %s != live hash %s",
                original_snapshot_hash,
                current_hash,
            )
            new_entry = await create_conflict_recheck(queue_id, fresh_live_state, redis)
            return {
                "status": "conflict",
                "new_queue_id": new_entry.get("id", queue_id),
                "message": "Cluster state changed since detection. Please review updated diff.",
            }

        # Safe - proceed with promotion
        await baseline_service.promote_baseline(baseline_id, body.actor, redis)
        await update_approval_queue_entry(
            queue_id,
            {
                "status": "PROMOTED",
                "resolved_by": body.actor,
                "resolved_at": datetime.now(timezone.utc).isoformat(),
            },
            redis,
        )
        return {"status": "promoted"}

    elif body.decision == "reject":
        await baseline_service.reject_baseline(baseline_id, redis)
        await update_approval_queue_entry(
            queue_id,
            {
                "status": "REJECTED",
                "resolved_by": body.actor,
                "resolved_at": datetime.now(timezone.utc).isoformat(),
            },
            redis,
        )
        return {"status": "rejected"}

    raise HTTPException(status_code=400, detail=f"Invalid decision '{body.decision}'")


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
    """Fetch the currently authoritative ACTIVE baseline for an SA or cluster."""
    redis = request.app.state.redis
    baseline = await baseline_service.get_active_baseline(sa_key, redis)
    if not baseline:
        raise HTTPException(status_code=404, detail=f"No active baseline for '{sa_key}'")
    return baseline


@router.get("/baselines/history")
async def get_baseline_history_endpoint(request: Request, sa_key: str = "__CLUSTER__"):
    """Fetch complete baseline version history (ACTIVE, SUPERSEDED, BROKEN_ROLLBACK, REJECTED)."""
    redis = request.app.state.redis
    history = await baseline_service.get_baseline_history(sa_key, redis)
    return {
        "sa_key": sa_key,
        "count": len(history),
        "history": history,
    }


@router.get("/baselines/{baseline_id}")
async def get_baseline_detail_endpoint(baseline_id: str, request: Request):
    """Fetch detail of a specific baseline version."""
    redis = request.app.state.redis
    b = await baseline_service.get_baseline(baseline_id, redis)
    if not b:
        raise HTTPException(status_code=404, detail="Baseline not found")
    return b


@router.post("/baselines/{baseline_id}/rollback")
async def rollback_baseline_endpoint(baseline_id: str, request: Request):
    """
    Transition an ACTIVE baseline to BROKEN_ROLLBACK:
    1. Sets status to BROKEN_ROLLBACK
    2. Blocklists canonical hash in rbac:baselines:broken_hashes
    3. Restores parent baseline (parent_id) to ACTIVE
    """
    redis = request.app.state.redis
    baseline = await baseline_service.get_baseline(baseline_id, redis)
    if not baseline:
        raise HTTPException(status_code=404, detail="Baseline not found")

    parent_id = baseline.get("parent_id")
    await baseline_service.mark_broken_rollback(baseline_id, redis)

    restored = await baseline_service.get_baseline(parent_id, redis) if parent_id else None

    return {
        "status": "rolled_back",
        "broken_baseline_id": baseline_id,
        "restored_parent_id": parent_id,
        "restored_baseline": restored,
        "message": f"Baseline {baseline_id} marked BROKEN_ROLLBACK. Parent baseline {parent_id} restored to ACTIVE.",
    }

