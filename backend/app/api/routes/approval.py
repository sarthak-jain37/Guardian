from datetime import datetime, timezone
import logging
from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import StreamingResponse

from backend.app.models.approval import ApprovalDecision
from backend.app.services import baseline_service
from backend.app.services.canonical_hash import canonical_hash
from backend.app.services.drift_detector import create_conflict_recheck, run_drift_scan
from backend.app.services.event_bus import publish_event, sse_event_stream
from backend.app.services.redis_service import (
    get_approval_queue_entry,
    get_pending_approvals,
    get_resolved_approvals,
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
async def submit_decision(queue_id: str, body: ApprovalDecision, request: Request):
    """
    body: { "decision": "promote" | "reject" | "revert" | "dismiss", "actor": "username", "note": "...", "apply_to_cluster": bool }

    If promote:
    1. Checkpoint 2 (Version Guard): re-read cluster state and compare hashes.
    2. Call baseline_service.promote_baseline(baseline_id, actor)
    3. If apply_to_cluster or NEW_POLICY, apply approved state to live K8s cluster.
    4. Update queue entry status to PROMOTED and broadcast BASELINE_PROMOTED.

    If reject:
    1. Call baseline_service.reject_baseline(baseline_id)
    2. Update queue entry status to REJECTED and broadcast APPROVAL_DECISION.

    If revert:
    1. Fetch active baseline for queue_entry's sa_key.
    2. Call k8s.revert_to_baseline(active_baseline["rbac_state"]).
    3. Update queue entry status to REVERTED with execution receipt.
    4. Broadcast DRIFT_REVERTED.

    If dismiss:
    1. Mark queue entry status as DISMISSED.
    2. Broadcast APPROVAL_DECISION.
    """
    redis = request.app.state.redis
    k8s = getattr(request.app.state, "k8s", None)

    queue_entry = await get_approval_queue_entry(queue_id, redis)
    if not queue_entry:
        raise HTTPException(status_code=404, detail="Approval entry not found")

    baseline_id = queue_entry.get("baseline_id")
    if not baseline_id:
        raise HTTPException(status_code=400, detail="Approval entry missing baseline_id")

    sa_key = queue_entry.get("sa_key") or "__CLUSTER__"

    if body.decision == "promote":
        original_snapshot_hash = queue_entry.get("snapshot_hash")
        if k8s:
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

        # Optional or policy-triggered cluster push
        cluster_receipt = None
        if body.apply_to_cluster or queue_entry.get("event_type") == "NEW_POLICY":
            promoted_b = await baseline_service.get_baseline(baseline_id, redis)
            if promoted_b and promoted_b.get("rbac_state") and k8s:
                cluster_receipt = k8s.apply_state(promoted_b["rbac_state"])

        await update_approval_queue_entry(
            queue_id,
            {
                "status": "PROMOTED",
                "resolved_by": body.actor,
                "resolved_at": datetime.now(timezone.utc).isoformat(),
            },
            redis,
        )

        event_payload = {
            "queue_id": queue_id,
            "baseline_id": baseline_id,
            "actor": body.actor,
            "cluster_receipt": cluster_receipt,
        }
        await publish_event("BASELINE_PROMOTED", event_payload, redis=redis)
        return {"status": "promoted", "cluster_receipt": cluster_receipt}

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
        await publish_event(
            "APPROVAL_DECISION",
            {"queue_id": queue_id, "decision": "reject", "actor": body.actor},
            redis=redis,
        )
        return {"status": "rejected"}

    elif body.decision == "revert":
        active_baseline = await baseline_service.get_active_baseline(sa_key, redis)
        if not active_baseline or not active_baseline.get("rbac_state"):
            raise HTTPException(status_code=400, detail=f"No active baseline found for '{sa_key}' to revert to.")

        if not k8s:
            raise HTTPException(status_code=500, detail="Kubernetes service unavailable for cluster reversion.")

        receipt = k8s.revert_to_baseline(active_baseline["rbac_state"])
        await update_approval_queue_entry(
            queue_id,
            {
                "status": "REVERTED",
                "resolved_by": body.actor,
                "resolved_at": datetime.now(timezone.utc).isoformat(),
                "revert_receipt": receipt,
            },
            redis,
        )

        await publish_event(
            "DRIFT_REVERTED",
            {"queue_id": queue_id, "sa_key": sa_key, "receipt": receipt, "actor": body.actor},
            redis=redis,
        )
        return {
            "status": "reverted",
            "receipt": receipt,
            "message": f"Cluster permissions reverted to approved active baseline {active_baseline.get('baseline_id')}.",
        }

    elif body.decision == "dismiss":
        await update_approval_queue_entry(
            queue_id,
            {
                "status": "DISMISSED",
                "resolved_by": body.actor,
                "resolved_at": datetime.now(timezone.utc).isoformat(),
                "note": body.note or "",
            },
            redis,
        )
        await publish_event(
            "APPROVAL_DECISION",
            {"queue_id": queue_id, "decision": "dismiss", "actor": body.actor},
            redis=redis,
        )
        return {"status": "dismissed", "queue_id": queue_id}

    raise HTTPException(status_code=400, detail=f"Invalid decision '{body.decision}'")


@router.post("/approval/{queue_id}/revert")
async def revert_drift_endpoint(queue_id: str, request: Request, actor: str = "admin"):
    """
    Dedicated endpoint to immediately enforce active baseline on K8s and reconcile the drift.
    """
    redis = request.app.state.redis
    k8s = getattr(request.app.state, "k8s", None)

    queue_entry = await get_approval_queue_entry(queue_id, redis)
    if not queue_entry:
        raise HTTPException(status_code=404, detail="Approval entry not found")

    sa_key = queue_entry.get("sa_key") or "__CLUSTER__"
    active_baseline = await baseline_service.get_active_baseline(sa_key, redis)
    if not active_baseline or not active_baseline.get("rbac_state"):
        raise HTTPException(status_code=400, detail=f"No active baseline found for '{sa_key}' to revert to.")

    if not k8s:
        raise HTTPException(status_code=500, detail="Kubernetes service unavailable for cluster reversion.")

    receipt = k8s.revert_to_baseline(active_baseline["rbac_state"])
    await update_approval_queue_entry(
        queue_id,
        {
            "status": "REVERTED",
            "resolved_by": actor,
            "resolved_at": datetime.now(timezone.utc).isoformat(),
            "revert_receipt": receipt,
        },
        redis,
    )

    await publish_event(
        "DRIFT_REVERTED",
        {"queue_id": queue_id, "sa_key": sa_key, "receipt": receipt, "actor": actor},
        redis=redis,
    )

    return {
        "status": "reverted",
        "queue_id": queue_id,
        "receipt": receipt,
        "message": f"Cluster permissions successfully reverted to active baseline {active_baseline.get('baseline_id')}.",
    }


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
    4. Actively enforces restored parent baseline on the live Kubernetes cluster.
    """
    redis = request.app.state.redis
    k8s = getattr(request.app.state, "k8s", None)

    baseline = await baseline_service.get_baseline(baseline_id, redis)
    if not baseline:
        raise HTTPException(status_code=404, detail="Baseline not found")

    parent_id = baseline.get("parent_id")
    if not parent_id:
        raise HTTPException(
            status_code=400,
            detail=f"Cannot rollback baseline {baseline_id}: it has no parent baseline.",
        )

    await baseline_service.mark_broken_rollback(baseline_id, redis)
    restored = await baseline_service.get_baseline(parent_id, redis)

    enforcement_receipt = None
    if restored and restored.get("rbac_state") and k8s:
        try:
            enforcement_receipt = k8s.revert_to_baseline(restored["rbac_state"])
        except Exception as e:
            logger.error(f"Failed enforcing parent baseline {parent_id} on cluster during rollback: {e}")
            enforcement_receipt = {"status": "error", "message": str(e)}

    await publish_event(
        "BASELINE_ROLLED_BACK",
        {
            "broken_baseline_id": baseline_id,
            "restored_parent_id": parent_id,
            "enforcement_receipt": enforcement_receipt,
        },
        redis=redis,
    )

    return {
        "status": "rolled_back",
        "broken_baseline_id": baseline_id,
        "restored_parent_id": parent_id,
        "restored_baseline": restored,
        "enforcement_receipt": enforcement_receipt,
        "message": f"Baseline {baseline_id} marked BROKEN_ROLLBACK. Parent baseline {parent_id} restored and enforced on cluster.",
    }


@router.post("/baselines/{baseline_id}/apply")
async def apply_baseline_endpoint(baseline_id: str, request: Request):
    """
    Explicit endpoint to apply any approved baseline directly to the live Kubernetes cluster.
    """
    redis = request.app.state.redis
    k8s = getattr(request.app.state, "k8s", None)

    if not k8s:
        raise HTTPException(status_code=500, detail="Kubernetes service unavailable for resource application.")

    baseline = await baseline_service.get_baseline(baseline_id, redis)
    if not baseline:
        raise HTTPException(status_code=404, detail="Baseline not found")

    rbac_state = baseline.get("rbac_state")
    if not rbac_state:
        raise HTTPException(status_code=400, detail=f"Baseline {baseline_id} has no RBAC state to apply.")

    receipt = k8s.revert_to_baseline(rbac_state)
    await publish_event(
        "POLICY_APPLIED",
        {"baseline_id": baseline_id, "receipt": receipt},
        redis=redis,
    )

    return {
        "status": "applied",
        "baseline_id": baseline_id,
        "receipt": receipt,
        "message": f"Baseline {baseline_id} permissions successfully applied to cluster.",
    }


