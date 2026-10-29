import json
import logging
import uuid
from datetime import datetime, timezone
from typing import Any
from deepdiff import DeepDiff
from redis.asyncio import Redis

from agents.summarizer import analyse_document
from backend.app.services.baseline_service import (
    create_baseline,
    get_active_baseline,
)
from backend.app.services.canonical_hash import canonical_hash
from backend.app.services.event_bus import publish_event
from backend.app.services.kubernetes_service import KubernetesService
from backend.app.services.redis_service import (
    get_approval_queue_entry,
    get_pending_approval_by_sa,
    save_approval_queue_entry,
    update_approval_queue_entry,
    save_rbac_state,
)

logger = logging.getLogger(__name__)

DANGEROUS_VERBS = {"bind", "impersonate", "escalate", "approve"}
HIGH_VALUE_RESOURCES = {
    "secrets",
    "rolebindings",
    "clusterroles",
    "certificatesigningrequests",
}
CRITICAL_NAMESPACES = {"kube-system", "kube-public"}
WILDCARD = "*"


def _sanitize_diff(diff_dict: Any) -> dict[str, Any]:
    """Convert DeepDiff output to a clean JSON-serializable dict."""
    if hasattr(diff_dict, "to_json"):
        return json.loads(diff_dict.to_json())
    try:
        return json.loads(json.dumps(diff_dict, default=str))
    except Exception:
        return {"raw": str(diff_dict)}


def _search_diff_strings(obj: Any) -> list[str]:
    """Extract all text tokens/strings from a nested diff structure."""
    tokens = []
    if isinstance(obj, dict):
        for k, v in obj.items():
            tokens.append(str(k))
            tokens.extend(_search_diff_strings(v))
    elif isinstance(obj, (list, tuple, set)):
        for item in obj:
            tokens.extend(_search_diff_strings(item))
    else:
        tokens.append(str(obj))
    return tokens


def classify_drift_risk(diff_dict: dict[str, Any], active_state: dict[str, Any], live_state: dict[str, Any]) -> str:
    """
    Returns "CRITICAL", "HIGH", or "LOW".

    CRITICAL if diff touches:
    - Any wildcard in verbs/resources/apiGroups
    - Any dangerous verb (bind, impersonate, escalate, approve)
    - Any change in kube-system or kube-public namespace

    HIGH if diff touches:
    - High-value resources (secrets, rolebindings, etc.)

    LOW otherwise.
    """
    tokens = [t.lower() for t in _search_diff_strings(diff_dict)]
    joined_text = " ".join(tokens)

    # 1. Check CRITICAL conditions
    for ns in CRITICAL_NAMESPACES:
        if ns in joined_text:
            return "CRITICAL"

    for dv in DANGEROUS_VERBS:
        if dv in tokens or f"'{dv}'" in joined_text or f'"{dv}"' in joined_text:
            return "CRITICAL"

    if WILDCARD in tokens or "'*'" in joined_text or '"*"' in joined_text:
        return "CRITICAL"

    # 2. Check HIGH conditions
    for hr in HIGH_VALUE_RESOURCES:
        if hr in tokens or f"'{hr}'" in joined_text or f'"{hr}"' in joined_text:
            return "HIGH"

    return "LOW"


async def run_drift_scan(redis: Redis, k8s: KubernetesService) -> list[dict[str, Any]]:
    """
    Main entry point for drift scanning. Called by:
    - The scheduled worker loop
    - A manual "Scan Now" API endpoint

    Steps:
    1. Get current live RBAC state from K8s API
    2. Get the ACTIVE baseline from Redis (via baseline_service)
    3. If no active baseline exists -> retain observed state without adoption
    4. Compare canonical hashes
    5. If match -> return empty list (no drift)
    6. If mismatch:
       a. Compute DeepDiff(active_state, live_state)
       b. Classify risk tier
       c. Run LLM analysis on the diff
       d. Handle Lazy Grouping / update or create approval queue entry
       e. Create PENDING_APPROVAL baseline entry
       f. Return list of drift findings
    """
    try:
        live_state = k8s.get_rbac_state()
    except Exception as e:
        logger.error(f"Failed to fetch live RBAC state from K8s: {e}")
        return []

    sa_key = "__CLUSTER__"
    active_baseline = await get_active_baseline(sa_key, redis)

    if not active_baseline or not active_baseline.get("rbac_state"):
        logger.info("No approved baseline; retaining observed state for initial analysis.")
        await save_rbac_state("rbac:current", live_state, redis)
        return []

    live_hash = canonical_hash(live_state)
    active_state = active_baseline["rbac_state"]
    active_hash = active_baseline.get("canonical_hash") or canonical_hash(active_state)

    if live_hash == active_hash:
        logger.debug("Live cluster RBAC matches active baseline (%s). No drift.", live_hash)
        return []

    logger.warning("Drift detected! Baseline hash: %s != Live hash: %s", active_hash, live_hash)

    # 6.a Compute DeepDiff
    diff_raw = DeepDiff(active_state, live_state, ignore_order=True)
    diff = _sanitize_diff(diff_raw)

    # 6.b Classify risk tier
    risk_tier = classify_drift_risk(diff, active_state, live_state)

    # 6.c Run LLM analysis on the diff
    try:
        llm_analysis = analyse_document(diff)
    except Exception as err:
        logger.warning(f"LLM summarizer failed on drift diff: {err}")
        llm_analysis = f"Automated analysis unavailable: {err}"

    # 6.d Lazy Grouping (Version Chain Collapse)
    pending_entry = await get_pending_approval_by_sa(sa_key, redis)
    now_iso = datetime.now(timezone.utc).isoformat()

    if pending_entry:
        queue_id = pending_entry["id"]
        prev_latest = pending_entry.get("latest_state") or active_state
        diff_from_prev = _sanitize_diff(DeepDiff(prev_latest, live_state, ignore_order=True))

        version_count = int(pending_entry.get("version_count", 1)) + 1
        version_chain = pending_entry.get("version_chain") or []
        version_chain.append({
            "version": version_count,
            "state_hash": live_hash,
            "diff_from_prev": diff_from_prev,
            "timestamp": now_iso,
            "severity": risk_tier,
            "confidence": 0.90,
        })

        original_state = pending_entry.get("original_state") or active_state
        net_diff = _sanitize_diff(DeepDiff(original_state, live_state, ignore_order=True))
        net_risk = classify_drift_risk(net_diff, original_state, live_state)

        try:
            net_llm = analyse_document(net_diff)
        except Exception:
            net_llm = llm_analysis

        new_baseline = await create_baseline(
            rbac_state=live_state,
            sa_key=sa_key,
            status="PENDING_APPROVAL",
            approved_by=None,
            run_id=None,
            redis=redis,
            parent_id=active_baseline.get("baseline_id"),
        )

        updates = {
            "baseline_id": new_baseline["baseline_id"],
            "latest_state": live_state,
            "net_diff": net_diff,
            "diff_summary": net_diff,
            "risk_tier": net_risk,
            "llm_analysis": net_llm,
            "version_count": version_count,
            "version_chain": version_chain,
            "snapshot_hash": live_hash,
        }
        await update_approval_queue_entry(queue_id, updates, redis)
        finding = {
            "queue_id": queue_id,
            "baseline_id": new_baseline["baseline_id"],
            "sa_key": sa_key,
            "risk_tier": net_risk,
            "diff": net_diff,
            "llm_analysis": net_llm,
            "lazy_grouped": True,
            "version_count": version_count,
        }
        await publish_event("DRIFT_DETECTED", finding, redis=redis)
        return [finding]

    else:
        new_baseline = await create_baseline(
            rbac_state=live_state,
            sa_key=sa_key,
            status="PENDING_APPROVAL",
            approved_by=None,
            run_id=None,
            redis=redis,
            parent_id=active_baseline.get("baseline_id"),
        )

        queue_id = str(uuid.uuid4())
        initial_chain = [{
            "version": 1,
            "state_hash": live_hash,
            "diff_from_prev": diff,
            "timestamp": now_iso,
            "severity": risk_tier,
            "confidence": 0.90,
        }]

        queue_entry = {
            "id": queue_id,
            "baseline_id": new_baseline["baseline_id"],
            "event_type": "DRIFT_DETECTED",
            "risk_tier": risk_tier,
            "status": "PENDING",
            "diff_summary": diff,
            "llm_analysis": llm_analysis,
            "sa_key": sa_key,
            "created_at": now_iso,
            "snapshot_hash": live_hash,
            "original_state": active_state,
            "latest_state": live_state,
            "net_diff": diff,
            "version_count": 1,
            "version_chain": initial_chain,
        }
        await save_approval_queue_entry(queue_entry, redis)

        finding = {
            "queue_id": queue_id,
            "baseline_id": new_baseline["baseline_id"],
            "sa_key": sa_key,
            "risk_tier": risk_tier,
            "diff": diff,
            "llm_analysis": llm_analysis,
            "lazy_grouped": False,
            "version_count": 1,
        }
        await publish_event("DRIFT_DETECTED", finding, redis=redis)
        return [finding]


async def scan_single_sa(
    sa_key: str,
    active_baseline: dict[str, Any],
    live_state: dict[str, Any],
    redis: Redis,
) -> dict[str, Any] | None:
    """Compare a single service account's baseline vs live state."""
    active_state = active_baseline.get("rbac_state") or {}
    live_hash = canonical_hash(live_state)
    active_hash = canonical_hash(active_state)

    if live_hash == active_hash:
        return None

    diff = _sanitize_diff(DeepDiff(active_state, live_state, ignore_order=True))
    risk_tier = classify_drift_risk(diff, active_state, live_state)
    return {
        "sa_key": sa_key,
        "risk_tier": risk_tier,
        "diff": diff,
        "canonical_hash_live": live_hash,
        "canonical_hash_active": active_hash,
    }


async def propose_llm_policy(
    input_state: dict[str, Any],
    llm_output: dict[str, Any],
    k8s: KubernetesService,
    redis: Redis,
    retry_count: int = 0,
) -> dict[str, Any]:
    """
    Checkpoint 1 (LLM Generation Race):
    Verify that cluster state did not change while LLM was generating a policy.
    Caps retries at 3 attempts per Section 6.4.
    """
    input_hash = canonical_hash(input_state)
    fresh_state = k8s.get_rbac_state()
    fresh_hash = canonical_hash(fresh_state)

    if fresh_hash != input_hash:
        if retry_count >= 3:
            msg = "Cluster state is actively changing. Manual review required."
            logger.warning("Version Guard: %s", msg)
            return {"status": "manual_review_required", "message": msg}

        logger.warning("Version Guard: cluster changed during LLM generation, re-running (attempt %d/3)", retry_count + 1)
        return {"status": "stale", "message": "Cluster state changed, re-running analysis"}

    # Safe to propose to approval queue
    sa_key = llm_output.get("sa_key", "__CLUSTER__")
    queue_id = str(uuid.uuid4())
    queue_entry = {
        "id": queue_id,
        "baseline_id": llm_output.get("baseline_id", ""),
        "event_type": "NEW_POLICY",
        "risk_tier": llm_output.get("risk_tier", "LOW"),
        "status": "PENDING",
        "diff_summary": llm_output.get("diff", {}),
        "llm_analysis": llm_output.get("analysis", ""),
        "sa_key": sa_key,
        "created_at": datetime.now(timezone.utc).isoformat(),
        "snapshot_hash": fresh_hash,
        "original_state": input_state,
        "latest_state": fresh_state,
        "net_diff": llm_output.get("diff", {}),
        "version_count": 1,
        "version_chain": [],
    }
    await save_approval_queue_entry(queue_entry, redis)
    await publish_event("NEW_POLICY_PROPOSED", {"queue_id": queue_id, "sa_key": sa_key, "risk_tier": queue_entry["risk_tier"]}, redis=redis)
    return {"status": "proposed", "queue_id": queue_id}


async def create_conflict_recheck(
    queue_id: str,
    fresh_live_state: dict[str, Any],
    redis: Redis,
) -> dict[str, Any]:
    """
    Called when human approval encounters a cluster state conflict (Checkpoint 2).
    Updates queue entry with new live state and net diff.
    """
    entry = await get_approval_queue_entry(queue_id, redis)
    original_state = entry.get("original_state", {}) if entry else {}
    net_diff = _sanitize_diff(DeepDiff(original_state, fresh_live_state, ignore_order=True))
    fresh_hash = canonical_hash(fresh_live_state)
    risk_tier = classify_drift_risk(net_diff, original_state, fresh_live_state)

    updates = {
        "latest_state": fresh_live_state,
        "net_diff": net_diff,
        "diff_summary": net_diff,
        "snapshot_hash": fresh_hash,
        "risk_tier": risk_tier,
    }
    await update_approval_queue_entry(queue_id, updates, redis)
    await publish_event("APPROVAL_CONFLICT", {"queue_id": queue_id, "risk_tier": risk_tier}, redis=redis)
    updated = await get_approval_queue_entry(queue_id, redis)
    return updated or {"id": queue_id}
