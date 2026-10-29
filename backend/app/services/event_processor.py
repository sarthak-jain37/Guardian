from agents.summarizer import analyse_document
from backend.app.services.kubernetes_service import KubernetesService
from backend.app.services.permission_scanner import scan_dangerous_permissions
from backend.app.services.script_runner import run_apply_script, run_modify_script
from backend.app.services.drift_detector import run_drift_scan
from backend.app.services.redis_service import (
    get_last_processed_timestamp,
    get_rbac_state,
    save_dangerous_permissions,
    save_drift_event,
    save_rbac_state,
    set_last_processed_timestamp,
)
from backend.app.utils.helpers import get_latest_event_timestamp, parse_timestamp

APPLY_FIELDS = [
    "kubectl-client-side-apply",
    "kubectl-server-side-apply"
]

MODIFY_FIELDS = [
    "kubectl-edit",
    "kubectl-create",
    "kubectl-patch"
] 

BASELINE_KEY = "rbac:baseline"
CURRENT_KEY = "rbac:current"


async def process_events(data, redis, k8s: KubernetesService) -> None:
    most_recent_apply = get_latest_event_timestamp(data, APPLY_FIELDS)
    most_recent_modify = get_latest_event_timestamp(data, MODIFY_FIELDS)

    last_processed_apply = await get_last_processed_timestamp("apply", redis)
    last_processed_modify = await get_last_processed_timestamp("modify", redis)

    if last_processed_apply:
        last_processed_apply = parse_timestamp(last_processed_apply)
    if last_processed_modify:
        last_processed_modify = parse_timestamp(last_processed_modify)

    if most_recent_apply and (last_processed_apply is None or most_recent_apply > last_processed_apply):
        observed = run_apply_script(k8s)
        # fieldManager/userAgent are provenance, never approval. An external
        # apply updates observed state without replacing approved desired state.
        await save_rbac_state(CURRENT_KEY, observed, redis)
        await set_last_processed_timestamp("apply", most_recent_apply.isoformat(), redis)

        # Trigger dangerous permission scan on new baseline apply
        findings = scan_dangerous_permissions(observed)
        await save_dangerous_permissions(findings, redis)
        
    if most_recent_modify and (last_processed_modify is None or most_recent_modify > last_processed_modify):
        # On modify events: trigger drift detection
        try:
            await run_drift_scan(redis, k8s)
        except Exception:
            pass

        baseline = await get_rbac_state(BASELINE_KEY, redis)
        current, diff_dict = run_modify_script(k8s, baseline)
        
        await save_rbac_state(CURRENT_KEY, current, redis)
        
        if diff_dict:
            try:
                llm_response = analyse_document(diff_dict)
            except Exception:
                llm_response = "Automated analysis unavailable"
            
            await save_drift_event(diff_dict, llm_response, redis)
        
        await set_last_processed_timestamp("modify", most_recent_modify.isoformat(), redis)

        # Trigger dangerous permission scan on RBAC modification
        findings = scan_dangerous_permissions(current)
        await save_dangerous_permissions(findings, redis)
