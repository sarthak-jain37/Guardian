from backend.app.services.kubernetes_service import KubernetesService
from backend.app.services.script_runner import run_apply_script, run_modify_script
from backend.app.services.redis_service import get_last_processed_timestamp, set_last_processed_timestamp
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
        run_apply_script(k8s)

        await set_last_processed_timestamp( "apply", most_recent_apply.isoformat(), redis)
        
    if most_recent_modify and (last_processed_modify is None or most_recent_modify > last_processed_modify):
        run_modify_script(k8s)
        
        await set_last_processed_timestamp("modify", most_recent_modify.isoformat(), redis)