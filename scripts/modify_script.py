import json
from deepdiff import DeepDiff
from backend.app.services.kubernetes_service import KubernetesService
import logging

logger = logging.getLogger(__name__)

def run_modify(k8s: KubernetesService, baseline: dict) -> tuple[dict, dict | None]:

    """Fetch current RBAC state, compare against baseline, and record drift."""

    if baseline is None:
        logger.warning("Baseline is missing or empty.")

    current = k8s.get_rbac_state()

    diff = DeepDiff(
        baseline,
        current,
        ignore_order=True,
        verbose_level=2,
    )

    if not diff:
        logger.info("No RBAC drift detected.")
        return current, None
    
    diff_dict = json.loads(diff.to_json())
    
    return current, diff_dict