import json
from datetime import datetime, timezone
from deepdiff import DeepDiff
from backend.app.services.kubernetes_service import KubernetesService
from backend.app.utils.yaml_utils import load_yaml, save_yaml
import logging

logger = logging.getLogger(__name__)

def run_modify(k8s: KubernetesService,
    baseline_file="baseline.yaml",
    current_file="current.yaml",
    diff_file="rbac_diff.yaml",
) -> None:

    """Fetch current RBAC state, compare against baseline, and record drift."""

    baseline_state = load_yaml(baseline_file)

    if not baseline_state:
        logger.warning("%s is missing or empty.", baseline_file)

    current_state = k8s.get_rbac_state()
    save_yaml(current_state, current_file)

    diff = DeepDiff(
        baseline_state,
        current_state,
        ignore_order=True,
        verbose_level=2,
    )

    if diff:
        diff_dict = json.loads(diff.to_json())

        diff_dict["_guardian_metadata"] = {
            "drift_detected_at": datetime.now(timezone.utc).strftime(
                "%Y-%m-%d-%H:%MUTC"
            )
        }

        save_yaml(diff_dict, diff_file)
        logger.info("Drift detected. Differences saved to %s", diff_file)

    else:
        save_yaml(
            {
                "status": (
                    f"No differences found at "
                    f"{datetime.now(timezone.utc).strftime('%Y-%m-%d-%H:%MUTC')}"
                )
            },
            diff_file,
        )

        logger.info("No RBAC drift detected between current cluster state and baseline.")