from backend.app.services.kubernetes_service import KubernetesService
from backend.app.utils.yaml_utils import save_yaml


def run_apply(k8s: KubernetesService, baseline_file="baseline.yaml") -> None:
    """Fetch live Kubernetes RBAC state and update the baseline."""

    rbac_state = k8s.get_rbac_state()
    save_yaml(rbac_state, baseline_file)
