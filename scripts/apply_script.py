from backend.app.services.kubernetes_service import KubernetesService


def run_apply(k8s: KubernetesService) -> dict:
    """Fetch live Kubernetes RBAC state and update the baseline."""

    rbac_state = k8s.get_rbac_state()
    return rbac_state
