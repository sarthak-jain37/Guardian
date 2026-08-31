from backend.app.services.kubernetes_service import KubernetesService
from scripts.apply_script import run_apply
from scripts.modify_script import run_modify
import logging

logger = logging.getLogger(__name__)

def run_apply_script(k8s: KubernetesService) -> None:
    logger.info("Executing APPLY SCRIPT...")
    run_apply(k8s)

def run_modify_script(k8s: KubernetesService):
    logger.info("Executing MODIFY SCRIPT...")
    run_modify(k8s)