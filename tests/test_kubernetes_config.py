import os
import unittest
from unittest.mock import patch
from kubernetes.config import ConfigException
from backend.app.services.kubernetes_service import KubernetesService


class KubernetesConfigTests(unittest.TestCase):
    @patch.dict(os.environ, {'KUBECONFIG': '/tmp/guardian-test-kubeconfig'})
    @patch('backend.app.services.kubernetes_service.ApiClient')
    @patch('backend.app.services.kubernetes_service.config.load_kube_config')
    @patch('backend.app.services.kubernetes_service.config.load_incluster_config', side_effect=ConfigException('outside cluster'))
    def test_explicit_kubeconfig_is_honored(self, incluster, kubeconfig, api_client):
        KubernetesService()
        kubeconfig.assert_called_once_with(config_file='/tmp/guardian-test-kubeconfig')

    @patch('backend.app.services.kubernetes_service.ApiClient')
    @patch('backend.app.services.kubernetes_service.config.load_kube_config')
    @patch('backend.app.services.kubernetes_service.config.load_incluster_config')
    def test_incluster_config_remains_preferred(self, incluster, kubeconfig, api_client):
        KubernetesService()
        incluster.assert_called_once_with()
        kubeconfig.assert_not_called()
