import unittest
from unittest.mock import MagicMock, patch
from kubernetes.client.exceptions import ApiException

from backend.app.services.kubernetes_service import KubernetesService


class TestKubernetesServiceMutations(unittest.TestCase):
    @patch("backend.app.services.kubernetes_service.config")
    def setUp(self, mock_config):
        self.k8s = KubernetesService()
        self.k8s.rbac_api = MagicMock()
        self.k8s.core_api = MagicMock()
        self.k8s.api_client = MagicMock()
        self.k8s.api_client.sanitize_for_serialization.side_effect = lambda x: x

    def test_apply_role_create_when_not_found(self):
        role_dict = {"kind": "Role", "metadata": {"name": "reader", "namespace": "default"}, "rules": []}
        self.k8s.rbac_api.read_namespaced_role.side_effect = ApiException(status=404)
        self.k8s.rbac_api.create_namespaced_role.return_value = role_dict

        res = self.k8s.apply_role("default", role_dict)
        self.k8s.rbac_api.create_namespaced_role.assert_called_once_with(namespace="default", body=role_dict)
        self.assertEqual(res["metadata"]["name"], "reader")

    def test_apply_role_replace_when_existing(self):
        role_dict = {"kind": "Role", "metadata": {"name": "reader", "namespace": "default"}, "rules": []}
        existing_mock = MagicMock()
        existing_mock.metadata.resource_version = "12345"
        self.k8s.rbac_api.read_namespaced_role.return_value = existing_mock
        self.k8s.rbac_api.replace_namespaced_role.return_value = role_dict

        res = self.k8s.apply_role("default", role_dict)
        self.k8s.rbac_api.replace_namespaced_role.assert_called_once()
        call_kwargs = self.k8s.rbac_api.replace_namespaced_role.call_args.kwargs
        self.assertEqual(call_kwargs["name"], "reader")
        self.assertEqual(call_kwargs["body"]["metadata"]["resourceVersion"], "12345")

    def test_apply_cluster_role(self):
        cr_dict = {"kind": "ClusterRole", "metadata": {"name": "cluster-reader"}, "rules": []}
        self.k8s.rbac_api.read_cluster_role.side_effect = ApiException(status=404)
        self.k8s.rbac_api.create_cluster_role.return_value = cr_dict

        res = self.k8s.apply_cluster_role(cr_dict)
        self.k8s.rbac_api.create_cluster_role.assert_called_once_with(body=cr_dict)

    def test_delete_rbac_resource(self):
        self.k8s.rbac_api.delete_namespaced_role.return_value = True
        res = self.k8s.delete_rbac_resource("Role", "default", "old-role")
        self.assertTrue(res)
        self.k8s.rbac_api.delete_namespaced_role.assert_called_once_with(name="old-role", namespace="default")

        # 404 returns False gracefully
        self.k8s.rbac_api.delete_namespaced_role.side_effect = ApiException(status=404)
        res_404 = self.k8s.delete_rbac_resource("Role", "default", "absent-role")
        self.assertFalse(res_404)

    def test_revert_to_baseline_prunes_rogue_and_applies_baseline(self):
        baseline_state = {
            "Role_default_approved-role": {
                "kind": "Role",
                "metadata": {"name": "approved-role", "namespace": "default"},
                "rules": [{"verbs": ["get"], "resources": ["pods"]}],
            }
        }
        current_state = {
            "Role_default_approved-role": {
                "kind": "Role",
                "metadata": {"name": "approved-role", "namespace": "default"},
                "rules": [{"verbs": ["get", "list"], "resources": ["pods"]}],
            },
            "Role_default_rogue-admin": {
                "kind": "Role",
                "metadata": {"name": "rogue-admin", "namespace": "default"},
                "rules": [{"verbs": ["*"], "resources": ["*"]}],
            },
        }

        self.k8s.delete_rbac_resource = MagicMock(return_value=True)
        self.k8s.apply_rbac_resource = MagicMock(return_value={"status": "applied"})

        receipt = self.k8s.revert_to_baseline(baseline_state, current_state)
        self.assertEqual(receipt["status"], "success")
        self.assertIn("Role_default_rogue-admin", receipt["deleted"])
        self.assertIn("Role_default_approved-role", receipt["applied"])

        self.k8s.delete_rbac_resource.assert_called_once_with("Role", "default", "rogue-admin")
        self.k8s.apply_rbac_resource.assert_called_once_with(baseline_state["Role_default_approved-role"])


if __name__ == "__main__":
    unittest.main()
