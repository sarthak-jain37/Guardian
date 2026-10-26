import unittest

from backend.app.services.permission_scanner import (
    scan_dangerous_permissions,
    DANGEROUS_VERBS,
    SENSITIVE_RESOURCES,
)


class TestPermissionScanner(unittest.TestCase):

    # Test: Validates graceful handling of empty ({}) or None input without throwing exceptions.
    def test_empty_and_none_state(self):
        self.assertEqual(scan_dangerous_permissions({}), [])
        self.assertEqual(scan_dangerous_permissions(None), [])

    # Test: Verifies that least-privilege roles (e.g. read-only pod access) produce zero false-positive alerts.
    def test_benign_role_has_no_findings(self):
        state = {
            "Role_default_pod-reader": {
                "kind": "Role",
                "metadata": {"name": "pod-reader", "namespace": "default"},
                "rules": [
                    {
                        "apiGroups": [""],
                        "resources": ["pods", "configmaps"],
                        "verbs": ["get", "list", "watch"],
                    }
                ],
            }
        }
        findings = scan_dangerous_permissions(state)
        self.assertEqual(len(findings), 0)

    # Test: Ensures non-role Kubernetes objects (ServiceAccounts, RoleBindings) are skipped during rule evaluation.
    def test_ignored_kinds(self):
        state = {
            "ServiceAccount_default_my-sa": {
                "kind": "ServiceAccount",
                "metadata": {"name": "my-sa", "namespace": "default"},
            },
            "RoleBinding_default_read-pods": {
                "kind": "RoleBinding",
                "metadata": {"name": "read-pods", "namespace": "default"},
            },
        }
        findings = scan_dangerous_permissions(state)
        self.assertEqual(len(findings), 0)

    # Test: Validates membership check for wildcard verbs within arrays (e.g. ['get', '*']) to prevent evasion.
    def test_wildcard_array_trap(self):
        """Ensure ['get', '*'] is caught as a wildcard verb, not bypassed by strict equality."""
        state = {
            "Role_default_sneaky-role": {
                "kind": "Role",
                "metadata": {"name": "sneaky-role", "namespace": "default"},
                "rules": [
                    {
                        "apiGroups": [""],
                        "resources": ["pods"],
                        "verbs": ["get", "*"],  # Multiple verbs including wildcard
                    }
                ],
            }
        }
        findings = scan_dangerous_permissions(state)
        self.assertEqual(len(findings), 1)
        role = findings[0]
        self.assertIn("WILDCARD_VERBS", role["flags"])
        self.assertEqual(role["severity"], "HIGH")

    # Test: Verifies case-normalization prevents uppercase or mixed-case evasion (e.g. 'BIND', 'SECRETS').
    def test_case_insensitivity(self):
        """Ensure uppercase or mixed case verbs and resources are correctly flagged."""
        state = {
            "ClusterRole_cluster_caps-role": {
                "kind": "ClusterRole",
                "metadata": {"name": "caps-role"},
                "rules": [
                    {
                        "apiGroups": ["*"],
                        "resources": ["SECRETS"],
                        "verbs": ["BIND"],
                    }
                ],
            }
        }
        findings = scan_dangerous_permissions(state)
        self.assertEqual(len(findings), 1)
        role = findings[0]
        self.assertIn("DANGEROUS_VERB_BIND", role["flags"])
        self.assertIn("SENSITIVE_RESOURCE_SECRETS", role["flags"])
        self.assertIn("WILDCARD_API_GROUPS", role["flags"])
        self.assertEqual(role["severity"], "CRITICAL")

    # Test: Validates individual detection and CRITICAL severity assignment for 'bind', 'impersonate', and 'escalate'.
    def test_all_dangerous_verbs(self):
        """Test bind, impersonate, and escalate detection."""
        for verb in ["bind", "impersonate", "escalate"]:
            with self.subTest(verb=verb):
                state = {
                    f"Role_prod_test-{verb}": {
                        "kind": "Role",
                        "metadata": {"name": f"test-{verb}", "namespace": "prod"},
                        "rules": [
                            {
                                "apiGroups": ["rbac.authorization.k8s.io"],
                                "resources": ["roles"],
                                "verbs": [verb],
                            }
                        ],
                    }
                }
                findings = scan_dangerous_permissions(state)
                self.assertEqual(len(findings), 1)
                flag = f"DANGEROUS_VERB_{verb.upper()}"
                self.assertIn(flag, findings[0]["flags"])
                self.assertEqual(findings[0]["severity"], "CRITICAL")

    # Test: Verifies cluster-admin superuser access ('*' verbs on '*' resources) is flagged as CRITICAL.
    def test_full_cluster_admin_wildcard(self):
        """Test * verb and * resource combination."""
        state = {
            "ClusterRole_cluster_cluster-admin": {
                "kind": "ClusterRole",
                "metadata": {"name": "cluster-admin"},
                "rules": [
                    {
                        "apiGroups": ["*"],
                        "resources": ["*"],
                        "verbs": ["*"],
                    }
                ],
            }
        }
        findings = scan_dangerous_permissions(state)
        self.assertEqual(len(findings), 1)
        role = findings[0]
        self.assertIn("FULL_ADMIN_WILDCARD", role["flags"])
        self.assertEqual(role["severity"], "CRITICAL")

    # Test: Validates detection of sensitive subresources (e.g. 'serviceaccounts/token' credential minting).
    def test_sensitive_subresource(self):
        """Test subresource like serviceaccounts/token."""
        state = {
            "Role_kube-system_token-stealer": {
                "kind": "Role",
                "metadata": {"name": "token-stealer", "namespace": "kube-system"},
                "rules": [
                    {
                        "apiGroups": [""],
                        "resources": ["serviceaccounts/token"],
                        "verbs": ["create"],
                    }
                ],
            }
        }
        findings = scan_dangerous_permissions(state)
        self.assertEqual(len(findings), 1)
        self.assertIn("SENSITIVE_RESOURCE_SERVICEACCOUNTS", findings[0]["flags"])

    # Test: Verifies findings list is sorted in descending severity order (CRITICAL -> HIGH -> MEDIUM).
    def test_severity_sorting(self):
        """CRITICAL findings must come before HIGH and MEDIUM."""
        state = {
            "Role_dev_high-role": {
                "kind": "Role",
                "metadata": {"name": "high-role", "namespace": "dev"},
                "rules": [
                    {
                        "apiGroups": [""],
                        "resources": ["secrets"],
                        "verbs": ["get"],  # HIGH: sensitive resource
                    }
                ],
            },
            "Role_dev_critical-role": {
                "kind": "Role",
                "metadata": {"name": "critical-role", "namespace": "dev"},
                "rules": [
                    {
                        "apiGroups": [""],
                        "resources": ["users"],
                        "verbs": ["impersonate"],  # CRITICAL: dangerous verb
                    }
                ],
            },
        }
        findings = scan_dangerous_permissions(state)
        self.assertEqual(len(findings), 2)
        self.assertEqual(findings[0]["role_name"], "critical-role")
        self.assertEqual(findings[0]["severity"], "CRITICAL")
        self.assertEqual(findings[1]["role_name"], "high-role")
        self.assertEqual(findings[1]["severity"], "HIGH")


if __name__ == "__main__":
    unittest.main()
