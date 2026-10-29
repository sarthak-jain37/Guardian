import logging
import os
from datetime import datetime, timezone
from typing import Any
from kubernetes import client, config
from kubernetes.client.api_client import ApiClient
from kubernetes.client.exceptions import ApiException

logger = logging.getLogger(__name__)

IGNORED_METADATA_FIELDS = {
    "creationTimestamp",
    "managedFields",
    "generation",
}


class KubernetesService:

    def __init__(self):
        try:
            config.load_incluster_config()
        except config.ConfigException:
            config.load_kube_config(config_file=os.getenv("KUBECONFIG"))

        self.api_client = ApiClient()
        self.rbac_api = client.RbacAuthorizationV1Api(self.api_client)
        self.core_api = client.CoreV1Api(self.api_client)
        self.apps_api = client.AppsV1Api(self.api_client)
        self.batch_api = client.BatchV1Api(self.api_client)

    def get_workload_inventory(self, namespace):
        objects, errors = [], []
        readers = [(self.core_api.list_namespaced_pod, "Pod"),
                   (self.core_api.list_namespaced_replication_controller, "ReplicationController"),
                   (self.apps_api.list_namespaced_deployment, "Deployment"),
                   (self.apps_api.list_namespaced_replica_set, "ReplicaSet"),
                   (self.apps_api.list_namespaced_stateful_set, "StatefulSet"),
                   (self.apps_api.list_namespaced_daemon_set, "DaemonSet"),
                   (self.batch_api.list_namespaced_job, "Job"),
                   (self.batch_api.list_namespaced_cron_job, "CronJob")]
        for reader, kind in readers:
            try:
                result = reader(namespace, _request_timeout=(5, 10))
                for item in result.items:
                    value = self.api_client.sanitize_for_serialization(item)
                    value["kind"] = kind
                    objects.append(value)
            except Exception:
                errors.append("inventory_unavailable_" + kind.lower())
        return {"objects": objects, "errors": errors}

    def get_rbac_state(self) -> dict:
        state = {}

        def process(items) -> None:
            for item in items:
                clean_obj = self.sanitize(item)

                kind = clean_obj.get(
                    "kind",
                    item.__class__.__name__.replace("V1", "")
                )

                namespace = clean_obj.get(
                    "metadata", {}
                ).get("namespace", "cluster")

                name = clean_obj["metadata"]["name"]

                clean_obj["kind"] = kind
                state[f"{kind}_{namespace}_{name}"] = clean_obj

        process(
            self.rbac_api
            .list_role_for_all_namespaces(_request_timeout=30)
            .items
        )

        process(
            self.rbac_api
            .list_cluster_role(_request_timeout=30)
            .items
        )

        process(
            self.rbac_api
            .list_role_binding_for_all_namespaces(_request_timeout=30)
            .items
        )

        process(
            self.rbac_api
            .list_cluster_role_binding(_request_timeout=30)
            .items
        )

        process(
            self.core_api
            .list_service_account_for_all_namespaces(_request_timeout=30)
            .items
        )

        return state

    def sanitize(self, k8s_obj) -> dict:
        obj = self.api_client.sanitize_for_serialization(k8s_obj)

        metadata = obj.get("metadata")

        if metadata:
            for field in IGNORED_METADATA_FIELDS:
                metadata.pop(field, None)

        obj.pop("status", None)

        return obj

    def apply_role(self, namespace: str, role_dict: dict[str, Any]) -> dict[str, Any]:
        """Apply a Role (create or replace if existing)."""
        name = role_dict["metadata"]["name"]
        try:
            existing = self.rbac_api.read_namespaced_role(name=name, namespace=namespace)
            body = dict(role_dict)
            body["metadata"] = dict(body.get("metadata", {}))
            body["metadata"]["resourceVersion"] = existing.metadata.resource_version
            res = self.rbac_api.replace_namespaced_role(name=name, namespace=namespace, body=body)
        except ApiException as e:
            if e.status == 404:
                res = self.rbac_api.create_namespaced_role(namespace=namespace, body=role_dict)
            else:
                raise
        return self.api_client.sanitize_for_serialization(res)

    def apply_cluster_role(self, cluster_role_dict: dict[str, Any]) -> dict[str, Any]:
        """Apply a ClusterRole (create or replace if existing)."""
        name = cluster_role_dict["metadata"]["name"]
        try:
            existing = self.rbac_api.read_cluster_role(name=name)
            body = dict(cluster_role_dict)
            body["metadata"] = dict(body.get("metadata", {}))
            body["metadata"]["resourceVersion"] = existing.metadata.resource_version
            res = self.rbac_api.replace_cluster_role(name=name, body=body)
        except ApiException as e:
            if e.status == 404:
                res = self.rbac_api.create_cluster_role(body=cluster_role_dict)
            else:
                raise
        return self.api_client.sanitize_for_serialization(res)

    def apply_role_binding(self, namespace: str, binding_dict: dict[str, Any]) -> dict[str, Any]:
        """Apply a RoleBinding (create or replace if existing)."""
        name = binding_dict["metadata"]["name"]
        try:
            existing = self.rbac_api.read_namespaced_role_binding(name=name, namespace=namespace)
            body = dict(binding_dict)
            body["metadata"] = dict(body.get("metadata", {}))
            body["metadata"]["resourceVersion"] = existing.metadata.resource_version
            res = self.rbac_api.replace_namespaced_role_binding(name=name, namespace=namespace, body=body)
        except ApiException as e:
            if e.status == 404:
                res = self.rbac_api.create_namespaced_role_binding(namespace=namespace, body=binding_dict)
            else:
                raise
        return self.api_client.sanitize_for_serialization(res)

    def apply_cluster_role_binding(self, binding_dict: dict[str, Any]) -> dict[str, Any]:
        """Apply a ClusterRoleBinding (create or replace if existing)."""
        name = binding_dict["metadata"]["name"]
        try:
            existing = self.rbac_api.read_cluster_role_binding(name=name)
            body = dict(binding_dict)
            body["metadata"] = dict(body.get("metadata", {}))
            body["metadata"]["resourceVersion"] = existing.metadata.resource_version
            res = self.rbac_api.replace_cluster_role_binding(name=name, body=body)
        except ApiException as e:
            if e.status == 404:
                res = self.rbac_api.create_cluster_role_binding(body=binding_dict)
            else:
                raise
        return self.api_client.sanitize_for_serialization(res)

    def apply_service_account(self, namespace: str, sa_dict: dict[str, Any]) -> dict[str, Any]:
        """Apply a ServiceAccount (create or replace if existing)."""
        name = sa_dict["metadata"]["name"]
        try:
            existing = self.core_api.read_namespaced_service_account(name=name, namespace=namespace)
            body = dict(sa_dict)
            body["metadata"] = dict(body.get("metadata", {}))
            body["metadata"]["resourceVersion"] = existing.metadata.resource_version
            res = self.core_api.replace_namespaced_service_account(name=name, namespace=namespace, body=body)
        except ApiException as e:
            if e.status == 404:
                res = self.core_api.create_namespaced_service_account(namespace=namespace, body=sa_dict)
            else:
                raise
        return self.api_client.sanitize_for_serialization(res)

    def apply_rbac_resource(self, resource: dict[str, Any]) -> dict[str, Any]:
        """Dispatch resource to the appropriate apply method based on kind."""
        kind = resource.get("kind", "")
        namespace = resource.get("metadata", {}).get("namespace", "default")
        name = resource.get("metadata", {}).get("name", "")

        if kind == "Role":
            applied_obj = self.apply_role(namespace, resource)
        elif kind == "ClusterRole":
            applied_obj = self.apply_cluster_role(resource)
        elif kind == "RoleBinding":
            applied_obj = self.apply_role_binding(namespace, resource)
        elif kind == "ClusterRoleBinding":
            applied_obj = self.apply_cluster_role_binding(resource)
        elif kind == "ServiceAccount":
            applied_obj = self.apply_service_account(namespace, resource)
        else:
            raise ValueError(f"Unsupported RBAC resource kind: '{kind}'")

        return {
            "status": "applied",
            "kind": kind,
            "namespace": namespace,
            "name": name,
            "resource": applied_obj,
        }

    def delete_rbac_resource(self, kind: str, namespace: str, name: str) -> bool:
        """Delete an RBAC resource. Returns True if deleted, False if already absent."""
        try:
            if kind == "Role":
                self.rbac_api.delete_namespaced_role(name=name, namespace=namespace)
            elif kind == "ClusterRole":
                self.rbac_api.delete_cluster_role(name=name)
            elif kind == "RoleBinding":
                self.rbac_api.delete_namespaced_role_binding(name=name, namespace=namespace)
            elif kind == "ClusterRoleBinding":
                self.rbac_api.delete_cluster_role_binding(name=name)
            elif kind == "ServiceAccount":
                self.core_api.delete_namespaced_service_account(name=name, namespace=namespace)
            else:
                logger.warning(f"Unsupported resource kind for deletion: {kind}")
                return False
            return True
        except ApiException as e:
            if e.status == 404:
                return False
            raise

    def apply_state(self, state: dict[str, Any]) -> dict[str, Any]:
        """Apply all RBAC resources in the given state dictionary to the cluster."""
        applied = []
        errors = []
        for key, resource in state.items():
            try:
                self.apply_rbac_resource(resource)
                applied.append(key)
            except Exception as e:
                errors.append(f"Failed applying {key}: {str(e)}")

        return {
            "status": "success" if not errors else "partial_failure",
            "applied": applied,
            "errors": errors,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }

    def revert_to_baseline(
        self,
        baseline_state: dict[str, Any],
        current_state: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        """
        Actively revert cluster permissions to the approved baseline:
        1. Compares live state against baseline_state.
        2. Deletes rogue / unapproved resources created during drift.
        3. Re-applies all approved baseline resources.
        4. Returns an execution receipt.
        """
        if current_state is None:
            current_state = self.get_rbac_state()

        applied = []
        deleted = []
        errors = []

        # 1. Prune rogue resources in current_state that are not in baseline_state
        for key, obj in current_state.items():
            if key not in baseline_state:
                kind = obj.get("kind", "")
                name = obj.get("metadata", {}).get("name", "")
                namespace = obj.get("metadata", {}).get("namespace", "default")
                try:
                    success = self.delete_rbac_resource(kind, namespace, name)
                    if success:
                        deleted.append(key)
                except Exception as e:
                    errors.append(f"Failed deleting rogue resource {key}: {str(e)}")

        # 2. Re-apply all resources defined in baseline_state
        for key, resource in baseline_state.items():
            try:
                self.apply_rbac_resource(resource)
                applied.append(key)
            except Exception as e:
                errors.append(f"Failed applying baseline resource {key}: {str(e)}")

        return {
            "status": "success" if not errors else "partial_failure",
            "applied": applied,
            "deleted": deleted,
            "errors": errors,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }
