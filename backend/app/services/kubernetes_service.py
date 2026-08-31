from kubernetes import client, config
from kubernetes.client.api_client import ApiClient

IGNORED_METADATA_FIELDS = {
    "uid",
    "resourceVersion",
    "creationTimestamp",
    "managedFields",
    "generation",
}


class KubernetesService:

    def __init__(self):
        try:
            config.load_incluster_config()
        except config.ConfigException:
            config.load_kube_config()

        self.api_client = ApiClient()
        self.rbac_api = client.RbacAuthorizationV1Api(self.api_client)
        self.core_api = client.CoreV1Api(self.api_client)

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
            .list_role_for_all_namespaces()
            .items
        )

        process(
            self.rbac_api
            .list_cluster_role()
            .items
        )

        process(
            self.rbac_api
            .list_role_binding_for_all_namespaces()
            .items
        )

        process(
            self.rbac_api
            .list_cluster_role_binding()
            .items
        )

        process(
            self.core_api
            .list_service_account_for_all_namespaces()
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