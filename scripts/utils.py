import os
import yaml
from kubernetes import client, config
from kubernetes.client.api_client import ApiClient

def get_k8s_apis():
    """Initializes and returns Kubernetes API clients."""
    try:
        config.load_incluster_config()
    except config.ConfigException:
        config.load_kube_config()
    
    api_client = ApiClient()
    rbac_api = client.RbacAuthorizationV1Api()
    core_api = client.CoreV1Api()
    return api_client, rbac_api, core_api

def sanitize(api_client, k8s_obj):
    """Strips dynamic metadata fields and status from Kubernetes objects."""
    obj = api_client.sanitize_for_serialization(k8s_obj)
    ignored_fields = ['uid', 'resourceVersion', 'creationTimestamp', 'managedFields', 'generation']
    
    if 'metadata' in obj:
        for field in ignored_fields:
            obj['metadata'].pop(field, None)
    obj.pop('status', None)
    return obj

def get_rbac_state():
    """Fetches and sanitizes all RBAC state from the Kubernetes cluster."""
    api_client, rbac_api, core_api = get_k8s_apis()
    state = {}
    
    def process(items):
        for item in items:
            clean_obj = sanitize(api_client, item)
            kind = clean_obj.get('kind', item.__class__.__name__.replace('V1', ''))
            ns = clean_obj.get('metadata', {}).get('namespace', 'cluster')
            name = clean_obj['metadata']['name']
            clean_obj['kind'] = kind
            state[f"{kind}_{ns}_{name}"] = clean_obj

    process(rbac_api.list_role_for_all_namespaces().items)
    process(rbac_api.list_cluster_role().items)
    process(rbac_api.list_role_binding_for_all_namespaces().items)
    process(rbac_api.list_cluster_role_binding().items)
    process(core_api.list_service_account_for_all_namespaces().items)
    
    return state

def save_yaml(data, filepath):
    """Saves dictionary data to a YAML file."""
    with open(filepath, 'w') as f:
        yaml.dump(data, f, default_flow_style=False, sort_keys=True)

def load_yaml(filepath):
    """Loads dictionary data from a YAML file."""
    if os.path.exists(filepath):
        with open(filepath, 'r') as f:
            return yaml.safe_load(f) or {}
    return {}
