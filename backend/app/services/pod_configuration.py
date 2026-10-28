"""Read-only configuration and related resources for a pod."""
from kubernetes import client
from backend.app.services.pod_evidence import grants_for_pod


def pod_configuration(k8s, namespace, name):
    serialize = k8s.api_client.sanitize_for_serialization
    def clean(obj):
        result = serialize(obj)
        result.get('metadata', {}).pop('managedFields', None)
        return result
    pod = clean(k8s.core_api.read_namespaced_pod(name, namespace, _request_timeout=30))
    state = k8s.get_rbac_state()
    access = grants_for_pod(pod, state)
    bindings, roles = [], []
    for obj in state.values():
        meta = obj.get('metadata', {})
        provenance = access['grants'] + access['unresolved_bindings']
        if any(obj.get('kind') == g['binding_kind'] and meta.get('name') == g['binding_name']
               and meta.get('namespace') == g['binding_namespace'] for g in provenance):
            bindings.append(obj)
        if any(obj.get('kind') == g['role_kind'] and meta.get('name') == g['role_name']
               and (obj.get('kind') == 'ClusterRole' or meta.get('namespace') == g['binding_namespace']) for g in provenance):
            roles.append(obj)
    labels = pod.get('metadata', {}).get('labels', {})
    services = []
    for service in k8s.core_api.list_namespaced_service(namespace, _request_timeout=30).items:
        obj = clean(service)
        selector = obj.get('spec', {}).get('selector') or {}
        if selector and all(labels.get(key) == value for key, value in selector.items()):
            services.append(obj)
    apps, batch = client.AppsV1Api(k8s.api_client), client.BatchV1Api(k8s.api_client)
    readers = {'ReplicaSet': apps.read_namespaced_replica_set, 'Deployment': apps.read_namespaced_deployment,
               'StatefulSet': apps.read_namespaced_stateful_set, 'DaemonSet': apps.read_namespaced_daemon_set,
               'Job': batch.read_namespaced_job, 'CronJob': batch.read_namespaced_cron_job}
    workloads, warnings, seen = [], [], set()
    owners = pod.get('metadata', {}).get('ownerReferences', [])
    while owners:
        owner = next((o for o in owners if o.get('controller')), owners[0])
        key = (owner['kind'], owner['name'])
        if key in seen:
            break
        seen.add(key)
        reader = readers.get(owner['kind'])
        if reader is None:
            warnings.append('Owner type ' + owner['kind'] + ' is not supported for configuration lookup.')
            break
        try:
            obj = clean(reader(owner['name'], namespace, _request_timeout=30))
        except client.exceptions.ApiException as exc:
            warnings.append('Could not read ' + '/'.join(key) + ': HTTP ' + str(exc.status))
            break
        if owner.get('uid') and obj.get('metadata', {}).get('uid') != owner['uid']:
            warnings.append('Owner was replaced; its current configuration is not associated with this pod.')
            break
        obj.setdefault('kind', owner['kind'])
        workloads.append(obj)
        owners = obj.get('metadata', {}).get('ownerReferences', [])
    return {'pod': pod, 'roles': roles, 'bindings': bindings, 'workloads': workloads,
            'services': services, 'permissions': access, 'warnings': warnings}
