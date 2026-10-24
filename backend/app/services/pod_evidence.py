"""Read-only pod inventory and RBAC provenance. Never authorizes or revokes access."""
import asyncio
import json
import hashlib
import os
from datetime import datetime, timezone


def grants_for_pod(pod, state):
    meta, spec = pod['metadata'], pod.get('spec', {})
    namespace = meta['namespace']
    sa = spec.get('serviceAccountName', 'default')
    username = f'system:serviceaccount:{namespace}:{sa}'
    groups = {'system:serviceaccounts', f'system:serviceaccounts:{namespace}', 'system:authenticated'}
    result, unresolved = [], []
    objects = list(state.values())
    for binding in objects:
        kind = binding.get('kind')
        if kind not in ('RoleBinding', 'ClusterRoleBinding'):
            continue
        bm = binding.get('metadata', {})
        matches = any(
            (s.get('kind') == 'ServiceAccount' and s.get('name') == sa and s.get('namespace', bm.get('namespace')) == namespace)
            or (s.get('kind') == 'User' and s.get('name') == username)
            or (s.get('kind') == 'Group' and s.get('name') in groups)
            for s in binding.get('subjects', []))
        if not matches:
            continue
        ref = binding.get('roleRef', {})
        roles = [r for r in objects if r.get('kind') == ref.get('kind') and r.get('metadata', {}).get('name') == ref.get('name')
                 and (ref.get('kind') == 'ClusterRole' or r.get('metadata', {}).get('namespace') == bm.get('namespace'))]
        provenance = {'binding_kind': kind, 'binding_name': bm.get('name'), 'binding_namespace': bm.get('namespace'),
                      'role_kind': ref.get('kind'), 'role_name': ref.get('name'),
                      'scope': '*' if kind == 'ClusterRoleBinding' else bm.get('namespace')}
        if not roles:
            unresolved.append(provenance)
        for role in roles:
            for rule in role.get('rules', []):
                signals = []
                verbs, resources = set(rule.get('verbs', [])), set(rule.get('resources', []))
                if verbs & {'create', 'delete', 'deletecollection', 'patch', 'update', '*'} and resources & {'pods', 'deployments', 'daemonsets', 'statefulsets', 'jobs', 'cronjobs', 'replicasets', '*'}:
                    signals.append('workload_mutation_permission')
                if resources & {'pods/exec', 'pods/attach', 'pods/ephemeralcontainers', 'pods/portforward', '*'}:
                    signals.append('pod_interaction_permission')
                if resources & {'secrets', 'serviceaccounts/token', '*'}:
                    signals.append('credential_access_permission')
                if verbs & {'bind', 'escalate', 'impersonate', '*'}:
                    signals.append('privilege_escalation_permission')
                result.append({**provenance, 'rule': rule, 'signals': signals})
    return {'service_account': username, 'grants': result, 'unresolved_bindings': unresolved,
            'limitations': ['RBAC snapshot grants only; admission, other authorizers and token availability can change actual access',
                            'resourceNames and API groups retained; create/deletecollection cannot generally be restricted by resourceNames',
                            'Shared service account permissions apply to every pod using that identity']}


def inventory_pod(pod, state):
    meta, spec, status = pod['metadata'], pod.get('spec', {}), pod.get('status', {})
    containers = []
    for category in ('containers', 'initContainers', 'ephemeralContainers'):
        for container in spec.get(category, []):
            containers.append({'name': container['name'], 'type': category, 'image': container.get('image'),
                               'security_context': container.get('securityContext', {}),
                               'resources': container.get('resources', {}), 'volume_mounts': container.get('volumeMounts', [])})
    volumes = []
    for volume in spec.get('volumes', []):
        volumes.append({k: volume[k] for k in ('name', 'hostPath', 'secret', 'configMap', 'projected', 'persistentVolumeClaim') if k in volume})
    return {'namespace': meta['namespace'], 'pod': meta['name'], 'uid': meta.get('uid'),
            'owners': meta.get('ownerReferences', []), 'node': spec.get('nodeName'), 'pod_ip': status.get('podIP'),
            'service_account_name': spec.get('serviceAccountName', 'default'),
            'automount_service_account_token': spec.get('automountServiceAccountToken'),
            'host_network': spec.get('hostNetwork', False), 'host_pid': spec.get('hostPID', False),
            'host_ipc': spec.get('hostIPC', False), 'security_context': spec.get('securityContext', {}),
            'containers': containers, 'volumes': volumes, 'phase': status.get('phase'),
            'container_statuses': [{k: c[k] for k in ('name', 'imageID', 'containerID', 'restartCount', 'ready', 'state', 'lastState') if k in c}
                                   for category in ('containerStatuses', 'initContainerStatuses', 'ephemeralContainerStatuses') for c in status.get(category, [])],
            'permissions': grants_for_pod(pod, state)}


async def refresh_inventory(service, k8s):
    interval = max(15, int(os.getenv('POD_INVENTORY_INTERVAL', '60')))
    while True:
        try:
            def read():
                state = k8s.get_rbac_state()
                # Direct serialization preserves pod UID and status for reliable correlation.
                pods = k8s.api_client.sanitize_for_serialization(k8s.core_api.list_pod_for_all_namespaces(_request_timeout=30)).get('items', [])
                return [inventory_pod(p, state) for p in pods]
            pods = await asyncio.to_thread(read)
            snapshot = {'observed_at': datetime.now(timezone.utc).isoformat(), 'pods': pods}
            previous = json.loads(await service.redis.get(service.prefix + ':inventory') or '{}')
            old_pods = {(p['namespace'], p['pod'], p['uid']): p for p in previous.get('pods', [])}
            for current in pods:
                old = old_pods.get((current['namespace'], current['pod'], current['uid']))
                if not old:
                    continue
                changed = {key: {'before': old.get(key), 'after': current.get(key)} for key in
                           ('containers', 'permissions', 'volumes', 'security_context', 'host_network', 'host_pid', 'host_ipc', 'container_statuses')
                           if old.get(key) != current.get(key)}
                if changed:
                    event = {'cluster': service.cluster, 'source': 'inventory', 'kind': 'pod_configuration_change',
                             'timestamp': snapshot['observed_at'], 'observed_at': snapshot['observed_at'],
                             'source_pod': {k: current[k] for k in ('namespace', 'pod', 'uid')},
                             'changes': changed, 'signals': ['pod_configuration_or_status_changed']}
                    event['id'] = hashlib.sha256(json.dumps(event, sort_keys=True).encode()).hexdigest()
                    await service.save(event)
            await service.redis.set(service.prefix + ':inventory', json.dumps(snapshot), ex=service.ttl)
            service.health['inventory'] = {'state': 'ready', 'observed_at': snapshot['observed_at'], 'pod_count': len(pods)}
        except asyncio.CancelledError:
            raise
        except Exception as exc:
            service.health['inventory'] = {'state': 'error', 'error': str(exc)}
        await asyncio.sleep(interval)


async def pod_evidence(service, namespace=None, pod=None, limit=100):
    snapshot = json.loads(await service.redis.get(service.prefix + ':inventory') or '{}')
    pods = snapshot.get('pods', [])
    if namespace:
        pods = [p for p in pods if p['namespace'] == namespace]
    if pod:
        pods = [p for p in pods if p['pod'] == pod]
    events = await service.events(service.maximum, namespace)
    result = []
    for identity in pods:
        direct, shared = [], []
        for event in events:
            source = event.get('source_pod', {})
            if event['kind'] == 'kubernetes_audit':
                if event.get('actor') != identity['permissions']['service_account']:
                    continue
                token_uid = event.get('token_pod_uid')
                if token_uid and token_uid == identity['uid']:
                    direct.append(event)
                elif not token_uid:
                    shared.append(event)
            elif source.get('namespace') == identity['namespace'] and source.get('pod') == identity['pod']:
                # Runtime UID, if supplied, prevents attribution across recreated pods.
                if not source.get('uid') or source['uid'] == identity['uid']:
                    direct.append(event)
        result.append({'identity': identity, 'events': direct[:limit], 'shared_identity_audit_events': shared[:limit],
                       'attribution_note': 'Token pod UID identifies the credential binding, not proof of the physical caller; name-only runtime correlation can include recreated pods.'})
    return {'inventory_observed_at': snapshot.get('observed_at'), 'coverage': service.health,
            'pods': result, 'event_limit_per_pod': limit, 'scoring_enabled': False, 'remediation_enabled': False}
