"""Human-readable capability summaries and bounded, traceable pod review evidence."""
from backend.app.services.pod_evidence import pod_evidence

SIGNALS = {
    'network_policy_or_delivery_failure': 'Traffic was dropped or a network delivery failure was observed',
    'root_process_observed': 'A process ran as root',
    'shell_process_observed': 'A shell process started inside the pod',
    'execution_from_writable_directory': 'A program executed from a temporary writable directory',
    'powerful_linux_capability_observed': 'A process held a powerful Linux capability',
    'sensitive_file_access_attempt': 'A process attempted to access a sensitive file',
    'namespace_change_attempt': 'A process attempted to enter another Linux namespace',
    'namespace_creation_attempt': 'A process attempted to create a Linux namespace',
    'mount_operation_attempt': 'A process attempted a mount operation',
    'process_inspection_attempt': 'A process attempted to inspect or control another process',
    'bpf_operation_attempt': 'A process attempted a BPF operation',
    'kubernetes_mutation_attempt': 'Service-account credentials attempted to change Kubernetes resources',
    'pod_interaction_attempt': 'Credentials attempted exec, attach, port forwarding or ephemeral-container access',
    'credential_api_access_attempt': 'Credentials attempted to access secrets or request a service-account token',
    'api_authentication_or_authorization_denied': 'The API server denied an authentication or authorization request',
    'destination_namespace_outside_boundary': 'Traffic targeted a namespace outside the configured boundary',
    'unresolved_or_external_destination': 'Traffic targeted an external or unresolved endpoint',
    'binary_outside_boundary': 'A program outside the configured executable allowlist ran',
    'pod_configuration_or_status_changed': 'The pod configuration or container status changed',
}


def permission_points(identity):
    points = []
    seen = set()
    for grant in identity.get('permissions', {}).get('grants', []):
        rule = grant.get('rule', {})
        verbs, resources = set(rule.get('verbs', [])), set(rule.get('resources', []))
        groups = set(rule.get('apiGroups', []))
        def has(verb, resource, group=''):
            return (verb in verbs or '*' in verbs) and (resource in resources or '*' in resources) and (group in groups or '*' in groups)
        actions = []
        for verb in ('create', 'delete', 'deletecollection', 'patch', 'update'):
            if has(verb, 'pods'):
                actions.append((verb + ' pods', 'Can ' + ('delete multiple pods' if verb == 'deletecollection' else verb + ' pods')))
        for resource, text in (('pods/exec', 'Can open execution sessions in pods'), ('pods/attach', 'Can attach to running containers'), ('pods/portforward', 'Can forward ports into pods'), ('pods/ephemeralcontainers', 'Can modify ephemeral containers')):
            if any(has(v, resource) for v in ('get','create','patch','update')):
                actions.append((resource, text))
        if any(has(v, 'secrets') for v in ('get','list','watch')):
            actions.append(('read secrets', 'Can read Kubernetes secrets'))
        if has('create', 'serviceaccounts/token'):
            actions.append(('request tokens', 'Can request service-account tokens'))
        for group, resource in (('apps','deployments'),('apps','daemonsets'),('apps','statefulsets'),('batch','jobs'),('batch','cronjobs')):
            if any(has(v, resource, group) for v in ('create','delete','patch','update')):
                actions.append((resource, 'Can '+', '.join(sorted(verbs & {'create','delete','patch','update'}) or {'manage'})+' '+resource))
        for verb in ('bind','escalate','impersonate'):
            if verb in verbs or '*' in verbs:
                actions.append((verb, 'Has '+verb+' permission on '+', '.join(sorted(resources))))
        for action, text in actions:
            key=(action, grant.get('scope'), grant.get('binding_name'), tuple(rule.get('resourceNames', [])))
            if key in seen:continue
            seen.add(key)
            points.append({'action': action, 'summary': text, 'scope': grant.get('scope'),
                           'binding': grant.get('binding_name'), 'binding_kind': grant.get('binding_kind'),
                           'binding_namespace': grant.get('binding_namespace'), 'role': grant.get('role_name'),
                           'resource_names': rule.get('resourceNames', []), 'verbs': sorted(verbs)})
    return points


def event_summary(event):
    kind = event.get('kind','')
    if kind == 'kubernetes_audit':
        target=event.get('target',{})
        target_name='/'.join(str(target.get(k,'')) for k in ('namespace','resource','name') if target.get(k))
        return f"{event.get('verb', 'API request')} {target_name} — {event.get('outcome','unknown')} ({event.get('status_code')})"
    if event.get('http'):
        http=event['http']
        return f"HTTP {http.get('method','')} {http.get('host','')}{http.get('path','')}" + (f" — {http['code']}" if http.get('code') else '')
    if event.get('dns'):
        return 'DNS lookup: '+str(event['dns'].get('query','unknown'))
    if kind == 'network':
        dest=event.get('destination_pod',{})
        return f"{event.get('verdict','Flow')} → {dest.get('pod') or dest.get('ip') or 'unknown endpoint'}"
    if kind == 'pod_configuration_change':
        return 'Configuration changed: '+', '.join(event.get('changes',{}))
    process=event.get('process',{})
    runtime=event.get('runtime',{})
    path=', '.join(runtime.get('file_paths',[]))
    return ' · '.join(str(v) for v in (process.get('binary'), event.get('function_name'), path) if v) or kind.replace('_',' ')


def representative_events(events, limit):
    # Include multiple evidence channels before filling with distinct actions.
    selected=[]; ids=set(); buckets=set()
    ordered=sorted(events,key=lambda e:(bool(e.get('findings')),e.get('kind')=='kubernetes_audit'),reverse=True)
    groups=[
        lambda e:e.get('kind')=='kubernetes_audit',
        lambda e:e.get('kind')=='process_exec' and bool(e.get('findings')),
        lambda e:bool(e.get('http')),
        lambda e:bool(e.get('runtime',{}).get('file_paths')),
        lambda e:e.get('verdict')=='DROPPED',
        lambda e:e.get('kind')=='pod_configuration_change',
        lambda e:bool(e.get('dns')),
    ]
    def bucket(e):
        return (e.get('kind'),e.get('verb'),(e.get('target') or {}).get('resource'),e.get('function_name'),e.get('process',{}).get('binary'),e.get('verdict') if e.get('kind')=='network' else None,bool(e.get('http')),bool(e.get('dns')))
    for match in groups:
        candidates=[e for e in ordered if e['id'] not in ids and match(e)]
        if candidates:
            candidate=max(candidates,key=lambda e:int('binary_outside_boundary' in e.get('findings',[]))+int(any(path.endswith('/token') for path in e.get('runtime',{}).get('file_paths',[]))))
            selected.append(candidate);ids.add(candidate['id']);buckets.add(bucket(candidate))
        if len(selected)>=limit:return selected
    for event in ordered:
        key=bucket(event)
        if event['id'] not in ids and key not in buckets:
            selected.append(event);ids.add(event['id']);buckets.add(key)
        if len(selected)>=limit:return selected
    return selected+[e for e in events if e['id'] not in ids][:limit-len(selected)]


def compact_event(event):
    result={k:event[k] for k in ('id','timestamp','observed_at','source','kind','findings','verdict','drop_reason','http','dns','verb','target','status_code','outcome','actor','token_pod_uid','source_pod','destination_pod','process','parent_binary','function_name','policy_name') if k in event}
    runtime=event.get('runtime') or {}
    if runtime:
        result['runtime']={k:runtime[k] for k in ('file_paths','numeric_arguments','return_value','parent') if runtime.get(k)}
    if event.get('changes'):
        result['changed_fields']=list(event['changes'])
    result['description']=event_summary(event)
    return result


async def review_context(service, namespace, pod, limit=12):
    evidence=await pod_evidence(service, namespace, pod, service.maximum)
    if not evidence['pods']:return None
    record=evidence['pods'][0];identity=record['identity']
    selected=representative_events(record['events'],limit)
    shared=representative_events(record['shared_identity_audit_events'],min(limit,3))
    return {'cluster':service.cluster, 'pod':{k:identity.get(k) for k in ('namespace','pod','uid','service_account_name','node','phase','host_network','host_pid','host_ipc','security_context')},
            'containers':[{k:c.get(k) for k in ('name','image','security_context','resources','volume_mounts')} for c in identity.get('containers',[])],
            'permission_points':permission_points(identity), 'events':[compact_event(e) for e in selected],
            'shared_identity_events':[compact_event(e) for e in shared],
            'boundaries':[b for b in service.boundaries if b.get('namespace')==namespace and b.get('pod',pod)==pod],
            'coverage':service.health,'inventory_observed_at':evidence['inventory_observed_at'],
            'sample':{'selected':len(selected),'retained_attributed_events':len(record['events']),'shared_identity_events':len(record['shared_identity_audit_events']),'strategy':'Distinct actions prioritized by observed signals; normal observations are also sampled. Not a complete history.'},
            'limitations':['Permissions are current RBAC grants, not proof of misuse.','Token pod UID binds credentials, not the physical caller.','Shared identity events do not prove this pod acted.','No score or automated remediation is enabled.']}
