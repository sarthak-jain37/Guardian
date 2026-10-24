"""Allowlisted evidence only; no file contents, process arguments or credentials."""
SENSITIVE_PREFIXES = ('/var/run/secrets/', '/run/secrets/', '/etc/shadow', '/etc/kubernetes/', '/root/.ssh/', '/proc/kcore', '/var/run/docker.sock', '/run/containerd/')


def runtime_details(payload):
    process = payload.get('process') or {}
    details = {k: process[k] for k in ('docker', 'tid', 'auid', 'cwd', 'cap', 'ns') if k in process}
    details['parent'] = {k: payload.get('parent', {})[k] for k in ('exec_id', 'pid', 'binary', 'uid') if k in (payload.get('parent') or {})}
    details['container'] = {k: (process.get('pod', {}).get('container') or {})[k] for k in ('id', 'name', 'image') if k in (process.get('pod', {}).get('container') or {})}
    paths, numbers = [], []
    for arg in payload.get('args', []):
        for key in ('file_arg', 'path_arg'):
            value = arg.get(key)
            if isinstance(value, dict) and isinstance(value.get('path'), str):
                paths.append(value['path'][:4096])
        for key in ('int_arg', 'long_arg', 'uint_arg', 'size_arg'):
            if key in arg:
                numbers.append({'index': arg.get('index'), 'type': key, 'value': arg[key]})
    details['file_paths'] = paths
    details['numeric_arguments'] = numbers
    ret = payload.get('return') or {}
    details['return_value'] = {k: ret[k] for k in ('int_arg', 'long_arg', 'uint_arg') if k in ret}
    signals = []
    if process.get('binary') in ('/bin/sh', '/bin/bash', '/bin/dash', '/usr/bin/bash', '/bin/ash'):
        signals.append('shell_process_observed')
    if process.get('binary', '').startswith(('/tmp/', '/var/tmp/', '/dev/shm/')):
        signals.append('execution_from_writable_directory')
    effective = (process.get('cap') or {}).get('effective', [])
    if isinstance(effective, list) and set(effective) & {'CAP_SYS_ADMIN', 'CAP_SYS_PTRACE', 'CAP_SYS_MODULE', 'CAP_BPF', 'CAP_NET_ADMIN'}:
        signals.append('powerful_linux_capability_observed')
    if any(path.startswith(SENSITIVE_PREFIXES) for path in paths):
        signals.append('sensitive_file_access_attempt')
    function = payload.get('function_name', '')
    for fragment, signal in (('setns', 'namespace_change_attempt'), ('unshare', 'namespace_creation_attempt'),
                             ('mount', 'mount_operation_attempt'), ('ptrace', 'process_inspection_attempt'),
                             ('bpf', 'bpf_operation_attempt'), ('init_module', 'kernel_module_operation_attempt')):
        if fragment in function:
            signals.append(signal)
    if (process.get('ns') or {}).get('pid', {}).get('is_host'):
        signals.append('host_pid_namespace_observed')
    return details, signals


def audit_details(raw):
    if raw.get('stage') not in ('ResponseComplete', 'ResponseStarted'):
        return None
    user = raw.get('user') or {}
    actor = user.get('username', '')
    if not actor.startswith('system:serviceaccount:'):
        return None
    pieces = actor.split(':', 3)
    extra = user.get('extra') or {}
    def first(key):
        value = extra.get('authentication.kubernetes.io/' + key, [])
        return value[0] if isinstance(value, list) and value else None
    ref = raw.get('objectRef') or {}
    verb = raw.get('verb')
    code = (raw.get('responseStatus') or {}).get('code')
    signals = []
    if verb in ('create', 'delete', 'deletecollection', 'patch', 'update'):
        signals.append('kubernetes_mutation_attempt')
    if ref.get('subresource') in ('exec', 'attach', 'portforward', 'ephemeralcontainers'):
        signals.append('pod_interaction_attempt')
    if ref.get('resource') == 'secrets' or (ref.get('resource') == 'serviceaccounts' and ref.get('subresource') == 'token'):
        signals.append('credential_api_access_attempt')
    if code in (401, 403):
        signals.append('api_authentication_or_authorization_denied')
    return {'kind': 'kubernetes_audit', 'timestamp': raw.get('requestReceivedTimestamp'),
            'audit_id': raw.get('auditID'), 'stage': raw.get('stage'), 'actor': actor,
            'source_pod': {'namespace': pieces[2], 'pod': first('pod-name') or '', 'uid': first('pod-uid')},
            'token_pod_uid': first('pod-uid'), 'verb': verb,
            'target': {k: ref[k] for k in ('apiGroup', 'resource', 'subresource', 'namespace', 'name', 'uid') if k in ref},
            'status_code': code, 'outcome': 'success' if isinstance(code, int) and 200 <= code < 300 else 'denied' if code in (401, 403) else 'other_or_unknown',
            'source_ips': raw.get('sourceIPs', []), 'user_agent': raw.get('userAgent'),
            'impersonated_username': (raw.get('impersonatedUser') or {}).get('username'),
            'authorization_decision': (raw.get('annotations') or {}).get('authorization.k8s.io/decision'),
            'signals': signals}
