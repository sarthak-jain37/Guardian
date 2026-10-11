"""Audit entry -> normalized usage events / RBAC-change events. Pure functions, no I/O."""
from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from urllib.parse import urlsplit

from .schema import RequestKey

EPOCH = datetime(1970, 1, 1, tzinfo=timezone.utc)
HOUR_US = 3_600_000_000
SA_PREFIX = 'system:serviceaccount:'
RBAC_GROUP = 'rbac.authorization.k8s.io'
RBAC_RESOURCES = frozenset({'roles', 'rolebindings', 'clusterroles', 'clusterrolebindings'})
MUTATING = frozenset({'create', 'update', 'patch', 'delete', 'deletecollection'})
NAMED_VERBS = frozenset({'get', 'update', 'patch', 'delete'})
STAGES = ('ResponseStarted', 'ResponseComplete', 'Panic')

# Audit events don't say whether a resource is namespaced. Without discovery data we can only
# label well-known cluster-scoped kinds; everything else with no namespace is 'unknown'
# (never guessed). Replace is_namespaced() with a discovery-backed function for exact scope.
CLUSTER_SCOPED = frozenset({
    ('', 'nodes'), ('', 'namespaces'), ('', 'persistentvolumes'), ('', 'componentstatuses'),
    (RBAC_GROUP, 'clusterroles'), (RBAC_GROUP, 'clusterrolebindings'),
    ('apiextensions.k8s.io', 'customresourcedefinitions'),
    ('storage.k8s.io', 'storageclasses'), ('storage.k8s.io', 'volumeattachments'),
    ('storage.k8s.io', 'csidrivers'), ('storage.k8s.io', 'csinodes'),
    ('admissionregistration.k8s.io', 'mutatingwebhookconfigurations'),
    ('admissionregistration.k8s.io', 'validatingwebhookconfigurations'),
    ('certificates.k8s.io', 'certificatesigningrequests'),
    ('scheduling.k8s.io', 'priorityclasses'), ('networking.k8s.io', 'ingressclasses'),
    ('node.k8s.io', 'runtimeclasses'), ('apiregistration.k8s.io', 'apiservices'),
    ('authentication.k8s.io', 'tokenreviews'), ('authorization.k8s.io', 'subjectaccessreviews'),
    ('authorization.k8s.io', 'selfsubjectaccessreviews'), ('authorization.k8s.io', 'selfsubjectrulesreviews'),
})


def is_namespaced(group: str, resource: str) -> bool | None:
    return False if (group, resource) in CLUSTER_SCOPED else None


def parse_us(s) -> int | None:
    if not s or not isinstance(s, str):
        return None
    try:
        dt = datetime.fromisoformat(s.replace('Z', '+00:00'))
    except ValueError:
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return (dt - EPOCH) // timedelta(microseconds=1)


def from_us(us: int) -> datetime:
    return EPOCH + timedelta(microseconds=us)


def parse_sa(username: str) -> tuple[str, str] | None:
    parts = username.split(':')
    if username.startswith(SA_PREFIX) and len(parts) == 4 and parts[2] and parts[3]:
        return parts[2], parts[3]
    return None


def _id(s, n=256):
    return (s or None) and str(s)[:n]


def _digest(d: dict, prefix: str) -> str:
    return prefix + hashlib.sha256(json.dumps(d, sort_keys=True, separators=(',', ':')).encode()).hexdigest()[:32]


def key_id(rk: RequestKey) -> str:
    """Deterministic id of a canonical request key (what the orchestrator passes in requested_key_ids)."""
    return _digest(rk.model_dump(), 'rk_')


def family_id(rk: RequestKey) -> str:
    """Same key with the name dimension erased; groups all observed names for 'any_name' queries."""
    d = rk.model_dump()
    d.update(resource_name=None, name_resolution='any_name', name_field_selector=None)
    return _digest(d, 'rf_')


def classify(stage: str, decision: str, code: int) -> str | None:
    if stage == 'ResponseStarted':
        return 'authorized_incomplete' if decision == 'allow' else 'unknown'
    if stage in ('ResponseComplete', 'Panic'):
        if decision == 'forbid':
            return 'denied'
        if decision == 'allow':
            if not code:
                return 'unknown'              # allowed, but no status recorded: don't guess success/failure
            if stage == 'ResponseComplete' and 200 <= code < 400:
                return 'successful_completed'
            return 'authorized_error'         # incl. 4xx/5xx and admission denials (authz said allow)
        return 'unknown'
    return None


def build_request_key(entry: dict) -> RequestKey | None:
    verb = entry.get('verb') or ''
    if not verb:
        return None
    obj = entry.get('objectRef') or {}
    resource = obj.get('resource') or None
    if not resource:
        path = urlsplit(entry.get('requestURI') or '').path
        return RequestKey(kind='non_resource', verb=_id(verb), api_group=None, resource=None, subresource=None,
                          scope='non_resource', namespace=None, resource_name=None,
                          name_resolution='not_applicable', name_field_selector=None,
                          non_resource_path=path[:2048] or None)
    group = obj.get('apiGroup') or ''
    ns = obj.get('namespace') or None
    name = obj.get('name') or None
    if (group, resource) == ('', 'namespaces'):       # apiserver puts the namespace's own name in Namespace
        ns, scope = None, 'cluster'
    elif ns:
        scope = 'namespaced'
    else:
        nsd = is_namespaced(group, resource)
        scope = 'cluster' if nsd is False else ('all_namespaces' if nsd and verb in ('list', 'watch', 'deletecollection') else 'unknown')

    selector = None
    if verb in NAMED_VERBS:
        res = 'explicit' if name else 'unknown'
    elif verb in ('list', 'watch'):
        res = 'explicit' if name else 'collection'   # apiserver derives Name from fieldSelector=metadata.name=...
        selector = f'metadata.name={name}' if name else None
    elif verb == 'create':
        res, name = 'not_applicable', None           # resourceNames can't restrict create; avoids generateName blow-up
    elif verb == 'deletecollection':
        res, name = 'collection', None
    else:
        res = 'explicit' if name else 'unknown'
    return RequestKey(kind='resource', verb=_id(verb), api_group=group, resource=_id(resource),
                      subresource=_id(obj.get('subresource')), scope=scope, namespace=_id(ns),
                      resource_name=_id(name), name_resolution=res, name_field_selector=_id(selector),
                      non_resource_path=None)


def _impersonate_key(target: str) -> RequestKey:
    sa = parse_sa(target)
    if sa:
        res, scope, ns, name = 'serviceaccounts', 'namespaced', sa[0], sa[1]
    else:
        res, scope, ns, name = 'users', 'cluster', None, target
    return RequestKey(kind='resource', verb='impersonate', api_group='', resource=res, subresource=None,
                      scope=scope, namespace=ns, resource_name=_id(name), name_resolution='explicit',
                      name_field_selector=None, non_resource_path=None)


@dataclass
class UsageEvent:
    username: str
    subject: dict
    key: RequestKey
    key_id: str
    family_id: str
    stage: str
    outcome: str
    ts_us: int            # requestReceivedTimestamp: bucketing time
    stage_ts_us: int
    audit_id: str


@dataclass
class Extracted:
    usage: list
    rbac: dict | None
    secret_body_seen: bool = False


def extract(entry: dict) -> Extracted:
    empty = Extracted([], None)
    if not isinstance(entry, dict) or entry.get('stage') not in STAGES:
        return empty
    stage, audit_id, verb = entry['stage'], entry.get('auditID') or '', entry.get('verb') or ''
    user = entry.get('user') or {}
    username = user.get('username') or ''
    ts = parse_us(entry.get('requestReceivedTimestamp'))
    sts = parse_us(entry.get('stageTimestamp')) or ts
    if not (audit_id and verb and username and ts):
        return empty
    ann = entry.get('annotations') or {}
    decision = ann.get('authorization.k8s.io/decision', '')
    code = (entry.get('responseStatus') or {}).get('code') or 0
    outcome = classify(stage, decision, code)
    obj = entry.get('objectRef') or {}
    secret = obj.get('resource') == 'secrets' and bool(entry.get('requestObject') or entry.get('responseObject'))
    key = build_request_key(entry)
    if outcome is None or key is None:
        return Extracted([], None, secret)

    # Impersonation: the request itself is authorized as the impersonated identity; the real caller
    # exercised 'impersonate'. (Approximation: both share the one recorded decision/status.)
    imp = entry.get('impersonatedUser') or {}
    pairs = [(username, user, key)]
    if imp.get('username'):
        pairs = [(username, user, _impersonate_key(imp['username'])), (imp['username'], imp, key)]
    usage = []
    for uname, u, k in pairs:
        if not parse_sa(uname):
            continue
        usage.append(UsageEvent(
            username=uname, key=k, key_id=key_id(k), family_id=family_id(k), stage=stage, outcome=outcome,
            ts_us=ts, stage_ts_us=sts, audit_id=audit_id,
            subject={'groups': [str(g)[:256] for g in (u.get('groups') or [])[:128]],
                     'uid': u.get('uid') or '', 'evidence': audit_id}))

    rbac = None
    if (stage == 'ResponseComplete' and obj.get('apiGroup') == RBAC_GROUP
            and obj.get('resource') in RBAC_RESOURCES and verb in MUTATING):
        rbac = {'audit_id': audit_id, 'ts_us': ts, 'stage_ts_us': sts, 'actor': username,
                'impersonated_user': imp.get('username', ''), 'verb': verb, 'resource': obj['resource'],
                'resource_name': obj.get('name', ''), 'namespace': obj.get('namespace', ''),
                'status_code': code, 'decision': decision, 'user_agent': entry.get('userAgent', '')[:256]}
    return Extracted(usage, rbac, secret)
