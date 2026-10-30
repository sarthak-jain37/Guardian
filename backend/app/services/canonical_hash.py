"""Versioned RBAC semantics; execution identities/versions remain separate."""
import hashlib
import json

VERSION = 'guardian.rbac-semantic.v2'


def ordered(values):
    return sorted(values, key=lambda value: json.dumps(value, sort_keys=True))


def canonical_hash(rbac_state):
    objects = []
    for obj in (rbac_state or {}).values():
        if not isinstance(obj, dict):
            continue
        kind = obj.get('kind')
        if kind not in ('Role','ClusterRole','RoleBinding','ClusterRoleBinding','ServiceAccount'):
            continue
        metadata = obj.get('metadata', {})
        item = {'kind':kind,'name':metadata.get('name'),
                'namespace':metadata.get('namespace','default' if kind in ('Role','RoleBinding','ServiceAccount') else None)}
        if kind in ('Role','ClusterRole'):
            item['rules'] = ordered([{key:ordered(value) if isinstance(value,list) else value
                                     for key,value in rule.items()} for rule in obj.get('rules',[]) or []])
            item['aggregationRule'] = obj.get('aggregationRule')
        elif kind.endswith('Binding'):
            item.update(roleRef=obj.get('roleRef'),subjects=ordered(obj.get('subjects',[]) or []))
        else:
            item['automountServiceAccountToken'] = obj.get('automountServiceAccountToken')
        objects.append(item)
    encoded = json.dumps({'version':VERSION,'objects':ordered(objects)},sort_keys=True,separators=(',',':'))
    return 'sha256:'+hashlib.sha256(encoded.encode()).hexdigest()
