"""Material observation identity for scheduling; never an approved baseline."""
from backend.app.services.canonical_hash import canonical_hash
from backend.app.services.governance_store import digest


def observation_hash(state,inventory,namespace):
    scoped={key:value for key,value in state.items() if value.get('kind') in ('ClusterRole','ClusterRoleBinding')
        or value.get('metadata',{}).get('namespace')==namespace}
    objects=[]
    for obj in inventory['objects']:
        metadata=obj.get('metadata',{});status=obj.get('status',{})
        objects.append({'kind':obj.get('kind'),'uid':metadata.get('uid'),'owners':metadata.get('ownerReferences',[]),
            'spec':obj.get('spec',{}),'images':[{'imageID':c.get('imageID'),'restartCount':c.get('restartCount'),
                'ready':c.get('ready')} for c in status.get('containerStatuses',[])]})
    context={'objects':sorted(objects,key=lambda o:(o['kind'] or '',o['uid'] or '')),'errors':sorted(inventory['errors'])}
    # UID changes are material even when policy semantics stay the same.
    identities=[]
    for obj in scoped.values():
        metadata=obj.get('metadata',{})
        identities.append({'kind':obj.get('kind',''),'namespace':metadata.get('namespace') or '',
            'name':metadata.get('name',''),'uid':metadata.get('uid'),
            'owners':metadata.get('ownerReferences',[]),
            'managed_by':metadata.get('labels',{}).get('app.kubernetes.io/managed-by')})
    identities.sort(key=lambda o:(o['kind'],o['namespace'],o['name']))
    return digest([canonical_hash(scoped),identities,context])
