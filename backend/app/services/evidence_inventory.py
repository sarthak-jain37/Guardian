"""Read-only namespace inventory -> immutable, provenance-bound EvidenceBundle."""
import json
from datetime import datetime, timezone
from uuid import uuid4

from contracts.usage_summary_v1 import Subject, RequestKey
from agents.guardian.contracts import Binding, EvidenceBundle, EvidencePolicy, RoleRule, Target, WorkloadContext
from agents.guardian.policy import operations
from backend.app.models.evidence import UsageQuery
from backend.app.services.governance_store import digest
from backend.app.services.pod_evidence import grants_for_pod
from backend.app.services.inventory_semantics import observation_hash


class EvidenceInventory:
    def __init__(self,usage,k8s,*,controlled_namespaces=(),policies=None):
        self.usage,self.db,self.k8s=usage,usage.db,k8s
        self.controlled=set(controlled_namespaces)
        self.policies=policies or {}
        with self.db._connect() as db:
            db.executescript('''
            CREATE TABLE IF NOT EXISTS evidence_snapshots (
              snapshot_id TEXT PRIMARY KEY, cluster_id TEXT NOT NULL, namespace TEXT NOT NULL,
              target_uid TEXT NOT NULL, payload TEXT NOT NULL, content_hash TEXT NOT NULL);
            CREATE TRIGGER IF NOT EXISTS snapshots_no_update BEFORE UPDATE ON evidence_snapshots
              BEGIN SELECT RAISE(ABORT,'immutable_evidence'); END;
            CREATE TRIGGER IF NOT EXISTS snapshots_no_delete BEFORE DELETE ON evidence_snapshots
              BEGIN SELECT RAISE(ABORT,'immutable_evidence'); END;
            CREATE TABLE IF NOT EXISTS evidence_snapshot_observations (snapshot_id TEXT PRIMARY KEY,observed_hash TEXT NOT NULL);
            CREATE TRIGGER IF NOT EXISTS snapshot_observations_no_update BEFORE UPDATE ON evidence_snapshot_observations
              BEGIN SELECT RAISE(ABORT,'immutable_evidence'); END;
            CREATE TRIGGER IF NOT EXISTS snapshot_observations_no_delete BEFORE DELETE ON evidence_snapshot_observations
              BEGIN SELECT RAISE(ABORT,'immutable_evidence'); END;
            ''')

    def load(self,snapshot_id):
        with self.db._connect() as db:
            row=db.execute('SELECT payload FROM evidence_snapshots WHERE snapshot_id=?',(snapshot_id,)).fetchone()
            if row is None:raise LookupError('snapshot_not_found')
            return EvidenceBundle.model_validate_json(row['payload'])

    def observed_hash(self,snapshot_id):
        with self.db._connect() as db:
            row=db.execute('SELECT observed_hash FROM evidence_snapshot_observations WHERE snapshot_id=?',(snapshot_id,)).fetchone()
            return row[0] if row else None

    def capture(self,cluster_id,namespace,role_name,window,*,owner_note=None,owner_notes=()):
        state=self.k8s.get_rbac_state()
        inventory=self.k8s.get_workload_inventory(namespace)
        roles=[r for r in state.values() if r.get('kind')=='Role' and r['metadata'].get('namespace')==namespace and r['metadata']['name']==role_name]
        if len(roles)!=1:raise ValueError('target_role_not_found_or_ambiguous')
        role=roles[0];metadata=role['metadata'];errors=list(inventory.get('errors',[]))
        bindings=[b for b in state.values() if b.get('kind')=='RoleBinding' and b['metadata'].get('namespace')==namespace
            and b.get('roleRef',{}).get('kind')=='Role' and b['roleRef'].get('name')==role_name]
        if len(bindings)!=1:raise ValueError('analysis_requires_one_dedicated_binding')
        raw_binding=bindings[0];subjects=raw_binding.get('subjects',[])
        if len(subjects)!=1 or subjects[0].get('kind')!='ServiceAccount':raise ValueError('analysis_requires_dedicated_service_account')
        sa_name=subjects[0]['name'];sa_namespace=subjects[0].get('namespace',namespace)
        if sa_namespace!=namespace:errors.append('cross_namespace_consumer_inventory_unresolved')
        sas=[o for o in state.values() if o.get('kind')=='ServiceAccount' and o['metadata'].get('namespace')==sa_namespace and o['metadata']['name']==sa_name]
        if len(sas)!=1:raise ValueError('service_account_identity_unavailable')
        sa=sas[0];uid=sa['metadata'].get('uid')
        if not uid or not metadata.get('uid') or not metadata.get('resourceVersion'):raise ValueError('identity_version_envelope_missing')
        ref='inventory:'+digest(state).split(':')[1]
        subject=Subject(username=f'system:serviceaccount:{sa_namespace}:{sa_name}',kind='service_account',namespace=sa_namespace,
            name=sa_name,uid=uid,uid_status='verified',groups=['system:authenticated','system:serviceaccounts',f'system:serviceaccounts:{sa_namespace}'],
            identity_evidence_refs=[ref])
        bm=raw_binding['metadata']
        binding=Binding(binding_id=f'{namespace}/{bm["name"]}',uid=bm['uid'],resource_version=bm['resourceVersion'],
            namespace=namespace,role_name=role_name,role_kind='Role',subjects=[subject],evidence_refs=[ref])
        target=Target(cluster_id=cluster_id,kind='Role',namespace=namespace,name=role_name,uid=metadata['uid'],
            resource_version=metadata['resourceVersion'],rules=[RoleRule.model_validate(r) for r in role.get('rules',[])],
            controller_managed=bool(metadata.get('ownerReferences') or metadata.get('labels',{}).get('app.kubernetes.io/managed-by')))
        objects=inventory.get('objects',[])
        by_uid={o['metadata']['uid']:o for o in objects if o.get('metadata',{}).get('uid')}
        def spec(obj):
            if obj.get('kind')=='Pod':return obj.get('spec',{})
            template=obj.get('spec',{}).get('jobTemplate',{}).get('spec',{}).get('template',{}) if obj.get('kind')=='CronJob' else obj.get('spec',{}).get('template',{})
            return template.get('spec',{})
        roots={}
        for obj in objects:
            if spec(obj).get('serviceAccountName','default')!=sa_name:continue
            current=obj;visited=set()
            while current.get('metadata',{}).get('ownerReferences'):
                owners=[r for r in current['metadata']['ownerReferences'] if r.get('controller')]
                if len(owners)!=1 or owners[0].get('uid') not in by_uid or owners[0]['uid'] in visited:
                    errors.append('unresolved_workload_owner');break
                visited.add(owners[0]['uid']);current=by_uid[owners[0]['uid']]
            if current.get('metadata',{}).get('uid'):roots[current['metadata']['uid']]=current
        pods=[o for o in objects if o.get('kind')=='Pod' and spec(o).get('serviceAccountName','default')==sa_name]
        images=sorted({status.get('imageID','') for pod in pods for status in pod.get('status',{}).get('containerStatuses',[]) if '@sha256:' in status.get('imageID','')})
        if not images:errors.append('workload_image_digest_unavailable')
        pseudo={'metadata':{'namespace':namespace},'spec':{'serviceAccountName':sa_name}}
        grants=grants_for_pod(pseudo,state)
        target_ops=operations([r.model_dump(mode='json') for r in target.rules])
        alternate=set()
        for grant in grants['grants']:
            if grant['binding_kind']=='RoleBinding' and grant['binding_namespace']==namespace and grant['binding_name']==bm['name']:continue
            if grant['scope'] not in ('*',namespace):continue
            rule=grant['rule']
            if any((group in rule.get('apiGroups',[]) or '*' in rule.get('apiGroups',[]))
                and (resource in rule.get('resources',[]) or '*' in rule.get('resources',[]) or resource.partition('/')[0]+'/*' in rule.get('resources',[]))
                and (verb in rule.get('verbs',[]) or '*' in rule.get('verbs',[])) for group,resource,verb in target_ops):
                alternate.add(f'{grant["binding_kind"]}:{grant["binding_namespace"]}:{grant["binding_name"]}')
        if grants['unresolved_bindings']:errors.append('unresolved_alternate_grant')
        schedules=[{'uid':o['metadata'].get('uid'),'kind':o.get('kind'),'schedule':o.get('spec',{}).get('schedule'),
            'timeZone':o.get('spec',{}).get('timeZone'),'suspend':o.get('spec',{}).get('suspend'),'status':o.get('status',{})}
            for o in roots.values() if o.get('kind') in ('CronJob','Job')]
        if schedules:errors.append('scheduled_workflow_requires_validation')
        context=WorkloadContext(context_id='context-'+uuid4().hex,workload_uid=next(iter(roots)) if len(roots)==1 else 'unresolved',
            image_digest=digest(images),subject_uid=uid,known_consumers=sorted(roots)[:64],
            consumer_inventory_complete=namespace in self.controlled and not errors and len(roots)==1,
            alternate_grants=sorted(alternate)[:64],collected_at=self.usage.clock(),provenance='cluster_metadata',
            evidence_refs=[ref],exercised_behaviors=[],known_dependencies=[],unexercised_operations=[],
            optional_documents=([json.dumps({'scheduled_workloads':schedules})[:4000]] if schedules else [])+
                ([owner_note] if owner_note else [])+list(owner_notes),conflicts=[])
        keys={}
        for group,resource,verb in sorted(target_ops):
            base,_,subresource=resource.partition('/')
            request_key=RequestKey(kind='resource',verb=verb,api_group=group,resource=base,subresource=subresource or None,
                scope='namespaced',namespace=namespace,resource_name=None,name_resolution='any_name',name_field_selector=None,non_resource_path=None)
            keys['request-'+digest(request_key.model_dump(mode='json')).split(':')[1]]=request_key
        summary=self.usage.query(UsageQuery(cluster_id=cluster_id,namespace=namespace,subject=subject,window=window,keys=keys))
        policy=self.policies.get(namespace) or EvidencePolicy(policy_version='guardian.evidence-policy.v1',allowed_namespaces=[namespace],
            profile='controlled-lab' if namespace=='guardian-demo' else 'operational',minimum_observation_seconds=300 if namespace=='guardian-demo' else 7*86400)
        evidence=EvidenceBundle(snapshot_id='snapshot-'+uuid4().hex,revision=1,source_mode='captured',target=target,subject=subject,
            binding=binding,context=context,usage=summary,baseline_id=None,policy=policy,evidence_refs=[ref,summary.summary_id],source_errors=sorted(set(errors))[:32])
        with self.db.transaction() as db:
            db.execute('INSERT INTO evidence_snapshots VALUES (?,?,?,?,?,?)',
                (evidence.snapshot_id,cluster_id,namespace,target.uid,evidence.model_dump_json(),digest(evidence.model_dump(mode='json'))))
            db.execute('INSERT INTO evidence_snapshot_observations VALUES (?,?)',
                (evidence.snapshot_id,observation_hash(state,inventory,namespace)))
        return evidence
