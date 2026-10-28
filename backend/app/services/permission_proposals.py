"""Client-approved, reduction-only changes to dedicated namespaced RBAC roles."""
import asyncio
import copy
import hashlib
import json
import uuid
from datetime import datetime, timezone


def now(): return datetime.now(timezone.utc).isoformat()
def digest(obj): return hashlib.sha256(json.dumps(obj,sort_keys=True).encode()).hexdigest()


def candidates(state, namespace, account):
    result=[]
    bindings=[o for o in state.values() if o.get('kind') in ('RoleBinding','ClusterRoleBinding')]
    for role in state.values():
        if role.get('kind')!='Role' or role.get('metadata',{}).get('namespace')!=namespace:continue
        refs=[b for b in bindings if b.get('roleRef',{}).get('kind')=='Role' and b['roleRef'].get('name')==role['metadata']['name'] and b.get('metadata',{}).get('namespace')==namespace]
        def dedicated(b):
            subjects=b.get('subjects',[])
            return len(subjects)==1 and subjects[0].get('kind')=='ServiceAccount' and subjects[0].get('name')==account and subjects[0].get('namespace',namespace)==namespace
        if refs and all(dedicated(b) for b in refs):
            for index,rule in enumerate(role.get('rules',[])):
                # The model may only remove existing rules, never add grants.
                result.append({'id':role['metadata']['name']+':'+str(index),'role':role['metadata']['name'],'index':index,'rule':rule,'bindings':[b['metadata']['name'] for b in refs]})
    return result


class PermissionProposals:
    def __init__(self,redis,k8s,cluster):
        self.redis,self.k8s=redis,k8s
        self.prefix='guardian:permissions:'+cluster
        self.review_prefix='guardian:telemetry:'+cluster+':grading:reviews:'
        self.tasks=set()

    async def log(self,proposal,event,**fields):
        await self.redis.xadd(self.prefix+':decisions',{'proposal_id':proposal['id'],'pod_uid':proposal['uid'],'event':event,'namespace':proposal['namespace'],'pod':proposal['pod'],'timestamp':now(),'details':json.dumps(fields)})

    async def get(self,identifier):
        raw=await self.redis.get(self.prefix+':proposal:'+identifier)
        return json.loads(raw) if raw else None

    async def put(self,proposal):
        await self.redis.set(self.prefix+':proposal:'+proposal['id'],json.dumps(proposal))

    async def list(self):
        ids=await self.redis.zrevrange(self.prefix+':index',0,199)
        return [p for identifier in ids if (p:=await self.get(identifier))]

    async def recover_interrupted(self):
        for proposal in await self.list():
            if proposal['status'] in ('generating','applying'):
                was=proposal['status']
                proposal.update(status='interrupted' if was=='generating' else 'application_unknown',
                    error='Service restarted during '+was+'. Inspect the recorded receipt before any further action.')
                await self.put(proposal);await self.log(proposal,'interrupted',previous_status=was)

    async def ensure(self,record,document):
        key=self.prefix+':trigger:'+record['uid']+':'+record['fingerprint']
        identifier=str(uuid.uuid4())
        if not await self.redis.set(key,identifier,nx=True):
            existing_id=await self.redis.get(key)
            existing=await self.get(existing_id) if existing_id else None
            if existing and existing.get('status')=='interrupted':
                await self.redis.delete(key)
                return await self.ensure(record,document)
            if existing and existing.get('status')=='generating' and not any(not task.done() and task.get_name()==existing_id for task in self.tasks):
                task=asyncio.create_task(self.generate(existing,record,document),name=existing_id)
                self.tasks.add(task);task.add_done_callback(self.tasks.discard)
            return
        proposal={'id':identifier,'uid':record['uid'],'namespace':record['namespace'],'pod':record['pod'],
                  'service_account':document['pod'].get('service_account_name','default'),'severity':record['severity'],
                  'assessment_fingerprint':record['fingerprint'],'status':'generating','created_at':now(),'changes':[],
                  'explanation':'Preparing a reduction-only permission proposal. No changes have been applied.'}
        await self.put(proposal)
        await self.redis.zadd(self.prefix+':index',{identifier:datetime.now(timezone.utc).timestamp()})
        await self.log(proposal,'proposal_requested')
        task=asyncio.create_task(self.generate(proposal,record,document),name=identifier)
        self.tasks.add(task);task.add_done_callback(self.tasks.discard)

    async def generate(self,proposal,record,document):
        try:
            def read():
                state=self.k8s.get_rbac_state()
                inventory=self.k8s.api_client.sanitize_for_serialization(self.k8s.core_api.list_namespaced_pod(proposal['namespace'],_request_timeout=30))
                return state,inventory
            state,inventory=await asyncio.to_thread(read)
            options=candidates(state,proposal['namespace'],proposal['service_account'])
            proposal['affected_pods']=[p['metadata']['name'] for p in inventory.get('items',[]) if p.get('spec',{}).get('serviceAccountName','default')==proposal['service_account']]
            proposal['affected_instances']={p['metadata']['uid']:p['metadata']['name'] for p in inventory.get('items',[]) if p.get('spec',{}).get('serviceAccountName','default')==proposal['service_account']}
            proposal['limitations']=['All pods sharing this service account are affected. Removing rules can break workload functionality.',
                'ClusterRoles, group grants and shared roles are not changed; these may still grant the same access.']
            if not options:raise ValueError('No dedicated namespaced Roles can be reduced safely. Shared or cluster-wide grants require a manually scoped proposal.')
            from agents.summarizer import propose_permission_reductions
            recommendation=await asyncio.to_thread(propose_permission_reductions,record,options)
            selected=set(recommendation['remove_rule_ids'])
            if not selected or not selected <= {o['id'] for o in options}:raise ValueError('Model did not select valid existing rules to remove')
            changes=[]
            for role_name in sorted({o['role'] for o in options if o['id'] in selected}):
                role=next(o for o in state.values() if o.get('kind')=='Role' and o['metadata'].get('namespace')==proposal['namespace'] and o['metadata']['name']==role_name)
                # Re-read full objects to capture UID/resourceVersion for optimistic concurrency.
                before=self.k8s.api_client.sanitize_for_serialization(await asyncio.to_thread(self.k8s.rbac_api.read_namespaced_role,role_name,proposal['namespace'],_request_timeout=30))
                if before.get('rules',[])!=role.get('rules',[]):raise ValueError('Role changed during proposal generation; request a new proposal')
                after=copy.deepcopy(before)
                after['rules']=[rule for i,rule in enumerate(before.get('rules',[])) if role_name+':'+str(i) not in selected]
                changes.append({'kind':'Role','name':role_name,'before':before,'after':after})
                for binding_name in sorted({b for o in options if o['role']==role_name for b in o['bindings']}):
                    before_binding=self.k8s.api_client.sanitize_for_serialization(await asyncio.to_thread(self.k8s.rbac_api.read_namespaced_role_binding,binding_name,proposal['namespace'],_request_timeout=30))
                    after_binding=copy.deepcopy(before_binding)
                    after_binding.setdefault('metadata',{}).setdefault('annotations',{})['guardian/permission-proposal']=proposal['id']
                    changes.append({'kind':'RoleBinding','name':binding_name,'before':before_binding,'after':after_binding})
            proposal.update(status='pending',explanation=recommendation['explanation'],changes=changes,snapshot_hash=digest(state))
            await self.put(proposal);await self.log(proposal,'proposal_ready',explanation=proposal['explanation'])
        except Exception as exc:
            proposal.update(status='blocked',explanation=str(exc))
            await self.put(proposal);await self.log(proposal,'proposal_blocked',reason=str(exc))

    async def decide(self,identifier,decision,actor,note):
        if decision not in ('accept','reject') or not actor.strip():raise ValueError('A valid decision and actor name are required')
        token=str(uuid.uuid4());lock=self.prefix+':lock:'+identifier
        if not await self.redis.set(lock,token,nx=True,ex=1800):raise ValueError('Another decision is in progress')
        try:
            proposal=await self.get(identifier)
            if not proposal:raise LookupError('Proposal not found')
            if proposal['status']!='pending':raise ValueError('Proposal is no longer pending; repeated decisions are not applied')
            # Log the decision before any Kubernetes write, including failed attempts.
            await self.log(proposal,'decision',decision=decision,actor=actor,note=note)
            proposal.update(decided_by=actor,decision=decision,note=note,decided_at=now())
            if decision=='reject':
                proposal['status']='rejected';await self.put(proposal);return proposal
            proposal['status']='applying';await self.put(proposal)
            applied=[]
            try:
                raw_latest=await self.redis.get(self.review_prefix+proposal['uid'])
                latest=json.loads(raw_latest) if raw_latest else {}
                if latest.get('status')!='assessed' or latest.get('severity',0)<=8 or not latest.get('critical_confirmed') or latest.get('fingerprint')!=proposal['assessment_fingerprint']:
                    raise ValueError('The critical assessment changed or is unavailable; review a new proposal')
                pod=self.k8s.api_client.sanitize_for_serialization(await asyncio.to_thread(self.k8s.core_api.read_namespaced_pod,proposal['pod'],proposal['namespace'],_request_timeout=30))
                if pod['metadata']['uid']!=proposal['uid'] or pod.get('spec',{}).get('serviceAccountName','default')!=proposal['service_account']:
                    raise ValueError('Pod instance or service account changed; review a new proposal')
                inventory=self.k8s.api_client.sanitize_for_serialization(await asyncio.to_thread(self.k8s.core_api.list_namespaced_pod,proposal['namespace'],_request_timeout=30))
                affected={p['metadata']['uid']:p['metadata']['name'] for p in inventory.get('items',[]) if p.get('spec',{}).get('serviceAccountName','default')==proposal['service_account']}
                if affected!=proposal.get('affected_instances',{}):raise ValueError('Pods sharing this service account changed; review a new proposal')
                state=await asyncio.to_thread(self.k8s.get_rbac_state)
                if digest(state)!=proposal['snapshot_hash']:raise ValueError('RBAC changed since the proposal; no changes applied')
                # Verify all versions before starting, then enforce each resourceVersion on replace.
                for change in proposal['changes']:
                    reader=self.k8s.rbac_api.read_namespaced_role if change['kind']=='Role' else self.k8s.rbac_api.read_namespaced_role_binding
                    current=self.k8s.api_client.sanitize_for_serialization(await asyncio.to_thread(reader,change['name'],proposal['namespace'],_request_timeout=30))
                    if current['metadata'].get('resourceVersion')!=change['before']['metadata'].get('resourceVersion') or current['metadata'].get('uid')!=change['before']['metadata'].get('uid'):
                        raise ValueError('Resource changed since proposal; no changes applied')
                for change in proposal['changes']:
                    writer=self.k8s.rbac_api.replace_namespaced_role if change['kind']=='Role' else self.k8s.rbac_api.replace_namespaced_role_binding
                    response=await asyncio.to_thread(writer,change['name'],proposal['namespace'],change['after'],_request_timeout=30)
                    receipt={'kind':change['kind'],'name':change['name'],'result':self.k8s.api_client.sanitize_for_serialization(response)}
                    applied.append(receipt)
                    await self.log(proposal,'resource_applied',actor=actor,resource=receipt)
                proposal.update(status='applied',applied_at=now(),receipt=applied)
            except Exception as exc:
                proposal.update(status='partial_failure' if applied else 'conflict',error=str(exc),receipt=applied)
            await self.put(proposal)
            await self.log(proposal,'execution_result',status=proposal['status'],receipt=applied,error=proposal.get('error'))
            return proposal
        finally:
            await self.redis.eval("if redis.call('GET',KEYS[1]) == ARGV[1] then return redis.call('DEL',KEYS[1]) end return 0",1,lock,token)

    async def history(self):
        return [{'id':identifier,**fields,'details':json.loads(fields['details'])} for identifier,fields in await self.redis.xrevrange(self.prefix+':decisions',count=200)]
