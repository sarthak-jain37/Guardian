"""Explicit disposable Kind pilot setup. Never records a human approval.

All writes target guardian-release and its private kubeconfig. Existing clusters
and the user's default kubeconfig are not changed. See docs/demo-runbook.md.
"""
import argparse,hashlib,json,os,subprocess,sys
from pathlib import Path
from datetime import datetime,timezone
import yaml

VERSION='0.2.0-rc.1'
NODE='kindest/node@sha256:047357ac0cfea04663786a612ba1eaba9702bef25227a794b52890dd8bcd692e'
ROOT=Path(__file__).resolve().parents[1]


def run(*args,**kwargs):return subprocess.run(list(args),check=True,**kwargs)


def kube(directory,*args,**kwargs):return run('kubectl','--kubeconfig',str(directory/'kubeconfig'),'--context','kind-guardian-release',*args,**kwargs)


def setup(directory):
    from backend.app.core.auth import Principal
    from scripts.guardian_auth import issue
    from scripts.guardian_archive_keys import main as unused
    from cryptography.fernet import Fernet
    directory.mkdir(parents=True,exist_ok=True,mode=0o700);(directory/'audit').mkdir(exist_ok=True)
    policy=(ROOT/'k8s/guardian-usage-audit-policy.yaml').read_bytes();(directory/'audit-policy.yaml').write_bytes(policy)
    patch='''kind: ClusterConfiguration
apiServer:
  extraArgs:
    audit-policy-file: /etc/guardian/audit-policy.yaml
    audit-log-path: /var/log/guardian-audit/audit.log
    audit-log-maxage: "7"
    audit-log-maxbackup: "10"
    audit-log-maxsize: "100"
  extraVolumes:
    - {name: guardian-policy, hostPath: /etc/guardian, mountPath: /etc/guardian, readOnly: true}
    - {name: guardian-audit, hostPath: /var/log/guardian-audit, mountPath: /var/log/guardian-audit}
'''
    config={'kind':'Cluster','apiVersion':'kind.x-k8s.io/v1alpha4','nodes':[{'role':'control-plane','kubeadmConfigPatches':[patch],
        'extraMounts':[{'hostPath':str(directory/'audit-policy.yaml'),'containerPath':'/etc/guardian/audit-policy.yaml','readOnly':True},
            {'hostPath':str(directory/'audit'),'containerPath':'/var/log/guardian-audit'}]}]}
    (directory/'kind.yaml').write_text(yaml.safe_dump(config,sort_keys=False))
    clusters=run('kind','get','clusters',capture_output=True,text=True).stdout.split()
    if 'guardian-release' not in clusters:
        run('kind','create','cluster','--name','guardian-release','--image',NODE,'--config',str(directory/'kind.yaml'),'--kubeconfig',str(directory/'kubeconfig'),'--wait','90s')
    if not (directory/'kubeconfig').exists():raise ValueError('existing_pilot_requires_its_original_private_kubeconfig')
    for namespace in ('guardian-demo','guardian-system'):
        result=kube(directory,'create','namespace',namespace,'--dry-run=client','-o','yaml',capture_output=True,text=True)
        kube(directory,'apply','-f','-',input=result.stdout,text=True)
    # Only the new pilot's own audit export receives the collector's read group.
    run('docker','exec','guardian-release-control-plane','sh','-c',
        'chgrp 10001 /var/log/guardian-audit /var/log/guardian-audit/audit.log && chmod 0750 /var/log/guardian-audit && chmod 0640 /var/log/guardian-audit/audit.log')
    registry=directory/'registry.json'
    for name,kind,permissions in [('reviewer','human',['read','review','operate']),('worker','service',['read','publish','deliver'])]:
        token=directory/(name+'.token')
        if not token.exists():
            value=issue(registry,Principal(actor='pilot-'+name,kind=kind,grants=[{'cluster_id':'guardian-release','namespace':'guardian-demo','permissions':permissions}]),hours=24)
            token.write_text(value+'\n');token.chmod(0o600)
    keys=directory/'archive-keys.json'
    if not keys.exists():keys.write_text(json.dumps({'active':'pilot-v1','keys':{'pilot-v1':Fernet.generate_key().decode()}}));keys.chmod(0o600)
    source={'schema_version':'guardian.collection-policy.v1','cluster_id':'guardian-release','source_id':'pilot-audit-v1','namespace':'guardian-demo',
        'audit_policy_ref':'guardian-release-audit-v1','resources':['/pods','/secrets','/configmaps'],
        'resource_scopes':{r:'namespaced' for r in ['/pods','/secrets','/configmaps']},
        'approved_policy_sha256':hashlib.sha256(policy).hexdigest(),'completeness_attested':True,'maximum_lag_seconds':30}
    (directory/'source.json').write_text(json.dumps(source))
    for name,files in [('guardian-auth',{'registry.json':registry}),('guardian-worker',{'worker.token':directory/'worker.token'}),
        ('guardian-archive',{'archive-keys.json':keys}),('guardian-collection',{'source.json':directory/'source.json','audit-policy.yaml':directory/'audit-policy.yaml'})]:
        value=kube(directory,'-n','guardian-system','create','secret','generic',name,*['--from-file='+k+'='+str(v) for k,v in files.items()],'--dry-run=client','-o','yaml',capture_output=True,text=True)
        kube(directory,'apply','-f','-',input=value.stdout,text=True)
    print('Private pilot credentials created. Reviewer token: '+str(directory/'reviewer.token'))


def workload(directory,image):
    if image.endswith(':latest') or '@sha256:' not in image:raise ValueError('workload_requires_loaded_image_digest')
    common={'namespace':'guardian-demo','labels':{'guardian-demo-owner':'guardian-release'}}
    objects=[{'apiVersion':'v1','kind':'ServiceAccount','metadata':{**common,'name':'pod-reader'}},
        {'apiVersion':'rbac.authorization.k8s.io/v1','kind':'Role','metadata':{**common,'name':'pod-reader'},
         'rules':[{'apiGroups':[''],'resources':['pods','secrets'],'verbs':['get']}]},
        {'apiVersion':'rbac.authorization.k8s.io/v1','kind':'RoleBinding','metadata':{**common,'name':'pod-reader'},
         'roleRef':{'apiGroup':'rbac.authorization.k8s.io','kind':'Role','name':'pod-reader'},
         'subjects':[{'kind':'ServiceAccount','name':'pod-reader','namespace':'guardian-demo'}]},
        {'apiVersion':'apps/v1','kind':'Deployment','metadata':{**common,'name':'pod-reader'},'spec':{'replicas':1,
         'selector':{'matchLabels':{'app':'guardian-pod-reader'}},'template':{'metadata':{'labels':{'app':'guardian-pod-reader'}},
         'spec':{'serviceAccountName':'pod-reader','securityContext':{'runAsNonRoot':True,'runAsUser':10001,'seccompProfile':{'type':'RuntimeDefault'}},
         'containers':[{'name':'reader','image':image,'imagePullPolicy':'IfNotPresent','env':[{'name':'POD_NAME','valueFrom':{'fieldRef':{'fieldPath':'metadata.name'}}}],
         'ports':[{'containerPort':8080}],'resources':{'requests':{'cpu':'50m','memory':'32Mi'},'limits':{'cpu':'250m','memory':'128Mi'}},
         'securityContext':{'allowPrivilegeEscalation':False,'readOnlyRootFilesystem':True,'capabilities':{'drop':['ALL']}},
         'readinessProbe':{'httpGet':{'path':'/health','port':8080},'initialDelaySeconds':2}}]}}}}]
    target=directory/'workload.yaml';target.write_text(yaml.safe_dump_all(objects,sort_keys=False))
    existing=kube(directory,'get','role','pod-reader','-n','guardian-demo','--ignore-not-found','-o','json',capture_output=True,text=True).stdout
    if existing:raise ValueError('workload_already_installed_use_explicit_scenario_reset_not_apply')
    kube(directory,'apply','-f',str(target));kube(directory,'rollout','status','deployment/pod-reader','-n','guardian-demo','--timeout=90s')


def execution_policy(directory):
    from backend.app.models.execution import ExecutionPolicy,FunctionalProfile
    from backend.app.services.governance_store import digest
    def obj(kind,name):return json.loads(kube(directory,'get',kind,name,'-n','guardian-demo','-o','json',capture_output=True,text=True).stdout)
    role,sa,workload=obj('role','pod-reader'),obj('serviceaccount','pod-reader'),obj('deployment','pod-reader')
    pods=json.loads(kube(directory,'get','pods','-n','guardian-demo','-l','app=guardian-pod-reader','-o','json',capture_output=True,text=True).stdout)['items']
    images=sorted({s['imageID'] for p in pods for s in p.get('status',{}).get('containerStatuses',[]) if '@sha256:' in s.get('imageID','')})
    if not images:raise ValueError('running_digest_unavailable')
    code="import hashlib,json;from pathlib import Path;print(json.dumps({p:hashlib.sha256(Path(p).read_bytes()).hexdigest() for p in ['/app/.venv/bin/python','/app/demo/checks/pod_reader.py']}))"
    hashes=json.loads(kube(directory,'-n','guardian-system','exec','deploy/guardian-backend','--','python','-c',code,capture_output=True,text=True).stdout)
    profile=FunctionalProfile(namespace='guardian-demo',role_name='pod-reader',target_uid=role['metadata']['uid'],subject_uid=sa['metadata']['uid'],
        workload_uid=workload['metadata']['uid'],image_digest=digest(images),argv=['/app/.venv/bin/python','/app/demo/checks/pod_reader.py','--artifacts=/state/behavior'],
        artifact_hashes=hashes,timeout_seconds=30,observation_seconds=10)
    policy=ExecutionPolicy(cluster_id='guardian-release',enabled=True,namespaces=['guardian-demo'],profiles=[profile])
    # TOML supports the nested profile table; write fixed fields without a new dependency.
    lines=['schema_version="guardian.execution-policy.v1"','enabled=true','cluster_id="guardian-release"','namespaces=["guardian-demo"]',
        'recovery_mode="optional_advance_exact"','recovery_seconds=600','[[profiles]]']
    for key,value in profile.model_dump().items():
        if key=='artifact_hashes':continue
        lines.append(key+'='+json.dumps(value))
    lines.append('[profiles.artifact_hashes]')
    lines.extend(json.dumps(k)+'='+json.dumps(v) for k,v in hashes.items())
    path=directory/'execution.toml';path.write_text('\n'.join(lines)+'\n')
    import tomllib
    ExecutionPolicy.model_validate(tomllib.loads(path.read_text()))
    secret=kube(directory,'-n','guardian-system','create','secret','generic','guardian-execution','--from-file=execution.toml='+str(path),'--dry-run=client','-o','yaml',capture_output=True,text=True)
    kube(directory,'apply','-f','-',input=secret.stdout,text=True)
    print('Identity-bound execution policy prepared. Enabling the chart still requires explicit operator action; no human approval was recorded.')


def scenario(directory,kind):
    row=json.loads(kube(directory,'get','role','pod-reader','-n','guardian-demo','-o','json',capture_output=True,text=True).stdout)
    if row['metadata'].get('labels',{}).get('guardian-demo-owner')!='guardian-release':raise ValueError('owned_disposable_role_required')
    rules=[{'apiGroups':[''],'resources':['pods','secrets'] if kind in ('reset','drift') else ['pods'],'verbs':['get']}]
    patch=[{'op':'test','path':'/metadata/uid','value':row['metadata']['uid']},{'op':'test','path':'/metadata/resourceVersion','value':row['metadata']['resourceVersion']},{'op':'replace','path':'/rules','value':rules}]
    kube(directory,'patch','role','pod-reader','-n','guardian-demo','--type=json','-p',json.dumps(patch))
    print('Scenario setup changed only the owned demo Role; decision/evidence history was preserved.')


def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--directory',type=Path,default=ROOT/'data/pilot')
    sub=p.add_subparsers(dest='command',required=True);sub.add_parser('setup')
    w=sub.add_parser('workload');w.add_argument('--image',required=True)
    sub.add_parser('execution-policy')
    s=sub.add_parser('scenario');s.add_argument('kind',choices=['reset','drift','narrow']);s.add_argument('--confirm-disposable',action='store_true',required=True)
    args=p.parse_args();os.umask(0o077);directory=args.directory.resolve()
    if args.command=='setup':setup(directory)
    elif args.command=='workload':workload(directory,args.image)
    elif args.command=='execution-policy':execution_policy(directory)
    else:scenario(directory,args.kind)


if __name__=='__main__':main()
