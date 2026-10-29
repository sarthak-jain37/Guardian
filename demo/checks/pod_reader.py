"""Meaningful pilot harness: exact live workload plus its actual behavior endpoint."""
import argparse,json,os,sys
from datetime import datetime,timezone
from pathlib import Path
from uuid import uuid4
from kubernetes import client,config
sys.path.insert(0,str(Path(__file__).resolve().parents[2]))
from backend.app.services.governance_store import digest
from backend.app.services.kube_transport import api_call


def check(request,api,*,namespace='guardian-demo',role_name='pod-reader',artifact_directory):
    started=datetime.now(timezone.utc);core=client.CoreV1Api(api);apps=client.AppsV1Api(api);rbac=client.RbacAuthorizationV1Api(api)
    role=rbac.read_namespaced_role(role_name,namespace,_request_timeout=(3,5))
    deployment=apps.read_namespaced_deployment('pod-reader',namespace,_request_timeout=(3,5))
    sa=core.read_namespaced_service_account('pod-reader',namespace,_request_timeout=(3,5))
    pods=core.list_namespaced_pod(namespace,label_selector='app=guardian-pod-reader',_request_timeout=(3,5)).items
    running=[p for p in pods if p.status.phase=='Running' and p.metadata.deletion_timestamp is None]
    if len(running)!=1:raise ValueError('one_running_reader_required')
    pod=running[0]
    images=sorted({s.image_id for s in pod.status.container_statuses or [] if '@sha256:' in (s.image_id or '')})
    if (request['namespace'],request['target_uid'],request['workload_uid'],request['image_digest'],request['subject']['uid'])!=(
            namespace,role.metadata.uid,deployment.metadata.uid,digest(images),sa.metadata.uid):raise ValueError('live_profile_identity_changed')
    if pod.spec.service_account_name!='pod-reader' or not images:raise ValueError('reader_identity_unavailable')
    # Kubernetes pod proxy uses this harness's scoped identity. The actual reads
    # occur inside the application with its own mounted ServiceAccount token.
    response=api_call(api,'/api/v1/namespaces/{namespace}/pods/{name}/proxy/check','POST',
        path_params={'namespace':namespace,'name':pod.metadata.name+':8080'},auth_settings=['BearerToken'],
        response_type='object',_return_http_data_only=True,_request_timeout=(3,15))
    if set(response.get('checks',{}))!={'startup','normal','restart'}:raise ValueError('behavior_contract_missing')
    directory=Path(artifact_directory);directory.mkdir(mode=0o700,parents=True,exist_ok=True)
    identifier='behavior-'+uuid4().hex
    artifact=directory/(identifier+'.json');artifact.write_text(json.dumps({'request':request,'observation':response},sort_keys=True))
    artifact.chmod(0o600)
    return {'schema_version':'guardian.functional-proof.v1','phase':request['phase'],'workload_uid':request['workload_uid'],
        'image_digest':request['image_digest'],'started_at':started.isoformat(),'completed_at':datetime.now(timezone.utc).isoformat(),
        'runner_healthy':response['runner_healthy'],'dependencies_healthy':response['dependencies_healthy'],
        'checks':response['checks'],'evidence_refs':['pilot-behavior:'+identifier+':sha256:'+__import__('hashlib').sha256(artifact.read_bytes()).hexdigest()]}


def main():
    p=argparse.ArgumentParser();p.add_argument('--artifacts',required=True);args=p.parse_args()
    raw=sys.stdin.buffer.read(32769)
    if len(raw)>32768:raise ValueError('functional_request_too_large')
    request=json.loads(raw)
    try:config.load_incluster_config()
    except config.ConfigException:config.load_kube_config(config_file=os.environ.get('KUBECONFIG'))
    with client.ApiClient() as api:print(json.dumps(check(request,api,artifact_directory=args.artifacts)))


if __name__=='__main__':main()
