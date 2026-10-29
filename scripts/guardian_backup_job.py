"""Opt-in single-host scheduled backup with explicit quiescence and restart fencing."""
import fcntl,json,os,time,tempfile
from datetime import datetime,timedelta,timezone
from pathlib import Path
from contextlib import contextmanager
from scripts.guardian_backup import create


@contextmanager
def quiesce(apps,core,namespace,release,*,sleeper=time.sleep):
    originals={}
    try:
        for component in ('backend','collector','worker'):
            name=release+'-'+component;row=apps.read_namespaced_deployment(name,namespace,_request_timeout=(3,10))
            if row.spec.replicas!=1:raise ValueError('backup_requires_running_singleton_'+component)
            originals[name]=(row.metadata.uid,row.spec.replicas)
        for name in originals:
            row=apps.read_namespaced_deployment(name,namespace,_request_timeout=(3,10))
            if row.metadata.uid!=originals[name][0]:raise ValueError('deployment_recreated_before_quiescence')
            apps.patch_namespaced_deployment(name,namespace,{'metadata':{'resourceVersion':row.metadata.resource_version},'spec':{'replicas':0}},_request_timeout=(3,10))
        for attempt in range(90):
            pods=[p for name in originals for p in core.list_namespaced_pod(namespace,label_selector='app='+name,_request_timeout=(3,10)).items]
            if not pods:break
            sleeper(1)
        else:raise TimeoutError('pods_not_quiesced_no_backup_taken')
        yield
    finally:
        for name,(uid,replicas) in originals.items():
            current=apps.read_namespaced_deployment(name,namespace,_request_timeout=(3,10))
            if current.metadata.uid==uid and current.spec.replicas==0:
                apps.patch_namespaced_deployment(name,namespace,{'metadata':{'resourceVersion':current.metadata.resource_version},'spec':{'replicas':replicas}},_request_timeout=(3,10))
            # Never overwrite a new UID or an operator's changed replica count.


def main():
    from kubernetes import client,config
    from backend.app.services.governance_store import GovernanceStore
    from backend.app.services.usage_store import UsageStore
    from backend.app.services.evidence_archive import EvidenceArchive
    config.load_incluster_config();os.umask(0o077)
    root=Path('/backups');root.mkdir(exist_ok=True,parents=True,mode=0o700)
    with (root/'backup-job.lock').open('a') as lock:
        fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
        intent=root/'coordination.json'
        if intent.exists() and json.loads(intent.read_text())['status']!='DONE':raise ValueError('previous_backup_interrupted_operator_reconciliation_required')
        now=datetime.now(timezone.utc);tag=now.strftime('%Y%m%dT%H%M%SZ')
        record={'schema_version':'guardian.backup-coordination.v1','started_at':now.isoformat(),'status':'STOPPING','singleton_components':['backend','collector','worker']}
        intent.write_text(json.dumps(record));intent.chmod(0o600)
        with client.ApiClient() as api,quiesce(client.AppsV1Api(api),client.CoreV1Api(api),os.environ['POD_NAMESPACE'],os.environ['GUARDIAN_RELEASE']):
            usage=UsageStore(GovernanceStore('/state/guardian/governance.sqlite3'))
            archive=EvidenceArchive(usage,'/state/archive','/keys/archive-keys.json');archive.seal()
            # Kubernetes projects Secrets through symlinks. Copy this one
            # explicitly trusted named Secret into a private regular-file root;
            # arbitrary state/checkpoint symlinks remain forbidden.
            with tempfile.TemporaryDirectory() as key_stage:
                key_bytes=Path('/keys/archive-keys.json').read_bytes()
                if len(key_bytes)>16384:raise ValueError('archive_key_registry_too_large')
                (Path(key_stage)/'archive-keys.json').write_bytes(key_bytes)
                record['backup']=create({'state':'/state','worker':'/worker','keys':key_stage},root/('guardian-'+tag+'.fernet'),'/backup-key/backup.key',quiesced=True)
        record['status']='DONE';record['completed_at']=datetime.now(timezone.utc).isoformat()
        intent.write_text(json.dumps(record,indent=2));(root/('coordination-'+tag+'.json')).write_text(json.dumps(record,indent=2))
        # Strictly named expired bundles only. Separate replicas/key custody are
        # still required; this PVC alone is a local restore point.
        for path in root.glob('guardian-*.fernet'):
            try:at=datetime.strptime(path.stem[9:],'%Y%m%dT%H%M%SZ').replace(tzinfo=timezone.utc)
            except ValueError:continue
            if at<now-timedelta(days=30):path.unlink()
        print(json.dumps(record,indent=2))


if __name__=='__main__':main()
