"""Deployment invariants and real local encrypted backup/restore, without a cluster."""
import json,os,sqlite3,subprocess,tempfile,unittest
from pathlib import Path
from cryptography.fernet import Fernet,InvalidToken
import yaml
from scripts.guardian_backup import create,restore
from scripts.guardian_capacity import measure
from backend.app.services.governance_store import GovernanceStore
from backend.app.services.usage_store import UsageStore

ROOT=Path(__file__).resolve().parents[1]


class DeploymentTests(unittest.TestCase):
    def test_rendered_chart_has_separate_identities_persistent_state_and_no_default_write(self):
        helm=ROOT/'data/tools/helm'
        if not helm.exists():self.skipTest('Helm optional; run helm lint/template from the deployment runbook')
        text=subprocess.run([str(helm),'template','guardian',str(ROOT/'deploy/helm/guardian'),'--namespace','guardian-system'],capture_output=True,text=True,check=True).stdout
        docs=list(yaml.safe_load_all(text));roles=[d for d in docs if d['kind'] in ('Role','ClusterRole')]
        self.assertFalse(any('patch' in r['verbs'] or '*' in r['verbs'] for role in roles for r in role.get('rules',[])))
        self.assertEqual(len([d for d in docs if d['kind']=='PersistentVolumeClaim']),3)
        deployments={d['metadata']['name']:d for d in docs if d['kind']=='Deployment'}
        self.assertEqual(len(deployments),5)
        for name in ('worker','dashboard'):
            spec=deployments['guardian-'+name]['spec']['template']['spec']
            self.assertFalse(spec['automountServiceAccountToken'])
            self.assertFalse(any(v.get('secret',{}).get('secretName') in ('guardian-auth','guardian-archive') for v in spec['volumes']))
        enabled=subprocess.run([str(helm),'template','guardian',str(ROOT/'deploy/helm/guardian'),'--set','execution.enabled=true'],capture_output=True,text=True,check=True).stdout
        writes=[r for d in yaml.safe_load_all(enabled) if d['kind']=='Role' for r in d.get('rules',[]) if 'patch' in r['verbs']]
        self.assertEqual(len(writes),1);self.assertEqual(writes[0]['resourceNames'],['pod-reader'])
        invalid=subprocess.run([str(helm),'template','guardian',str(ROOT/'deploy/helm/guardian'),'--set','image.tag=latest'],capture_output=True)
        self.assertNotEqual(invalid.returncode,0)

    def test_real_encrypted_backup_restore_and_explicit_new_path(self):
        with tempfile.TemporaryDirectory() as temp:
            root=Path(temp);state=root/'state';state.mkdir();key=root/'backup.key';key.write_bytes(Fernet.generate_key())
            ledger=GovernanceStore(state/'governance.sqlite3');UsageStore(ledger)
            (state/'archive').mkdir();(state/'archive/segment').write_bytes(b'encrypted retained archive example')
            (state/'private-key-config').write_text('private key recovery configuration')
            destination=root/'bundle.fernet'
            with self.assertRaisesRegex(ValueError,'quiesced'):create({'state':state},destination,key)
            result=create({'state':state},destination,key,quiesced=True)
            self.assertEqual(result['files'],3)
            self.assertNotIn(b'private key recovery',destination.read_bytes())
            restored=root/'restored';proof=restore(destination,restored,key)
            self.assertFalse(proof['execution_enabled']);self.assertTrue((restored/'state/restore-required').exists())
            self.assertEqual((restored/'state/archive/segment').read_bytes(),(state/'archive/segment').read_bytes())
            with sqlite3.connect(restored/'state/governance.sqlite3') as db:self.assertEqual(db.execute('PRAGMA integrity_check').fetchone()[0],'ok')
            with self.assertRaisesRegex(ValueError,'nonexistent'):restore(destination,restored,key)
            tampered=root/'bad';tampered.write_bytes(destination.read_bytes()[:-5]+b'xxxxx')
            with self.assertRaises(InvalidToken):restore(tampered,root/'tampered-output',key)
            self.assertFalse((root/'tampered-output').exists())
            report=measure(state,state/'governance.sqlite3')
            self.assertIsNone(report['projected_encoded_retention_with_30pct_headroom'])

    def test_backup_rejects_symlinks(self):
        with tempfile.TemporaryDirectory() as temp:
            root=Path(temp);state=root/'state';state.mkdir();(root/'outside').write_text('secret')
            (state/'link').symlink_to(root/'outside');key=root/'key';key.write_bytes(Fernet.generate_key())
            with self.assertRaisesRegex(ValueError,'symlinks'):create({'state':state},root/'bundle',key,quiesced=True)

class BackupCoordinationTests(unittest.TestCase):
    def test_backup_failure_restores_only_same_uid_and_unchanged_stopped_replicas(self):
        from types import SimpleNamespace as N
        from unittest.mock import MagicMock
        from scripts.guardian_backup_job import quiesce
        state={name:N(metadata=N(uid=name,resource_version='1'),spec=N(replicas=1)) for name in ('g-backend','g-collector','g-worker')}
        apps=MagicMock();core=MagicMock();core.list_namespaced_pod.return_value.items=[]
        apps.read_namespaced_deployment.side_effect=lambda name,*a,**kw:state[name]
        def patch(name,ns,body,**kw):state[name].spec.replicas=body['spec']['replicas']
        apps.patch_namespaced_deployment.side_effect=patch
        with self.assertRaisesRegex(RuntimeError,'snapshot failed'):
            with quiesce(apps,core,'guardian-system','g',sleeper=lambda _:None):
                self.assertTrue(all(v.spec.replicas==0 for v in state.values()))
                state['g-worker'].metadata.uid='recreated-by-operator'
                raise RuntimeError('snapshot failed')
        self.assertEqual(state['g-backend'].spec.replicas,1);self.assertEqual(state['g-collector'].spec.replicas,1)
        self.assertEqual(state['g-worker'].spec.replicas,0)
