import hashlib
import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import MagicMock

from agents.guardian.fixtures import demo_evidence
from backend.app.models.execution import FunctionalProfile
from backend.app.services.conditional_role import ConditionalRoleDriver
from backend.app.services.functional_verifier import FunctionalVerifier
from backend.app.services.governance_store import GovernanceStore


class ExecutionPortTests(unittest.TestCase):
    def test_dry_run_and_write_are_exact_separate_conditional_role_calls(self):
        k8s=MagicMock();driver=ConditionalRoleDriver(k8s);rules=[{'apiGroups':[''],'resources':['pods'],'verbs':['get']}]
        driver.dry_run('guardian-demo','reader','uid','17',rules,'nonce')
        dry=k8s.api_client.call_api.call_args
        self.assertEqual(dry.args[1],'PATCH');self.assertIn(('dryRun','All'),dry.kwargs['query_params'])
        self.assertEqual(dry.kwargs['header_params']['Content-Type'],'application/json-patch+json')
        self.assertEqual(dry.kwargs['body'],[{'op':'test','path':'/metadata/uid','value':'uid'},
            {'op':'test','path':'/metadata/resourceVersion','value':'17'},{'op':'replace','path':'/rules','value':rules}])
        driver.apply('guardian-demo','reader','uid','17',rules,'nonce')
        self.assertFalse(any(key=='dryRun' for key,value in k8s.api_client.call_api.call_args.kwargs['query_params']))
        self.assertEqual(k8s.api_client.call_api.call_count,2)

    def test_access_uses_exact_subject_groups_subresource_and_preserves_errors(self):
        k8s=MagicMock();k8s.api_client.call_api.return_value={'status':{'allowed':True,'evaluationError':'authorizer unavailable'}}
        driver=ConditionalRoleDriver(k8s);subject=demo_evidence().subject
        result=driver.access(subject,'guardian-demo','','pods/log','get')
        self.assertEqual(result['evaluation_error'],'authorizer unavailable')
        spec=k8s.api_client.call_api.call_args.kwargs['body']['spec']
        self.assertEqual(spec['groups'],subject.groups);self.assertEqual(spec['uid'],subject.uid)
        self.assertEqual(spec['resourceAttributes']['subresource'],'log')
        self.assertEqual(spec['resourceAttributes']['namespace'],'guardian-demo')

    def harness(self,source):
        self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup)
        script=Path(self.temp.name)/'probe.py';script.write_text(source)
        executable=str(Path(sys.executable).resolve())
        profile=FunctionalProfile(namespace='guardian-demo',role_name='reader',target_uid='uid',subject_uid='sa',
            workload_uid='fixture-workload',image_digest='sha256:test',argv=[executable,str(script)],
            artifact_hashes={name:hashlib.sha256(Path(name).read_bytes()).hexdigest() for name in [executable,str(script)]},timeout_seconds=1)
        verifier=FunctionalVerifier(GovernanceStore(Path(self.temp.name)/'state.sqlite3'))
        return verifier,profile,script

    def test_exit_zero_and_http_style_empty_success_cannot_prove_functional_behavior(self):
        verifier,profile,script=self.harness('print("{}")')
        with self.assertRaises(ValueError):verifier.check(profile,demo_evidence(),'pre')

    def test_harness_digest_timeout_and_output_limits_fail_closed(self):
        verifier,profile,script=self.harness('import time\ntime.sleep(20)')
        with self.assertRaises(TimeoutError):verifier.check(profile,demo_evidence(),'pre')
        script.write_text('print("x"*70000)')
        with self.assertRaisesRegex(ValueError,'artifact_changed'):verifier.check(profile,demo_evidence(),'pre')
        profile=profile.model_copy(update={'artifact_hashes':{name:hashlib.sha256(Path(name).read_bytes()).hexdigest() for name in profile.artifact_hashes}})
        with self.assertRaisesRegex(ValueError,'output_too_large'):verifier.check(profile,demo_evidence(),'pre')
