import json
import unittest
from unittest.mock import AsyncMock
from backend.app.services.pod_evidence import grants_for_pod, inventory_pod, pod_evidence
from backend.app.services.telemetry import Telemetry, normalize


def pod(name='web', uid='uid-1'):
    return {'metadata': {'namespace': 'app', 'name': name, 'uid': uid}, 'spec': {'serviceAccountName': 'worker', 'containers': [{'name': 'web', 'image': 'app:v1', 'env': [{'value': 'secret'}]}]}}


def state():
    return {'role': {'kind': 'ClusterRole', 'metadata': {'name': 'operator'}, 'rules': [{'apiGroups': [''], 'verbs': ['delete', 'create'], 'resources': ['pods'], 'resourceNames': ['test']}]},
            'binding': {'kind': 'RoleBinding', 'metadata': {'namespace': 'target', 'name': 'grant'}, 'subjects': [{'kind': 'ServiceAccount', 'namespace': 'app', 'name': 'worker'}], 'roleRef': {'kind': 'ClusterRole', 'name': 'operator'}}}


class PodEvidenceTests(unittest.IsolatedAsyncioTestCase):
    def test_cross_namespace_grant_preserves_scope_and_resource_names(self):
        result = grants_for_pod(pod(), state())
        self.assertEqual(result['grants'][0]['scope'], 'target')
        self.assertEqual(result['grants'][0]['rule']['resourceNames'], ['test'])
        self.assertIn('workload_mutation_permission', result['grants'][0]['signals'])

    def test_group_subject_and_no_grant_for_other_sa(self):
        data = state()
        data['binding']['subjects'] = [{'kind': 'Group', 'name': 'system:serviceaccounts:app'}]
        self.assertEqual(len(grants_for_pod(pod(), data)['grants']), 1)
        data['binding']['subjects'] = [{'kind': 'ServiceAccount', 'namespace': 'other', 'name': 'worker'}]
        self.assertEqual(grants_for_pod(pod(), data)['grants'], [])

    def test_inventory_never_stores_env_values(self):
        self.assertNotIn('secret', json.dumps(inventory_pod(pod(), state())))

    def test_runtime_file_return_and_credentials_are_allowlisted(self):
        event = normalize({'process_kprobe': {'function_name': 'security_file_permission', 'process': {'pod': {'namespace': 'app', 'name': 'web', 'uid': 'uid-1'}, 'cap': {'effective': ['CAP_SYS_ADMIN']}}, 'args': [{'file_arg': {'path': '/var/run/secrets/kubernetes.io/serviceaccount/token'}}, {'string_arg': 'secret-body'}], 'return': {'int_arg': -13}}}, 'tetragon', 'test')
        self.assertIn('sensitive_file_access_attempt', event['signals'])
        self.assertEqual(event['runtime']['return_value']['int_arg'], -13)
        self.assertNotIn('secret-body', json.dumps(event))
        self.assertEqual(event['source_pod']['uid'], 'uid-1')

    async def test_audit_attribution_does_not_blame_shared_pods(self):
        raw = {'auditID': 'a1', 'stage': 'ResponseComplete', 'verb': 'delete', 'user': {'username': 'system:serviceaccount:app:worker'}, 'objectRef': {'resource': 'pods', 'namespace': 'target', 'name': 'victim'}, 'responseStatus': {'code': 403}, 'requestObject': {'secret': 'do-not-store'}}
        event = normalize(raw, 'audit', 'test')
        self.assertNotIn('do-not-store', json.dumps(event))
        self.assertEqual(event['outcome'], 'denied')
        redis = AsyncMock()
        redis.get.return_value = json.dumps({'pods': [inventory_pod(pod(), state())]})
        service = Telemetry(redis)
        service.events = AsyncMock(return_value=[event])
        evidence = await pod_evidence(service, 'app', 'web')
        self.assertEqual(evidence['pods'][0]['events'], [])
        self.assertEqual(len(evidence['pods'][0]['shared_identity_audit_events']), 1)
        raw['user']['extra'] = {'authentication.kubernetes.io/pod-uid': ['uid-1']}
        service.events.return_value = [normalize(raw, 'audit', 'test')]
        evidence = await pod_evidence(service, 'app', 'web')
        self.assertEqual(len(evidence['pods'][0]['events']), 1)
        raw['user']['extra']['authentication.kubernetes.io/pod-uid'] = ['different-uid']
        service.events.return_value = [normalize(raw, 'audit', 'test')]
        evidence = await pod_evidence(service, 'app', 'web')
        self.assertEqual(evidence['pods'][0]['events'], [])

    def test_non_service_account_audit_is_not_attributed(self):
        self.assertIsNone(normalize({'stage': 'ResponseComplete', 'user': {'username': 'admin'}}, 'audit', 'test'))
