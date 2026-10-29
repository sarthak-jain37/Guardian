import copy
import unittest
from unittest.mock import MagicMock
from contracts.usage_summary_v1 import Window
from backend.app.services.evidence_inventory import EvidenceInventory
from backend.app.services.canonical_hash import canonical_hash
from tests.test_usage_store import START, subject
import tests.test_usage_store as fixture


class InventoryTests(unittest.TestCase):
    setUp=fixture.UsageTests.setUp

    def producer(self):
        state={
          'r':{'kind':'Role','metadata':{'name':'reader','namespace':'guardian-demo','uid':'role-uid','resourceVersion':'7'},'rules':[{'apiGroups':[''],'resources':['pods','secrets'],'verbs':['get']}]},
          'b':{'kind':'RoleBinding','metadata':{'name':'reader','namespace':'guardian-demo','uid':'binding-uid','resourceVersion':'8'},'roleRef':{'kind':'Role','name':'reader'},'subjects':[{'kind':'ServiceAccount','name':'reader','namespace':'guardian-demo'}]},
          'sa':{'kind':'ServiceAccount','metadata':{'name':'reader','namespace':'guardian-demo','uid':'sa-uid','resourceVersion':'9'}}}
        workload={'kind':'Deployment','metadata':{'name':'app','uid':'app-uid'},'spec':{'replicas':1,'template':{'spec':{'serviceAccountName':'reader'}}}}
        pod={'kind':'Pod','metadata':{'name':'app-pod','namespace':'guardian-demo','uid':'pod-uid','ownerReferences':[{'uid':'app-uid','controller':True}]},
             'spec':{'serviceAccountName':'reader'},'status':{'containerStatuses':[{'imageID':'registry/app@sha256:123'}]}}
        k8s=MagicMock();k8s.get_rbac_state.return_value=state
        k8s.get_workload_inventory.return_value={'objects':[workload,pod],'errors':[]}
        return EvidenceInventory(self.store,k8s,controlled_namespaces=['guardian-demo']),state,k8s

    def test_real_snapshot_preserves_identity_and_never_invents_exercised_behaviors(self):
        producer,state,k8s=self.producer()
        e=producer.capture('lab','guardian-demo','reader',Window(start=START,end=self.now))
        self.assertEqual(e.target.resource_version,'7');self.assertEqual(e.target.uid,'role-uid')
        self.assertTrue(e.context.consumer_inventory_complete)
        self.assertEqual(e.context.known_consumers,['app-uid'])
        self.assertEqual(e.context.exercised_behaviors,[])
        self.assertIsNone(e.baseline_id)
        self.assertEqual(producer.load(e.snapshot_id),e)
        self.assertEqual(k8s.apply_state.call_count,0)

    def test_scaled_zero_and_scheduled_consumers_are_included(self):
        producer,state,k8s=self.producer()
        k8s.get_workload_inventory.return_value['objects'].append({'kind':'CronJob','metadata':{'uid':'monthly'},
            'spec':{'schedule':'0 0 1 * *','suspend':True,'jobTemplate':{'spec':{'template':{'spec':{'serviceAccountName':'reader'}}}}}})
        e=producer.capture('lab','guardian-demo','reader',Window(start=START,end=self.now))
        self.assertIn('monthly',e.context.known_consumers)
        self.assertFalse(e.context.consumer_inventory_complete)
        self.assertIn('scheduled_workflow_requires_validation',e.source_errors)

    def test_alternate_grants_are_resolved_but_unrelated_discovery_grants_are_not_false_overlap(self):
        producer,state,k8s=self.producer()
        state['extra-role']={'kind':'ClusterRole','metadata':{'name':'extra'},'rules':[{'apiGroups':[''],'resources':['secrets'],'verbs':['*']}]}
        state['extra-binding']={'kind':'ClusterRoleBinding','metadata':{'name':'extra'},'roleRef':{'kind':'ClusterRole','name':'extra'},
            'subjects':[{'kind':'Group','name':'system:authenticated'}]}
        e=producer.capture('lab','guardian-demo','reader',Window(start=START,end=self.now))
        self.assertTrue(e.context.alternate_grants)

    def test_binding_restriction_and_object_kind_changes_affect_semantic_hash(self):
        producer,state,k8s=self.producer();original=canonical_hash(state)
        for mutate in (
            lambda s:s['b']['subjects'][0].update(name='other'),
            lambda s:s['r']['rules'][0].update(resourceNames=['one']),
            lambda s:s['r'].update(kind='ClusterRole')):
            changed=copy.deepcopy(state);mutate(changed)
            self.assertNotEqual(canonical_hash(changed),original)
        changed=copy.deepcopy(state);changed['r']['metadata']['resourceVersion']='new'
        self.assertEqual(canonical_hash(changed),original)
