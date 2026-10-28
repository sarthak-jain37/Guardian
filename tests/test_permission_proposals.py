import copy
import json
import unittest
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock
from backend.app.services.permission_proposals import PermissionProposals, candidates, digest


def state():
    return {'role':{'kind':'Role','metadata':{'namespace':'test','name':'operator'},'rules':[{'apiGroups':[''],'resources':['pods'],'verbs':['create','delete']}]},
            'binding':{'kind':'RoleBinding','metadata':{'namespace':'test','name':'operator'},'roleRef':{'kind':'Role','name':'operator','apiGroup':'rbac.authorization.k8s.io'},'subjects':[{'kind':'ServiceAccount','namespace':'test','name':'worker'}]}}

class CandidateTests(unittest.TestCase):
    def test_only_exclusive_roles_are_eligible(self):
        original=state()
        self.assertEqual(len(candidates(original,'test','worker')),1)
        original['binding']['subjects'].append({'kind':'ServiceAccount','namespace':'test','name':'other'})
        self.assertEqual(candidates(original,'test','worker'),[])
    def test_role_shared_by_other_binding_is_blocked(self):
        original=state();other=copy.deepcopy(original['binding']);other['subjects'][0]['name']='other';original['other']=other
        self.assertEqual(candidates(original,'test','worker'),[])

class DecisionTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.redis=AsyncMock();self.redis.set.return_value=True
        self.k8s=MagicMock();self.k8s.api_client.sanitize_for_serialization.side_effect=lambda value:value
        self.state=state()
        pod={'metadata':{'uid':'uid','name':'controller'},'spec':{'serviceAccountName':'worker'}}
        self.k8s.core_api.read_namespaced_pod.return_value=pod
        self.k8s.core_api.list_namespaced_pod.return_value={'items':[pod]}
        self.k8s.get_rbac_state.return_value=self.state
        role=copy.deepcopy(self.state['role']);role['metadata'].update(uid='role-uid',resourceVersion='1')
        binding=copy.deepcopy(self.state['binding']);binding['metadata'].update(uid='binding-uid',resourceVersion='2')
        after=copy.deepcopy(role);after['rules']=[]
        self.k8s.rbac_api.read_namespaced_role.return_value=role
        self.k8s.rbac_api.read_namespaced_role_binding.return_value=binding
        self.k8s.rbac_api.replace_namespaced_role.return_value=after
        self.k8s.rbac_api.replace_namespaced_role_binding.return_value=binding
        self.proposal={'id':'proposal','uid':'uid','namespace':'test','pod':'controller','service_account':'worker','status':'pending','snapshot_hash':digest(self.state),
            'assessment_fingerprint':'assessment','affected_instances':{'uid':'controller'},'changes':[{'kind':'Role','name':'operator','before':role,'after':after},{'kind':'RoleBinding','name':'operator','before':binding,'after':binding}]}
        self.redis.get.side_effect=lambda key: json.dumps({'status':'assessed','severity':9,'critical_confirmed':True,'fingerprint':'assessment'}) if ':grading:reviews:' in key else json.dumps(self.proposal)
        self.service=PermissionProposals(self.redis,self.k8s,'test')
    async def test_rejection_logs_and_never_writes(self):
        result=await self.service.decide('proposal','reject','operator','Keep permissions')
        self.assertEqual(result['status'],'rejected')
        self.k8s.rbac_api.replace_namespaced_role.assert_not_called()
        self.k8s.rbac_api.replace_namespaced_role_binding.assert_not_called()
        event=self.redis.xadd.await_args_list[0].args[1]
        self.assertEqual(json.loads(event['details'])['decision'],'reject')
    async def test_accept_applies_role_and_binding_and_logs(self):
        result=await self.service.decide('proposal','accept','operator','Reduce access')
        self.assertEqual(result['status'],'applied')
        self.k8s.rbac_api.replace_namespaced_role.assert_called_once()
        self.k8s.rbac_api.replace_namespaced_role_binding.assert_called_once()
        self.assertEqual(len(result['receipt']),2)
        self.assertIn('execution_result',[c.args[1]['event'] for c in self.redis.xadd.await_args_list])
    async def test_stale_snapshot_blocks_all_writes(self):
        self.k8s.get_rbac_state.return_value={}
        result=await self.service.decide('proposal','accept','operator','')
        self.assertEqual(result['status'],'conflict')
        self.k8s.rbac_api.replace_namespaced_role.assert_not_called()
    async def test_replaced_pod_blocks_all_writes(self):
        self.k8s.core_api.read_namespaced_pod.return_value={'metadata':{'uid':'replaced'},'spec':{'serviceAccountName':'worker'}}
        result=await self.service.decide('proposal','accept','operator','')
        self.assertEqual(result['status'],'conflict')
        self.k8s.rbac_api.replace_namespaced_role.assert_not_called()
    async def test_partial_execution_is_recorded(self):
        self.k8s.rbac_api.replace_namespaced_role_binding.side_effect=RuntimeError('conflict')
        result=await self.service.decide('proposal','accept','operator','')
        self.assertEqual(result['status'],'partial_failure')
        self.assertEqual(len(result['receipt']),1)
    async def test_repeated_decision_is_not_applied(self):
        self.proposal['status']='applied'
        with self.assertRaises(ValueError):await self.service.decide('proposal','accept','operator','')
        self.k8s.rbac_api.replace_namespaced_role.assert_not_called()

    async def test_resolved_critical_assessment_blocks_application(self):
        self.redis.get.side_effect=lambda key: json.dumps({'status':'assessed','severity':2,'fingerprint':'new'}) if ':grading:reviews:' in key else json.dumps(self.proposal)
        result=await self.service.decide('proposal','accept','operator','')
        self.assertEqual(result['status'],'conflict')
        self.k8s.rbac_api.replace_namespaced_role.assert_not_called()

    async def test_generation_builds_only_reductions_without_cluster_writes(self):
        import sys
        from unittest.mock import patch
        proposal={**self.proposal,'status':'generating'}
        record={'severity':9,'reasons':['Observed evidence needs investigation.'],'history_summary':{}}
        model=SimpleNamespace(propose_permission_reductions=lambda record,options:{'remove_rule_ids':['operator:0'],'explanation':'Remove workload mutation access; the workload may stop creating pods.'})
        with patch.dict(sys.modules,{'agents.summarizer':model}):
            await self.service.generate(proposal,record,{})
        self.assertEqual(proposal['status'],'pending')
        self.assertEqual(proposal['changes'][0]['after']['rules'],[])
        self.assertEqual(proposal['changes'][1]['after']['metadata']['annotations']['guardian/permission-proposal'],'proposal')
        self.k8s.rbac_api.replace_namespaced_role.assert_not_called()
        self.k8s.rbac_api.replace_namespaced_role_binding.assert_not_called()
