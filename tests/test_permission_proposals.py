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
    async def test_legacy_service_cannot_bypass_retired_http_routes(self):
        redis, k8s = AsyncMock(), MagicMock()
        service = PermissionProposals(redis, k8s, 'test')
        for decision in ('accept', 'reject'):
            with self.assertRaisesRegex(ValueError, 'legacy_execution_retired'):
                await service.decide('proposal', decision, 'admin', '')
        self.assertEqual(k8s.mock_calls, [])
        self.assertEqual(redis.mock_calls, [])
