import json
import unittest
from unittest.mock import AsyncMock, patch
from backend.app.services.pod_review import permission_points, representative_events, review_context


class PodReviewTests(unittest.IsolatedAsyncioTestCase):
    def test_permission_summary_respects_verbs_and_api_group(self):
        identity={'permissions':{'grants':[{'scope':'app','binding_name':'limited','binding_kind':'RoleBinding','role_name':'reader','rule':{'verbs':['get'],'apiGroups':[''],'resources':['pods']}}]}}
        self.assertEqual(permission_points(identity),[])
        identity['permissions']['grants'][0]['rule']={'verbs':['delete'],'apiGroups':[''],'resources':['pods'],'resourceNames':['temporary']}
        points=permission_points(identity)
        self.assertEqual([p['action'] for p in points],['delete pods'])
        self.assertEqual(points[0]['resource_names'],['temporary'])
        identity['permissions']['grants'][0]['rule']['apiGroups']=['unrelated.example']
        self.assertEqual(permission_points(identity),[])

    def test_sampling_includes_distinct_audit_and_runtime_activity(self):
        events=[{'id':str(i),'kind':'network','verdict':'FORWARDED'} for i in range(20)]
        events += [{'id':'exec','kind':'process_exec','process':{'binary':'/bin/sh'},'findings':['shell_process_observed']},
                   {'id':'audit','kind':'kubernetes_audit','verb':'delete','target':{'resource':'pods'},'findings':['kubernetes_mutation_attempt']}]
        selected=representative_events(events,3)
        self.assertEqual({e['id'] for e in selected},{'0','exec','audit'})

    async def test_review_preserves_evidence_ids_and_separates_shared_identity(self):
        snapshot={'inventory_observed_at':'now','pods':[{'identity':{'namespace':'app','pod':'web','uid':'u','permissions':{'grants':[]}},'events':[{'id':'runtime-id','kind':'process_exec','process':{'binary':'/app/server'},'runtime':{'cap':{'effective':['CAP_SYS_ADMIN']},'file_paths':['/tmp/example']}}], 'shared_identity_audit_events':[{'id':'shared-id','kind':'kubernetes_audit','verb':'get','target':{'resource':'secrets'}}]}]}
        service=AsyncMock();service.maximum=100;service.cluster='test';service.health={};service.boundaries=[]
        with patch('backend.app.services.pod_review.pod_evidence',new=AsyncMock(return_value=snapshot)):
            result=await review_context(service,'app','web',3)
        self.assertEqual(result['events'][0]['id'],'runtime-id')
        self.assertEqual(result['shared_identity_events'][0]['id'],'shared-id')
        self.assertEqual(result['events'][0]['runtime']['cap']['effective'],['CAP_SYS_ADMIN'])

    async def test_missing_pod_is_not_an_empty_success(self):
        service=AsyncMock();service.maximum=100
        with patch('backend.app.services.pod_review.pod_evidence',new=AsyncMock(return_value={'pods':[]})):
            self.assertIsNone(await review_context(service,'app','gone',3))
