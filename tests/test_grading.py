import asyncio
import copy
import json
import unittest
from types import SimpleNamespace
from unittest.mock import AsyncMock, patch
from backend.app.services.grading import Grade, PodGrader, fingerprint, validate_grade, alert_freshness


def document():
    return {'cluster':'test', 'pod':{'uid':'pod-uid','namespace':'app','pod':'client'},
            'containers':[], 'permission_points':[], 'boundaries':[], 'coverage':{'hubble':{'state':'following','last_event_at':'a'}},
            'sample':{'selected':1}, 'events':[{'id':'evidence-1','kind':'process_exec','process':{'binary':'/bin/sh'},'findings':['shell_process_observed']}],
            'shared_identity_events':[{'id':'shared-1','kind':'kubernetes_audit'}]}


def grade(score=8):
    return {'status':'assessed','severity':score,'reasons':['Observed shell requires investigation.'],
            'evidence_ids':['evidence-1'],'uncertainty':'Shells can be legitimate.', 'next_checks':['Check the deployment intent.']}


class MemoryRedis:
    def __init__(self):
        self.values={}; self.sets={}
    async def get(self,key):return self.values.get(key)
    async def mget(self,keys):return [self.values.get(k) for k in keys]
    async def zrevrange(self,key,start,end):return list(reversed(list(self.sets.get(key,{}))))
    def pipeline(self,transaction=True):
        parent=self
        class Pipeline:
            async def __aenter__(self):return self
            async def __aexit__(self,*args):pass
            def set(self,key,value,ex):parent.values[key]=value
            def zadd(self,key,value):parent.sets.setdefault(key,{}).update(value)
            def zremrangebyscore(self,*args):pass
            async def execute(self):return []
        return Pipeline()


class GradingTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.doc=document(); self.redis=MemoryRedis()
        self.telemetry=SimpleNamespace(redis=self.redis,prefix='test',ttl=604800)
        self.redis.values['test:inventory']=json.dumps({'pods':[self.doc['pod']]})
        self.infer=lambda d:grade()
        self.service=PodGrader(self.telemetry,lambda d:self.infer(d))

    def test_invalid_scores_and_citations(self):
        for bad in (-1,11,7.5,True,'8'):
            with self.assertRaises(ValueError):validate_grade({**grade(),'severity':bad},self.doc)
        for ids in ([],['invented'],['shared-1']):
            with self.assertRaises(ValueError):validate_grade({**grade(),'evidence_ids':ids},self.doc)
        with self.assertRaises(ValueError):validate_grade({**grade(),'status':'insufficient_evidence'},self.doc)
        self.assertEqual(validate_grade(grade(0),self.doc)['severity'],0)

    def test_fingerprint_ignores_clock_but_not_coverage_or_identity(self):
        changed=copy.deepcopy(self.doc);changed['coverage']['hubble']['last_event_at']='b'
        self.assertEqual(fingerprint(changed),fingerprint(self.doc))
        changed['coverage']['hubble']['state']='error'
        self.assertNotEqual(fingerprint(changed),fingerprint(self.doc))
        changed=copy.deepcopy(self.doc);changed['pod']['uid']='replacement'
        self.assertNotEqual(fingerprint(changed),fingerprint(self.doc))

    async def test_alert_ack_repeat_reopen_and_resolution(self):
        self.infer=lambda d:grade(7)
        result=await self.service.review(self.doc)
        self.assertEqual(result['severity'],7)
        alert=(await self.service.records('alerts'))[0]
        self.assertTrue(alert['active']);self.assertFalse(alert['acknowledged'])
        await self.service.acknowledge('pod-uid',alert['version'])
        await self.service.review(self.doc,force=True)
        alert=await self.service.get('alerts','pod-uid')
        self.assertTrue(alert['acknowledged'])
        with self.assertRaises(ValueError):await self.service.acknowledge('pod-uid',1)
        self.infer=lambda d:grade(8)
        await self.service.review(self.doc,force=True)
        alert=await self.service.get('alerts','pod-uid');self.assertFalse(alert['acknowledged'])
        await self.service.acknowledge('pod-uid',alert['version'])
        changed=copy.deepcopy(self.doc);changed['events'][0]['findings'].append('sensitive_file_access_attempt')
        await self.service.review(changed,force=True)
        self.assertFalse((await self.service.get('alerts','pod-uid'))['acknowledged'])
        self.infer=lambda d:grade(2)
        await self.service.review(changed,force=True)
        self.assertFalse((await self.service.get('alerts','pod-uid'))['active'])
        self.assertEqual(await self.service.records('alerts','other'),[])

    async def test_errors_and_missing_evidence_do_not_clear_alert(self):
        await self.service.review(self.doc)
        self.infer=lambda d:{**grade(),'evidence_ids':['made-up']}
        result=await self.service.review(self.doc,force=True)
        self.assertEqual(result['status'],'error');self.assertIsNone(result['severity'])
        self.assertTrue((await self.service.get('alerts','pod-uid'))['active'])
        self.doc['events']=[]
        result=await self.service.review(self.doc,force=True)
        self.assertEqual(result['status'],'insufficient_evidence')
        self.assertTrue((await self.service.get('alerts','pod-uid'))['active'])

    async def test_unchanged_evidence_skips_model(self):
        await self.service.review(self.doc)
        self.infer=lambda d:self.fail('Should not infer again')
        await self.service.review(self.doc)

    async def test_replaced_pod_does_not_publish_stale_assessment(self):
        self.redis.values['test:inventory']=json.dumps({'pods':[{**self.doc['pod'],'uid':'new-uid'}]})
        result=await self.service.review(self.doc)
        self.assertEqual(result['status'],'superseded')
        self.assertEqual(await self.service.records('reviews'),[])

    async def test_acknowledgement_not_blocked_by_model_inference(self):
        await self.service.review(self.doc)
        async with self.service.lock:
            result=await asyncio.wait_for(self.service.acknowledge('pod-uid',1),timeout=1)
        self.assertTrue(result['acknowledged'])

    async def test_same_evidence_is_reanalysed_after_due_time(self):
        await self.service.review(self.doc)
        calls=[]
        self.infer=lambda d:(calls.append(d) or grade(3))
        with patch('backend.app.services.grading.time.time',return_value=__import__('time').time()+self.service.interval+1):
            result=await self.service.review(self.doc)
        self.assertEqual(len(calls),1)
        self.assertEqual(result['severity'],3)
        self.assertIsNotNone(result['next_review_due_at'])
        self.assertIn('previous_assessment',calls[0])

    def test_duplicate_explanations_rejected(self):
        with self.assertRaises(ValueError):
            validate_grade({**grade(),'reasons':['A process ran as root.','A process ran as root.']},self.doc)

    def test_repeated_sentences_inside_one_reason_rejected(self):
        with self.assertRaises(ValueError):
            validate_grade({**grade(),'reasons':['A shell process started inside the pod. A shell process started inside the pod.']},self.doc)

    def test_missing_current_evidence_keeps_warning_historical(self):
        alert={'assessment_version':2,'status':'assessed','severity':8,'active':True,'reviewed_at':'2026-10-25T00:00:00+00:00'}
        latest={'status':'insufficient_evidence','severity':None,'reviewed_at':'2026-10-29T00:00:00+00:00'}
        result=alert_freshness(alert,latest)
        self.assertTrue(result['historical'])
        self.assertIsNone(result['current_severity'])
        self.assertEqual(result['severity'],8)
        self.assertTrue(result['active'])

    def test_matching_current_valid_alert_is_not_historical(self):
        alert={'assessment_version':2,'status':'assessed','severity':8,'active':True,'reviewed_at':'2026-10-29T00:00:00+00:00'}
        self.assertFalse(alert_freshness(alert,alert)['historical'])

    async def test_critical_rejected_without_corroboration(self):
        self.infer=lambda d:grade(9)
        result=await self.service.review(self.doc,force=True)
        self.assertEqual(result['status'],'error')
        self.assertIsNone(result['severity'])
        self.assertEqual(await self.service.records('alerts'),[])

    async def test_critical_requires_second_confirmation(self):
        self.doc['events'][0].update(source='tetragon',findings=['binary_outside_boundary'])
        self.doc['events'].append({'id':'evidence-2','source':'hubble','kind':'network','findings':['destination_namespace_outside_boundary']})
        calls=[]
        def infer(d):
            calls.append(d)
            return {**grade(9),'evidence_ids':['evidence-1','evidence-2']}
        self.infer=infer
        result=await self.service.review(self.doc,force=True)
        self.assertTrue(result['critical_confirmed'])
        self.assertEqual(result['severity'],9)
        self.assertEqual(len(calls),2)

    async def test_exactly_eight_is_not_critical(self):
        result=await self.service.review(self.doc,force=True)
        self.assertEqual(result['severity'],8)
        self.assertFalse(result.get('critical_confirmed',False))
