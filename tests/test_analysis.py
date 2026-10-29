"""Integrated producer -> HTTP ports -> real graph -> durable nonwriting review."""
import json
import tempfile
import unittest
from datetime import timedelta
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor
from unittest.mock import patch

from fastapi import FastAPI
from fastapi.testclient import TestClient
from agents.guardian.modeling import ModelConfig
from agents.guardian.runner import configured_model
from agents.guardian.service_worker import process_job
from backend.app.api.routes.analysis import router
from backend.app.api.routes.evidence import router as evidence_router
from backend.app.core.auth import Authenticator,Principal
from backend.app.models.analysis import AnalysisIntake,JobClaim,BudgetRequest,ReportDecision
from backend.app.services.analysis_store import AnalysisStore
from backend.app.services.governance_store import LedgerError
from backend.app.workers.analysis import schedule_once
from contracts.usage_summary_v1 import Window
from scripts.guardian_auth import issue
from tests.test_usage_store import START
import tests.test_usage_store as usage_fixture
import tests.test_evidence_inventory as inventory_fixture


class HttpClient:
    def __init__(self,client,token):self.client=client;self.headers={'Authorization':'Bearer '+token}
    def call(self,method,path,body=None):
        r=self.client.request(method,path,json=body,headers=self.headers)
        r.raise_for_status();return r.json()


class AnalysisTests(unittest.TestCase):
    def setUp(self):
        usage_fixture.UsageTests.setUp(self)
        self.inventory,state,self.k8s=inventory_fixture.InventoryTests.producer(self)
        self.state=state
        self.analysis=AnalysisStore(self.db,self.inventory,model_config=ModelConfig(),capacity=4)
        self.human=Principal(actor='alice',kind='human',grants=[{'cluster_id':'lab','namespace':'guardian-demo','permissions':['read','review']}])
        self.worker=Principal(actor='analysis-worker',kind='service',grants=[{'cluster_id':'lab','namespace':'guardian-demo','permissions':['read','publish','deliver']}])
        self.other=Principal(actor='other',kind='human',grants=[{'cluster_id':'lab','namespace':'other','permissions':['read','review']}])
        path=Path(self.temp.name)/'auth.json'
        self.human_token=issue(path,self.human);self.worker_token=issue(path,self.worker);self.other_token=issue(path,self.other)
        app=FastAPI();app.include_router(router);app.include_router(evidence_router)
        app.state.authenticator=Authenticator(path);app.state.analysis=self.analysis;app.state.analysis_cluster_id='lab'
        app.state.evidence_inventory=self.inventory
        self.client=TestClient(app);self.addCleanup(self.client.close)
        self.worker_client=HttpClient(self.client,self.worker_token)
        self.human_client=HttpClient(self.client,self.human_token)
        self.checkpoints=Path(self.temp.name)/'checkpoints';self.checkpoints.mkdir()

    def intake(self,**changes):
        value={'cluster_id':'lab','namespace':'guardian-demo','role_name':'reader',
            'window':Window(start=START,end=self.now),'idempotency_key':'initial-0001'}
        value.update(changes);return AnalysisIntake(**value)

    def queued(self):
        run=self.analysis.enqueue(self.intake(),self.human)
        self.assertTrue(self.analysis.prepare_next())
        return self.analysis.get(run['run_id'],self.human)

    def run_job(self):
        run=self.queued()
        job=self.worker_client.call('POST','/analysis/jobs/claim',{'cluster_id':'lab','namespace':'guardian-demo'})['job']
        result=process_job(self.worker_client,job,self.checkpoints,clock=self.db.now)
        self.assertEqual(result['execution_requests'],0)
        return self.analysis.get(run['run_id'],self.human),job

    def decision(self,run,kind='acknowledge',**changes):
        value={'kind':kind,'expected_revision':run['revision'],'expected_report_hash':run['report_hash'],
            'idempotency_key':'decision-0001','note':'Operator review.'}
        value.update(changes);return ReportDecision(**value)

    def test_actual_capture_crosses_serialized_ports_and_persists_exact_report(self):
        run,job=self.run_job()
        self.assertEqual(run['status'],'DONE');self.assertEqual(run['report']['mode'],'preview')
        self.assertEqual(run['report']['status'],'BLOCKED')
        self.assertEqual(run['report']['model_calls'],1)
        self.assertFalse(run['report']['readiness']['execution_ready'])
        self.assertIsNone(run['proposal']);self.assertFalse(run['execution_available'])
        self.assertTrue(run['report']['trace']);self.assertEqual(run['request']['target_uid'],'role-uid')
        report=run['report']
        # Re-delivery of a terminal checkpoint reuses exact output and spends no calls.
        process_job(self.worker_client,job,self.checkpoints,clock=self.db.now)
        self.assertEqual(self.analysis.get(run['run_id'],self.human)['report'],report)
        self.k8s.apply_state.assert_not_called()
        decision=self.analysis.decide(run['run_id'],self.decision(run),self.human)
        self.assertEqual(decision['review_outcome'],'NO_CHANGE');self.assertFalse(decision['execution_authorized'])
        self.assertEqual(self.analysis.get(run['run_id'],self.human)['report'],report)

    def test_context_decision_atomically_creates_fresh_revision_and_keeps_prior_report(self):
        run,job=self.run_job();body=self.decision(run,'request_context',note='A monthly backup may need these permissions.')
        decision=self.analysis.decide(run['run_id'],body,self.human)
        self.assertEqual(self.analysis.decide(run['run_id'],body,self.human),decision)
        successor=self.analysis.get(decision['successor_run_id'],self.human)
        self.assertEqual(successor['case_id'],run['case_id']);self.assertEqual(successor['revision'],2)
        self.assertTrue(self.analysis.prepare_next())
        successor=self.analysis.get(successor['run_id'],self.human)
        self.assertNotEqual(successor['request']['snapshot_id'],run['request']['snapshot_id'])
        snapshot=self.inventory.load(successor['request']['snapshot_id'])
        self.assertIn('alice',snapshot.context.optional_documents[-1]);self.assertIn('monthly backup',snapshot.context.optional_documents[-1])
        self.assertEqual(snapshot.context.exercised_behaviors,[])
        next_job=self.analysis.claim(JobClaim(cluster_id='lab',namespace='guardian-demo'),self.worker)
        process_job(self.worker_client,next_job,self.checkpoints,clock=self.db.now)
        self.assertEqual(self.analysis.get(successor['run_id'],self.human)['report']['model_calls'],1)
        self.assertEqual(self.analysis.get(run['run_id'],self.human)['report'],run['report'])

    def test_intake_scope_idempotency_capacity_and_no_model_at_enqueue(self):
        body=self.intake();first=self.analysis.enqueue(body,self.human)
        self.assertEqual(self.analysis.enqueue(body,self.human)['run_id'],first['run_id'])
        self.k8s.get_rbac_state.assert_not_called()
        with self.assertRaises(LedgerError):self.analysis.enqueue(self.intake(role_name='other'),self.human)
        with self.assertRaises(Exception):self.analysis.enqueue(body,self.other)
        for i in range(3):self.analysis.enqueue(self.intake(idempotency_key=f'intake-{i:04}'),self.human)
        with self.assertRaisesRegex(LedgerError,'analysis_queue_full'):
            self.analysis.enqueue(self.intake(idempotency_key='intake-full'),self.human)
        self.assertEqual(self.client.post('/analysis/runs',json=body.model_dump(mode='json')).status_code,401)
        self.assertEqual(self.client.post('/analysis/runs',json={**body.model_dump(mode='json'),'actor':'forged'},
            headers=self.human_client.headers).status_code,422)

    def test_lease_takeover_fences_publication_and_budget_after_restart(self):
        run=self.queued();claim=JobClaim(cluster_id='lab',namespace='guardian-demo')
        job=self.analysis.claim(claim,self.worker)
        self.assertIsNone(self.analysis.claim(claim,self.worker))
        body=BudgetRequest(lease_token=job['lease_token'],operation='reserve_model',stage='investigator')
        self.assertEqual(self.analysis.budget(run['run_id'],body,self.worker),1)
        restarted=AnalysisStore(self.db,self.inventory,model_config=ModelConfig())
        self.now+=timedelta(seconds=121)
        newer=restarted.claim(claim,self.worker)
        self.assertNotEqual(job['lease_token'],newer['lease_token'])
        with self.assertRaisesRegex(LedgerError,'analysis_lease_lost'):restarted.budget(run['run_id'],body,self.worker)
        self.assertEqual(restarted.budget(run['run_id'],BudgetRequest(lease_token=newer['lease_token'],operation='count'),self.worker),1)

    def test_durable_budget_repair_and_lookup_scope_are_server_owned(self):
        run=self.queued();job=self.analysis.claim(JobClaim(cluster_id='lab',namespace='guardian-demo'),self.worker)
        def budget(operation,**kwargs):return self.analysis.budget(run['run_id'],BudgetRequest(lease_token=job['lease_token'],operation=operation,**kwargs),self.worker)
        budget('reserve_model',stage='investigator');budget('reserve_model',stage='investigator',repair=True)
        with self.assertRaises(LedgerError):budget('reserve_model',stage='investigator',repair=True)
        req=run['request'];snapshot=self.inventory.load(req['snapshot_id'])
        lookups=[{'tool':'get_workload_context','subject_id':snapshot.subject.username,'case_id':req['case_id']}]
        batch=budget('reserve_lookup',batch_key='known-batch',requests=lookups)
        self.assertEqual(batch['total_calls'],1)
        self.assertIsNone(budget('begin_lookup',batch_key='known-batch',index=0))
        with self.assertRaises(LedgerError):budget('begin_lookup',batch_key='known-batch',index=0)
        with self.assertRaises(ValueError):budget('reserve_lookup',batch_key='forged-batch',requests=[{**lookups[0],'subject_id':'other'}])
        for _ in range(4):budget('reserve_model',stage='planner')
        with self.assertRaises(LedgerError):budget('reserve_model',stage='planner')

    def test_review_expiry_stale_hash_and_concurrent_decisions(self):
        run,job=self.run_job()
        with self.assertRaises(LedgerError):self.analysis.decide(run['run_id'],self.decision(run,expected_report_hash='wrong'),self.human)
        with self.assertRaisesRegex(LedgerError,'governed_executor_unavailable'):
            self.analysis.decide(run['run_id'],self.decision(run,'approve_remediation'),self.human)
        def decide(kind):
            try:return self.analysis.decide(run['run_id'],self.decision(run,kind,idempotency_key='race-'+kind),self.human)
            except LedgerError as exc:return exc.code
        with ThreadPoolExecutor(2) as pool:answers=list(pool.map(decide,['reject','acknowledge']))
        self.assertEqual(sum(isinstance(a,dict) for a in answers),1)
        self.assertEqual(self.analysis.get(run['run_id'],self.human)['report'],run['report'])
        fresh=self.analysis.enqueue(self.intake(idempotency_key='fresh-0001',supersedes_run_id=run['run_id']),self.human)
        self.analysis.prepare_next();job=self.analysis.claim(JobClaim(cluster_id='lab',namespace='guardian-demo'),self.worker)
        process_job(self.worker_client,job,self.checkpoints,clock=self.db.now)
        fresh=self.analysis.get(fresh['run_id'],self.human);self.now+=timedelta(days=2)
        with self.assertRaisesRegex(LedgerError,'report_review_expired'):
            self.analysis.decide(fresh['run_id'],self.decision(fresh,idempotency_key='late-review'),self.human)
        self.assertEqual(self.analysis.get(fresh['run_id'],self.human)['review_state'],'EXPIRED')

    def test_preparation_failure_and_missing_usage_stay_non_executable(self):
        run=self.analysis.enqueue(self.intake(role_name='missing',idempotency_key='missing-0001'),self.human)
        self.analysis.prepare_next();run=self.analysis.get(run['run_id'],self.human)
        self.assertEqual(run['status'],'FAILED');self.assertIsNone(run['report'])
        self.store.gap('audit',START,self.now,'source_loss')
        run,job=self.run_job()
        self.assertEqual(run['report']['status'],'BLOCKED');self.assertIsNone(run['proposal'])
        self.assertTrue(any('coverage' in reason for f in run['report']['facts'] for reason in f['reason_codes']))
        self.k8s.apply_state.assert_not_called()

    def test_watch_scheduler_queues_material_changes_without_a_baseline(self):
        run,job=self.run_job()
        schedule_once(self.analysis,'lab',['guardian-demo'])
        self.assertEqual(len(self.analysis.list('lab','guardian-demo',self.human)),1)
        self.state['r']['rules'][0]['verbs'].append('list')
        schedule_once(self.analysis,'lab',['guardian-demo'])
        rows=self.analysis.list('lab','guardian-demo',self.human)
        self.assertEqual(len(rows),2)
        current=self.analysis.get(rows[0]['run_id'],self.human)
        self.assertEqual(current['revision'],2);self.assertEqual(current['intake']['trigger'],'drift')
        self.assertIsNone(run['request']['baseline_id'])

    def test_lost_completion_ack_replays_without_changing_report_or_spending_model_calls(self):
        run=self.queued();job=self.analysis.claim(JobClaim(cluster_id='lab',namespace='guardian-demo'),self.worker)
        original=self.worker_client.call;lost=False
        def transport(method,path,body=None):
            nonlocal lost
            result=original(method,path,body)
            if path.endswith('/complete') and not lost:
                lost=True;raise ConnectionError('Simulated lost acknowledgement')
            return result
        with patch.object(self.worker_client,'call',side_effect=transport):
            with self.assertRaises(ConnectionError):process_job(self.worker_client,job,self.checkpoints,clock=self.db.now)
        saved=self.analysis.get(run['run_id'],self.human)
        process_job(self.worker_client,job,self.checkpoints,clock=self.db.now)
        self.assertEqual(self.analysis.get(run['run_id'],self.human)['report'],saved['report'])
        self.assertEqual(saved['report']['model_calls'],1)

    def test_claim_and_renew_cannot_reset_active_deadline(self):
        run=self.queued();claim=JobClaim(cluster_id='lab',namespace='guardian-demo')
        job=self.analysis.claim(claim,self.worker)
        self.now+=timedelta(seconds=500)
        replacement=self.analysis.claim(claim,self.worker)
        self.assertIsNotNone(replacement)
        self.now+=timedelta(seconds=101)
        with self.assertRaisesRegex(LedgerError,'analysis_lease_lost'):
            self.analysis.renew(run['run_id'],replacement['lease_token'],self.worker)
        self.assertIsNone(self.analysis.claim(claim,self.worker))
        self.assertEqual(self.analysis.get(run['run_id'],self.human)['error'],'analysis_active_deadline')

    def test_exact_preview_candidate_remains_blocked_and_is_reviewable(self):
        from unittest.mock import MagicMock
        from agents.guardian.fixtures import demo_evidence
        from agents.guardian.contracts import EvidenceBundle
        value=demo_evidence(now=self.now).model_dump(mode='json')
        value['source_mode']='captured';value['target']['cluster_id']='lab';value['usage']['cluster_id']='lab'
        evidence=EvidenceBundle.model_validate(value)
        inventory=MagicMock();inventory.capture.return_value=evidence;inventory.load.return_value=evidence
        store=AnalysisStore(self.db,inventory,model_config=ModelConfig());self.client.app.state.analysis=store
        self.client.app.state.evidence_inventory=inventory
        run=store.enqueue(self.intake(role_name=evidence.target.name),self.human);store.prepare_next()
        job=store.claim(JobClaim(cluster_id='lab',namespace='guardian-demo'),self.worker)
        process_job(self.worker_client,job,self.checkpoints,clock=self.db.now)
        saved=store.get(run['run_id'],self.human)
        self.assertEqual(saved['report']['model_calls'],2)
        self.assertEqual(saved['proposal']['status'],'BLOCKED');self.assertFalse(saved['proposal']['simulation'])
        self.assertIn('"/metadata/uid"',json.dumps(saved['proposal']['patch']))
        self.assertFalse(saved['report']['readiness']['execution_ready'])
        self.assertEqual(store.decide(run['run_id'],self.decision(saved,'reject'),self.human)['review_outcome'],'REJECTED')

    def test_report_and_history_are_immutable_and_context_intake_failure_rolls_back_decision(self):
        import sqlite3
        run,job=self.run_job()
        with self.assertRaises(sqlite3.IntegrityError),self.db.transaction() as db:
            db.execute("UPDATE analysis_results SET payload='{}' WHERE run_id=?",(run['run_id'],))
        self.analysis.capacity=1
        self.analysis.enqueue(self.intake(idempotency_key='capacity-occupied'),self.human)
        with self.assertRaisesRegex(LedgerError,'analysis_queue_full'):
            self.analysis.decide(run['run_id'],self.decision(run,'request_context'),self.human)
        saved=self.analysis.get(run['run_id'],self.human)
        self.assertIsNone(saved['decision']);self.assertEqual(saved['review_state'],'OPEN')
