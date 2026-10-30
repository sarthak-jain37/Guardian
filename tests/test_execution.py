"""Actual graph/intake/authority/actuator protocol with a recording API boundary.

No test here contacts Kubernetes. Failed application checks are deliberately
injected recovery-protocol cases, not model-quality or live-acceptance results.
"""
import copy
import hashlib
import json
import sys
import unittest
from datetime import timedelta
from pathlib import Path
from uuid import uuid4

from agents.guardian.policy import canonical_hash
from backend.app.api.routes.governance import router as governance_router
from backend.app.api.routes.execution import router as execution_router
from backend.app.models.execution import ExecutionPolicy,FunctionalProfile,PrepareReview,RevokeAuthority,FreshRecovery
from backend.app.models.governance import DecisionInput,HoldInput
from backend.app.services.execution_store import ExecutionStore
from backend.app.services.functional_verifier import FunctionalVerifier
from backend.app.services.governance_store import LedgerError
from scripts.guardian_auth import revoke
from tests.test_usage_store import event
import tests.test_analysis as analysis_fixture
import tests.test_usage_store as usage_fixture


class RecordingRoleAPI:
    def __init__(self,state):
        self.state=state;self.applies=[];self.dry_runs=[];self.lose_response=False;self.access_error=None
        self.post_access_inconsistent=False
    def read(self,namespace,name):return copy.deepcopy(self.state['r'])
    def dry_run(self,namespace,name,uid,version,rules,identifier):
        self.dry_runs.append([uid,version,copy.deepcopy(rules)])
        result=copy.deepcopy(self.state['r']);result['rules']=copy.deepcopy(rules);return result
    def apply(self,namespace,name,uid,version,rules,identifier):
        role=self.state['r']
        if role['metadata']['uid']!=uid or role['metadata']['resourceVersion']!=version:
            from kubernetes.client.exceptions import ApiException
            raise ApiException(status=409)
        self.applies.append({'uid':uid,'version':version,'rules':copy.deepcopy(rules),'id':identifier})
        role['rules']=copy.deepcopy(rules);role['metadata']['resourceVersion']=str(int(version)+1)
        if self.lose_response:raise TimeoutError('injected lost acknowledgement')
        return copy.deepcopy(role)
    def access(self,subject,namespace,group,resource,verb):
        allowed=any(group in r['apiGroups'] and resource in r['resources'] and verb in r['verbs'] for r in self.state['r']['rules'])
        if self.post_access_inconsistent:allowed=True
        return {'allowed':allowed,'denied':False,'evaluation_error':self.access_error,'reason':'recording authorizer'}


class RecordingFunctionalVerifier:
    def __init__(self,db):
        self.db=db;self.real=FunctionalVerifier(db);self.counter=0;self.fail_post=False;self.unknown_post=False
        self.before_post=None;self.fail_restore=False
    def profile_hash(self,profile):return self.real.profile_hash(profile)
    def check(self,profile,evidence,phase):
        self.counter+=1
        if phase=='post' and self.before_post:self.before_post()
        result={'check_id':'functional-'+str(self.counter),'profile_hash':self.profile_hash(profile),
            'schema_version':'guardian.functional-proof.v1','phase':phase,'workload_uid':profile.workload_uid,
            'image_digest':profile.image_digest,'started_at':self.db.now().isoformat(),'completed_at':self.db.now().isoformat(),
            'runner_healthy':True,'dependencies_healthy':not (phase=='post' and self.unknown_post),
            'checks':{'startup':'pass','normal':'fail' if phase=='post' and self.fail_post or phase=='restored' and self.fail_restore else 'pass','restart':'pass'},
            'evidence_refs':['synthetic-functional-observation']}
        with self.db.transaction() as db:db.execute('INSERT INTO functional_checks VALUES (?,?,?)',
            (result['check_id'],json.dumps(result),self.db.now().isoformat()))
        return result


class ExecutionTests(unittest.TestCase):
    intake=analysis_fixture.AnalysisTests.intake
    queued=analysis_fixture.AnalysisTests.queued
    run_job=analysis_fixture.AnalysisTests.run_job

    def setUp(self):
        analysis_fixture.AnalysisTests.setUp(self)
        usage_fixture.UsageTests.ingest(self,event('observed-pod-read'))
        self.client.app.include_router(governance_router);self.client.app.include_router(execution_router)
        self.client.app.state.governance=self.db
        self.client.app.state.usage=self.store
        from backend.app.services.evidence_archive import EvidenceArchive
        from cryptography.fernet import Fernet
        keys=Path(self.temp.name)/'archive-keys.json'
        keys.write_text(json.dumps({'active':'test','keys':{'test':Fernet.generate_key().decode()}}))
        self.analysis.archive=EvidenceArchive(self.store,Path(self.temp.name)/'archive',keys)
        self.human=self.client.app.state.authenticator.authenticate(self.human_token)
        self.driver=RecordingRoleAPI(self.state);self.verifier=RecordingFunctionalVerifier(self.db)
        initial=self.inventory.capture('lab','guardian-demo','reader',self.intake().window)
        executable=str(Path(sys.executable).resolve())
        profile=FunctionalProfile(namespace='guardian-demo',role_name='reader',target_uid=initial.target.uid,
            subject_uid=initial.subject.uid,workload_uid=initial.context.workload_uid,image_digest=initial.context.image_digest,
            argv=[executable],artifact_hashes={executable:hashlib.sha256(Path(executable).read_bytes()).hexdigest()},
            observation_seconds=1,timeout_seconds=1)
        policy=ExecutionPolicy(cluster_id='lab',enabled=True,namespaces=['guardian-demo'],profiles=[profile])
        self.execution=ExecutionStore(self.db,self.analysis,self.inventory,self.driver,self.verifier,
            self.client.app.state.authenticator,policy,sleeper=self.advance)
        self.client.app.state.execution=self.execution

    def advance(self,seconds):self.now+=timedelta(seconds=seconds)

    def prepared(self,action='remediate'):
        run,job=self.run_job()
        self.assertEqual(run['report']['model_calls'],2)
        body=PrepareReview(source_run_id=run['run_id'],expected_report_hash=run['report_hash'],
            idempotency_key='prepare-'+action,action=action)
        queued=self.execution.submit(body,self.human)
        self.assertTrue(self.execution.prepare_next())
        prepared=self.execution.preparation(queued['preparation_id'],self.human)
        self.assertEqual(prepared['status'],'DONE',prepared)
        return run,self.execution.review_detail(prepared['proposal_id'],self.human)

    def approve(self,review,recovery=False,**changes):
        p=review['proposal'];value={'kind':'approve_remediation' if p['action']=='remediate' else 'adopt_baseline',
            'expected_revision':p['revision'],'expected_approval_hash':p['approval_hash'],
            'idempotency_key':'approve-'+uuid4().hex,'accept_residual_risk':True,'opt_in_recovery':recovery,
            'expected_recovery_hash':review['recovery_hash'] if recovery else None}
        value.update(changes)
        return self.db.record_decision(p['proposal_id'],DecisionInput(**value),self.human)

    def execute(self,review,decision):return self.execution.execute(review['proposal_id'],decision['decision_id'])

    def test_initial_hardening_uses_exact_guarded_rules_and_activates_first_baseline_only_after_checks(self):
        run,review=self.prepared();self.assertIsNone(self.execution.baseline_id(self.inventory.load(run['request']['snapshot_id']).target))
        decision=self.approve(review)
        result=self.execute(review,decision)
        self.assertEqual(result.phase,'completed',result)
        self.assertEqual(result.verification_status,'passed');self.assertEqual(len(self.driver.applies),1)
        self.assertTrue(result.baseline_activated);self.assertEqual(self.driver.applies[0]['version'],'7')
        self.assertEqual(self.driver.applies[0]['rules'],[{'apiGroups':[''],'resources':['pods'],'verbs':['get']}])
        duplicate=self.execute(review,decision)
        self.assertEqual(duplicate.receipt_id,result.receipt_id);self.assertEqual(len(self.driver.applies),1)
        notices=self.execution.notifications('lab','guardian-demo',self.human)
        self.assertTrue(notices);self.assertFalse(notices[0]['acknowledged'])
        self.assertFalse(self.execution.acknowledge_notification(notices[0]['notification_id'],self.human)['pause_changed'])
        self.assertEqual(self.analysis.get(run['run_id'],self.human)['report'],run['report'])
        with self.db._connect() as db:
            self.assertGreater(db.execute('SELECT count(*) FROM archive_pins WHERE case_id=?',(review['proposal']['case_id'],)).fetchone()[0],1)
        self.assertTrue(any(r.startswith('snapshot-') for r in result.check_refs))

    def test_rejection_and_nonwriting_reviews_cause_zero_calls_to_actuator(self):
        run,review=self.prepared();p=review['proposal']
        self.db.record_decision(p['proposal_id'],DecisionInput(kind='reject',expected_revision=p['revision'],
            expected_approval_hash=p['approval_hash'],idempotency_key='reject-action-1'),self.human)
        self.assertTrue(self.execution.execute_next());self.assertEqual(self.driver.applies,[])
        self.assertEqual(self.execution.baselines('lab','guardian-demo',self.human)[0]['status'],'REJECTED')

    def test_dispatch_rechecks_freshness_after_capture_and_explains_zero_writes(self):
        from unittest.mock import patch
        run,review=self.prepared();decision=self.approve(review)
        original=self.execution._fresh
        def slow_capture(*args,**kwargs):
            evidence=original(*args,**kwargs)
            self.advance(evidence.policy.maximum_source_lag_seconds+1)
            return evidence
        with patch.object(self.execution,'_fresh',side_effect=slow_capture):
            result=self.execute(review,decision)
        self.assertEqual(result.phase,'stale');self.assertEqual(result.apply_status,'not_started')
        self.assertEqual(self.driver.applies,[])
        detail=self.execution.review_detail(review['proposal_id'],self.human)
        self.assertEqual(detail['outcome_reason'],'audit_source_too_old_for_execution')
        self.assertTrue(any('audit_source_too_old_for_execution' in n['message'] for n in
            self.execution.notifications('lab','guardian-demo',self.human)))
        self.assertEqual(self.execute(review,decision).receipt_id,result.receipt_id)
        self.assertEqual(self.driver.applies,[])

    def test_exact_advance_recovery_requires_opt_in_and_restoration_verification(self):
        run,review=self.prepared();decision=self.approve(review,recovery=True);self.verifier.fail_post=True
        result=self.execute(review,decision)
        self.assertEqual(result.phase,'rolled_back',result)
        self.assertFalse(result.baseline_activated);self.assertEqual(result.recovery_status,'verified')
        self.assertEqual(len(self.driver.applies),2)
        self.assertEqual(self.driver.applies[1]['version'],'8')
        self.assertEqual(result.restored_rules_hash,review['recovery_contract']['original_rules_hash'])
        self.assertIsNone(self.execution.baseline(self.inventory.load(run['request']['snapshot_id']).target))
        self.assertEqual(self.execute(review,decision).receipt_id,result.receipt_id);self.assertEqual(len(self.driver.applies),2)

    def test_no_consent_and_infrastructure_ambiguity_never_trigger_automatic_recovery(self):
        run,review=self.prepared();decision=self.approve(review);self.verifier.fail_post=True
        result=self.execute(review,decision)
        self.assertEqual(result.phase,'manual');self.assertEqual(len(self.driver.applies),1)
        self.assertFalse(result.baseline_activated)

    def test_inconclusive_probe_blocks_recovery_even_with_advance_consent(self):
        run,review=self.prepared();decision=self.approve(review,recovery=True);self.verifier.unknown_post=True
        result=self.execute(review,decision)
        self.assertEqual(result.phase,'manual');self.assertEqual(result.verification_status,'inconclusive')
        self.assertEqual(len(self.driver.applies),1)

    def test_lost_apply_response_is_not_inferred_from_matching_rules_or_retried(self):
        run,review=self.prepared();decision=self.approve(review,recovery=True);self.driver.lose_response=True
        result=self.execute(review,decision)
        self.assertEqual(result.phase,'manual');self.assertEqual(result.apply_status,'unknown')
        self.assertFalse(result.baseline_activated);self.assertEqual(len(self.driver.applies),1)
        self.assertTrue(any(r.startswith('reconcile-') for r in result.check_refs))
        self.assertEqual(self.execute(review,decision).receipt_id,result.receipt_id);self.assertEqual(len(self.driver.applies),1)

    def test_expired_revoked_paused_and_changed_versions_fail_before_any_write(self):
        run,review=self.prepared();decision=self.approve(review)
        self.execution.revoke(decision['decision_id'],RevokeAuthority(reason='Operator canceled'),self.human)
        with self.assertRaises(LedgerError):self.execute(review,decision)
        self.assertEqual(self.driver.applies,[])

    def test_changed_role_after_approval_and_new_usage_make_decision_stale(self):
        run,review=self.prepared();decision=self.approve(review)
        self.state['r']['metadata']['resourceVersion']='99'
        result=self.execute(review,decision)
        self.assertEqual(result.phase,'stale');self.assertEqual(self.driver.applies,[])

    def test_human_scope_and_risk_recovery_hash_cannot_be_forged(self):
        run,review=self.prepared()
        with self.assertRaisesRegex(LedgerError,'residual_risk'):self.approve(review,accept_residual_risk=False)
        with self.assertRaisesRegex(LedgerError,'recovery_contract'):self.approve(review,recovery=True,expected_recovery_hash='wrong')
        self.assertEqual(self.driver.applies,[])

    def test_adoption_records_exact_snapshot_with_no_patch_or_model_round_trip(self):
        run,review=self.prepared(action='adopt_baseline');calls=run['report']['model_calls']
        decision=self.approve(review);result=self.execute(review,decision)
        self.assertEqual(result.phase,'completed');self.assertEqual(result.action,'adopt_baseline')
        self.assertEqual(self.driver.applies,[]);self.assertEqual(review['proposal']['patch'],[])
        self.assertEqual(self.analysis.get(run['run_id'],self.human)['report']['model_calls'],calls)

    def test_revoked_exact_credential_blocks_approval_despite_same_named_actor(self):
        run,review=self.prepared();revoke(Path(self.temp.name)/'auth.json',self.human.credential_id)
        with self.assertRaisesRegex(LedgerError,'credential'):self.approve(review)
        self.assertEqual(self.driver.applies,[])

    def test_fresh_human_recovery_after_declining_advance_recovery(self):
        run,review=self.prepared();decision=self.approve(review);self.verifier.fail_post=True
        result=self.execute(review,decision);self.assertEqual(result.phase,'manual')
        detail=self.execution.review_detail(review['proposal_id'],self.human)
        request=FreshRecovery(expected_sequence=result.sequence,expected_recovery_hash=detail['fresh_recovery_hash'],idempotency_key='fresh-consent-001')
        self.execution.fresh_recovery(result.action_key,request,self.human)
        self.assertTrue(self.execution.recover_next())
        latest=self.execution.latest_receipt(result.action_key)
        self.assertEqual(latest.phase,'rolled_back',latest);self.assertEqual(len(self.driver.applies),2)

    def test_advance_recovery_is_blocked_by_incident_without_clearing_hold(self):
        run,review=self.prepared();decision=self.approve(review,recovery=True);self.verifier.fail_post=True
        def incident():
            with self.db.transaction() as db:
                db.execute("INSERT INTO holds(cluster_id,namespace,kind,active,reason,actor,recorded_at) VALUES ('lab','guardian-demo','incident',1,'Suspected exploitation','operator',?)",(self.now.isoformat(),))
        self.verifier.before_post=incident
        result=self.execute(review,decision)
        self.assertEqual(result.phase,'manual');self.assertEqual(len(self.driver.applies),1)
        with self.db._connect() as db:self.assertEqual(db.execute("SELECT active FROM holds ORDER BY sequence DESC LIMIT 1").fetchone()[0],1)

    def test_pause_before_dispatch_allows_zero_writes(self):
        run,review=self.prepared();decision=self.approve(review)
        with self.db.transaction() as db:
            db.execute("INSERT INTO holds(cluster_id,namespace,kind,active,reason,actor,recorded_at) VALUES ('lab','guardian-demo','pause',1,'Paused','operator',?)",(self.now.isoformat(),))
        self.assertTrue(self.execution.execute_next());self.assertEqual(self.driver.applies,[])
        receipt=self.execution.review_detail(review['proposal_id'],self.human)['receipt']
        self.assertEqual(receipt['phase'],'stale');self.assertFalse(receipt['baseline_activated'])

    def test_expired_execution_cannot_start_a_write(self):
        run,review=self.prepared();decision=self.approve(review);self.advance(301)
        with self.assertRaisesRegex(LedgerError,'deadline'):self.execute(review,decision)
        self.assertEqual(self.driver.applies,[])

    def test_changed_binding_before_approval_is_rejected(self):
        run,review=self.prepared();self.state['b']['metadata']['resourceVersion']='changed'
        with self.assertRaisesRegex(LedgerError,'context_changed'):self.approve(review)
        self.assertEqual(self.driver.applies,[])

    def test_new_authorized_use_of_candidate_before_dispatch_blocks_write(self):
        run,review=self.prepared();decision=self.approve(review)
        usage_fixture.UsageTests.ingest(self,event('new-secret-use',resource='secrets',at=500))
        result=self.execute(review,decision)
        self.assertEqual(result.phase,'stale');self.assertEqual(self.driver.applies,[])

    def test_review_and_execution_have_independent_deadlines(self):
        from contracts.usage_summary_v1 import Window
        run,review=self.prepared();old=self.now;self.advance(86390)
        self.store.health('audit',Window(start=old,end=self.now),self.now,'fresh-late-review-health')
        decision=self.approve(review)
        self.assertGreater(decision['execution_expires_at'],review['review_expires_at'])
        result=self.execute(review,decision)
        self.assertEqual(result.phase,'completed',result)
        self.advance(1000)
        self.assertEqual(self.execute(review,decision).receipt_id,result.receipt_id)

    def test_error_sar_does_not_authorize_approval(self):
        run,review=self.prepared();self.driver.access_error='independent authorizer unavailable'
        with self.assertRaisesRegex(LedgerError,'access_check'):self.approve(review)
        self.assertEqual(self.driver.applies,[])

    def test_postchange_effective_access_failure_does_not_invent_recovery_trigger(self):
        run,review=self.prepared();decision=self.approve(review,recovery=True);self.driver.post_access_inconsistent=True
        result=self.execute(review,decision)
        self.assertEqual(result.phase,'manual');self.assertEqual(len(self.driver.applies),1)
        self.assertFalse(result.baseline_activated)

    def test_dry_run_semantics_changed_before_approval_cause_zero_writes(self):
        from unittest.mock import patch
        run,review=self.prepared()
        with patch.object(self.driver,'dry_run',return_value={'kind':'Role','metadata':{'uid':'role-uid'},'rules':[]}):
            with self.assertRaisesRegex(LedgerError,'dry_run_semantics'):self.approve(review)
        self.assertEqual(self.driver.applies,[])

    def test_failed_restore_never_claims_rolled_back(self):
        run,review=self.prepared();decision=self.approve(review,recovery=True);self.verifier.fail_post=True;self.verifier.fail_restore=True
        result=self.execute(review,decision)
        self.assertEqual(result.phase,'manual');self.assertEqual(result.recovery_status,'inconclusive')
        self.assertEqual(len(self.driver.applies),2);self.assertFalse(result.baseline_activated)
        self.assertIsNone(result.restored_resource_version)

    def test_acknowledged_apply_crash_resumes_without_second_apply(self):
        from unittest.mock import patch
        run,review=self.prepared();decision=self.approve(review)
        class SimulatedCrash(BaseException):pass
        with patch.object(self.execution,'_verify_forward',side_effect=SimulatedCrash):
            with self.assertRaises(SimulatedCrash):self.execute(review,decision)
        result=self.execute(review,decision)
        self.assertEqual(result.phase,'completed',result);self.assertEqual(len(self.driver.applies),1)

    def test_acknowledged_restore_crash_reverifies_without_another_restore(self):
        from unittest.mock import patch
        run,review=self.prepared();decision=self.approve(review,recovery=True);self.verifier.fail_post=True
        real=self.execution._verify
        class SimulatedCrash(BaseException):pass
        def verify(*args,**kwargs):
            if kwargs.get('restored'):raise SimulatedCrash()
            return real(*args,**kwargs)
        with patch.object(self.execution,'_verify',side_effect=verify):
            with self.assertRaises(SimulatedCrash):self.execute(review,decision)
        result=self.execute(review,decision)
        self.assertEqual(result.phase,'rolled_back',result);self.assertEqual(len(self.driver.applies),2)

    def test_http_approval_preflight_and_receipt_share_strict_consumer_contracts(self):
        from agents.guardian.contracts import Proposal
        from agents.guardian.governance import GovernedDecision,validate_preflight,validate_receipt,action_key
        from backend.app.core.auth import Principal
        from scripts.guardian_auth import issue
        run,review=self.prepared();p=Proposal.model_validate(review['proposal'])
        body={'kind':'approve_remediation','expected_revision':p.revision,'expected_approval_hash':p.approval_hash,
            'idempotency_key':'http-approval-1','accept_residual_risk':True}
        response=self.client.post('/governance/reviews/'+p.proposal_id+'/decisions',json=body,
            headers={'Authorization':'Bearer '+self.human_token})
        self.assertEqual(response.status_code,200,response.text)
        decision=GovernedDecision.model_validate(response.json());self.assertIsNone(decision.recovery_authority_id)
        request={'proposal_id':p.proposal_id,'decision_id':decision.decision_id,'action_key':action_key(p,decision.decision_id),'action':p.action}
        for path in ('/execution/preflight','/execution/requests'):
            denied=self.client.post(path,json=request,headers={'Authorization':'Bearer '+self.worker_token})
            self.assertEqual(denied.status_code,403,denied.text)
        executor=Principal(actor='executor-port',kind='service',grants=[{'cluster_id':'lab','namespace':'guardian-demo','permissions':['read','execute']}])
        token=issue(Path(self.temp.name)/'auth.json',executor)
        headers={'Authorization':'Bearer '+token}
        pre=self.client.post('/execution/preflight',json=request,headers=headers)
        self.assertEqual(pre.status_code,200,pre.text)
        validate_preflight(pre.json(),p,decision,self.db.now())
        queue=self.client.post('/execution/requests',json=request,headers=headers)
        self.assertEqual(queue.status_code,202,queue.text);self.assertEqual(self.driver.applies,[])
        self.assertTrue(self.execution.execute_next())
        result=self.client.get('/execution/receipts/'+request['action_key'],headers=headers)
        validate_receipt(result.json(),p,decision.decision_id,self.db.now())
        self.assertEqual(result.json()['phase'],'completed');self.assertEqual(len(self.driver.applies),1)
        forged=self.client.post('/execution/requests',json={**request,'rules':[]},headers=headers)
        self.assertEqual(forged.status_code,422)
        foreign=self.client.get('/execution/reviews/'+p.proposal_id,headers={'Authorization':'Bearer '+self.other_token})
        self.assertEqual(foreign.status_code,403)

    def test_revocation_projection_and_recovery_only_revocation(self):
        run,review=self.prepared();decision=self.approve(review,recovery=True)
        self.execution.revoke(decision['decision_id'],RevokeAuthority(reason='decline restoration',kind='recovery'),self.human)
        self.assertFalse(self.db.get_decision(decision['decision_id'],self.human)['revoked'])
        self.verifier.fail_post=True
        result=self.execute(review,decision)
        self.assertEqual(result.phase,'manual');self.assertEqual(len(self.driver.applies),1)
        self.execution.revoke(decision['decision_id'],RevokeAuthority(reason='stop all authority'),self.human)
        self.assertTrue(self.db.get_decision(decision['decision_id'],self.human)['revoked'])

    def test_changed_policy_and_expired_recovery_do_not_restore(self):
        run,review=self.prepared();decision=self.approve(review,recovery=True)
        def expire():self.advance(601)
        self.verifier.before_post=expire;self.verifier.fail_post=True
        result=self.execute(review,decision)
        self.assertEqual(result.phase,'manual');self.assertEqual(len(self.driver.applies),1)

    def test_preparation_lease_expiry_fences_publication(self):
        from unittest.mock import patch
        run,job=self.run_job()
        queued=self.execution.submit(PrepareReview(source_run_id=run['run_id'],expected_report_hash=run['report_hash'],
            idempotency_key='lease-test-prepare'),self.human)
        dry=self.driver.dry_run
        def expire(*args,**kwargs):
            result=dry(*args,**kwargs);self.advance(601);return result
        with patch.object(self.driver,'dry_run',side_effect=expire):self.execution.prepare_next()
        status=self.execution.preparation(queued['preparation_id'],self.human)
        self.assertEqual(status['status'],'BLOCKED');self.assertEqual(status['error'],'preparation_lease_lost')
        self.assertEqual(self.execution.list_reviews('lab','guardian-demo',self.human),[])

    def test_source_supersession_and_disabled_policy_block_old_approval(self):
        run,review=self.prepared()
        self.analysis.enqueue(self.intake(idempotency_key='supersede-prepare',supersedes_run_id=run['run_id']),self.human)
        with self.assertRaises(LedgerError):self.approve(review)
        self.execution.policy=self.execution.policy.model_copy(update={'enabled':False})
        self.assertFalse(self.execution.review_detail(review['proposal_id'],self.human)['execution_available'])
        self.assertEqual(self.driver.applies,[])

    def test_existing_baseline_survives_failed_later_drift_and_verified_restore(self):
        run,adoption=self.prepared('adopt_baseline');decision=self.approve(adoption)
        self.assertEqual(self.execute(adoption,decision).phase,'completed')
        target=self.inventory.load(run['request']['snapshot_id']).target
        baseline=self.execution.baseline_id(target);self.assertIsNotNone(baseline)
        # A later externally added grant is analysed against the approved baseline.
        self.state['r']['rules'].append({'apiGroups':[''],'resources':['configmaps'],'verbs':['get']})
        self.state['r']['metadata']['resourceVersion']='8'
        intake=self.intake(idempotency_key='later-drift',supersedes_run_id=run['run_id'],trigger='manual')
        latest=self.analysis.enqueue(intake,self.human);self.analysis.prepare_next()
        job=self.worker_client.call('POST','/analysis/jobs/claim',{'cluster_id':'lab','namespace':'guardian-demo'})['job']
        from agents.guardian.service_worker import process_job
        process_job(self.worker_client,job,self.checkpoints,clock=self.db.now)
        source=self.analysis.get(latest['run_id'],self.human)
        queued=self.execution.submit(PrepareReview(source_run_id=source['run_id'],expected_report_hash=source['report_hash'],
            idempotency_key='later-drift-prepare'),self.human)
        self.execution.prepare_next();ready=self.execution.preparation(queued['preparation_id'],self.human)
        self.assertEqual(ready['status'],'DONE',ready)
        review=self.execution.review_detail(ready['proposal_id'],self.human)
        self.assertEqual(review['expected_baseline_id'],baseline)
        decision=self.approve(review,recovery=True);self.verifier.fail_post=True
        result=self.execute(review,decision)
        self.assertEqual(result.phase,'rolled_back',result);self.assertEqual(self.execution.baseline_id(target),baseline)
        self.assertEqual(len(self.driver.applies),2)

    def test_fresh_recovery_crash_after_restore_ack_resumes_without_third_write(self):
        from unittest.mock import patch
        run,review=self.prepared();decision=self.approve(review);self.verifier.fail_post=True
        first=self.execute(review,decision)
        detail=self.execution.review_detail(review['proposal_id'],self.human)
        self.execution.fresh_recovery(first.action_key,FreshRecovery(expected_sequence=first.sequence,
            expected_recovery_hash=detail['fresh_recovery_hash'],idempotency_key='fresh-crash-consent'),self.human)
        real=self.execution._verify
        class SimulatedCrash(BaseException):pass
        def verify(*args,**kwargs):
            if kwargs.get('restored'):raise SimulatedCrash()
            return real(*args,**kwargs)
        with patch.object(self.execution,'_verify',side_effect=verify):
            with self.assertRaises(SimulatedCrash):self.execution.recover_next()
        self.assertTrue(self.execution.recover_next())
        self.assertEqual(self.execution.latest_receipt(first.action_key).phase,'rolled_back')
        self.assertEqual(len(self.driver.applies),2)

    def test_inference_delivery_permission_cannot_steal_backend_action_outbox(self):
        from backend.app.models.governance import DeliveryClaim
        run,review=self.prepared();decision=self.approve(review)
        self.assertEqual(self.db.claim_deliveries(DeliveryClaim(cluster_id='lab',namespace='guardian-demo'),self.worker),[])
        self.assertTrue(self.execution.execute_next());self.assertEqual(len(self.driver.applies),1)

    def test_new_action_review_invalidates_undispatched_older_approval(self):
        run,review=self.prepared();decision=self.approve(review)
        queued=self.execution.submit(PrepareReview(source_run_id=run['run_id'],expected_report_hash=run['report_hash'],
            idempotency_key='replacement-action'),self.human)
        self.execution.prepare_next()
        self.assertEqual(self.execution.preparation(queued['preparation_id'],self.human)['status'],'DONE')
        self.execution.execute_next()
        old=self.execution.review_detail(review['proposal_id'],self.human)
        self.assertEqual(old['receipt']['phase'],'stale');self.assertEqual(self.driver.applies,[])

    def test_new_revocation_after_fresh_recovery_consent_stops_restore(self):
        run,review=self.prepared();decision=self.approve(review);self.verifier.fail_post=True
        first=self.execute(review,decision);detail=self.execution.review_detail(review['proposal_id'],self.human)
        self.execution.fresh_recovery(first.action_key,FreshRecovery(expected_sequence=first.sequence,
            expected_recovery_hash=detail['fresh_recovery_hash'],idempotency_key='fresh-revoke-consent'),self.human)
        self.execution.revoke(decision['decision_id'],RevokeAuthority(reason='stop queued restoration',kind='recovery'),self.human)
        self.execution.recover_next()
        self.assertEqual(self.execution.latest_receipt(first.action_key).phase,'manual')
        self.assertEqual(len(self.driver.applies),1)

    def test_governed_context_delivery_replays_after_lost_ack_without_duplicate_analysis(self):
        from unittest.mock import patch
        run,review=self.prepared();p=review['proposal']
        decision=self.db.record_decision(p['proposal_id'],DecisionInput(kind='request_context',
            expected_revision=p['revision'],expected_approval_hash=p['approval_hash'],
            idempotency_key='context-action-1',note='scheduled '+('x'*1990)),self.human)
        with patch.object(self.db,'acknowledge_delivery',side_effect=RuntimeError('lost acknowledgement')):
            with self.assertRaises(RuntimeError):self.execution.execute_next()
        self.advance(601)
        self.assertTrue(self.execution.execute_next())
        runs=self.analysis.list('lab','guardian-demo',self.human)
        self.assertEqual(len(runs),2)
        latest=self.analysis.get(runs[0]['run_id'],self.human)
        self.assertIn(decision['decision_id'],latest['intake']['context_note'])
        self.assertEqual(latest['intake']['supersedes_run_id'],run['run_id'])
        self.assertEqual(self.driver.applies,[])
        self.assertEqual(self.analysis.get(run['run_id'],self.human)['report'],run['report'])

    def test_restored_authority_is_revoked_and_runtime_guard_blocks_enabled_policy(self):
        from cryptography.fernet import Fernet
        from scripts.guardian_backup import create,restore
        from backend.app.services.governance_store import GovernanceStore
        import shutil
        run,review=self.prepared();decision=self.approve(review)
        state=Path(self.temp.name)/'backup-state';state.mkdir()
        with self.db._connect() as source:
            import sqlite3
            target=sqlite3.connect(state/'governance.sqlite3')
            try:source.backup(target)
            finally:target.close()
        key=Path(self.temp.name)/'backup.key';key.write_bytes(Fernet.generate_key())
        bundle=Path(self.temp.name)/'backup.fernet';create({'state':state},bundle,key,quiesced=True)
        destination=Path(self.temp.name)/'restored';restore(bundle,destination,key)
        restored=GovernanceStore(destination/'state/governance.sqlite3',clock=self.db.clock)
        executor=ExecutionStore(restored,self.analysis,self.inventory,self.driver,self.verifier,self.client.app.state.authenticator,self.execution.policy)
        self.assertFalse(executor.enabled)
        self.assertTrue(restored.get_decision(decision['decision_id'],self.human)['revoked'])
        with self.assertRaises(LedgerError):executor.execute(review['proposal_id'],decision['decision_id'])
        self.assertEqual(self.driver.applies,[])
