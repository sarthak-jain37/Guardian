"""Backend-owned governed Role execution and exact, separately consented recovery.

No model is imported or called. The same implementation is exercised with a
recording API-server boundary in tests; production uses ConditionalRoleDriver.
"""
import fcntl
import json
import os
import time
from contextlib import contextmanager
from datetime import datetime,timedelta
from pathlib import Path
from uuid import uuid4

from agents.guardian.contracts import AnalysisReport, EvidenceBundle, Proposal, Gate, ReadinessAssessment
from agents.guardian.governance import GovernedDecision, ExecutionReceipt, action_key
from agents.guardian.policy import (canonical_hash,build_facts,global_gates,operations,rule_dicts,
    render,validate_investigation,validate_plan,risk_findings)
from agents.guardian.review import adoption_gates
from agents.guardian.versions import current_versions
from backend.app.core.auth import Principal
from backend.app.models.execution import ExecutionPolicy,PrepareReview
from backend.app.models.governance import ReviewPublication
from backend.app.services.governance_store import LedgerError,encode,digest,validate

TERMINAL={'completed','rolled_back','manual','stale','failed'}


def context_key(e):
    context=e.context.model_dump(mode='json') if e.context else None
    if context:
        for key in ('context_id','collected_at','evidence_refs','exercised_behaviors'):context.pop(key,None)
    def material(value):
        if isinstance(value,dict):return {k:material(v) for k,v in value.items() if k not in ('evidence_refs','identity_evidence_refs')}
        if isinstance(value,list):return [material(v) for v in value]
        return value
    return canonical_hash(material({'subject':e.subject.model_dump(exclude={'identity_evidence_refs'},mode='json'),
        'binding':e.binding.model_dump(exclude={'evidence_refs'},mode='json') if e.binding else None,
        'context':context,'policy':e.policy.model_dump(mode='json')}))


def scope_key(target):return canonical_hash([target.cluster_id,target.kind,target.namespace,target.name])


def healthy(proof):
    return proof.get('runner_healthy') is True and proof.get('dependencies_healthy') is True


def passed(proof):return healthy(proof) and set(proof['checks'].values())=={'pass'}


class ExecutionStore:
    def __init__(self,governance,analysis,inventory,driver,verifier,authenticator,policy,*,sleeper=time.sleep):
        self.db,self.analysis,self.inventory=governance,analysis,inventory
        self.driver,self.verifier,self.auth=driver,verifier,authenticator
        self.policy=ExecutionPolicy.model_validate(policy.model_dump(mode='json') if isinstance(policy,ExecutionPolicy) else policy)
        self.sleep=sleeper
        self.service=Principal(actor='guardian-execution-backend',kind='service',grants=[
            {'cluster_id':self.policy.cluster_id,'namespace':ns,'permissions':['read','publish','deliver']} for ns in self.policy.namespaces] or
            [{'cluster_id':self.policy.cluster_id,'namespace':'execution-disabled','permissions':['read']}])
        with self.db._connect() as db:
            db.executescript('''
            CREATE TABLE IF NOT EXISTS execution_preparations (
              preparation_id TEXT PRIMARY KEY,source_run_id TEXT,cluster_id TEXT,namespace TEXT,actor TEXT,
              idempotency_key TEXT,request_hash TEXT,payload TEXT,status TEXT,lease_until TEXT,
              proposal_id TEXT,error TEXT,UNIQUE(actor,idempotency_key));
            CREATE TABLE IF NOT EXISTS execution_plans (
              proposal_id TEXT PRIMARY KEY,source_run_id TEXT,payload TEXT,content_hash TEXT);
            CREATE TABLE IF NOT EXISTS execution_authorities (
              decision_id TEXT PRIMARY KEY,proposal_id TEXT,actor TEXT,credential_id TEXT,
              recovery_id TEXT,payload TEXT);
            CREATE TABLE IF NOT EXISTS execution_revocations (
              sequence INTEGER PRIMARY KEY AUTOINCREMENT,decision_id TEXT,kind TEXT,actor TEXT,reason TEXT,recorded_at TEXT);
            CREATE TABLE IF NOT EXISTS execution_actions (
              action_key TEXT PRIMARY KEY,proposal_id TEXT UNIQUE,decision_id TEXT,scope_key TEXT,
              state TEXT,dispatch_id TEXT,confirmed TEXT,recovery_confirmed TEXT,recovery_started INTEGER DEFAULT 0,
              recovery_authority TEXT);
            CREATE TABLE IF NOT EXISTS execution_receipts (
              receipt_id TEXT PRIMARY KEY,action_key TEXT,sequence INTEGER,payload TEXT,UNIQUE(action_key,sequence));
            CREATE TABLE IF NOT EXISTS execution_baselines (
              baseline_id TEXT PRIMARY KEY,scope_key TEXT,target_uid TEXT,proposal_id TEXT,payload TEXT);
            CREATE TABLE IF NOT EXISTS execution_baseline_state (
              baseline_id TEXT PRIMARY KEY,scope_key TEXT,status TEXT);
            CREATE UNIQUE INDEX IF NOT EXISTS one_active_execution_baseline ON execution_baseline_state(scope_key) WHERE status='ACTIVE';
            CREATE TABLE IF NOT EXISTS execution_failures (
              failure_id TEXT PRIMARY KEY,cluster_id TEXT,target_uid TEXT,candidate_hash TEXT,workload_uid TEXT,
              image_digest TEXT,policy_version TEXT,payload TEXT);
            CREATE TABLE IF NOT EXISTS execution_notifications (
              notification_id TEXT PRIMARY KEY,action_key TEXT,actor TEXT,cluster_id TEXT,namespace TEXT,payload TEXT);
            CREATE TABLE IF NOT EXISTS execution_notification_ack (notification_id TEXT PRIMARY KEY,actor TEXT,recorded_at TEXT);
            CREATE TABLE IF NOT EXISTS execution_fresh_recovery (
              recovery_id TEXT PRIMARY KEY,action_key TEXT,actor TEXT,credential_id TEXT,idempotency_key TEXT,
              request_hash TEXT,payload TEXT,UNIQUE(actor,idempotency_key));
            ''')
            for table in ('execution_plans','execution_authorities','execution_revocations','execution_receipts',
                          'execution_baselines','execution_failures','execution_notifications','execution_fresh_recovery'):
                for action in ('UPDATE','DELETE'):
                    db.execute(f"CREATE TRIGGER IF NOT EXISTS {table}_no_{action.lower()} BEFORE {action} ON {table} "
                        "BEGIN SELECT RAISE(ABORT,'immutable_execution_record'); END")
        self.db.execution_gate=self
        self.inventory.context_provider=self.enrich
        self.inventory.baseline_provider=self.baseline_id

    @property
    def enabled(self):return self.policy.enabled and self.auth is not None and self.analysis.archive is not None and not (self.db.path.parent/'restore-required').exists()

    def profile(self,e):
        matches=[p for p in self.policy.profiles if (p.namespace,p.role_name)==(e.target.namespace,e.target.name)]
        if len(matches)!=1:raise LedgerError('meaningful_functional_profile_unavailable',503)
        profile=matches[0];context=e.context
        if not context or (profile.target_uid,profile.subject_uid,profile.workload_uid,profile.image_digest)!=(
                e.target.uid,e.subject.uid,context.workload_uid,context.image_digest):
            raise LedgerError('functional_profile_identity_changed')
        return profile

    def enrich(self,e):
        """Called before inventory persistence; a profile's existence is not proof."""
        if not any((p.namespace,p.role_name)==(e.target.namespace,e.target.name) for p in self.policy.profiles):return e
        try:
            proof=self.verifier.check(self.profile(e),e,'observe')
            if not passed(proof):return e
            context=e.context.model_copy(update={'exercised_behaviors':['startup','normal','restart'],
                'evidence_refs':e.context.evidence_refs+[proof['check_id']]})
            return EvidenceBundle.model_validate({**e.model_dump(mode='json'),'context':context.model_dump(mode='json'),
                'evidence_refs':e.evidence_refs+[proof['check_id']]})
        except Exception:return e

    def baseline(self,target):
        with self.db._connect() as db:
            row=db.execute("SELECT b.* FROM execution_baselines b JOIN execution_baseline_state s USING(baseline_id) WHERE s.scope_key=? AND s.status='ACTIVE'",(scope_key(target),)).fetchone()
        return dict(row) if row else None

    def baseline_id(self,target):
        row=self.baseline(target)
        return row['baseline_id'] if row and row['target_uid']==target.uid else None

    def available(self,proposal_id):
        if not self.enabled:return False
        with self.db._connect() as db:
            row=db.execute('SELECT payload FROM execution_plans WHERE proposal_id=?',(proposal_id,)).fetchone()
        return bool(row)

    def plan(self,proposal_id,db=None):
        if db is None:
            with self.db._connect() as connection:return self.plan(proposal_id,connection)
        row=db.execute('SELECT payload FROM execution_plans WHERE proposal_id=?',(proposal_id,)).fetchone()
        if row is None:raise LedgerError('backend_prepared_action_required',503)
        return json.loads(row[0])

    def _require_enabled(self,cluster,namespace):
        if not self.enabled:raise LedgerError('governed_executor_unavailable',503)
        if cluster!=self.policy.cluster_id or namespace not in self.policy.namespaces or namespace not in self.inventory.controlled:
            raise LedgerError('controlled_execution_scope_required',403)

    def _holds(self,db,cluster,namespace):
        rows=db.execute('''SELECT * FROM holds WHERE cluster_id=? AND namespace=? AND sequence IN (
            SELECT MAX(sequence) FROM holds WHERE cluster_id=? AND namespace=? GROUP BY kind)''',
            (cluster,namespace,cluster,namespace)).fetchall()
        if any(r['active'] for r in rows):raise LedgerError('execution_paused_or_incident_held')
        return max([r['sequence'] for r in rows],default=0)

    def _credential(self,actor,identifier,p):
        if not self.auth or not self.auth.current_authority(actor,identifier,p.target.cluster_id,p.target.namespace):
            raise LedgerError('approval_credential_expired_revoked_or_out_of_scope',403)

    def _control(self,db,plan,p,*,require_source=True):
        self._require_enabled(p.target.cluster_id,p.target.namespace)
        source=self.analysis.row(db,plan['source_run_id'])
        case=db.execute('SELECT latest_run_id FROM analysis_cases WHERE case_id=?',(source['case_id'],)).fetchone()
        if require_source and (case is None or case[0]!=source['run_id']):raise LedgerError('source_analysis_superseded')
        if require_source:
            revision=db.execute('SELECT MAX(revision) FROM reviews WHERE case_id=?',(p.case_id,)).fetchone()[0]
            if revision is not None and revision!=p.revision:raise LedgerError('action_review_superseded')
        row=db.execute('SELECT report_hash,payload FROM analysis_results WHERE run_id=?',(source['run_id'],)).fetchone()
        if row is None or row[0]!=plan['source_report_hash']:raise LedgerError('source_report_changed')
        versions=json.loads(row['payload'])['report']['versions']
        if versions!=current_versions(p.policy_version).model_dump(mode='json'):raise LedgerError('analysis_versions_changed_fresh_review_required')
        self._holds(db,p.target.cluster_id,p.target.namespace)
        current=db.execute("SELECT baseline_id FROM execution_baseline_state WHERE scope_key=? AND status='ACTIVE'",(scope_key(p.target),)).fetchone()
        if (current[0] if current else None)!=plan['expected_baseline_id']:raise LedgerError('approved_baseline_changed')

    def _failure(self,e,candidate):
        if not e.context:return True
        with self.db._connect() as db:
            return bool(db.execute('''SELECT 1 FROM execution_failures WHERE cluster_id=? AND target_uid=? AND candidate_hash=?
                AND workload_uid=? AND image_digest=? AND policy_version=? AND COALESCE(json_extract(payload,'$.blocks_candidate'),1)=1''',(e.target.cluster_id,e.target.uid,candidate,
                e.context.workload_uid,e.context.image_digest,e.policy.policy_version)).fetchone())

    def _fresh(self,original,*,same_version=True):
        usage=original.usage
        if usage is None:raise LedgerError('usage_window_unavailable')
        now=self.db.now()
        with self.db._connect() as db:
            progress=db.execute('''SELECT MAX(processed_through) FROM evidence_coverage JOIN evidence_sources USING(source_id)
                WHERE cluster_id=? AND namespace=?''',(original.target.cluster_id,original.target.namespace)).fetchone()[0]
        end=min(now,datetime.fromisoformat(progress)) if progress else now
        notes=[d for d in original.context.optional_documents if d.startswith('Authenticated operator note')] if original.context else []
        current=self.inventory.capture(original.target.cluster_id,original.target.namespace,original.target.name,
            {'start':end-(usage.query_window.end-usage.query_window.start),'end':end},owner_notes=notes)
        if (current.target.uid!=original.target.uid or current.target.rules!=original.target.rules
                or context_key(current)!=context_key(original)
                or (same_version and current.target.resource_version!=original.target.resource_version)):
            raise LedgerError('target_consumers_workload_or_context_changed')
        return current

    def _dry_run(self,target,rules,identifier,*,version=None):
        response=self.driver.dry_run(target.namespace,target.name,target.uid,version or target.resource_version,rules,identifier)
        if (response.get('kind')!='Role' or response.get('metadata',{}).get('uid')!=target.uid
                or response.get('rules',[])!=rules):raise LedgerError('dry_run_semantics_changed_or_unavailable')
        return response

    def _access(self,e,rules,removed=(),*,pre=False):
        values=[];refs=[];unknown=False;failed=[];required_fail=[]
        probes=sorted(operations(rules))
        if len(probes)>16:raise LedgerError('pilot_verification_supports_at_most_16_exact_operations')
        for group,resource,verb in probes:
            expected=True if pre else (group,resource,verb) not in removed
            try:result=self.driver.access(e.subject,e.target.namespace,group,resource,verb)
            except Exception:result={'allowed':None,'denied':None,'evaluation_error':'access_check_unavailable','reason':''}
            certain=(type(result.get('allowed')) is bool and type(result.get('denied')) is bool
                and not result.get('evaluation_error') and not (result['allowed'] and result['denied']))
            name=canonical_hash([group,resource,verb])
            if not certain:unknown=True
            elif result['allowed']!=expected:
                failed.append(name)
                if expected:required_fail.append(name)
            values.append({'operation':[group,resource,verb],'expected_allowed':expected,**result})
        identifier='access-'+canonical_hash(values).split(':')[1]
        with self.db.transaction() as db:
            db.execute('INSERT OR IGNORE INTO functional_checks VALUES (?,?,?)',
                (identifier,encode({'kind':'subject_access_review','results':values}),self.db.now().isoformat()))
        return {'check_id':identifier,'unknown':unknown,'failed':failed,'required_failed':required_fail,'results':values}

    def submit(self,body,principal):
        body=validate(PrepareReview,body);source=self.analysis.get(body.source_run_id,principal)
        principal.require('review',source['cluster_id'],source['namespace'])
        if principal.kind!='human':raise LedgerError('human_review_request_required',403)
        self._require_enabled(source['cluster_id'],source['namespace'])
        if source['status']!='DONE' or source['report_hash']!=body.expected_report_hash:raise LedgerError('analysis_report_not_current')
        encoded=body.model_dump_json();request_hash=digest(body.model_dump(mode='json'))
        with self.db.transaction() as db:
            old=db.execute('SELECT * FROM execution_preparations WHERE actor=? AND idempotency_key=?',(principal.actor,body.idempotency_key)).fetchone()
            if old:
                if old['request_hash']!=request_hash:raise LedgerError('preparation_idempotency_conflict')
                return {key:old[key] for key in ('preparation_id','source_run_id','status','proposal_id','error')}
            count=db.execute("SELECT count(*) FROM execution_preparations WHERE cluster_id=? AND namespace=? AND status IN ('QUEUED','RUNNING')",(source['cluster_id'],source['namespace'])).fetchone()[0]
            if count>=8:raise LedgerError('preparation_queue_full',503)
            identifier='prepare-'+uuid4().hex
            db.execute("INSERT INTO execution_preparations VALUES (?,?,?,?,?,?,?,?, 'QUEUED',NULL,NULL,NULL)",
                (identifier,body.source_run_id,source['cluster_id'],source['namespace'],principal.actor,body.idempotency_key,request_hash,encoded))
        return self.preparation(identifier,principal)

    def preparation(self,identifier,principal):
        with self.db._connect() as db:
            row=db.execute('SELECT * FROM execution_preparations WHERE preparation_id=?',(identifier,)).fetchone()
            if row is None:raise LedgerError('preparation_not_found',404)
            principal.require('read',row['cluster_id'],row['namespace'])
        return {key:row[key] for key in ('preparation_id','source_run_id','status','proposal_id','error')}

    def prepare_next(self):
        with self.db.transaction() as db:
            row=db.execute("SELECT * FROM execution_preparations WHERE status='QUEUED' OR (status='RUNNING' AND lease_until<=?) ORDER BY rowid LIMIT 1",(self.db.now().isoformat(),)).fetchone()
            if row is None:return False
            row=dict(row)
            row['lease_until']=(self.db.now()+timedelta(minutes=10)).isoformat()
            db.execute("UPDATE execution_preparations SET status='RUNNING',lease_until=? WHERE preparation_id=?",(row['lease_until'],row['preparation_id']))
        try:self._prepare(row)
        except Exception as error:
            code=error.code if isinstance(error,LedgerError) else 'independent_preparation_unavailable'
            with self.db.transaction() as db:
                db.execute("UPDATE execution_preparations SET status='BLOCKED',error=? WHERE preparation_id=? AND status='RUNNING' AND lease_until=?",
                    (code,row['preparation_id'],row['lease_until']))
        return True

    def _retain(self,e,case_id):
        if self.analysis.archive is None:raise LedgerError('durable_case_archive_required',503)
        if e.usage:self.analysis.archive.pin(case_id,e.usage.summary_id,self.db.now()+timedelta(days=90))

    def _prepare(self,row):
        self._require_enabled(row['cluster_id'],row['namespace'])
        body=PrepareReview.model_validate_json(row['payload'])
        source=self.analysis.get(body.source_run_id,self.service)
        if source['report_hash']!=body.expected_report_hash:raise LedgerError('analysis_report_changed')
        if source['report']['versions']!=current_versions(source['report']['versions']['policy_version']).model_dump(mode='json'):
            raise LedgerError('analysis_versions_changed_fresh_analysis_required')
        original=self.inventory.load(source['request']['snapshot_id'])
        if original.source_mode!='captured':raise LedgerError('captured_source_required')
        current=self._fresh(original,same_version=False)
        profile=None;pre_proof=None;pre_access=None
        if body.action=='remediate':
            if not source['proposal'] or not source['report']['investigation'] or not source['report']['plan']:
                raise LedgerError('supported_remediation_candidate_unavailable')
            from agents.guardian.contracts import Investigation,ChangePlan
            investigation=Investigation.model_validate(source['report']['investigation']);plan=ChangePlan.model_validate(source['report']['plan'])
            original_facts,_=build_facts(original,max(original.context.collected_at,original.usage.generated_at))
            validate_investigation(investigation,original_facts,original)
            validate_plan(plan,original_facts,investigation,original)
            removed={p.permission_id for p in plan.decisions if p.action=='remove'}
            facts,gates=build_facts(current,self.db.now())
            if not removed or not removed<={f['permission_id'] for f in facts if f['eligible']} or any(g.result!='pass' for g in gates):
                raise LedgerError('independent_removal_readiness_failed')
            rendered=render(current,removed)
            if not rendered['result_rules']:raise LedgerError('empty_role_outside_pod_reader_verification_profile')
            profile=self.profile(current);pre_proof=self.verifier.check(profile,current,'pre')
            if not passed(pre_proof):raise LedgerError('prechange_functional_check_failed_or_inconclusive')
            pre_access=self._access(current,rule_dicts(current.target),pre=True)
            if pre_access['unknown'] or pre_access['failed']:raise LedgerError('prechange_access_check_failed_or_inconclusive')
            candidate=canonical_hash({'target_uid':current.target.uid,'namespace':current.target.namespace,
                'strategy':'narrow_dedicated_role','rules':rendered['result_rules']})
            if self._failure(current,candidate):raise LedgerError('candidate_previously_failed_in_this_context')
            self._dry_run(current.target,rendered['result_rules'],row['preparation_id'])
            gates=gates+[Gate(gate_id=name,result='pass',reasons=[]) for name in (
                'backend_prechange_access','backend_functional_profile','backend_forced_dry_run','backend_candidate_failure_history')]
        else:
            class AdoptionChecks:
                def check_adoption(self,e):return [{'gate_id':'backend_snapshot','result':'pass','reasons':[]}]
            gates=adoption_gates(current,AdoptionChecks(),self.db.now())
            if any(g.result!='pass' for g in gates):raise LedgerError('independent_adoption_readiness_failed')
            rendered=render(current,set());rendered.update(patch=[],diff='')
            removed=set();candidate=canonical_hash({'action':'adopt_baseline','target':current.target.model_dump(mode='json')})
        self._retain(current,'execution-'+source['case_id'])
        profile_hash=self.verifier.profile_hash(profile) if profile else None
        recovery={'mode':self.policy.recovery_mode,'original_rules_hash':canonical_hash([r.model_dump(mode='json') for r in current.target.rules]),
            'original_rules':[r.model_dump(mode='json') for r in current.target.rules],
            'window_seconds':self.policy.recovery_seconds,'logical_action_limit':1,
            'triggers':['repeatable_required_access_failure','repeatable_functional_failure'],
            'exclusions':['unknown_apply','timeout','unhealthy_runner','unhealthy_dependency','changed_context','pause','incident','revocation'],
            'restored_security_findings':risk_findings(current)} if body.action=='remediate' else None
        with self.db.transaction() as db:
            # All prepared sidecar, candidate baseline and review rows commit together.
            claim=db.execute('SELECT status,lease_until FROM execution_preparations WHERE preparation_id=?',(row['preparation_id'],)).fetchone()
            if (claim is None or claim['status']!='RUNNING' or claim['lease_until']!=row['lease_until']
                    or self.db.now()>=datetime.fromisoformat(row['lease_until'])):
                raise LedgerError('preparation_lease_lost')
            latest=self.analysis.row(db,body.source_run_id)
            if db.execute('SELECT latest_run_id FROM analysis_cases WHERE case_id=?',(latest['case_id'],)).fetchone()[0]!=body.source_run_id:
                raise LedgerError('source_analysis_superseded')
            self._holds(db,current.target.cluster_id,current.target.namespace)
            previous=db.execute('SELECT MAX(revision) FROM reviews WHERE case_id=?',('execution-'+source['case_id'],)).fetchone()[0]
            revision=(previous or 0)+1;now=self.db.now();identifier='proposal-'+row['preparation_id']
            baseline=self.baseline(current.target)
            contract={'source_run_id':body.source_run_id,'source_report_hash':source['report_hash'],
                'evidence':current.model_dump(mode='json'),'context_key':context_key(current),
                'expected_baseline_id':baseline['baseline_id'] if baseline else None,
                'policy_hash':canonical_hash(self.policy.model_dump(mode='json')),'profile':profile.model_dump(mode='json') if profile else None,
                'profile_hash':profile_hash,'pre_functional':pre_proof,'pre_access':pre_access,'recovery':recovery,
                'recovery_hash':canonical_hash(recovery) if recovery else None,
                'uncertainty':['Finite observations and sampled behavior do not establish every future need.',
                    'Audit delivery lag can hide very recent use.','Role conditions do not freeze bindings or workload edits.']}
            approval=canonical_hash({'candidate':candidate,'contract':contract,'rendered':rendered,'versions':source['report']['versions']})
            proposal=Proposal(proposal_id=identifier,case_id='execution-'+source['case_id'],run_id='review-'+row['preparation_id'],
                revision=revision,action=body.action,simulation=False,status='PENDING_APPROVAL',target=current.target,
                unchanged_binding=current.binding,evidence_hash=canonical_hash(current.model_dump(mode='json')),candidate_hash=candidate,
                approval_hash=approval,policy_version=current.policy.policy_version,removed_permission_ids=sorted(removed),
                gates=gates,uncertainty=contract['uncertainty'],published_at=now,review_expires_at=now+timedelta(seconds=self.db.review_seconds),
                execution_window_seconds=self.db.execution_seconds,verification_profile_id=profile.profile_id if profile else None,**rendered)
            contract['proposal']=proposal.model_dump(mode='json')
            readiness=ReadinessAssessment(policy_version=current.policy.policy_version,evidence_revision=current.revision,
                gates=gates,allowed_removal_ids=sorted(removed),protected_permission_ids=[f['permission_id'] for f in facts if f['protected']],
                residual_uncertainties=contract['uncertainty'],execution_ready=True).model_dump(mode='json') if body.action=='remediate' else None
            report=AnalysisReport.model_validate({**source['report'],'case_id':proposal.case_id,'run_id':proposal.run_id,
                'mode':'governed','status':'PENDING_REVIEW','reason':None,'execution_outcome':None,'readiness':readiness,
                'trace':source['report']['trace']+[{'node':'backend_independent_readiness','source_run_id':body.source_run_id}]})
            db.execute('INSERT INTO execution_plans VALUES (?,?,?,?)',(identifier,body.source_run_id,encode(contract),canonical_hash(contract)))
            self.db.publish_review(ReviewPublication(proposal=proposal,report=report),self.service,_connection=db)
            baseline_id='baseline-'+identifier
            db.execute('INSERT INTO execution_baselines VALUES (?,?,?,?,?)',(baseline_id,scope_key(current.target),current.target.uid,identifier,
                encode({'target':current.target.model_dump(mode='json'),'rules':rendered['result_rules'],'action':body.action})))
            db.execute("INSERT INTO execution_baseline_state VALUES (?,?,'PENDING_APPROVAL')",(baseline_id,scope_key(current.target)))
            db.execute("UPDATE execution_preparations SET status='DONE',proposal_id=?,error=NULL WHERE preparation_id=?",(identifier,row['preparation_id']))

    def _validate_plan_now(self,plan,p,*,prechange=True):
        with self.db._connect() as db:self._control(db,plan,p)
        if canonical_hash(self.policy.model_dump(mode='json'))!=plan['policy_hash']:raise LedgerError('execution_policy_changed')
        old=EvidenceBundle.model_validate(plan['evidence'])
        current=self._fresh(old)
        self._retain(current,p.case_id)
        if p.action=='remediate':
            facts,gates=build_facts(current,self.db.now())
            if any(g.gate_id=='source_freshness' and 'stale_source' in g.reasons for g in gates):
                raise LedgerError('audit_source_too_old_for_execution')
            if any(g.result!='pass' for g in gates) or not set(p.removed_permission_ids)<={f['permission_id'] for f in facts if f['eligible']}:
                raise LedgerError('new_use_or_evidence_readiness_changed')
            profile=self.profile(current)
            if self.verifier.profile_hash(profile)!=plan['profile_hash']:raise LedgerError('verification_profile_changed')
            if self._failure(current,p.candidate_hash):raise LedgerError('candidate_previously_failed_in_this_context')
            proof=self.verifier.check(profile,current,'pre')
            if not passed(proof):raise LedgerError('current_functional_check_not_passing')
            access=self._access(current,rule_dicts(current.target),pre=True)
            if access['unknown'] or access['failed']:raise LedgerError('current_access_check_not_passing')
            rendered=render(current,set(p.removed_permission_ids))
            if rendered['patch']!=p.patch or rendered['result_rules']!=[r.model_dump(exclude_defaults=True) for r in p.result_rules]:
                raise LedgerError('stored_candidate_semantics_changed')
            self._dry_run(p.target,rendered['result_rules'],p.proposal_id)
        else:
            required={'supported_target','consumer_inventory','context_integrity','source_and_failure_status'}
            if any(g.result!='pass' for g in global_gates(current,self.db.now()) if g.gate_id in required):
                raise LedgerError('current_adoption_preconditions_failed')
            if not current.context or not 0<=(self.db.now()-current.context.collected_at).total_seconds()<=current.policy.maximum_source_lag_seconds:
                raise LedgerError('current_adoption_snapshot_stale')
        return current

    def prepare_decision(self,proposal_id,request,principal):
        plan=self.plan(proposal_id);p=Proposal.model_validate(plan['proposal'])
        self._require_enabled(p.target.cluster_id,p.target.namespace)
        self._credential(principal.actor,principal.credential_id,p)
        with self.db.transaction() as db:
            row=self.db.expire(db,self.db.review_row(db,proposal_id),self.db.now())
            closed=row['status']!='OPEN'
        if closed:raise LedgerError('review_expired_or_not_open')
        expected='approve_remediation' if p.action=='remediate' else 'adopt_baseline'
        if request.kind!=expected or (request.expected_revision,request.expected_approval_hash)!=(p.revision,p.approval_hash):
            raise LedgerError('review_action_revision_or_hash_changed')
        if not request.accept_residual_risk:raise LedgerError('explicit_residual_risk_acceptance_required',422)
        if request.opt_in_recovery and (self.policy.recovery_mode!='optional_advance_exact' or request.expected_recovery_hash!=plan['recovery_hash']):
            raise LedgerError('exact_recovery_contract_not_available')
        self._validate_plan_now(plan,p)
        return {'proposal_id':proposal_id,'plan_hash':canonical_hash(plan),'checked_at':self.db.now().isoformat()}

    def check_ticket(self,db,proposal_id,request,principal,ticket):
        plan=self.plan(proposal_id,db);p=Proposal.model_validate(plan['proposal'])
        if (not ticket or ticket['proposal_id']!=proposal_id or ticket['plan_hash']!=canonical_hash(plan)
                or not 0<=(self.db.now()-datetime.fromisoformat(ticket['checked_at'])).total_seconds()<10):
            raise LedgerError('fresh_backend_preflight_required')
        self._credential(principal.actor,principal.credential_id,p);self._control(db,plan,p)

    def commit_authority(self,db,proposal_id,decision_id,request,principal,now):
        plan=self.plan(proposal_id,db)
        recovery_id='recovery-'+uuid4().hex if request.opt_in_recovery else None
        recovery={'recovery_id':recovery_id,'contract_hash':plan['recovery_hash'],
            'expires_at':(now+timedelta(seconds=self.policy.recovery_seconds)).isoformat()} if recovery_id else None
        db.execute('INSERT INTO execution_authorities VALUES (?,?,?,?,?,?)',
            (decision_id,proposal_id,principal.actor,principal.credential_id,recovery_id,encode(recovery)))
        return recovery_id

    def _decision(self,db,decision_id):
        row=db.execute('SELECT payload FROM decisions WHERE decision_id=?',(decision_id,)).fetchone()
        if row is None:raise LedgerError('decision_not_found',404)
        return GovernedDecision.model_validate_json(row[0])

    def _authority(self,db,decision,p,*,recovery=False):
        row=db.execute('SELECT * FROM execution_authorities WHERE decision_id=?',(decision.decision_id,)).fetchone()
        if row is None:raise LedgerError('backend_authority_not_found')
        kind='recovery' if recovery else 'forward'
        if db.execute("SELECT 1 FROM execution_revocations WHERE decision_id=? AND kind IN (?, 'all')",(decision.decision_id,kind)).fetchone():
            raise LedgerError('action_authority_revoked')
        self._credential(row['actor'],row['credential_id'],p)
        if not recovery and self.db.now()>=decision.execution_expires_at:raise LedgerError('execution_start_deadline_expired')
        return row

    @contextmanager
    def worker_lock(self):
        # One local persistent-disk executor. A stale process holding this OS lock
        # cannot race a replacement worker into a second request after lease loss.
        path=str(self.db.path)+'.execution.lock'
        fd=os.open(path,os.O_CREAT|os.O_RDWR,0o600)
        try:
            try:fcntl.flock(fd,fcntl.LOCK_EX|fcntl.LOCK_NB)
            except BlockingIOError:
                yield False;return
            yield True
        finally:os.close(fd)

    def latest_receipt(self,key,db=None):
        if db is None:
            with self.db._connect() as connection:return self.latest_receipt(key,connection)
        row=db.execute('SELECT payload FROM execution_receipts WHERE action_key=? ORDER BY sequence DESC LIMIT 1',(key,)).fetchone()
        return ExecutionReceipt.model_validate_json(row[0]) if row else None

    def _record(self,key,plan,decision,phase,*,apply='not_started',verification='pending',recovery='not_requested',
                post_version=None,recovery_id=None,restored_version=None,checks=(),failure_class=None,stop_reason=None):
        p=Proposal.model_validate(plan['proposal'])
        if p.action=='adopt_baseline':verification='not_required'
        with self.db.transaction() as db:
            previous=self.latest_receipt(key,db);sequence=previous.sequence+1 if previous else 1
            notification='notice-'+uuid4().hex if phase in TERMINAL else None
            receipt=ExecutionReceipt(receipt_id='receipt-'+uuid4().hex,sequence=sequence,action_key=key,
                proposal_id=p.proposal_id,decision_id=decision.decision_id,action=p.action,cluster_id=p.target.cluster_id,
                target_uid=p.target.uid,approval_hash=p.approval_hash,candidate_hash=p.candidate_hash,phase=phase,
                apply_status=apply,verification_status=verification,recovery_status=recovery,baseline_activated=phase=='completed',
                post_resource_version=post_version,recovery_authority_id=recovery_id,
                restored_rules_hash=plan['recovery']['original_rules_hash'] if restored_version else None,
                restored_resource_version=restored_version,check_refs=list(checks)[:64],notification_intent_id=notification,recorded_at=self.db.now())
            if phase=='completed':
                current=db.execute("SELECT baseline_id FROM execution_baseline_state WHERE scope_key=? AND status='ACTIVE'",(scope_key(p.target),)).fetchone()
                if (current[0] if current else None)!=plan['expected_baseline_id']:raise LedgerError('baseline_changed_before_activation')
                db.execute("UPDATE execution_baseline_state SET status='SUPERSEDED' WHERE scope_key=? AND status='ACTIVE'",(scope_key(p.target),))
                db.execute("UPDATE execution_baseline_state SET status='ACTIVE' WHERE baseline_id=?",('baseline-'+p.proposal_id,))
            db.execute('INSERT INTO execution_receipts VALUES (?,?,?,?)',(receipt.receipt_id,key,sequence,receipt.model_dump_json()))
            db.execute('UPDATE execution_actions SET state=? WHERE action_key=?',(phase,key))
            if phase in ('manual','rolled_back') and verification in ('failed','inconclusive'):
                e=EvidenceBundle.model_validate(plan['evidence'])
                failure={'receipt_id':receipt.receipt_id,'action_key':key,'failure_class':failure_class or 'inconclusive',
                    'blocks_candidate':verification=='failed' and failure_class in ('suspected_policy_regression','confirmed_policy_regression'),
                    'recovery_status':recovery,'checks':list(checks)}
                db.execute('INSERT INTO execution_failures VALUES (?,?,?,?,?,?,?,?)',('failure-'+uuid4().hex,p.target.cluster_id,
                    p.target.uid,p.candidate_hash,e.context.workload_uid,e.context.image_digest,p.policy_version,encode(failure)))
            if notification:
                message={'completed':'The approved Role change or baseline adoption completed and its required checks passed.',
                    'rolled_back':'Verification failed after the approved Role change. Captured pre-change rules were restored under your recovery authorization, and restoration checks passed.',
                    'manual':'Recovery or application could not be confirmed; manual intervention required.',
                    'stale':'The approved action was not applied because current preconditions or authority changed.',
                    'failed':'The approved action failed before a confirmed change.'}[phase]
                if stop_reason:message+=' Reason: '+stop_reason+'.'
                db.execute('INSERT INTO execution_notifications VALUES (?,?,?,?,?,?)',(notification,key,decision.actor,
                    p.target.cluster_id,p.target.namespace,encode({'message':message,'receipt_id':receipt.receipt_id,'phase':phase,
                        'failure_class':failure_class,'delivered':False})))
            self.db.event(db,p.proposal_id,'execution_'+phase,'guardian-execution-backend',self.db.now(),
                receipt_id=receipt.receipt_id,**({'reason_code':stop_reason} if stop_reason else {}))
            self.analysis.event(db,plan['source_run_id'],'execution_outcome_recorded','guardian-execution-backend',
                receipt_id=receipt.receipt_id,action_key=key,phase=phase)
        return receipt

    def _relationships(self,plan,p,version,rules):
        original=EvidenceBundle.model_validate(plan['evidence'])
        # Capture current consumers/context but compare expected post-change rules.
        expected=original.model_copy(update={'target':original.target.model_copy(update={'rules':rules,'resource_version':version})})
        current=self._fresh(expected)
        self._retain(current,p.case_id)
        return current

    def _verify(self,plan,p,post_version,*,restored=False):
        e=EvidenceBundle.model_validate(plan['evidence']);profile=self.profile(e)
        original=rule_dicts(e.target)
        removed=operations(original)-operations([r.model_dump(exclude_defaults=True) for r in p.result_rules])
        checks=[];outcomes=[];start=self.db.now()
        def finished(result):
            payload={**result,'kind':'application_verification','phase':'restored' if restored else 'post',
                'target_uid':p.target.uid,'expected_resource_version':post_version,
                'started_at':start.isoformat(),'completed_at':self.db.now().isoformat(),
                'actual_observation_seconds':(self.db.now()-start).total_seconds(),
                'planned_observation_seconds':profile.observation_seconds}
            identifier='verification-'+canonical_hash(payload).split(':')[1]
            with self.db.transaction() as db:
                db.execute('INSERT OR IGNORE INTO functional_checks VALUES (?,?,?)',(identifier,encode(payload),self.db.now().isoformat()))
            return {**result,'checks':result['checks']+[identifier]}
        for attempt in range(profile.propagation_attempts):
            try:
                current=self._relationships(plan,p,post_version,e.target.rules if restored else p.result_rules)
                checks.append(current.snapshot_id)
                access=self._access(e,original,removed,pre=restored)
                functional=self.verifier.check(profile,e,'restored' if restored else 'post')
                checks.extend([access['check_id'],functional['check_id']])
                failed=set(access['required_failed'])|{'functional:'+k for k,v in functional['checks'].items() if v=='fail'}
                unknown=access['unknown'] or not healthy(functional) or 'unknown' in functional['checks'].values()
                ok=not unknown and not access['failed'] and passed(functional)
                outcomes.append({'ok':ok,'unknown':unknown,'failure_triggers':failed,
                    'infrastructure_failure':not healthy(functional),
                    'unexpected_access':bool(set(access['failed'])-set(access['required_failed']))})
            except Exception:outcomes.append({'ok':False,'unknown':True,'failure_triggers':set(),'unexpected_access':False,'infrastructure_failure':False})
            if attempt+1<profile.propagation_attempts:self.sleep(1)
        if all(o['ok'] for o in outcomes):
            remaining=profile.observation_seconds-(self.db.now()-start).total_seconds()
            if remaining>0:self.sleep(remaining)
            try:
                current=self._relationships(plan,p,post_version,e.target.rules if restored else p.result_rules)
                checks.append(current.snapshot_id)
                proof=self.verifier.check(profile,e,'restored' if restored else 'post');checks.append(proof['check_id'])
                if passed(proof):return finished({'status':'passed','trigger':False,'checks':checks,'observed_seconds':(self.db.now()-start).total_seconds()})
            except Exception:pass
            return finished({'status':'inconclusive','trigger':False,'checks':checks,'classification':'inconclusive'})
        certain=all(not o['unknown'] for o in outcomes)
        trigger=certain and bool(set.intersection(*(o['failure_triggers'] for o in outcomes))) and not any(o['unexpected_access'] for o in outcomes)
        return finished({'status':'failed' if certain else 'inconclusive','trigger':trigger,'checks':checks,
            'classification':'suspected_policy_regression' if trigger else 'infrastructure_failure' if any(o['infrastructure_failure'] for o in outcomes) else 'inconclusive'})

    def execute(self,proposal_id,decision_id):
        plan=self.plan(proposal_id);p=Proposal.model_validate(plan['proposal'])
        with self.worker_lock() as locked:
            if not locked:return None
            with self.db.transaction() as db:
                decision=self._decision(db,decision_id);key=action_key(p,decision_id)
                if decision.proposal_id!=proposal_id or decision.approval_hash!=p.approval_hash or decision.kind!=('approve_remediation' if p.action=='remediate' else 'adopt_baseline'):
                    raise LedgerError('exact_positive_decision_required')
                old=db.execute('SELECT * FROM execution_actions WHERE action_key=?',(key,)).fetchone()
                if old:existing=dict(old)
                else:existing=None
                if existing is None:
                    other=db.execute("SELECT 1 FROM execution_actions WHERE scope_key=? AND state NOT IN ('completed','rolled_back','manual','stale','failed')",(scope_key(p.target),)).fetchone()
                    if other:raise LedgerError('target_action_in_progress')
                    self._authority(db,decision,p);self._control(db,plan,p)
                    db.execute("INSERT INTO execution_actions(action_key,proposal_id,decision_id,scope_key,state,dispatch_id) VALUES (?,?,?,?,'requested',?)",
                        (key,proposal_id,decision_id,scope_key(p.target),uuid4().hex))
            if existing is not None:return self._reconcile_locked(existing,plan,decision)
            self._record(key,plan,decision,'requested')
            try:
                current=self._validate_plan_now(plan,p)
                with self.db._connect() as db:self._authority(db,decision,p);self._control(db,plan,p)
                # Last direct Role read precedes the conditional call; relationship
                # checks are sampled, not a global Kubernetes transaction.
                live=self.driver.read(p.target.namespace,p.target.name)
                if (live['metadata']['uid'],live['metadata']['resourceVersion'],live.get('rules',[]))!=(
                        p.target.uid,p.target.resource_version,rule_dicts(p.target)):
                    raise LedgerError('role_changed_before_dispatch')
            except Exception as error:
                return self._record(key,plan,decision,'stale',stop_reason=error.code if isinstance(error,LedgerError)
                    else 'execution_precondition_check_unavailable')
            if p.action=='adopt_baseline':
                return self._record(key,plan,decision,'completed',verification='not_required',checks=[current.snapshot_id])
            self._record(key,plan,decision,'applying')
            with self.db._connect() as db:
                intent=dict(db.execute('SELECT * FROM execution_actions WHERE action_key=?',(key,)).fetchone())
            try:
                with self.db._connect() as db:self._authority(db,decision,p);self._control(db,plan,p)
            except Exception as error:return self._record(key,plan,decision,'stale',
                stop_reason=error.code if isinstance(error,LedgerError) else 'execution_authority_check_unavailable')
            try:
                response=self.driver.apply(p.target.namespace,p.target.name,p.target.uid,p.target.resource_version,
                    [r.model_dump(exclude_defaults=True) for r in p.result_rules],intent['dispatch_id'])
                if (response['metadata']['uid']!=p.target.uid or not response['metadata'].get('resourceVersion')
                        or response.get('rules',[])!=[r.model_dump(exclude_defaults=True) for r in p.result_rules]):
                    raise ValueError('unconfirmed_conditional_response')
            except Exception as error:
                if getattr(error,'status',None) in (400,403,404,409,422):return self._record(key,plan,decision,'stale',
                    stop_reason='conditional_role_request_rejected_'+str(error.status))
                ref=self.reconcile_observation(key,plan)
                return self._record(key,plan,decision,'manual',apply='unknown',verification='inconclusive',checks=[ref],failure_class='inconclusive')
            # Persist the acknowledged response before verification; crash recovery
            # can resume without repeating the forward API request.
            with self.db.transaction() as db:
                db.execute('UPDATE execution_actions SET confirmed=? WHERE action_key=?',(encode(response),key))
            return self._verify_forward(key,plan,decision,response)

    def _reconcile_locked(self,action,plan,decision):
        # Called while the process-level actuator lock is held. No blind retry.
        previous=self.latest_receipt(action['action_key'])
        if previous and previous.phase in TERMINAL and action['state'] in TERMINAL:return previous
        if action['confirmed']:
            if action['recovery_started']:
                if action['recovery_confirmed']:
                    restored=json.loads(action['recovery_confirmed']);p=Proposal.model_validate(plan['proposal'])
                    result=self._verify(plan,p,restored['metadata']['resourceVersion'],restored=True)
                    if result['status']=='passed':
                        consent=json.loads(action['recovery_authority'])
                        return self._record(action['action_key'],plan,decision,'rolled_back',apply='confirmed',verification='failed',
                            recovery='verified',post_version=json.loads(action['confirmed'])['metadata']['resourceVersion'],
                            recovery_id=consent['recovery_id'],restored_version=restored['metadata']['resourceVersion'],
                            checks=result['checks'],failure_class='suspected_policy_regression')
                return self._record(action['action_key'],plan,decision,'manual',apply='confirmed',verification='failed',
                    recovery='inconclusive',post_version=json.loads(action['confirmed'])['metadata']['resourceVersion'],failure_class='inconclusive')
            return self._verify_forward(action['action_key'],plan,decision,json.loads(action['confirmed']))
        ref=self.reconcile_observation(action['action_key'],plan)
        return self._record(action['action_key'],plan,decision,'manual',apply='unknown' if action['state']=='applying' else 'not_started',
            verification='inconclusive',checks=[ref],failure_class='inconclusive')

    def _verify_forward(self,key,plan,decision,response):
        p=Proposal.model_validate(plan['proposal']);version=response['metadata']['resourceVersion']
        self._record(key,plan,decision,'verifying',apply='confirmed',post_version=version)
        result=self._verify(plan,p,version)
        if result['status']=='passed':
            return self._record(key,plan,decision,'completed',apply='confirmed',verification='passed',post_version=version,checks=result['checks'])
        if result['trigger']:
            try:return self._recover(key,plan,decision,response,result)
            except Exception:pass
        return self._record(key,plan,decision,'manual',apply='confirmed',verification=result['status'],recovery='blocked' if result['trigger'] else 'not_requested',
            post_version=version,checks=result['checks'],failure_class=result.get('classification','inconclusive'))

    def _recover(self,key,plan,decision,response,result,*,fresh=None):
        p=Proposal.model_validate(plan['proposal']);e=EvidenceBundle.model_validate(plan['evidence']);version=response['metadata']['resourceVersion']
        if canonical_hash(self.policy.model_dump(mode='json'))!=plan['policy_hash']:raise LedgerError('recovery_policy_changed')
        if not fresh and self.policy.recovery_mode!='optional_advance_exact':raise LedgerError('fresh_human_recovery_required')
        with self.db._connect() as db:
            self._control(db,plan,p,require_source=False)
            if fresh:
                self._fresh_authority(db,fresh,decision,p);consent=fresh
            else:
                authority=self._authority(db,decision,p,recovery=True);consent=json.loads(authority['payload'])
            if not consent or self.db.now()>=datetime.fromisoformat(consent['expires_at']):raise LedgerError('exact_recovery_authority_missing_or_expired')
            if consent['contract_hash']!=plan['recovery_hash']:raise LedgerError('recovery_contract_changed')
            self._holds(db,p.target.cluster_id,p.target.namespace)
        current=self._relationships(plan,p,version,p.result_rules)
        if self.verifier.profile_hash(self.profile(current))!=plan['profile_hash']:raise LedgerError('recovery_profile_changed')
        rules=rule_dicts(e.target)
        self._dry_run(p.target,rules,'recover-'+key.split(':')[-1],version=version)
        with self.db.transaction() as db:
            if fresh:self._fresh_authority(db,fresh,decision,p)
            else:self._authority(db,decision,p,recovery=True)
            self._control(db,plan,p,require_source=False)
            if self.db.now()>=datetime.fromisoformat(consent['expires_at']):raise LedgerError('recovery_deadline_expired')
            updated=db.execute("UPDATE execution_actions SET state='verifying',recovery_started=1,recovery_authority=? WHERE action_key=? AND recovery_started=0",
                (encode(consent),key)).rowcount
            if not updated:raise LedgerError('recovery_action_budget_exhausted')
        self._record(key,plan,decision,'verifying',apply='confirmed',verification='failed',recovery='pending',
            post_version=version,recovery_id=consent['recovery_id'],checks=result['checks'])
        try:
            restored=self.driver.apply(p.target.namespace,p.target.name,p.target.uid,version,rules,'recover-'+key.split(':')[-1])
            if restored['metadata']['uid']!=p.target.uid or restored.get('rules',[])!=rules or restored['metadata']['resourceVersion']==version:
                raise ValueError('restoration_response_unconfirmed')
        except Exception:
            return self._record(key,plan,decision,'manual',apply='confirmed',verification='failed',recovery='inconclusive',
                post_version=version,recovery_id=consent['recovery_id'],checks=result['checks'],failure_class=result.get('classification','suspected_policy_regression'))
        with self.db.transaction() as db:db.execute('UPDATE execution_actions SET recovery_confirmed=? WHERE action_key=?',(encode(restored),key))
        verification=self._verify(plan,p,restored['metadata']['resourceVersion'],restored=True)
        if verification['status']=='passed':
            return self._record(key,plan,decision,'rolled_back',apply='confirmed',verification='failed',recovery='verified',post_version=version,
                recovery_id=consent['recovery_id'],restored_version=restored['metadata']['resourceVersion'],checks=result['checks']+verification['checks'],
                failure_class='suspected_policy_regression')
        return self._record(key,plan,decision,'manual',apply='confirmed',verification='failed',recovery='inconclusive',post_version=version,
            recovery_id=consent['recovery_id'],checks=result['checks']+verification['checks'],failure_class=result.get('classification','suspected_policy_regression'))

    def _fresh_authority(self,db,consent,decision,p):
        self._credential(consent['actor'],consent['credential_id'],p)
        if db.execute("SELECT 1 FROM execution_revocations WHERE decision_id=? AND kind IN ('recovery','all') AND sequence>?",
                (decision.decision_id,consent['revocation_sequence'])).fetchone():
            raise LedgerError('fresh_recovery_authority_revoked')

    def execute_next(self):
        """Durable governed outbox consumer, independent of LangGraph/model uptime."""
        with self.db.transaction() as db:
            now=self.db.now();row=db.execute('''SELECT o.* FROM outbox o JOIN execution_plans p USING(proposal_id)
                WHERE o.status='PENDING' OR (o.status='CLAIMED' AND o.lease_expires_at<=?) ORDER BY o.rowid LIMIT 1''',(now.isoformat(),)).fetchone()
            if row is None:return False
            token=uuid4().hex
            db.execute("UPDATE outbox SET status='CLAIMED',owner=?,lease_token=?,lease_expires_at=?,attempts=attempts+1 WHERE delivery_id=?",
                (self.service.actor,token,(now+timedelta(minutes=10)).isoformat(),row['delivery_id']))
            work=json.loads(row['payload']);decision=self._decision(db,work['decision_id'])
        try:
            if decision.kind in ('approve_remediation','adopt_baseline'):
                receipt=self.execute(row['proposal_id'],decision.decision_id)
                if receipt is None:return False
            elif decision.kind=='request_context':
                self._queue_context(row['proposal_id'],decision)
            elif decision.kind=='reject':
                with self.db.transaction() as db:db.execute("UPDATE execution_baseline_state SET status='REJECTED' WHERE baseline_id=? AND status='PENDING_APPROVAL'",('baseline-'+row['proposal_id'],))
        except LedgerError as error:
            # Invalid/expired authority has no write. Preserve a durable terminal
            # receipt even when rejected before the first action was claimed.
            if decision.kind not in ('approve_remediation','adopt_baseline'):raise
            plan=self.plan(row['proposal_id']);p=Proposal.model_validate(plan['proposal']);key=action_key(p,decision.decision_id)
            with self.db.transaction() as db:
                db.execute("INSERT OR IGNORE INTO execution_actions(action_key,proposal_id,decision_id,scope_key,state,dispatch_id) VALUES (?,?,?,?,'requested',?)",
                    (key,p.proposal_id,decision.decision_id,scope_key(p.target),uuid4().hex))
            with self.db._connect() as db:
                action=db.execute('SELECT * FROM execution_actions WHERE action_key=?',(key,)).fetchone()
            if action['confirmed']:
                self._record(key,plan,decision,'manual',apply='confirmed',verification='inconclusive',
                    post_version=json.loads(action['confirmed'])['metadata']['resourceVersion'],failure_class='inconclusive')
            elif action['state']=='applying':
                ref=self.reconcile_observation(key,plan)
                self._record(key,plan,decision,'manual',apply='unknown',verification='inconclusive',checks=[ref],failure_class='inconclusive')
            else:self._record(key,plan,decision,'stale',stop_reason=error.code)
        self.db.acknowledge_delivery(row['delivery_id'],token,self.service)
        return True

    def _queue_context(self,proposal_id,decision):
        from backend.app.models.analysis import AnalysisIntake
        plan=self.plan(proposal_id);idem='governed-context-'+decision.decision_id
        with self.db._connect() as db:
            # Replaying a delivery must not rebuild a different time window or
            # supersedes ID after the original enqueue committed.
            if db.execute('SELECT 1 FROM analysis_runs WHERE actor=? AND idempotency_key=?',(self.service.actor,idem)).fetchone():return
            source=self.analysis.row(db,plan['source_run_id'])
            latest=db.execute('SELECT latest_run_id FROM analysis_cases WHERE case_id=?',(source['case_id'],)).fetchone()[0]
            note=db.execute('SELECT note FROM decisions WHERE decision_id=?',(decision.decision_id,)).fetchone()[0]
        source=self.analysis.get(latest,self.service)
        window=source['intake']['window'];start=datetime.fromisoformat(window['start'].replace('Z','+00:00'));end=datetime.fromisoformat(window['end'].replace('Z','+00:00'))
        context=f'Human context decision {decision.decision_id} by {decision.actor}: {note}'
        if len(context)>2000:context=context[:1940]+' [full note preserved in the referenced decision]'
        now=self.db.now()
        self.analysis.enqueue(AnalysisIntake(cluster_id=source['cluster_id'],namespace=source['namespace'],role_name=source['role_name'],
            window={'start':now-(end-start),'end':now},idempotency_key=idem,
            supersedes_run_id=latest,context_note=context),self.service)

    def review_detail(self,proposal_id,principal):
        review=self.db.get_review(proposal_id,principal)
        backend_report=review.pop('report')
        plan=self.plan(proposal_id)
        with self.db._connect() as db:
            action=db.execute('SELECT * FROM execution_actions WHERE proposal_id=?',(proposal_id,)).fetchone()
            receipt=self.latest_receipt(action['action_key'],db) if action else None
            stopped=db.execute("SELECT details FROM events WHERE proposal_id=? AND kind IN ('execution_stale','execution_failed') ORDER BY sequence DESC LIMIT 1",(proposal_id,)).fetchone()
            outcome_reason=json.loads(stopped[0]).get('reason_code') if stopped else None
            row=db.execute('SELECT payload FROM decisions WHERE proposal_id=?',(proposal_id,)).fetchone()
            decision=json.loads(row[0]) if row else None
            if decision:
                decision['revoked']=bool(db.execute("SELECT 1 FROM execution_revocations WHERE decision_id=? AND kind IN ('forward','all')",
                    (decision['decision_id'],)).fetchone())
            authority=db.execute('SELECT payload FROM execution_authorities WHERE proposal_id=?',(proposal_id,)).fetchone()
            consent=json.loads(authority[0]) if authority else None
            checks=[json.loads(r[0]) for identifier in receipt.check_refs for r in db.execute('SELECT payload FROM functional_checks WHERE check_id=?',(identifier,))] if receipt else []
            try:self._control(db,plan,Proposal.model_validate(plan['proposal']));blockers=[]
            except LedgerError as error:blockers=[error.code]
        usage=plan['evidence'].get('usage')
        return {**review,'execution_available':review['execution_available'] and review['status']=='OPEN' and not blockers,
            'execution_blockers':review['execution_blockers']+blockers,'backend_readiness':backend_report.get('readiness'),
            'decision':decision,'advance_recovery_consent':consent,'verification_evidence':checks,'outcome_reason':outcome_reason,
            'usage_window':usage['query_window'] if usage else None,'usage_processed_through':usage['processed_through'] if usage else None,
            'source_report_hash':plan['source_report_hash'],'source_run_id':plan['source_run_id'],'verification_contract':{
            'profile':plan['profile'],'profile_hash':plan['profile_hash'],'pre_functional':plan['pre_functional'],
            'pre_access':plan['pre_access'],'observation_seconds':plan['profile']['observation_seconds'] if plan['profile'] else 0},
            'recovery_contract':plan['recovery'],'recovery_hash':plan['recovery_hash'],
            'expected_baseline_id':plan['expected_baseline_id'],'receipt':receipt.model_dump(mode='json') if receipt else None,
            'action_key':action['action_key'] if action else None,
            'fresh_recovery_hash':canonical_hash({'action_key':action['action_key'],'sequence':receipt.sequence,
                'contract':plan['recovery'],'confirmed':action['confirmed']}) if action and receipt and action['confirmed'] and not action['recovery_started'] else None}

    def list_reviews(self,cluster,namespace,principal):
        principal.require('read',cluster,namespace)
        with self.db._connect() as db:
            rows=db.execute('''SELECT r.proposal_id FROM reviews r JOIN execution_plans p USING(proposal_id)
                WHERE r.cluster_id=? AND r.namespace=? ORDER BY r.rowid DESC LIMIT 50''',(cluster,namespace)).fetchall()
        values=[]
        for row in rows:
            review=self.db.get_review(row[0],principal);plan=self.plan(row[0])
            values.append({k:review[k] for k in ('proposal_id','status','review_expires_at','execution_available')}|
                {'source_run_id':plan['source_run_id'],'action':review['proposal']['action'],
                 'role_name':review['proposal']['target']['name'],'revision':review['proposal']['revision']})
        return values


    def revoke(self,decision_id,body,principal):
        with self.db.transaction() as db:
            decision=self._decision(db,decision_id);plan=self.plan(decision.proposal_id,db);p=Proposal.model_validate(plan['proposal'])
            if principal.kind!='human':raise LedgerError('human_revocation_required',403)
            principal.require('review' if principal.actor==decision.actor else 'operate',p.target.cluster_id,p.target.namespace)
            db.execute('INSERT INTO execution_revocations(decision_id,kind,actor,reason,recorded_at) VALUES (?,?,?,?,?)',
                (decision_id,body.kind,principal.actor,body.reason,self.db.now().isoformat()))
            self.db.event(db,p.proposal_id,'authority_revoked',principal.actor,self.db.now(),decision_id=decision_id,kind=body.kind,reason=body.reason)
        return {'decision_id':decision_id,'kind':body.kind,'revoked':True}

    def notifications(self,cluster,namespace,principal):
        principal.require('read',cluster,namespace)
        with self.db._connect() as db:
            return [{**{k:r[k] for k in ('notification_id','action_key','actor','cluster_id','namespace')},
                **json.loads(r['payload']),'acknowledged':r['acknowledged'] is not None}
                for r in db.execute('''SELECT n.*,a.notification_id AS acknowledged FROM execution_notifications n
                LEFT JOIN execution_notification_ack a USING(notification_id) WHERE n.cluster_id=? AND n.namespace=? ORDER BY n.rowid DESC LIMIT 100''',(cluster,namespace))]

    def acknowledge_notification(self,identifier,principal):
        with self.db.transaction() as db:
            row=db.execute('SELECT * FROM execution_notifications WHERE notification_id=?',(identifier,)).fetchone()
            if row is None:raise LedgerError('notification_not_found',404)
            principal.require('review',row['cluster_id'],row['namespace'])
            if principal.kind!='human' or principal.actor!=row['actor']:raise LedgerError('notification_recipient_required',403)
            db.execute('INSERT OR IGNORE INTO execution_notification_ack VALUES (?,?,?)',(identifier,principal.actor,self.db.now().isoformat()))
        return {'notification_id':identifier,'acknowledged':True,'pause_changed':False}

    def baselines(self,cluster,namespace,principal):
        principal.require('read',cluster,namespace)
        with self.db._connect() as db:
            rows=db.execute('''SELECT b.*,s.status FROM execution_baselines b JOIN execution_baseline_state s USING(baseline_id)
                JOIN reviews r ON b.proposal_id=r.proposal_id WHERE r.cluster_id=? AND r.namespace=? ORDER BY b.rowid DESC LIMIT 100''',(cluster,namespace)).fetchall()
        return [{k:r[k] for k in ('baseline_id','scope_key','target_uid','proposal_id','status')}|{'snapshot':json.loads(r['payload'])} for r in rows]

    def fresh_recovery(self,key,body,principal):
        """Fresh human fallback, never a renewal of expired advance consent."""
        from backend.app.models.execution import FreshRecovery
        body=validate(FreshRecovery,body)
        with self.db._connect() as db:
            row=db.execute('SELECT * FROM execution_actions WHERE action_key=?',(key,)).fetchone()
            if row is None:raise LedgerError('action_not_found',404)
            action=dict(row);plan=self.plan(action['proposal_id'],db);p=Proposal.model_validate(plan['proposal'])
            principal.require('review',p.target.cluster_id,p.target.namespace)
            if principal.kind!='human':raise LedgerError('fresh_human_recovery_required',403)
            self._credential(principal.actor,principal.credential_id,p)
            request_hash=canonical_hash({'key':key,**body.model_dump(mode='json')})
            old=db.execute('SELECT * FROM execution_fresh_recovery WHERE actor=? AND idempotency_key=?',(principal.actor,body.idempotency_key)).fetchone()
            if old:
                if old['request_hash']!=request_hash:raise LedgerError('fresh_recovery_idempotency_conflict')
                return {'recovery_id':old['recovery_id'],'queued':True}
            receipt=self.latest_receipt(key,db)
            expected=canonical_hash({'action_key':key,'sequence':receipt.sequence,'contract':plan['recovery'],'confirmed':action['confirmed']}) if receipt else None
            if (not receipt or receipt.sequence!=body.expected_sequence or expected!=body.expected_recovery_hash or receipt.phase!='manual'
                    or receipt.verification_status!='failed' or not action['confirmed'] or action['recovery_started']):
                raise LedgerError('fresh_recovery_requires_current_confirmed_failed_action')
            self._control(db,plan,p,require_source=False)
        response=json.loads(action['confirmed'])
        self._relationships(plan,p,response['metadata']['resourceVersion'],p.result_rules)
        identifier='fresh-recovery-'+uuid4().hex
        consent={'recovery_id':identifier,'contract_hash':plan['recovery_hash'],
            'expires_at':(self.db.now()+timedelta(seconds=self.policy.recovery_seconds)).isoformat(),
            'actor':principal.actor,'credential_id':principal.credential_id}
        with self.db.transaction() as db:
            current=self.latest_receipt(key,db)
            if not current or current.sequence!=body.expected_sequence:raise LedgerError('recovery_receipt_changed')
            self._credential(principal.actor,principal.credential_id,p);self._control(db,plan,p,require_source=False)
            consent['authorized_at']=self.db.now().isoformat()
            consent['revocation_sequence']=db.execute('SELECT COALESCE(MAX(sequence),0) FROM execution_revocations WHERE decision_id=?',
                (action['decision_id'],)).fetchone()[0]
            db.execute('INSERT INTO execution_fresh_recovery VALUES (?,?,?,?,?,?,?)',
                (identifier,key,principal.actor,principal.credential_id,body.idempotency_key,request_hash,encode(consent)))
            if not db.execute("UPDATE execution_actions SET state='fresh_recovery_queued',recovery_authority=? WHERE action_key=? AND recovery_started=0",(encode(consent),key)).rowcount:
                raise LedgerError('recovery_action_budget_exhausted')
            self.db.event(db,p.proposal_id,'fresh_recovery_authorized',principal.actor,self.db.now(),recovery_id=identifier,note=body.note)
        return {'recovery_id':identifier,'queued':True}

    def recover_next(self):
        with self.worker_lock() as locked:
            if not locked:return False
            with self.db._connect() as db:
                row=db.execute("SELECT * FROM execution_actions WHERE state='fresh_recovery_queued' OR (state='verifying' AND recovery_started=1) ORDER BY rowid LIMIT 1").fetchone()
                if row is None:return False
                action=dict(row);plan=self.plan(action['proposal_id'],db);decision=self._decision(db,action['decision_id'])
            if action['recovery_started']:
                self._reconcile_locked(action,plan,decision)
                return True
            p=Proposal.model_validate(plan['proposal']);response=json.loads(action['confirmed'])
            # Fresh consent still cannot turn a timeout or dependency outage into
            # an automatic regression trigger; repeat the approved checks.
            result=self._verify(plan,p,response['metadata']['resourceVersion'])
            try:
                if not result['trigger']:raise LedgerError('current_recovery_trigger_unconfirmed')
                self._recover(action['action_key'],plan,decision,response,result,fresh=json.loads(action['recovery_authority']))
            except Exception:
                self._record(action['action_key'],plan,decision,'manual',apply='confirmed',verification=result['status'],
                    recovery='blocked',post_version=response['metadata']['resourceVersion'],checks=result['checks'],failure_class='inconclusive')
            return True

    def request_execution(self,body,principal):
        plan=self.plan(body.proposal_id);p=Proposal.model_validate(plan['proposal'])
        principal.require('execute',p.target.cluster_id,p.target.namespace)
        if principal.kind!='service':raise LedgerError('executor_service_identity_required',403)
        with self.db._connect() as db:
            decision=self._decision(db,body.decision_id)
            if (body.action_key,body.action)!=(action_key(p,body.decision_id),p.action) or decision.proposal_id!=p.proposal_id:
                raise LedgerError('execution_request_scope_changed')
            self._authority(db,decision,p);self._control(db,plan,p)
            delivery=db.execute('SELECT status FROM outbox WHERE proposal_id=?',(p.proposal_id,)).fetchone()
        return {'action_key':body.action_key,'queued':delivery is not None,'receipt':self.latest_receipt(body.action_key).model_dump(mode='json') if self.latest_receipt(body.action_key) else None}

    def reconcile_observation(self,key,plan):
        """Record evidence without treating matching rules as an acknowledged write."""
        p=Proposal.model_validate(plan['proposal']);observed=None
        try:
            live=self.driver.read(p.target.namespace,p.target.name)
            observed={'uid':live['metadata'].get('uid'),'resource_version':live['metadata'].get('resourceVersion'),
                'rules_hash':canonical_hash(live.get('rules',[]))}
        except Exception:pass
        with self.db.transaction() as db:
            action=db.execute('SELECT dispatch_id FROM execution_actions WHERE action_key=?',(key,)).fetchone()
            refs=[r[0] for r in db.execute('''SELECT raw_ref FROM audit_raw WHERE cluster_id=?
                AND json_extract(payload,'$.userAgent')=? AND json_extract(payload,'$.stage')='ResponseComplete'
                AND json_extract(payload,'$.objectRef.resource')='roles' AND json_extract(payload,'$.objectRef.namespace')=?
                AND json_extract(payload,'$.objectRef.name')=? LIMIT 32''',
                (p.target.cluster_id,'guardian-executor/'+action['dispatch_id'],p.target.namespace,p.target.name))] if action else []
            payload={'kind':'uncertain_apply_reconciliation','live_observation':observed,'correlated_audit_refs':refs,
                'confirmation':'unavailable_without_acknowledged_post_write_version'}
            identifier='reconcile-'+canonical_hash(payload).split(':')[1]
            db.execute('INSERT OR IGNORE INTO functional_checks VALUES (?,?,?)',(identifier,encode(payload),self.db.now().isoformat()))
        return identifier

    def preflight(self,body,principal):
        from agents.guardian.governance import PreflightResult,PREFLIGHT_CHECKS
        plan=self.plan(body.proposal_id);p=Proposal.model_validate(plan['proposal'])
        principal.require('execute',p.target.cluster_id,p.target.namespace)
        if principal.kind!='service':raise LedgerError('executor_service_identity_required',403)
        with self.db._connect() as db:
            decision=self._decision(db,body.decision_id)
            if ((body.action_key,body.action)!=(action_key(p,decision.decision_id),p.action)
                    or decision.proposal_id!=p.proposal_id or decision.approval_hash!=p.approval_hash):
                raise LedgerError('preflight_scope_changed')
            self._authority(db,decision,p);self._control(db,plan,p)
        self._validate_plan_now(plan,p)
        with self.db._connect() as db:self._authority(db,decision,p);self._control(db,plan,p)
        now=self.db.now()
        return PreflightResult(proposal_id=p.proposal_id,decision_id=decision.decision_id,action_key=body.action_key,
            approval_hash=p.approval_hash,evidence_hash=p.evidence_hash,candidate_hash=p.candidate_hash,
            target_uid=p.target.uid,resource_version=p.target.resource_version,checked_at=now,
            expires_at=min(now+timedelta(seconds=10),decision.execution_expires_at),checks={name:'pass' for name in PREFLIGHT_CHECKS}).model_dump(mode='json')

    def receipt(self,key,principal):
        with self.db._connect() as db:
            row=db.execute('SELECT proposal_id FROM execution_actions WHERE action_key=?',(key,)).fetchone()
            if row is None:raise LedgerError('action_not_found',404)
            plan=self.plan(row[0],db);p=Proposal.model_validate(plan['proposal'])
            principal.require('read',p.target.cluster_id,p.target.namespace)
            receipt=self.latest_receipt(key,db)
        return receipt.model_dump(mode='json') if receipt else None
