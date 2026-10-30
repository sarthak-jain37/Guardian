"""Durable preview analysis, immutable reports and independent nonwriting review.

The backend owns intake, evidence, identity, budgets and deadlines. The inference
worker receives normalized snapshots over the scoped API, without Kubernetes or
archive credentials. Phase 4 must supply a separate independently verified action
transaction; a preview/report decision here can never authorize a cluster write.
"""
import json
from datetime import timedelta, datetime
from uuid import uuid4

from agents.guardian.contracts import AnalysisRequest, EvidenceBundle
from agents.guardian.modeling import ModelConfig
from agents.guardian.evidence_tools import validate_lookup, validate_result
from agents.guardian.policy import build_facts
from backend.app.models.analysis import AnalysisIntake, JobComplete, ReportDecision, BudgetRequest
from backend.app.services.governance_store import LedgerError, digest, encode, validate


class AnalysisStore:
    def __init__(self, governance, inventory, *, model_config=None, archive=None, capacity=8):
        if type(capacity) is not int or not 1<=capacity<=64:raise ValueError('invalid_analysis_capacity')
        self.db, self.inventory, self.archive = governance, inventory, archive
        self.model_config = model_config or ModelConfig(profile='dev-laptop', provider='ollama',
            model_name='qwen3.5:4b', endpoint='http://127.0.0.1:11434')
        self.capacity = capacity
        with self.db._connect() as db:
            db.executescript('''
            CREATE TABLE IF NOT EXISTS analysis_cases (
              case_id TEXT PRIMARY KEY,cluster_id TEXT,namespace TEXT,role_name TEXT,latest_run_id TEXT);
            CREATE TABLE IF NOT EXISTS analysis_runs (
              run_id TEXT PRIMARY KEY,case_id TEXT REFERENCES analysis_cases(case_id),revision INTEGER,
              cluster_id TEXT,namespace TEXT,role_name TEXT,actor TEXT,idempotency_key TEXT,request_hash TEXT,
              intake TEXT,created_at TEXT,model_config TEXT,status TEXT,request TEXT,error TEXT,
              owner TEXT,lease_token TEXT,lease_until TEXT,attempts INTEGER DEFAULT 0,
              review_state TEXT,review_expires TEXT,retention_state TEXT,
              active_deadline TEXT,
              UNIQUE(actor,idempotency_key),UNIQUE(case_id,revision));
            CREATE TABLE IF NOT EXISTS analysis_results (
              run_id TEXT PRIMARY KEY REFERENCES analysis_runs(run_id),payload TEXT,report_hash TEXT,publisher TEXT);
            CREATE TABLE IF NOT EXISTS analysis_events (
              sequence INTEGER PRIMARY KEY AUTOINCREMENT,run_id TEXT,kind TEXT,actor TEXT,recorded_at TEXT,details TEXT);
            CREATE TABLE IF NOT EXISTS analysis_decisions (
              decision_id TEXT PRIMARY KEY,run_id TEXT UNIQUE,actor TEXT,idempotency_key TEXT,request_hash TEXT,payload TEXT,
              UNIQUE(actor,idempotency_key));
            CREATE TABLE IF NOT EXISTS analysis_model_calls (
              run_id TEXT,number INTEGER,stage TEXT,repair INTEGER,PRIMARY KEY(run_id,number));
            CREATE TABLE IF NOT EXISTS analysis_lookup_batches (
              batch_key TEXT PRIMARY KEY,run_id TEXT,payload TEXT);
            CREATE TABLE IF NOT EXISTS analysis_observations (case_id TEXT PRIMARY KEY,content_hash TEXT);
            CREATE INDEX IF NOT EXISTS analysis_queue ON analysis_runs(status,cluster_id,namespace);
            ''')
            if 'active_deadline' not in {r['name'] for r in db.execute('PRAGMA table_info(analysis_runs)')}:
                db.execute('ALTER TABLE analysis_runs ADD COLUMN active_deadline TEXT')
            for table in ('analysis_results','analysis_events','analysis_decisions','analysis_model_calls'):
                for action in ('UPDATE','DELETE'):
                    db.execute(f"CREATE TRIGGER IF NOT EXISTS {table}_no_{action.lower()} BEFORE {action} ON {table} "
                        "BEGIN SELECT RAISE(ABORT,'immutable_analysis_record'); END")

    def event(self, db, run_id, kind, actor, **details):
        db.execute('INSERT INTO analysis_events(run_id,kind,actor,recorded_at,details) VALUES (?,?,?,?,?)',
            (run_id,kind,actor,self.db.now().isoformat(),encode(details)))

    @staticmethod
    def row(db, run_id):
        row=db.execute('SELECT * FROM analysis_runs WHERE run_id=?',(run_id,)).fetchone()
        if row is None:raise LedgerError('analysis_run_not_found',404)
        return row

    @staticmethod
    def scope(principal,row,permission):
        principal.require(permission,row['cluster_id'],row['namespace'])

    def _insert(self,db,body,actor):
        now=self.db.now()
        if body.window.end>now or (body.window.end-body.window.start).total_seconds()>90*86400:
            raise LedgerError('analysis_window_requires_past_90_days_or_less',422)
        request_hash=digest(body.model_dump(mode='json'))
        old=db.execute('SELECT * FROM analysis_runs WHERE actor=? AND idempotency_key=?',(actor,body.idempotency_key)).fetchone()
        if old:
            if old['request_hash']!=request_hash:raise LedgerError('analysis_idempotency_conflict')
            return old['run_id']
        count=db.execute("SELECT count(*) FROM analysis_runs WHERE cluster_id=? AND namespace=? AND status IN ('PREPARING','CAPTURING','QUEUED','CLAIMED')",
            (body.cluster_id,body.namespace)).fetchone()[0]
        if count>=self.capacity:raise LedgerError('analysis_queue_full',503)
        case_id,revision='case-'+uuid4().hex,1
        if body.supersedes_run_id:
            previous=self.row(db,body.supersedes_run_id)
            if (previous['cluster_id'],previous['namespace'],previous['role_name'])!=(body.cluster_id,body.namespace,body.role_name):
                raise LedgerError('revision_scope_cannot_change')
            latest=db.execute('SELECT latest_run_id FROM analysis_cases WHERE case_id=?',(previous['case_id'],)).fetchone()[0]
            if latest!=previous['run_id']:raise LedgerError('revision_is_not_latest')
            if previous['status'] not in ('DONE','FAILED'):raise LedgerError('analysis_still_running')
            case_id,revision=previous['case_id'],previous['revision']+1
            db.execute("UPDATE analysis_runs SET review_state='SUPERSEDED' WHERE run_id=? AND review_state='OPEN'",(previous['run_id'],))
            self.event(db,previous['run_id'],'superseded',actor,successor_revision=revision)
        run_id='run-'+uuid4().hex
        db.execute('INSERT INTO analysis_cases VALUES (?,?,?,?,?) ON CONFLICT(case_id) DO UPDATE SET latest_run_id=excluded.latest_run_id',
            (case_id,body.cluster_id,body.namespace,body.role_name,run_id))
        db.execute('''INSERT INTO analysis_runs(run_id,case_id,revision,cluster_id,namespace,role_name,actor,idempotency_key,
            request_hash,intake,created_at,model_config,status) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,'PREPARING')''',
            (run_id,case_id,revision,body.cluster_id,body.namespace,body.role_name,actor,body.idempotency_key,
             request_hash,body.model_dump_json(),now.isoformat(),self.model_config.model_dump_json()))
        self.event(db,run_id,'intake_accepted',actor,trigger=body.trigger,source_run_id=body.supersedes_run_id)
        return run_id

    def enqueue(self,body,principal):
        body=validate(AnalysisIntake,body)
        principal.require('review' if principal.kind=='human' else 'publish',body.cluster_id,body.namespace)
        principal.require('read',body.cluster_id,body.namespace)
        with self.db.transaction() as db:run_id=self._insert(db,body,principal.actor)
        return self.get(run_id,principal)

    def fresh_window(self,cluster,namespace,duration,*,connection=None):
        """Revisions end at verified collection progress, not an uncovered tail."""
        if connection is None:
            with self.db._connect() as db:
                return self.fresh_window(cluster,namespace,duration,connection=db)
        progress=connection.execute('''SELECT MAX(processed_through) FROM evidence_coverage
            JOIN evidence_sources USING(source_id) WHERE cluster_id=? AND namespace=?''',(cluster,namespace)).fetchone()[0]
        end=min(self.db.now(),datetime.fromisoformat(progress)) if progress else self.db.now()
        return {'start':end-duration,'end':end}

    def _expire(self,db,row):
        if row['review_state']=='OPEN' and self.db.now()>=datetime.fromisoformat(row['review_expires']):
            db.execute("UPDATE analysis_runs SET review_state='EXPIRED' WHERE run_id=?",(row['run_id'],))
            self.event(db,row['run_id'],'report_review_expired','backend')
            return self.row(db,row['run_id'])
        return row

    def get(self,run_id,principal):
        with self.db.transaction() as db:
            row=self.row(db,run_id);self.scope(principal,row,'read');row=self._expire(db,row)
            result=db.execute('SELECT * FROM analysis_results WHERE run_id=?',(run_id,)).fetchone()
            decision=db.execute('SELECT payload FROM analysis_decisions WHERE run_id=?',(run_id,)).fetchone()
            value={key:row[key] for key in ('run_id','case_id','revision','cluster_id','namespace','role_name','actor',
                'status','created_at','error','review_state','review_expires','retention_state','attempts')}
            value.update(intake=json.loads(row['intake']),model_config=json.loads(row['model_config']),
                request=json.loads(row['request']) if row['request'] else None,execution_available=False,
                decision=json.loads(decision['payload']) if decision else None,
                **(json.loads(result['payload']) if result else {'report':None,'proposal':None}),
                report_hash=result['report_hash'] if result else None)
            return value

    def list(self,cluster,namespace,principal,limit=50):
        principal.require('read',cluster,namespace)
        if not 1<=limit<=100:raise LedgerError('invalid_page_limit',422)
        with self.db._connect() as db:
            rows=db.execute('SELECT run_id FROM analysis_runs WHERE cluster_id=? AND namespace=? ORDER BY rowid DESC LIMIT ?',
                (cluster,namespace,limit)).fetchall()
        # Full reports are fetched individually; avoid unbounded model trace lists.
        return [{k:v for k,v in self.get(r['run_id'],principal).items() if k not in ('report','proposal','model_config','intake','request')}
                for r in rows]

    def history(self,run_id,principal,after=0):
        with self.db._connect() as db:
            self.scope(principal,self.row(db,run_id),'read')
            return [{**dict(r),'details':json.loads(r['details'])} for r in db.execute(
                'SELECT * FROM analysis_events WHERE run_id=? AND sequence>? ORDER BY sequence LIMIT 100',(run_id,after))]

    def prepare_next(self):
        """Backend-only inventory work. No inference; capture happens outside DB locks."""
        with self.db.transaction() as db:
            now=self.db.now()
            row=db.execute("SELECT * FROM analysis_runs WHERE status='PREPARING' OR (status='CAPTURING' AND lease_until<=?) ORDER BY rowid LIMIT 1",
                (now.isoformat(),)).fetchone()
            if row is None:return False
            run_id=row['run_id'];token=uuid4().hex
            db.execute("UPDATE analysis_runs SET status='CAPTURING',lease_token=?,lease_until=? WHERE run_id=?",
                (token,(now+timedelta(minutes=10)).isoformat(),run_id))
        error=None;evidence=None
        try:
            body=AnalysisIntake.model_validate_json(row['intake'])
            with self.db._connect() as db:
                history=db.execute("SELECT actor,created_at,intake FROM analysis_runs WHERE case_id=? AND json_extract(intake,'$.context_note')!='' ORDER BY revision",
                    (row['case_id'],)).fetchall()
            notes=[];seen=set()
            for previous in history:
                text=json.loads(previous['intake'])['context_note']
                if text in seen:continue
                seen.add(text)
                notes.append(f"Authenticated operator note by {previous['actor']} at {previous['created_at']}: {text}")
            if len(notes)>7:raise ValueError('owner_context_capacity_requires_review')
            evidence=self.inventory.capture(row['cluster_id'],row['namespace'],row['role_name'],body.window,
                owner_notes=notes)
            if evidence.source_mode!='captured':raise ValueError('captured_evidence_required')
            retention='hot_only_backup_unverified'
            if self.archive and evidence.usage:
                self.archive.pin(row['case_id'],evidence.usage.summary_id,self.db.now()+timedelta(days=90))
                retention='case_pinned_external_copy_unverified'
            request=AnalysisRequest(case_id=row['case_id'],run_id=run_id,revision=row['revision'],
                trigger=body.trigger,snapshot_id=evidence.snapshot_id,cluster_id=row['cluster_id'],
                target_uid=evidence.target.uid,baseline_id=evidence.baseline_id,
                policy_version=evidence.policy.policy_version,mode='preview')
        except ValueError as exc:
            error='unsupported_or_invalid_evidence:'+str(exc)[:160]
        except Exception:
            error='evidence_capture_unavailable'
        with self.db.transaction() as db:
            current=self.row(db,run_id)
            if current['status']!='CAPTURING' or current['lease_token']!=token:return True
            if error:
                db.execute("UPDATE analysis_runs SET status='FAILED',error=?,lease_token=NULL,lease_until=NULL WHERE run_id=?",(error,run_id))
                self.event(db,run_id,'evidence_unavailable','backend',reason=error)
            else:
                observed=self.inventory.observed_hash(evidence.snapshot_id)
                if isinstance(observed,str):
                    db.execute('INSERT INTO analysis_observations VALUES (?,?) ON CONFLICT(case_id) DO UPDATE SET content_hash=excluded.content_hash',
                        (row['case_id'],observed))
                db.execute("UPDATE analysis_runs SET status='QUEUED',request=?,retention_state=?,lease_token=NULL,lease_until=NULL WHERE run_id=?",
                    (request.model_dump_json(),retention,run_id))
                self.event(db,run_id,'snapshot_bound','backend',snapshot_id=evidence.snapshot_id,
                    target_uid=evidence.target.uid,retention_state=retention)
        return True

    def _service(self,principal,row):
        if principal.kind!='service':raise LedgerError('worker_identity_required',403)
        for permission in ('deliver','publish','read'):self.scope(principal,row,permission)

    def _leased(self,db,run_id,token,principal):
        row=self.row(db,run_id);self._service(principal,row)
        if (row['status']!='CLAIMED' or row['lease_token']!=token or row['owner']!=principal.actor
                or self.db.now()>=datetime.fromisoformat(row['lease_until'])
                or (row['active_deadline'] and self.db.now()>=datetime.fromisoformat(row['active_deadline']))):
            raise LedgerError('analysis_lease_lost')
        return row

    def claim(self,body,principal):
        self._service(principal,{'cluster_id':body.cluster_id,'namespace':body.namespace})
        with self.db.transaction() as db:
            now=self.db.now()
            for old in db.execute("SELECT run_id FROM analysis_runs WHERE status='CLAIMED' AND active_deadline<=?",(now.isoformat(),)).fetchall():
                db.execute("UPDATE analysis_runs SET status='FAILED',error='analysis_active_deadline' WHERE run_id=?",(old['run_id'],))
                self.event(db,old['run_id'],'analysis_active_deadline','backend')
            # Concurrency one across the ledger, not one per namespace/token.
            if db.execute("SELECT 1 FROM analysis_runs WHERE status='CLAIMED' AND lease_until>?",(now.isoformat(),)).fetchone():return None
            expired=db.execute("SELECT run_id FROM analysis_runs WHERE status='CLAIMED' AND lease_until<=? AND attempts>=3",(now.isoformat(),)).fetchall()
            for old in expired:
                db.execute("UPDATE analysis_runs SET status='FAILED',error='worker_retry_limit' WHERE run_id=?",(old['run_id'],))
                self.event(db,old['run_id'],'worker_retry_limit','backend')
            row=db.execute("SELECT * FROM analysis_runs WHERE cluster_id=? AND namespace=? AND (status='QUEUED' OR (status='CLAIMED' AND lease_until<=? AND attempts<3)) ORDER BY rowid LIMIT 1",
                (body.cluster_id,body.namespace,now.isoformat())).fetchone()
            if row is None:return None
            token=uuid4().hex;until=(now+timedelta(seconds=120)).isoformat()
            evidence=self.inventory.load(AnalysisRequest.model_validate_json(row['request']).snapshot_id)
            model=ModelConfig.model_validate_json(row['model_config'])
            deadline=(now+timedelta(seconds=min(evidence.policy.active_run_timeout_seconds,model.active_run_timeout_seconds))).isoformat()
            db.execute("UPDATE analysis_runs SET status='CLAIMED',owner=?,lease_token=?,lease_until=?,active_deadline=COALESCE(active_deadline,?),attempts=attempts+1 WHERE run_id=?",
                (principal.actor,token,until,deadline,row['run_id']))
            self.event(db,row['run_id'],'worker_claimed',principal.actor,attempt=row['attempts']+1)
            return {'run_id':row['run_id'],'request':json.loads(row['request']),'model_config':json.loads(row['model_config']),
                'lease_token':token,'lease_expires_at':until,'attempt':row['attempts']+1}

    def renew(self,run_id,token,principal):
        with self.db.transaction() as db:
            self._leased(db,run_id,token,principal)
            until=(self.db.now()+timedelta(seconds=120)).isoformat()
            db.execute('UPDATE analysis_runs SET lease_until=? WHERE run_id=?',(until,run_id))
            return {'lease_expires_at':until}

    def complete(self,run_id,body,principal):
        body=validate(JobComplete,body);payload={'report':body.report.model_dump(mode='json'),
            'proposal':body.proposal.model_dump(mode='json') if body.proposal else None};content_hash=digest(payload)
        with self.db.transaction() as db:
            row=self.row(db,run_id);self._service(principal,row)
            old=db.execute('SELECT * FROM analysis_results WHERE run_id=?',(run_id,)).fetchone()
            if old and row['owner']==principal.actor and row['lease_token']==body.lease_token:
                if old['report_hash']!=content_hash:raise LedgerError('immutable_report_conflict')
                return {'run_id':run_id,'report_hash':content_hash,'status':'DONE'}
            row=self._leased(db,run_id,body.lease_token,principal);req=AnalysisRequest.model_validate_json(row['request'])
            r,p=body.report,body.proposal
            calls=db.execute('SELECT count(*) FROM analysis_model_calls WHERE run_id=?',(run_id,)).fetchone()[0]
            if (r.run_id!=run_id or r.case_id!=req.case_id or r.mode!='preview' or r.execution_outcome is not None
                    or r.status not in ('BLOCKED','NO_CHANGE','FAILED') or (r.readiness and r.readiness.execution_ready)
                    or r.model_calls!=calls):raise LedgerError('invalid_preview_report',422)
            if p and (p.run_id!=run_id or p.case_id!=req.case_id or p.revision!=req.revision or p.simulation
                    or p.status!='BLOCKED' or (p.target.cluster_id,p.target.namespace,p.target.name,p.target.uid)!=
                    (row['cluster_id'],row['namespace'],row['role_name'],req.target_uid)):
                raise LedgerError('invalid_preview_proposal',422)
            db.execute('INSERT INTO analysis_results VALUES (?,?,?,?)',(run_id,encode(payload),content_hash,principal.actor))
            expires=(self.db.now()+timedelta(seconds=self.db.review_seconds)).isoformat()
            db.execute("UPDATE analysis_runs SET status='DONE',review_state='OPEN',review_expires=? WHERE run_id=?",(expires,run_id))
            self.event(db,run_id,'report_published',principal.actor,report_hash=content_hash,status=r.status)
            return {'run_id':run_id,'report_hash':content_hash,'status':'DONE'}

    def decide(self,run_id,body,principal):
        body=validate(ReportDecision,body);request_hash=digest({'run_id':run_id,**body.model_dump(mode='json')})
        expired=False
        with self.db.transaction() as db:
            row=self.row(db,run_id);self.scope(principal,row,'review')
            if principal.kind!='human':raise LedgerError('human_report_review_required',403)
            old=db.execute('SELECT * FROM analysis_decisions WHERE actor=? AND idempotency_key=?',(principal.actor,body.idempotency_key)).fetchone()
            if old:
                if old['request_hash']!=request_hash:raise LedgerError('decision_idempotency_conflict')
                return json.loads(old['payload'])
            if body.kind in ('approve_remediation','adopt_baseline'):raise LedgerError('governed_executor_unavailable',503)
            row=self._expire(db,row);expired=row['review_state']=='EXPIRED'
            if not expired:
                if row['status']!='DONE' or row['review_state']!='OPEN':raise LedgerError('report_review_not_open')
                result=db.execute('SELECT * FROM analysis_results WHERE run_id=?',(run_id,)).fetchone()
                if principal.actor==result['publisher']:raise LedgerError('independent_human_review_required',403)
                if (body.expected_revision,body.expected_report_hash)!=(row['revision'],result['report_hash']):
                    raise LedgerError('report_revision_or_hash_changed')
                successor=None
                if body.kind=='request_context':
                    old_intake=AnalysisIntake.model_validate_json(row['intake']);duration=old_intake.window.end-old_intake.window.start
                    intake=AnalysisIntake(cluster_id=row['cluster_id'],namespace=row['namespace'],role_name=row['role_name'],
                        window=self.fresh_window(row['cluster_id'],row['namespace'],duration,connection=db),idempotency_key='context-'+uuid4().hex,
                        trigger='manual',supersedes_run_id=run_id,context_note=body.note)
                    successor=self._insert(db,intake,principal.actor)
                value={'decision_id':'report-decision-'+uuid4().hex,'run_id':run_id,'revision':row['revision'],
                    'kind':body.kind,'actor':principal.actor,'report_hash':result['report_hash'],'note':body.note,
                    'recorded_at':self.db.now().isoformat(),'successor_run_id':successor,'execution_authorized':False,
                    'review_outcome':'REJECTED' if body.kind=='reject' else 'NO_CHANGE' if body.kind=='acknowledge' else 'WAITING_FOR_CONTEXT'}
                db.execute('INSERT INTO analysis_decisions VALUES (?,?,?,?,?,?)',
                    (value['decision_id'],run_id,principal.actor,body.idempotency_key,request_hash,encode(value)))
                db.execute("UPDATE analysis_runs SET review_state='RESOLVED' WHERE run_id=?",(run_id,))
                self.event(db,run_id,'report_reviewed',principal.actor,decision=value)
        if expired:raise LedgerError('report_review_expired')
        return value

    def budget(self,run_id,body,principal):
        body=validate(BudgetRequest,body)
        with self.db.transaction() as db:
            row=self._leased(db,run_id,body.lease_token,principal)
            evidence=self.inventory.load(AnalysisRequest.model_validate_json(row['request']).snapshot_id)
            policy=evidence.policy
            count=db.execute('SELECT count(*) FROM analysis_model_calls WHERE run_id=?',(run_id,)).fetchone()[0]
            if body.operation=='count':return count
            if body.operation in ('repair_count','reserve_model'):
                if body.stage is None:raise LedgerError('model_stage_required',422)
                repairs=db.execute('SELECT count(*) FROM analysis_model_calls WHERE run_id=? AND stage=? AND repair=1',(run_id,body.stage)).fetchone()[0]
                if body.operation=='repair_count':return repairs
                if count>=policy.model_calls or (body.repair and repairs):raise LedgerError('model_budget_exhausted')
                db.execute('INSERT INTO analysis_model_calls VALUES (?,?,?,?)',(run_id,count+1,body.stage,int(body.repair)))
                return count+1
            if not body.batch_key:raise LedgerError('lookup_batch_required',422)
            raw=db.execute('SELECT * FROM analysis_lookup_batches WHERE batch_key=?',(body.batch_key,)).fetchone()
            if raw and raw['run_id']!=run_id:raise LedgerError('lookup_outside_run')
            batch=json.loads(raw['payload']) if raw else None
            if body.operation=='reserve_lookup':
                if not body.requests:raise LedgerError('lookup_requests_required',422)
                requests=[r.model_dump(mode='json') for r in body.requests]
                if batch:
                    if [c['request'] for c in batch['calls']]!=requests:raise LedgerError('lookup_reservation_changed')
                    return batch
                req=AnalysisRequest.model_validate_json(row['request']);facts,_=build_facts(evidence,self.db.now())
                for lookup in body.requests:validate_lookup(lookup,req,evidence,facts)
                prior=[json.loads(r[0]) for r in db.execute('SELECT payload FROM analysis_lookup_batches WHERE run_id=?',(run_id,))]
                total=sum(len(b['calls']) for b in prior)+len(requests)
                if len(prior)>=policy.lookup_rounds or total>policy.lookup_calls:raise LedgerError('lookup_budget_exhausted')
                batch={'run_id':run_id,'round':len(prior)+1,'total_calls':total,
                    'calls':[{'request':r,'started':False,'result':None} for r in requests]}
                db.execute('INSERT INTO analysis_lookup_batches VALUES (?,?,?)',(body.batch_key,run_id,encode(batch)))
                return batch
            if batch is None or body.index is None or body.index>=len(batch['calls']):raise LedgerError('lookup_not_reserved')
            entry=batch['calls'][body.index]
            if body.operation=='begin_lookup':
                if entry['result'] is not None:return entry['result']
                if entry['started']:raise LedgerError('lookup_outcome_uncertain_after_restart')
                entry['started']=True;answer=None
            else:
                if not entry['started'] or body.result is None:raise LedgerError('lookup_not_started')
                req=AnalysisRequest.model_validate_json(row['request'])
                from agents.guardian.contracts import ContextLookup
                result=validate_result(body.result,ContextLookup.model_validate(entry['request']),req,evidence).model_dump(mode='json')
                if entry['result'] is not None and entry['result']!=result:raise LedgerError('lookup_result_conflict')
                entry['result']=result;answer=None
            db.execute('UPDATE analysis_lookup_batches SET payload=? WHERE batch_key=?',(encode(batch),body.batch_key))
            return answer
