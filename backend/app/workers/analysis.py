"""Backend inventory preparation and finite read-only watch scheduler; no model."""
import asyncio
import logging
from datetime import datetime, timedelta
from backend.app.core.auth import Principal
from backend.app.models.analysis import AnalysisIntake
from backend.app.services.governance_store import digest, LedgerError
from backend.app.services.canonical_hash import canonical_hash

logger=logging.getLogger(__name__)


def context_fingerprint(inventory):
    objects=[]
    for obj in inventory['objects']:
        metadata=obj.get('metadata',{});status=obj.get('status',{})
        objects.append({'kind':obj.get('kind'),'uid':metadata.get('uid'),'owners':metadata.get('ownerReferences',[]),
            'spec':obj.get('spec',{}),'images':[{'imageID':c.get('imageID'),'restartCount':c.get('restartCount'),
                'ready':c.get('ready')} for c in status.get('containerStatuses',[])]})
    return {'objects':sorted(objects,key=lambda o:(o['kind'] or '',o['uid'] or '')),'errors':sorted(inventory['errors'])}


def schedule_once(store,cluster,namespaces,*,period_seconds=3600):
    if not namespaces:return
    principal=Principal(actor='backend-analysis-scheduler',kind='service',grants=[
        {'cluster_id':cluster,'namespace':ns,'permissions':['read','publish','deliver']} for ns in namespaces])
    with store.db._connect() as db:
        cases=db.execute('SELECT c.*,r.intake,r.status,r.created_at FROM analysis_cases c JOIN analysis_runs r ON c.latest_run_id=r.run_id WHERE c.cluster_id=? ORDER BY c.rowid DESC LIMIT 64',(cluster,)).fetchall()
    cases=[c for c in cases if c['namespace'] in namespaces and c['status'] in ('DONE','FAILED')]
    if not cases:return
    state=store.inventory.k8s.get_rbac_state()
    inventories={ns:store.inventory.k8s.get_workload_inventory(ns) for ns in {c['namespace'] for c in cases}}
    for case in cases:
        namespace=case['namespace']
        scoped={key:value for key,value in state.items() if value.get('kind') in ('ClusterRole','ClusterRoleBinding')
            or value.get('metadata',{}).get('namespace')==namespace}
        # Separate observation cursor; this is never an approved baseline.
        current=digest([canonical_hash(scoped),context_fingerprint(inventories[namespace])])
        with store.db.transaction() as db:
            old=db.execute('SELECT content_hash FROM analysis_observations WHERE case_id=?',(case['case_id'],)).fetchone()
        now=store.db.now()
        trigger='drift' if old and old['content_hash']!=current else 'periodic'
        due=(now-datetime.fromisoformat(case['created_at'])).total_seconds()>=period_seconds
        if trigger=='drift' or due:
            previous=AnalysisIntake.model_validate_json(case['intake'])
            duration=previous.window.end-previous.window.start
            with store.db._connect() as db:
                progress=db.execute('''SELECT MAX(processed_through) FROM evidence_coverage JOIN evidence_sources USING(source_id)
                    WHERE cluster_id=? AND namespace=?''',(cluster,namespace)).fetchone()[0]
            end=min(now,datetime.fromisoformat(progress)) if progress else now
            body=AnalysisIntake(cluster_id=cluster,namespace=namespace,role_name=case['role_name'],
                window={'start':end-duration,'end':end},trigger=trigger,supersedes_run_id=case['latest_run_id'],
                idempotency_key='schedule-'+digest([case['latest_run_id'],trigger,current]).split(':')[1])
            try:store.enqueue(body,principal)
            except LedgerError as exc:
                if exc.code not in ('analysis_queue_full','revision_is_not_latest','analysis_still_running'):raise
                continue
        with store.db.transaction() as db:
            db.execute('INSERT INTO analysis_observations VALUES (?,?) ON CONFLICT(case_id) DO UPDATE SET content_hash=excluded.content_hash',
                (case['case_id'],current))


async def run_analysis_preparation(store,cluster,namespaces,*,poll_seconds=5):
    next_schedule=0
    while True:
        try:
            await asyncio.to_thread(store.prepare_next)
            now=asyncio.get_running_loop().time()
            if now>=next_schedule:
                await asyncio.to_thread(schedule_once,store,cluster,namespaces)
                next_schedule=now+60
        except asyncio.CancelledError:raise
        except Exception:logger.error('Analysis preparation unavailable; retrying with queued intake retained')
        await asyncio.sleep(poll_seconds)
