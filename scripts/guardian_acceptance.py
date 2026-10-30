"""Real collection/model/readiness smoke. Stops before the human approval boundary."""
import argparse,json,time
from datetime import datetime,timedelta,timezone
from pathlib import Path
from uuid import uuid4
import requests
from urllib.parse import urlencode


def run(base,token_file,directory,*,seconds=300,timeout=900,resume=False,follow_approval=False,
        cluster='guardian-release',namespace='guardian-demo',role='pod-reader'):
    directory=Path(directory);directory.mkdir(parents=True,exist_ok=resume)
    session=requests.Session();session.trust_env=False;session.headers['Connection']='close'
    from requests.adapters import HTTPAdapter
    from urllib3.util.retry import Retry
    session.mount('http://',HTTPAdapter(max_retries=Retry(total=3,backoff_factor=.5,allowed_methods={'GET','POST'},status_forcelist=[502,503,504])))
    session.headers['Authorization']='Bearer '+Path(token_file).read_text().strip()
    def call(method,path,body=None):
        response=session.request(method,base.rstrip('/')+path,json=body,timeout=60);response.raise_for_status();return response.json()
    started=time.monotonic();scope=urlencode({'cluster_id':cluster,'namespace':namespace})
    ready=call('GET','/ready');status=call('GET','/evidence/status?'+scope)
    if not status['processed_through']:raise ValueError('audit_watermark_unavailable_do_not_claim_coverage')
    end=datetime.fromisoformat(status['processed_through'].replace('Z','+00:00'))
    if resume:
        source=json.loads((directory/'intake.json').read_text())
    else:
        source=call('POST','/analysis/runs',{'cluster_id':cluster,'namespace':namespace,'role_name':role,
            'window':{'start':(end-timedelta(seconds=seconds)).isoformat(),'end':end.isoformat()},'idempotency_key':'pilot-'+uuid4().hex,'trigger':'initial'})
    (directory/'intake.json').write_text(json.dumps(source,indent=2))
    deadline=time.monotonic()+timeout
    while True:
        source=call('GET','/analysis/runs/'+source['run_id'])
        if source['status'] in ('DONE','FAILED'):break
        if time.monotonic()>deadline:raise TimeoutError('live_analysis_still_pending_see_saved_intake')
        (directory/'intake.json').write_text(json.dumps(source,indent=2));time.sleep(5)
    (directory/'analysis.json').write_text(json.dumps(source,indent=2))
    preparation=None;review=None
    saved_review=json.loads((directory/'review.json').read_text()) if resume and (directory/'review.json').exists() else None
    if saved_review:
        review=call('GET','/execution/reviews/'+saved_review['proposal']['proposal_id'])
        if (directory/'preparation.json').exists():preparation=json.loads((directory/'preparation.json').read_text())
    elif source.get('proposal'):
        saved_preparation=directory/'preparation.json'
        preparation=json.loads(saved_preparation.read_text()) if resume and saved_preparation.exists() else call('POST','/execution/reviews',{
            'source_run_id':source['run_id'],'expected_report_hash':source['report_hash'],
            'action':'remediate','idempotency_key':'pilot-prepare-'+source['run_id']})
        saved_preparation.write_text(json.dumps(preparation,indent=2))
        while True:
            preparation=call('GET','/execution/preparations/'+preparation['preparation_id'])
            saved_preparation.write_text(json.dumps(preparation,indent=2))
            if preparation['status'] in ('DONE','BLOCKED'):break
            if time.monotonic()>deadline:raise TimeoutError('readiness_still_pending')
            time.sleep(2)
        if preparation['proposal_id']:review=call('GET','/execution/reviews/'+preparation['proposal_id'])
    if follow_approval and review:
        (directory/'review.json').write_text(json.dumps(review,indent=2))
        print('Waiting for your governed decision on '+review['proposal']['proposal_id']+'. No approval is submitted by this command.',flush=True)
        while True:
            review=call('GET','/execution/reviews/'+review['proposal']['proposal_id'])
            receipt=review.get('receipt');decision=review.get('decision')
            if receipt and receipt['phase'] in ('completed','stale','failed','manual','rolled_back'):break
            if decision and decision['kind'] not in ('approve_remediation','adopt_baseline'):break
            if not decision and review['status'] not in ('OPEN',):break
            if time.monotonic()>deadline:raise TimeoutError('approval_or_execution_pending_resume_same_directory')
            time.sleep(2)
    evidence=call('GET','/evidence/snapshots/'+source['request']['snapshot_id']) if source.get('request') else None
    (directory/'evidence.json').write_text(json.dumps(evidence,indent=2));(directory/'review.json').write_text(json.dumps(review,indent=2))
    decision=review.get('decision') if review else None;receipt=review.get('receipt') if review else None
    verified=bool(receipt and receipt['phase']=='completed' and receipt['apply_status']=='confirmed' and receipt['verification_status']=='passed' and receipt['baseline_activated'])
    remaining='independent reproduction' if verified else ('execution outcome: '+receipt['phase'] if receipt else
        'human decision: '+decision['kind']+'; no execution requested' if decision and decision['kind'] not in ('approve_remediation','adopt_baseline') else
        'human exact-action approval and resulting verification' if review else 'supported analysis and independent readiness; no executable change is available')
    result={'schema_version':'guardian.live-readiness-smoke.v1','environment':'disposable_local_kind','recorded_at':datetime.now(timezone.utc).isoformat(),
        'ready':ready,'source_run_id':source['run_id'],'source_status':source['status'],'analysis_status':source['report']['status'] if source.get('report') else None,
        'model_calls':source['report']['model_calls'] if source.get('report') else 0,'model_config':source['model_config'],
        'analysis_is_preview':True,'governed_outcome':receipt['phase'] if receipt else None,
        'query_window':evidence['usage']['query_window'] if evidence and evidence['usage'] else None,
        'preparation':preparation,'proposal_id':review['proposal']['proposal_id'] if review else None,
        'human_approval_recorded':bool(decision and decision['kind'] in ('approve_remediation','adopt_baseline')),
        'human_decision_kind':decision['kind'] if decision else None,'remediation_requested':bool(decision and decision['kind']=='approve_remediation'),
        'target_writes_by_guardian':bool(receipt and receipt['apply_status']=='confirmed'),'execution_receipt':receipt,'live_execution_verified':verified,
        'duration_seconds':time.monotonic()-started,'ready_for_human_review':bool(review and review['execution_available']),
        'live_execution_acceptance':False,'remaining_gate':remaining}
    (directory/'acceptance.json').write_text(json.dumps(result,indent=2));return result


def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--backend',default='http://127.0.0.1:18000');p.add_argument('--token-file',type=Path,default=Path('data/pilot/reviewer.token'));p.add_argument('--directory',type=Path,required=True);p.add_argument('--seconds',type=int,default=300);p.add_argument('--resume',action='store_true')
    p.add_argument('--follow-approval',action='store_true',help='wait for the human decision and print its actual execution outcome; never submits approval')
    p.add_argument('--cluster',default='guardian-release');p.add_argument('--namespace',default='guardian-demo');p.add_argument('--role',default='pod-reader')
    a=p.parse_args();print(json.dumps(run(a.backend,a.token_file,a.directory,seconds=a.seconds,resume=a.resume,follow_approval=a.follow_approval,
        cluster=a.cluster,namespace=a.namespace,role=a.role),indent=2))


if __name__=='__main__':main()
