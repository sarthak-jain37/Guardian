"""Real collection/model/readiness smoke. Stops before the human approval boundary."""
import argparse,json,time
from datetime import datetime,timedelta,timezone
from pathlib import Path
from uuid import uuid4
import requests


def run(base,token_file,directory,*,seconds=300,timeout=900):
    directory=Path(directory);directory.mkdir(parents=True,exist_ok=False)
    session=requests.Session();session.trust_env=False
    session.headers['Authorization']='Bearer '+Path(token_file).read_text().strip()
    def call(method,path,body=None):
        response=session.request(method,base.rstrip('/')+path,json=body,timeout=60);response.raise_for_status();return response.json()
    started=time.monotonic();scope='cluster_id=guardian-release&namespace=guardian-demo'
    ready=call('GET','/ready');status=call('GET','/evidence/status?'+scope)
    if not status['processed_through']:raise ValueError('audit_watermark_unavailable_do_not_claim_coverage')
    end=datetime.fromisoformat(status['processed_through'].replace('Z','+00:00'))
    source=call('POST','/analysis/runs',{'cluster_id':'guardian-release','namespace':'guardian-demo','role_name':'pod-reader',
        'window':{'start':(end-timedelta(seconds=seconds)).isoformat(),'end':end.isoformat()},'idempotency_key':'pilot-'+uuid4().hex,'trigger':'initial'})
    deadline=time.monotonic()+timeout
    while True:
        source=call('GET','/analysis/runs/'+source['run_id'])
        if source['status'] in ('DONE','FAILED'):break
        if time.monotonic()>deadline:raise TimeoutError('live_analysis_still_pending_see_saved_intake')
        (directory/'intake.json').write_text(json.dumps(source,indent=2));time.sleep(5)
    (directory/'analysis.json').write_text(json.dumps(source,indent=2))
    preparation=None;review=None
    if source.get('proposal'):
        preparation=call('POST','/execution/reviews',{'source_run_id':source['run_id'],'expected_report_hash':source['report_hash'],
            'action':'remediate','idempotency_key':'pilot-prepare-'+uuid4().hex})
        while True:
            preparation=call('GET','/execution/preparations/'+preparation['preparation_id'])
            if preparation['status'] in ('DONE','BLOCKED'):break
            if time.monotonic()>deadline:raise TimeoutError('readiness_still_pending')
            time.sleep(2)
        if preparation['proposal_id']:review=call('GET','/execution/reviews/'+preparation['proposal_id'])
    evidence=call('GET','/evidence/snapshots/'+source['request']['snapshot_id']) if source.get('request') else None
    (directory/'evidence.json').write_text(json.dumps(evidence,indent=2));(directory/'review.json').write_text(json.dumps(review,indent=2))
    result={'schema_version':'guardian.live-readiness-smoke.v1','environment':'disposable_local_kind','recorded_at':datetime.now(timezone.utc).isoformat(),
        'ready':ready,'source_run_id':source['run_id'],'source_status':source['status'],'analysis_status':source['report']['status'] if source.get('report') else None,
        'model_calls':source['report']['model_calls'] if source.get('report') else 0,'model_config':source['model_config'],
        'query_window':evidence['usage']['query_window'] if evidence and evidence['usage'] else None,
        'preparation':preparation,'human_approval_recorded':False,'remediation_requested':False,'target_writes_by_guardian':False,
        'duration_seconds':time.monotonic()-started,'ready_for_human_review':bool(review and review['execution_available']),
        'live_execution_acceptance':False,'remaining_gate':'human exact-action approval, resulting verification and independent reproduction'}
    (directory/'acceptance.json').write_text(json.dumps(result,indent=2));return result


def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--backend',default='http://127.0.0.1:18000');p.add_argument('--token-file',type=Path,default=Path('data/pilot/reviewer.token'));p.add_argument('--directory',type=Path,required=True);p.add_argument('--seconds',type=int,default=300)
    a=p.parse_args();print(json.dumps(run(a.backend,a.token_file,a.directory,seconds=a.seconds),indent=2))


if __name__=='__main__':main()
