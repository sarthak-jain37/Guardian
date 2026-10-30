"""Run production preview jobs through scoped backend ports and durable checkpoints.

    python -m agents.guardian.service_worker --help

Inference runs here, not in the API/collector process. No execution port is wired.
"""
import argparse
import fcntl
import json
import os
import threading
import time
from pathlib import Path
from contextlib import contextmanager

from langgraph.checkpoint.sqlite import SqliteSaver
from agents.guardian.contracts import utc_now
from agents.guardian.graph import Runtime,build_graph
from agents.guardian.runner import config,configured_model
from agents.guardian.versions import require_compatible_state
from agents.guardian.adapters.local import PreviewVerificationPort
from agents.guardian.adapters.backend import BackendClient,BackendEvidencePort,BackendBudgetPort,BackendReviewPort


@contextmanager
def heartbeat(client,job):
    stopped=threading.Event();lost=threading.Event()
    def renew():
        while not stopped.wait(20):
            try:client.call('POST',f"/analysis/jobs/{job['run_id']}/renew",{'lease_token':job['lease_token']})
            except Exception:lost.set();return
    thread=threading.Thread(target=renew,daemon=True);thread.start()
    try:yield lost
    finally:stopped.set();thread.join(timeout=21)


def process_job(client,job,directory,*,model_factory=configured_model,clock=utc_now):
    """Also used by HTTP integration tests; only the factory is replaceable there."""
    run_id=job['run_id'];token=job['lease_token']
    # The server's generated run ID is still hashed before becoming a file name.
    import hashlib
    filename=hashlib.sha256(run_id.encode()).hexdigest()+'.sqlite3'
    model,_=model_factory(job['model_config'])
    review=BackendReviewPort(client,run_id,token)
    runtime=Runtime(BackendEvidencePort(client),model,review,PreviewVerificationPort(),None,
        budget=BackendBudgetPort(client,run_id,token),clock=clock)
    try:
        with heartbeat(client,job) as lost, SqliteSaver.from_conn_string(str(Path(directory)/filename)) as saver:
            graph=build_graph(runtime,saver);settings=config(run_id);saved=graph.get_state(settings)
            if saved.values:
                require_compatible_state(saved.values)
                if saved.values['request']!=job['request']:raise ValueError('checkpoint_intake_changed')
                if saved.next:
                    if any(task.interrupts for task in saved.tasks):raise ValueError('preview_cannot_wait_for_execution_review')
                    state=graph.invoke(None,settings)
                else:
                    state=saved.values
                    # Finalization appends a trace entry *after* publishing.
                    # Rebuilding from terminal state would change the immutable
                    # report. Read the acknowledged backend result on replay.
                    current=client.call('GET',f'/analysis/runs/{run_id}')
                    if current['status']!='DONE':raise ValueError('terminal_checkpoint_without_acknowledged_report')
            else:
                state=graph.invoke({'request':job['request']},settings)
            if lost.is_set():
                # Publication is independently fenced by the API even if the
                # heartbeat was interrupted after the final acknowledged write.
                current=client.call('GET',f'/analysis/runs/{run_id}')
                if current['status']!='DONE':raise ValueError('analysis_lease_lost')
            return {'run_id':run_id,'status':state['status'],'model_calls':state['model_calls'],
                'execution_requests':0}
    finally:
        if hasattr(model,'close'):model.close()


def main(argv=None):
    parser=argparse.ArgumentParser(description='Dedicated scoped Guardian analysis worker; preview only')
    parser.add_argument('--backend',default='http://127.0.0.1:8000')
    parser.add_argument('--token-file',required=True,type=Path)
    parser.add_argument('--cluster',required=True);parser.add_argument('--namespace',required=True)
    parser.add_argument('--directory',type=Path,default=Path('data/guardian/worker'))
    parser.add_argument('--once',action='store_true')
    args=parser.parse_args(argv)
    os.umask(0o077);args.directory.mkdir(parents=True,exist_ok=True,mode=0o700)
    client=BackendClient(args.backend,args.token_file)
    with (args.directory/'worker.lock').open('a') as lock:
        fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
        while True:
            try:
                job=client.call('POST','/analysis/jobs/claim',{'cluster_id':args.cluster,'namespace':args.namespace})['job']
                if job:
                    if job['model_config']['provider']=='scripted':raise ValueError('scripted_profile_is_test_only')
                    print(json.dumps(process_job(client,job,args.directory)),flush=True)
            except Exception:
                # Neither token-bearing HTTP exceptions nor evidence strings go
                # to logs. The durable lease/budget remains for bounded retry.
                print(json.dumps({'error':'analysis_worker_unavailable','execution_requests':0}),flush=True)
                if args.once:return 1
            if args.once:return 0
            time.sleep(5)


if __name__=='__main__':raise SystemExit(main())
