"""Terminal access to the same scoped review API used by Streamlit.

No rules, commands, force flags or automatic approvals are accepted. A decision
names the exact revision/hash the operator reviewed; execution stays backend-owned.
"""
import argparse
import json
import time
from pathlib import Path
from uuid import uuid4

from frontend.review_client import ReviewClient


def perform(client,args):
    command=args.command
    if command=='list':
        return client.call('GET','/execution/reviews',params={'cluster_id':args.cluster,'namespace':args.namespace})
    if command in ('show','watch'):
        deadline=time.monotonic()+getattr(args,'timeout',0)
        while True:
            value=client.call('GET','/execution/reviews/'+args.proposal)
            receipt=value.get('receipt');decision=value.get('decision')
            terminal=receipt and receipt['phase'] in ('completed','stale','failed','manual','rolled_back')
            if command=='show' or terminal or (not decision and value['status']!='OPEN') or decision and decision['kind'] not in ('approve_remediation','adopt_baseline'):
                return value
            if time.monotonic()>=deadline:raise TimeoutError('execution_pending_run_watch_again')
            time.sleep(2)
    if command=='prepare':
        return client.call('POST','/execution/reviews',body={'source_run_id':args.run,
            'expected_report_hash':args.expected_hash,'action':args.action,'idempotency_key':args.idempotency_key},timeout=600)
    writing=args.kind in ('approve_remediation','adopt_baseline')
    if writing and not args.accept_residual_risk:raise ValueError('explicit_residual_risk_acceptance_required')
    if args.recovery_hash and args.kind!='approve_remediation':raise ValueError('recovery_requires_remediation_approval')
    return client.call('POST','/governance/reviews/'+args.proposal+'/decisions',body={
        'kind':args.kind,'expected_revision':args.expected_revision,'expected_approval_hash':args.expected_hash,
        'idempotency_key':args.idempotency_key,'note':args.note,'accept_residual_risk':writing and args.accept_residual_risk,
        'opt_in_recovery':bool(args.recovery_hash),'expected_recovery_hash':args.recovery_hash},timeout=600)


def parser():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--backend',default='http://127.0.0.1:18000')
    p.add_argument('--token-file',type=Path,default=Path('data/pilot/reviewer.token'))
    sub=p.add_subparsers(dest='command',required=True)
    listing=sub.add_parser('list');listing.add_argument('--cluster',default='guardian-release');listing.add_argument('--namespace',default='guardian-demo')
    for name in ('show','watch'):
        cmd=sub.add_parser(name);cmd.add_argument('proposal')
        if name=='watch':cmd.add_argument('--timeout',type=int,default=300)
    prepare=sub.add_parser('prepare');prepare.add_argument('run');prepare.add_argument('--expected-hash',required=True)
    prepare.add_argument('--action',choices=['remediate','adopt_baseline'],default='remediate')
    prepare.add_argument('--idempotency-key',default='terminal-prepare-'+uuid4().hex)
    decide=sub.add_parser('decide');decide.add_argument('proposal')
    decide.add_argument('--kind',required=True,choices=['approve_remediation','adopt_baseline','reject','acknowledge','request_context'])
    decide.add_argument('--expected-revision',type=int,required=True);decide.add_argument('--expected-hash',required=True)
    decide.add_argument('--accept-residual-risk',action='store_true');decide.add_argument('--recovery-hash')
    decide.add_argument('--note',default='');decide.add_argument('--idempotency-key',default='terminal-decision-'+uuid4().hex)
    return p


def main():
    p=parser();args=p.parse_args()
    try:
        token=args.token_file.read_text().strip()
        print(json.dumps(perform(ReviewClient(args.backend,token),args),indent=2))
    except (ValueError,OSError,TimeoutError) as error:p.exit(1,str(error)+'\n')


if __name__=='__main__':main()
