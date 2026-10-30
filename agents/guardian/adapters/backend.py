"""Scoped HTTP ports for the dedicated worker. No Kubernetes or archive access."""
import json
from pathlib import Path
from urllib.parse import urlsplit, quote
from urllib.request import Request, HTTPRedirectHandler, build_opener

from agents.guardian.contracts import EvidenceBundle, Proposal, validate_request_evidence
from agents.guardian.evidence_tools import ToolResult


class BackendClient:
    maximum=2*1024*1024

    def __init__(self,url,token_file,*,timeout=20):
        parsed=urlsplit(url)
        if (parsed.scheme not in ('http','https') or not parsed.hostname or parsed.username or parsed.password
                or parsed.query or parsed.fragment):raise ValueError('invalid_backend_endpoint')
        self.url=url.rstrip('/');self.token_file=Path(token_file);self.timeout=timeout

    def call(self,method,path,body=None):
        class NoRedirect(HTTPRedirectHandler):
            def redirect_request(self,*args,**kwargs):raise ValueError('backend_redirect_rejected')
        with self.token_file.open('rb') as stream:raw=stream.read(513)
        token=raw.decode('ascii').strip()
        if not 32<=len(token)<=512:raise ValueError('invalid_worker_credential_file')
        data=json.dumps(body,allow_nan=False).encode() if body is not None else None
        if data and len(data)>self.maximum:raise ValueError('worker_request_too_large')
        request=Request(self.url+path,data=data,method=method,
            headers={'Authorization':'Bearer '+token,'Content-Type':'application/json'})
        with build_opener(NoRedirect()).open(request,timeout=self.timeout) as response:
            value=response.read(self.maximum+1)
        if len(value)>self.maximum:raise ValueError('backend_response_too_large')
        return json.loads(value)


class BackendEvidencePort:
    def __init__(self,client):self.client=client;self.snapshots={}

    def load(self,request):
        if request.snapshot_id not in self.snapshots:
            value=self.client.call('GET','/evidence/snapshots/'+quote(request.snapshot_id,safe=''))
            self.snapshots[request.snapshot_id]=EvidenceBundle.model_validate(value)
        result=self.snapshots[request.snapshot_id]
        validate_request_evidence(request,result)
        return result

    def current(self,request):return self.load(request)
    def fetch_context(self,request,lookup):return self.load(request)

    def lookup(self,request,lookup,*,timeout_seconds):
        evidence=self.load(request)
        base={'tool':lookup.tool,'case_id':request.case_id,'subject_id':evidence.subject.username,
            'target_uid':evidence.target.uid}
        if lookup.tool in ('check_access','get_failure_history'):
            return ToolResult(**base,status='unavailable',evidence_refs=[],
                reasons=['live_access_preflight_unavailable' if lookup.tool=='check_access' else 'verified_action_history_unavailable'])
        return ToolResult(**base,status='available',evidence=evidence,
            evidence_refs=evidence.evidence_refs,reasons=['immutable_case_snapshot'])


class BackendBudgetPort:
    def __init__(self,client,run_id,token):self.client,self.run_id,self.token=client,run_id,token
    def rpc(self,operation,**fields):
        return self.client.call('POST',f'/analysis/jobs/{self.run_id}/budget',
            {'lease_token':self.token,'operation':operation,**fields})['value']
    def require_run(self,run_id):
        if run_id!=self.run_id:raise ValueError('budget_outside_run')
    def model_call_count(self,run_id):
        self.require_run(run_id);return self.rpc('count')
    def model_repair_count(self,run_id,stage):
        self.require_run(run_id);return self.rpc('repair_count',stage=stage)
    def reserve_model_call(self,run_id,stage,limit,repair=False):
        self.require_run(run_id);return self.rpc('reserve_model',stage=stage,repair=repair)
    def reserve_lookup_batch(self,run_id,batch_key,requests,rounds,calls):
        self.require_run(run_id);return self.rpc('reserve_lookup',batch_key=batch_key,requests=requests)
    def begin_lookup(self,batch_key,index):return self.rpc('begin_lookup',batch_key=batch_key,index=index)
    def complete_lookup(self,batch_key,index,result):self.rpc('complete_lookup',batch_key=batch_key,index=index,result=result)
    def begin_action(self,action_key):raise ValueError('execution_not_available_in_preview_worker')


class BackendReviewPort:
    # Preview completion is reviewed outside the execution interrupt. This cannot
    # satisfy governed_transport or mint positive approval/adoption authority.
    authoritative=False

    def __init__(self,client,run_id,token):
        self.client,self.run_id,self.token=client,run_id,token
        self.proposal=None;self.saved_report=None

    def publish(self,proposal,report):
        value=Proposal.model_validate(proposal.model_dump(mode='json'))
        if value.run_id!=self.run_id or value.simulation or value.status!='BLOCKED':
            raise ValueError('preview_worker_cannot_publish_ready_proposal')
        self.proposal=value;return value

    def publish_report(self,run_id,report):
        if run_id!=self.run_id:raise ValueError('report_outside_run')
        self.saved_report=report;return report

    def project_proposal(self,proposal_id,status,reason):
        if self.proposal is None or proposal_id!=self.proposal.proposal_id or status!='BLOCKED':
            raise ValueError('invalid_preview_projection')
        return {'proposal_id':proposal_id,'status':status,'reason':reason}

    def finalize_run(self,run_id,result):
        if run_id!=self.run_id:raise ValueError('report_outside_run')
        self.client.call('POST',f'/analysis/jobs/{run_id}/complete',{'lease_token':self.token,'report':result,
            'proposal':self.proposal.model_dump(mode='json') if self.proposal else None})
        return result
