"""The governed actuator can only conditionally replace one existing Role's rules.

Dry run is a separate method with dryRun=All fixed internally. No create, force,
metadata replacement, bindings or arbitrary resource/HTTP path are accepted here.
"""
from copy import deepcopy
from urllib.parse import quote
from agents.guardian.policy import canonical_hash


class ConditionalRoleDriver:
    def __init__(self,k8s):self.k8s=k8s

    @staticmethod
    def patch(uid,version,rules):
        return [{'op':'test','path':'/metadata/uid','value':uid},
                {'op':'test','path':'/metadata/resourceVersion','value':version},
                {'op':'replace','path':'/rules','value':deepcopy(rules)}]

    def read(self,namespace,name):
        value=self.k8s.rbac_api.read_namespaced_role(name,namespace,_request_timeout=(5,15))
        return self.k8s.api_client.sanitize_for_serialization(value)

    def _patch(self,namespace,name,uid,version,rules,action_id,*,dry_run):
        path='/apis/rbac.authorization.k8s.io/v1/namespaces/{namespace}/roles/{name}'
        query=[('fieldManager','guardian-'+action_id)]
        if dry_run:query.append(('dryRun','All'))
        return self.k8s.api_client.call_api(path,'PATCH',path_params={'namespace':namespace,'name':name},
            query_params=query,header_params={'Content-Type':'application/json-patch+json',
                'User-Agent':'guardian-executor/'+action_id},body=self.patch(uid,version,rules),
            auth_settings=['BearerToken'],response_type='object',_return_http_data_only=True,_request_timeout=(5,15))

    def dry_run(self,namespace,name,uid,version,rules,action_id):
        return self._patch(namespace,name,uid,version,rules,action_id,dry_run=True)

    def apply(self,namespace,name,uid,version,rules,action_id):
        return self._patch(namespace,name,uid,version,rules,action_id,dry_run=False)

    def access(self,subject,namespace,group,resource,verb):
        base,_,subresource=resource.partition('/')
        attributes={'namespace':namespace,'group':group,'resource':base,'verb':verb}
        if subresource:attributes['subresource']=subresource
        body={'apiVersion':'authorization.k8s.io/v1','kind':'SubjectAccessReview',
            'spec':{'user':subject.username,'uid':subject.uid,'groups':subject.groups,'resourceAttributes':attributes}}
        value=self.k8s.api_client.call_api('/apis/authorization.k8s.io/v1/subjectaccessreviews','POST',body=body,
            auth_settings=['BearerToken'],response_type='object',_return_http_data_only=True,_request_timeout=(5,15))
        status=value.get('status',{})
        return {'allowed':status.get('allowed'),'denied':status.get('denied',False),
                'evaluation_error':status.get('evaluationError'),'reason':str(status.get('reason',''))[:2000]}

    def reconcile(self,intent):
        # Metadata audit usually cannot establish the exact post-write version.
        # A matching live Role alone never proves this action applied. Preserve
        # uncertainty; an acknowledged durable response may be reconciled by the
        # service, otherwise operator investigation/fresh adoption is required.
        return None
