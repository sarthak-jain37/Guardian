"""Pure audit request normalization. No guessing authorization from HTTP 403/404."""
from datetime import datetime, timezone
from urllib.parse import parse_qs, urlsplit, unquote
from contracts.usage_summary_v1 import RequestKey, Subject
from backend.app.services.governance_store import digest

OUTCOMES = ('successful_completed','authorized_error','authorized_incomplete','denied','unknown')
STAGES = {'RequestReceived':0,'ResponseStarted':1,'Panic':2,'ResponseComplete':3}


def timestamp(value):
    result = datetime.fromisoformat(value.replace('Z','+00:00'))
    if result.tzinfo is None:
        raise ValueError('audit_timestamp_requires_timezone')
    return result.astimezone(timezone.utc)


def iso(value):
    return value.astimezone(timezone.utc).isoformat(timespec='microseconds')


def normalize(event, resource_scopes):
    if event.get('stage') not in STAGES or not event.get('auditID'):
        raise ValueError('missing_audit_identity_or_stage')
    start = timestamp(event['requestReceivedTimestamp'])
    observed = timestamp(event.get('stageTimestamp') or event['requestReceivedTimestamp'])
    if observed < start:
        raise ValueError('stage_precedes_request')
    user = event.get('impersonatedUser') or event.get('user') or {}
    username = user.get('username','')
    parts = username.split(':')
    sa = len(parts)==4 and parts[:2]==['system','serviceaccount']
    subject = Subject(username=username,kind='service_account' if sa else 'user',
        namespace=parts[2] if sa else None,name=parts[3] if sa else username,
        uid=user.get('uid') or None,uid_status='verified' if user.get('uid') else 'unknown',
        groups=sorted(set(user.get('groups',[]))),identity_evidence_refs=['audit:'+event['auditID']])
    ref = event.get('objectRef') or {}
    parsed = urlsplit(event.get('requestURI',''))
    if ref.get('resource'):
        group, resource = ref.get('apiGroup',''), ref['resource']
        declared = resource_scopes.get(group+'/'+resource)
        namespace = ref.get('namespace') or None
        scope = 'namespaced' if namespace else 'all_namespaces' if declared=='namespaced' else 'cluster' if declared=='cluster' else 'unknown'
        # Response stages can add a created name; request identity comes from
        # the URL so stage enrichment cannot turn one create into two requests.
        parts=[unquote(part) for part in parsed.path.split('/') if part]
        prefix=3 if parts[:1]==['apis'] else 2
        index=prefix+2 if len(parts)>prefix+2 and parts[prefix]=='namespaces' else prefix
        name=parts[index+1] if len(parts)>index+1 else None
        selector = parse_qs(parsed.query).get('fieldSelector',[None])[0]
        key = RequestKey(kind='resource',verb=event['verb'],api_group=group,resource=resource,
            subresource=ref.get('subresource') or None,scope=scope,namespace=namespace,
            resource_name=name,name_resolution='explicit' if name else 'unknown' if selector else 'collection',
            name_field_selector=selector,non_resource_path=None)
    else:
        key = RequestKey(kind='non_resource',verb=event['verb'],api_group=None,resource=None,subresource=None,
            scope='non_resource',namespace=None,resource_name=None,name_resolution='not_applicable',
            name_field_selector=None,non_resource_path=parsed.path or '/')
    annotations = event.get('annotations') or {}
    decision = annotations.get('authorization.k8s.io/decision')
    code = (event.get('responseStatus') or {}).get('code')
    success = isinstance(code,int) and 200<=code<300
    if success and decision=='forbid':
        raise ValueError('contradictory_authorization_outcome')
    stage = event['stage']
    outcome = ('successful_completed' if stage=='ResponseComplete' and success else
               'denied' if decision=='forbid' else
               'authorized_error' if stage=='ResponseComplete' and decision=='allow' else
               'authorized_incomplete' if decision=='allow' or stage=='ResponseStarted' and success else 'unknown')
    identity = {'subject':subject.model_dump(mode='json'),'key':key.model_dump(mode='json'),'started_at':iso(start)}
    return {**identity,'audit_id':event['auditID'],'observed_at':iso(observed),'stage':stage,'outcome':outcome,
            'identity_hash':digest(identity),'completed_at':iso(observed) if stage=='ResponseComplete' else None,
            'authorized_at':iso(observed) if outcome.startswith('authorized_') or outcome=='successful_completed' else None}


def matches(actual, requested):
    """any_name projects across names/selectors; it never changes RBAC rules."""
    fields = ('kind','verb','api_group','resource','subresource','scope','namespace','non_resource_path')
    if any(actual.get(field)!=getattr(requested,field) for field in fields):
        return False
    if requested.name_resolution=='any_name':
        return True
    return all(actual.get(field)==getattr(requested,field) for field in ('resource_name','name_resolution','name_field_selector'))
