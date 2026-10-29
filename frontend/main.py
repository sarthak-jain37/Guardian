import html
import time
import json
from pathlib import Path
import sys
from collections import Counter
from datetime import datetime
from urllib.parse import quote, urlencode

sys.path.insert(0,str(Path(__file__).resolve().parent.parent))
import requests
import streamlit as st
from backend.app.core.config import BACKEND_URL
from backend.app.services.pod_review import permission_points, event_summary, event_result, SIGNALS
from frontend.graph_view import render_graph
from frontend.analysis_workspace import workspace as analysis_workspace

st.set_page_config(page_title='Guardian · Cluster observability',page_icon='🛡️',layout='wide',initial_sidebar_state='collapsed')
# Refresh the whole page, including inventory and active pod details. Collection
# and model analysis run in the backend even without an open browser session.
st.session_state['_last_ui_render'] = time.monotonic()
@st.fragment(run_every='10s')
def refresh_dashboard():
    st.caption('Live monitoring · Page updates every 10 seconds · Collection and model reviews continue in the background.')
    if time.monotonic() - st.session_state['_last_ui_render'] >= 9:
        st.rerun(scope='app')

st.markdown('''<style>
.block-container{max-width:1480px;padding-top:2rem;padding-bottom:3rem}h1{font-size:2.1rem!important;letter-spacing:-.04em}h2{font-size:1.35rem!important;letter-spacing:-.02em}h3{font-size:1.1rem!important}.brand{font-size:12px;font-weight:650;letter-spacing:.16em;color:#7d9bb8;margin-bottom:12px}.muted{color:#8fa7bf}.pod-title{font-size:22px;font-weight:600;letter-spacing:-.025em}.eyebrow{font-size:11px;letter-spacing:.13em;color:#8ea7c0;text-transform:uppercase}.chip{display:inline-block;padding:4px 10px;border-radius:20px;background:rgba(85,169,144,.14);color:#72d7b8;font-size:12px;margin-right:5px}.chip.warn{background:rgba(224,168,84,.13);color:#e8bc77}[data-testid="stMetric"]{border:1px solid rgba(125,155,184,.2);border-radius:12px;padding:16px 19px;background:rgba(125,155,184,.035)}[data-testid="stMetricValue"]{font-size:1.8rem}div[data-testid="stVerticalBlockBorderWrapper"]>div{border-color:rgba(125,155,184,.2)}.stButton>button{border-radius:8px}[data-testid="stHeader"]{background:transparent}a{text-decoration:none}
</style>''',unsafe_allow_html=True)


@st.cache_data(ttl=5,show_spinner=False)
def fetch(path,params=None):
    response=requests.get(BACKEND_URL+path,params=params,timeout=25)
    response.raise_for_status()
    return response.json()


def api(path,params=None):
    try:return fetch(path,params)
    except (requests.RequestException,ValueError) as exc:
        st.error(f'Could not load cluster data: {exc}')
        st.caption('Check the backend and collector health, then refresh this page.')
        st.stop()


def ns_params(**extra):
    return {**({'namespace':namespace} if namespace else {}),**extra}


def timestamp(value):
    try:return datetime.fromisoformat(str(value).replace('Z','+00:00')).astimezone().strftime('%d %b %H:%M:%S')
    except (TypeError,ValueError):return value or 'Not reported'


def go_pod(pod):
    st.session_state['selected_pod']=(pod['namespace'],pod['pod'])
    if st.session_state.get('workspace_pod_picker') != (pod['namespace'],pod['pod']):
        st.session_state['workspace_pod_picker']=(pod['namespace'],pod['pod'])
    st.switch_page(pod_page,query_params={'namespace':pod['namespace'],'pod':pod['pod']})


def active_pod():
    choices={(p['namespace'],p['pod']):p for p in all_pods}
    requested=(st.query_params.get('namespace',''),st.query_params.get('pod',''))
    if requested in choices:st.session_state['selected_pod']=requested
    current=st.session_state.get('selected_pod')
    if current not in choices:
        visible=[p for p in all_pods if not namespace or p['namespace']==namespace]
        if not visible:
            st.info('No pods are available for this namespace. Check inventory collection.');st.stop()
        current=(visible[0]['namespace'],visible[0]['pod'])
    keys=list(choices)
    chosen=st.selectbox('Select a pod',keys,index=keys.index(current),format_func=lambda k:k[0]+'/'+k[1],key='workspace_pod_picker')
    st.session_state['selected_pod']=chosen
    return choices[chosen]


def readable_activity(event):
    kind=event.get('kind','')
    if kind=='pod_configuration_change':
        names={'container_statuses':'container health, readiness or restart status',
               'containers':'container image or settings','permissions':'service account permissions',
               'volumes':'attached storage','security_context':'security settings',
               'host_network':'host network setting','host_pid':'host process visibility',
               'host_ipc':'host IPC setting'}
        return 'Pod update: '+', '.join(names.get(k,k.replace('_',' ')) for k in event.get('changes',{}))
    if event.get('dns'):
        return 'Looked up the IP address for '+str(event['dns'].get('query','an unknown name'))
    if event.get('http'):
        http=event['http'];method=http.get('method','')
        action='Requested a web resource' if method=='GET' else 'Sent an HTTP '+method+' request'
        return action+': '+str(http.get('host') or '')+str(http.get('path') or '')
    if kind=='network':
        dest=event.get('destination_pod',{})
        return 'Network traffic to '+str(dest.get('pod') or dest.get('ip') or 'an unknown destination')
    return event_summary(event)


def readable_result(event):
    raw=event_result(event)
    return {'FORWARDED':'Allowed by the network', 'DROPPED':'Blocked or dropped by the network',
            'REDIRECTED':'Sent through a proxy for further handling', 'REJECTED':'Rejected',
            'success':'API request succeeded', 'denied':'API access denied',
            'other_or_unknown':'Outcome unknown', 'Change observed':'Update detected',
            'Execution observed':'Program execution detected', 'Outcome not captured':'Outcome unknown'}.get(raw,raw)


def event_table(events,key):
    if not events:
        st.info('No matching observations in the retained sample.');return
    rows=[{'When':timestamp(e.get('timestamp') or e.get('observed_at')),'Pod':e.get('source_pod',{}).get('pod') or 'Caller pod unknown','What happened':readable_activity(e),'Who did it':e.get('actor') or e.get('source_pod',{}).get('pod') or 'Not recorded','Pod instance':{'current':'Current UID','other':'Different UID','name_only':'Name only; UID not captured'}.get(e.get('instance_match'),'—'),'Collected by':{'hubble':'Hubble · network','tetragon':'Tetragon · runtime','audit':'Kubernetes audit log','inventory':'Pod settings and status check'}.get(e.get('source'),e.get('source','')),'Outcome':readable_result(e)} for e in events]
    st.dataframe(rows,hide_index=True,width='stretch')
    st.caption('Outcome means what the collector observed. Allowed traffic does not guarantee the destination received it or the application request succeeded.')
    with st.expander('What do these terms mean?'):
        st.markdown('**Allowed:** the network permitted the traffic. **Blocked/dropped:** traffic was stopped at the observation point. **Redirected:** traffic was sent through a proxy for inspection or routing; this is not automatically a failure. **Rejected:** a request was explicitly refused.')
        st.markdown('**Pod configuration** means its settings, such as image, permissions, storage and security options. **Container status** means its current condition, such as running, ready, restarting or stopped. A status update does not necessarily mean someone edited its settings.')
        st.markdown('**Outcome unknown:** the event was captured, but its final result was not. **Evidence ID:** a reference to the original event, available in the technical details below.')
    with st.expander('Inspect an observation · technical details'):

        chosen=st.selectbox('Observation',list(range(len(events))),format_func=lambda i:rows[i]['When']+' · '+rows[i]['What happened'],key=key+'_event')
        event=events[chosen]
        st.caption('Evidence ID: '+event['id'])
        for flag in event.get('findings',[]):st.write('• '+SIGNALS.get(flag,flag.replace('_',' ').capitalize()))
        st.json(event,expanded=False)


def permission_view(identity):
    points=permission_points(identity)
    if points:
        st.subheader('What this pod can do')
        for point in points[:12]:
            scope='across the cluster' if point['scope']=='*' else 'in '+str(point['scope'])
            restriction=(' · named resources: '+', '.join(point['resource_names'])) if point['resource_names'] else ''
            st.write('• '+point['summary']+' '+scope+restriction)
        if len(points)>12:st.caption(f'{len(points)-12} additional capabilities are listed below.')
        st.dataframe([{'Capability':p['summary'],'Scope':'Cluster-wide' if p['scope']=='*' else p['scope'],'Granted by':str(p['binding_kind'])+'/'+str(p['binding']),'Role':p['role'],'Named resources':', '.join(p['resource_names']) or 'Not restricted by name'} for p in points],hide_index=True,width='stretch')
    else:st.info('No workload-control or credential-access capabilities were identified in the current RBAC snapshot.')
    permissions=identity.get('permissions',{})
    st.caption('Identity: '+permissions.get('service_account','Unknown')+' · Permissions describe what may be requested, not proof of misuse.')
    if permissions.get('unresolved_bindings'):st.warning('Some bindings could not be resolved. This permission view is incomplete.')
    with st.expander('All granted access and binding provenance'):
        rows=[]
        for grant in permissions.get('grants',[]):
            rule=grant.get('rule',{})
            rows.append({'Actions':', '.join(rule.get('verbs',[])),'Resources':', '.join(rule.get('resources') or rule.get('nonResourceURLs',[])),'API groups':', '.join(rule.get('apiGroups',[])) or 'core','Scope':grant.get('scope'),'Role':grant.get('role_name'),'Binding':grant.get('binding_name')})
        st.dataframe(rows,hide_index=True,width='stretch')


def assessment_view(result):
    state=result.get('status','pending')
    severity=result.get('severity')
    if state=='error':
        st.error('Review error: the local model did not produce a valid assessment. No grade was assigned.')
    elif state=='insufficient_evidence':
        st.info('Insufficient evidence — no severity grade assigned.')
    elif state=='superseded':
        st.warning('This pod instance changed during review. Await a review of its current UID.')
    elif severity is not None:
        st.metric('Model-assessed severity',str(severity)+' / 10')
    st.caption('Assessed '+timestamp(result.get('reviewed_at'))+' · Pod UID: '+str(result.get('uid','unknown'))+' · Advisory model assessment requiring verification')
    history=result.get('history_summary',{})
    if history:
        st.write('**Recorded activity across retained history**')
        st.write(str(history.get('attributed_observations',0))+' observations · '+str(history.get('first_event') or 'No start time')+' to '+str(history.get('last_event') or 'No end time'))
        for action,count in history.get('api_actions',{}).items():st.write('• '+str(count)+' API observations: '+action)
        for outcome,count in history.get('network_outcomes',{}).items():st.write('• '+str(count)+' network observations: '+outcome)
        for binary,count in history.get('processes',{}).items():st.write('• '+str(count)+' runtime observations involving '+binary)
        st.caption('These are observation counts, not necessarily distinct requests or executions. History is limited by retention; lifecycle actions by other callers are kept separate.')
    st.write('**Activity explanation**')
    for reason in result.get('reasons',[]):st.text('• '+reason)
    st.text('Uncertainty: '+result.get('uncertainty','Not reported'))
    if result.get('next_checks'):
        st.write('**Recommended human checks**')
        for check in result['next_checks']:st.text('• '+check)
    if result.get('next_review_due_at'):st.caption('Next review due: '+timestamp(result['next_review_due_at']))
    with st.expander('Retained history used for this assessment'):
        st.json(result.get('history_summary',{}),expanded=True)
    with st.expander('Cited evidence and collection coverage'):
        st.write(result.get('evidence_ids',[]))
        st.json({'attributed_evidence': result.get('evidence',[]), 'shared_identity_evidence': result.get('shared_identity_evidence',[])},expanded=False)
        st.json({'sample':result.get('sample'), 'coverage':result.get('coverage')},expanded=False)
    st.caption('0–2 low concern in the sample · 3–4 needs checking · 5–6 concerning · 7–8 dangerous · 9–10 critical. A low grade does not prove safety. No automated remediation.')


@st.fragment(run_every='10s')
def continuous_assessment(uid):
    data=api('/telemetry/reviews')
    worker=data['worker']
    st.caption('Continuous review: '+worker.get('state','unknown')+' · Each pod is scheduled every '+str(worker['interval_seconds'])+' seconds. '+str(worker.get('overdue_pods',0))+' overdue; '+str(worker.get('queued_pods',0))+' queued.'+(' Reviewing '+str(worker['current_pod']) if worker.get('current_pod') else ''))
    result=next((r for r in data['reviews'] if r['uid']==uid),None)
    if result:
        assessment_view(result)
        alerts=api('/telemetry/alerts').get('alerts',[])
        previous=next((a for a in alerts if a.get('uid')==uid and a.get('historical') and a.get('active')),None)
        if previous:st.warning('Unresolved previous warning: '+str(previous['severity'])+'/10 assessed '+timestamp(previous['reviewed_at'])+'. This historical score is not the current review result.')
    else:st.info('Awaiting the first background assessment of this pod. CPU model reviews run one at a time.')


def permission_proposal_view(proposal):
    with st.expander('Permission proposal · '+proposal['status']+' · '+proposal['namespace']+'/'+proposal['pod'],expanded=proposal['status']=='pending'):
        st.write(proposal.get('explanation',''))
        if proposal.get('affected_pods'):st.warning('Affected pods sharing the service account: '+', '.join(proposal['affected_pods']))
        for limitation in proposal.get('limitations',[]):st.caption(limitation)
        for change in proposal.get('changes',[]):
            st.write('**'+change['kind']+'/'+change['name']+'**')
            left,right=st.columns(2)
            with left:st.caption('Current configuration at proposal time');st.json(change['before'],expanded=False)
            with right:st.caption('Proposed configuration');st.json(change['after'],expanded=False)
        if proposal['status']=='pending':
            st.info('This is a legacy draft. Applying changes is disabled while authenticated governed review and verification are integrated.')
        if proposal.get('error'):st.error(proposal['error'])
        if proposal.get('receipt'):
            with st.expander('Execution receipt'):st.json(proposal['receipt'])


def alerts_page():
    st.title('Pod alerts')
    st.write('Persistent local-model assessments. Acknowledgement marks an alert read; it does not revoke permissions or establish that the pod is safe.')
    @st.fragment(run_every='10s')
    def contents():
        data=api('/telemetry/alerts')
        st.caption('Alerts cover all namespaces so critical pods are always visible.')
        st.caption('Alert threshold: '+str(data['worker']['alert_threshold'])+'/10 · Notifications refresh every 10 seconds while this dashboard is open.')
        records=data['alerts']
        proposals=api('/telemetry/permission-proposals').get('proposals',[])
        critical=[a for a in records if a.get('active') and not a.get('historical') and a.get('severity',0)>8 and a.get('critical_confirmed')]
        if critical:st.error('CRITICAL · '+str(len(critical))+' pod(s) scored 9–10/10 after corroboration and a second model check. Review the permission proposals below.')
        if not records:st.info('No alerts have been recorded for this namespace. Check the Reviews below for pending assessments or errors.')
        for alert in sorted(records,key=lambda a:(a['active'],not a['acknowledged'],a['severity']),reverse=True):
            with st.container(border=True):
                if alert.get('severity',0)>8 and alert.get('critical_confirmed') and not alert.get('historical'):st.error('CRITICAL · '+alert['namespace']+'/'+alert['pod']+' · '+str(alert['severity'])+'/10')
                else:st.subheader(alert['namespace']+'/'+alert['pod'])
                st.write(('Unresolved historical warning — previous score '+str(alert['severity'])+'/10' if alert.get('historical') else 'Active — needs investigation' if alert['active'] else 'Latest valid assessment is below the alert threshold')+' · '+('Acknowledged' if alert['acknowledged'] else ('Unread' if alert['active'] else 'Unacknowledged history')))
                current=next((p for p in all_pods if p.get('uid')==alert['uid']),None)
                if current is None:st.caption('Historical pod instance; this UID is absent from the current inventory.')
                if alert.get('historical'):
                    latest=alert.get('latest_review')
                    st.warning(str(alert.get('history_reason'))+'. The previous score below is not a current assessment.')
                    if latest:
                        st.caption('Latest review: '+timestamp(latest['reviewed_at'])+' · '+latest['status'].replace('_',' '))
                        assessment_view(latest)
                    else:st.info('Current assessment unavailable.')
                    with st.expander('Previous warning · '+timestamp(alert['reviewed_at'])+' · '+str(alert['severity'])+'/10'):
                        if alert.get('assessment_version')!=2:st.caption('Legacy model output; not revalidated by the current review pipeline.')
                        assessment_view(alert)
                else:assessment_view(alert)
                url='/pod?'+urlencode({'namespace':alert['namespace'],'pod':alert['pod']})
                st.markdown('[Open pod workspace]('+url+')')
                for proposal in proposals:
                    if proposal['uid']==alert['uid']:permission_proposal_view(proposal)
                if not alert['acknowledged'] and st.button('Acknowledge',key='ack_'+alert['id']):
                    response=requests.post(BACKEND_URL+'/telemetry/alerts/'+quote(alert['id'],safe='')+'/acknowledge',json={'version':alert['version']},timeout=15)
                    if response.ok:st.cache_data.clear();st.rerun()
                    else:st.error('Alert changed or acknowledgement failed. Refresh and try again.')
        with st.expander('Permission decisions and execution log'):
            history=api('/telemetry/permission-proposals/history').get('history',[])
            if history:
                st.dataframe([{'When':timestamp(h['timestamp']),'Proposal':h['proposal_id'],'Event':h['event'],'Actor':h['details'].get('actor',''),'Decision':h['details'].get('decision',''),'Status':h['details'].get('status',''),'Note':h['details'].get('note','')} for h in history],hide_index=True,width='stretch')
                st.json(history,expanded=False)
            else:st.info('No permission decisions yet.')
        if st.session_state.get('permission_decision_receipt'):
            receipt=st.session_state['permission_decision_receipt']
            st.info('Last permission decision: '+receipt['status']+(' · '+receipt.get('error','') if receipt.get('error') else ''))
        st.subheader('Continuous pod reviews')
        reviews=api('/telemetry/reviews',ns_params())
        st.json(reviews['worker'],expanded=False)
        st.dataframe([{'Pod':r['namespace']+'/'+r['pod'],'Status':r['status'],'Severity /10':r.get('severity'),'Assessed':timestamp(r['reviewed_at']),'UID':r['uid']} for r in reviews['reviews']],hide_index=True,width='stretch')
    contents()


def review_panel(identity):
    ns,pod=identity['namespace'],identity['pod']
    path='/telemetry/pods/'+quote(ns,safe='')+'/'+quote(pod,safe='')
    st.subheader('Continuous severity assessment')
    continuous_assessment(identity.get('uid'))
    st.caption('Automatic analysis runs without clicking Analyze. The optional controls below request an extra review.')
    st.subheader('Optional additional review')
    st.write('Ask about this pod’s behavior. The review combines its permissions, distinct observed actions, configured boundaries and collection gaps.')
    question=st.text_area('What do you want to understand?',value='Assess whether this pod needs investigation. Explain what the evidence proves and what remains uncertain.',height=90,key='question_'+ns+'/'+pod)
    count=st.select_slider('Evidence records to sample',options=[3,5,8,12,20,30],value=8,key='review_limit_'+ns+'/'+pod)
    context=api(path+'/review-context',{'limit':count})
    sample=context.get('sample',{})
    a,b,c=st.columns(3);a.metric('Selected observations',sample.get('selected',0));b.metric('Retained pod observations',sample.get('retained_attributed_events',0));c.metric('Shared-identity observations',sample.get('shared_identity_events',0))
    st.caption('Distinct actions are sampled so repeated network records do not hide process or API evidence. Shared-identity activity remains separate.')
    with st.expander('Evidence that will be sent to the model'):
        st.dataframe([{'ID':e['id'][:12],'Activity':e['description'],'Source':e['source'],'When':timestamp(e.get('timestamp'))} for e in context.get('events',[])],hide_index=True,width='stretch')
        st.download_button('Download review evidence',json.dumps(context,indent=2),file_name=pod+'-review-evidence.json',mime='application/json')
    if st.button('Analyze '+pod,type='primary',key='analyze_'+ns+'/'+pod):
        try:
            with st.spinner('Reviewing this pod’s evidence locally. CPU inference can take a minute...'):
                response=requests.post(BACKEND_URL+path+'/review',json={'question':question,'event_limit':count},timeout=300)
            if not response.ok:
                try:message=response.json().get('detail',response.text)
                except ValueError:message=response.text
                st.error(str(message))
            else:st.session_state['review_'+ns+'/'+pod]=response.json()
        except requests.RequestException as exc:st.error('The local model did not complete: '+str(exc))
    result=st.session_state.get('review_'+ns+'/'+pod)
    if result:
        st.subheader('Requested assessment')
        assessment_view(result)


def overview():
    st.title('All pods')
    st.caption('Open a pod to inspect its live configuration, access grants and related resources.')
    pods=all_pods
    st.caption('Showing every namespace. The namespace filter applies to the other pages.')
    st.caption(str(len(pods))+' pods · Inventory snapshot: '+timestamp(inventory.get('observed_at')))
    if not pods:
        st.info('No pods found in the cluster inventory.')
    for identity in sorted(pods,key=lambda p:(p['namespace'],p['pod'])):
        ns,name=identity['namespace'],identity['pod']
        card_key='configuration_'+str(identity.get('uid') or ns+'/'+name)
        opened=st.session_state.get(card_key,False)
        label=('▾ ' if opened else '▸ ')+ns+' / '+name+' · '+str(identity.get('phase') or 'Unknown')
        label+='  ·  Node: '+str(identity.get('node') or 'Pending')+'  ·  Service account: '+identity.get('service_account_name','default')
        with st.container(border=True):
            if st.button(label,key='card_'+card_key,width='stretch',type='primary' if opened else 'secondary',help='Click anywhere on this card header to show or hide configuration'):
                st.session_state[card_key]=not opened
                st.rerun()
            if opened:
                path='/telemetry/pods/'+quote(ns,safe='')+'/'+quote(name,safe='')+'/configuration'
                try:
                    details=fetch(path)
                except (requests.RequestException,ValueError) as exc:
                    st.error('Could not load this pod configuration: '+str(exc))
                    continue
                for warning in details.get('warnings',[]):st.warning(warning)
                tabs=st.tabs(['Pod configuration','Roles','Role bindings','Deployments and owners','Services'])
                with tabs[0]:st.json(details['pod'],expanded=True)
                for tab,key,empty in [(tabs[1],'roles','No bound roles found.'),(tabs[2],'bindings','No role bindings found.'),(tabs[3],'workloads','No supported workload owner found; this may be a standalone pod.'),(tabs[4],'services','No services select this pod.')]:
                    with tab:
                        if not details[key]:st.info(empty)
                        for obj in details[key]:
                            st.write('**'+obj.get('kind',key.title())+' / '+obj['metadata']['name']+'**')
                            st.json(obj,expanded=True)
                if details['permissions'].get('unresolved_bindings'):
                    st.warning('Some referenced roles could not be resolved.')


def connections():
    st.title('Pod connections')
    st.write('Explore observed network traffic and pod-to-node relationships. Dashed links show scheduling; solid links show recorded traffic.')
    connection_view=st.radio('Connection type',['Both','Hubble traffic','Pod-to-node relationships'],horizontal=True,key='connection_type')
    st.caption({'Both':'Solid links: observed Hubble traffic. Dashed links: scheduling relationships from Kubernetes inventory.','Hubble traffic':'Only network connections recorded by Hubble. Pods without recorded traffic are hidden.','Pod-to-node relationships':'Only pod scheduling relationships from Kubernetes inventory. These links do not represent network traffic.'}[connection_view])
    controls=st.columns([1,2])
    limit=controls[0].selectbox('Network sample', [500,1000,2500,5000],index=1)
    live=controls[1].toggle('Refresh every 10 seconds',value=True)
    @st.fragment(run_every='10s' if live else None)
    def graph_fragment():
        graph=api('/telemetry/graph',{'limit':limit})
        if connection_view!='Both':
            topology=connection_view=='Pod-to-node relationships'
            selected_edges=[e for e in graph['edges'] if (e.get('kind')=='topology')==topology]
            visible_ids={e[k] for e in selected_edges for k in ('source','target')}
            graph={**graph,'edges':selected_edges,'nodes':[n for n in graph['nodes'] if n['id'] in visible_ids]}
        a,b,c=st.columns(3);a.metric('Endpoints',len(graph['nodes']));b.metric('Directed links',len(graph['edges']));c.metric('Drop observations',sum(e['drops'] for e in graph['edges']))
        render_graph(graph)
    graph_fragment()


def pod_workspace():
    identity=active_pod();ns,pod=identity['namespace'],identity['pod']
    st.caption('POD WORKSPACE / '+ns)
    st.title(pod)
    a,b,c,d=st.columns(4)
    a.metric('Phase',identity.get('phase') or 'Unknown');b.metric('Containers',len(identity.get('containers',[])));c.metric('Restarts',sum(c.get('restartCount',0) for c in identity.get('container_statuses',[])));d.metric('Node',identity.get('node') or 'Not assigned')
    st.caption('Service account: '+identity.get('service_account_name','default')+' · Pod UID: '+str(identity.get('uid')))
    path='/telemetry/pods/'+quote(ns,safe='')+'/'+quote(pod,safe='')
    evidence=api(path+'/evidence',{'limit':500})
    records=evidence.get('pods',[])
    record=records[0] if records else {'events':[],'shared_identity_audit_events':[]}
    events=record.get('events',[])
    tabs=st.tabs(['Summary','Connections','Permissions','Runtime and files','Kubernetes actions','HTTP and DNS','Configuration','LLM review'])
    with tabs[0]:
        st.subheader('Observed behavior that needs attention')
        flags=Counter(f for event in events for f in event.get('findings',[]))
        for flag,count in flags.most_common(12):st.write('• '+SIGNALS.get(flag,flag.replace('_',' ').capitalize())+' — '+str(count)+' observations')
        if not flags:st.info('No flags in this retained sample. This is not a statement that the pod is safe.')
        st.subheader('Recent activity');event_table(events[:20],'pod_summary')
        shared=record.get('shared_identity_audit_events',[])
        if shared:st.warning(str(len(shared))+' sampled audit events use the same service account but cannot be confidently attributed to this pod.')
        st.subheader('Actions affecting this pod · including creation and deletion')
        st.caption('Requests made by users and controllers about this pod. History includes previous instances with the same namespace and name. It is separate from actions performed by this pod; a name-only match does not identify a specific instance.')
        event_table(record.get('actions_affecting_pod',[]),'pod_lifecycle')
    with tabs[1]:render_graph(api('/telemetry/graph',{'namespace':ns,'limit':2500}),focus=(ns,pod))
    with tabs[2]:permission_view(identity)
    with tabs[3]:
        st.caption('Execution observed confirms a process event. Exit status describes process termination; kernel return values depend on the traced function. Outcome not captured means no return result was recorded.')
        event_table([e for e in events if e['kind'].startswith('process_')],'runtime')
    with tabs[4]:
        st.subheader('Actions attributed to this pod’s credentials');event_table([e for e in events if e['kind']=='kubernetes_audit'],'api_actions')
        st.subheader('Actions by users and controllers affecting this pod');event_table(record.get('actions_affecting_pod',[]),'api_target_actions')
        with st.expander('Shared service-account activity with uncertain pod attribution'):event_table(record.get('shared_identity_audit_events',[]),'shared_api')
    with tabs[5]:event_table([e for e in events if e.get('http') or e.get('dns')],'http_dns')
    with tabs[6]:
        st.subheader('Container configuration')
        for container in identity.get('containers',[]):
            st.write('**'+container['name']+'** · '+str(container.get('image')))
            security=container.get('security_context') or {}
            st.write('• Privileged: '+str(security.get('privileged',False))+' · Privilege escalation: '+str(security.get('allowPrivilegeEscalation','not specified')))
            st.write('• Run as user: '+str(security.get('runAsUser',(identity.get('security_context') or {}).get('runAsUser','image default'))))
            st.json({'security_context':security,'resources':container.get('resources',{}),'mounts':container.get('volume_mounts',[])},expanded=False)
        st.write('Host access: network '+str(identity.get('host_network'))+' · PID '+str(identity.get('host_pid'))+' · IPC '+str(identity.get('host_ipc')))
        st.subheader('Configuration and status changes');event_table([e for e in events if e['kind']=='pod_configuration_change'],'config')
        st.download_button('Download complete pod evidence',json.dumps(evidence,indent=2),file_name=pod+'-evidence.json',mime='application/json')
    with tabs[7]:review_panel(identity)


def permissions_page():
    st.title('Pod permissions')
    st.write('See the actions each workload identity can request, the namespace it can affect, and the binding that grants access.')
    identity=active_pod();permission_view(identity)
    if st.button('Open full pod workspace',type='primary'):go_pod(identity)
    with st.expander('RBAC changes across the cluster'):
        drift=api('/outputs/').get('events',[])
        if not drift:st.info('No RBAC drift events have been recorded.')
        for event in drift[-10:]:
            st.write('**'+timestamp(event.get('timestamp'))+'**')
            st.json(event.get('diff'),expanded=False)
            if event.get('llm_response'):st.write(event['llm_response'])


def evidence_page():
    st.title('Evidence explorer')
    st.write('Inspect the recorded facts behind a finding. Each observation keeps its source, time and evidence ID.')
    a,b,c=st.columns([2,1,1])
    kind=a.selectbox('Activity type',{'All activity':'','Network':'network','Kubernetes API':'kubernetes_audit','Process execution':'process_exec','Process exit':'process_exit','Kernel operations':'process_kprobe','Configuration changes':'pod_configuration_change'})
    mapping={'All activity':'','Network':'network','Kubernetes API':'kubernetes_audit','Process execution':'process_exec','Process exit':'process_exit','Kernel operations':'process_kprobe','Configuration changes':'pod_configuration_change'}
    limit=b.selectbox('Record limit',[100,500,1000],index=1)
    flagged=c.toggle('Flagged observations only',False)
    params=ns_params(limit=limit)
    if mapping[kind]:params['kind']=mapping[kind]
    events=api('/telemetry/events',params)['events']
    if flagged:events=[e for e in events if e.get('findings')]
    event_table(events,'explorer')


def llm_page():
    st.title('Pod reasoning')
    identity=active_pod();review_panel(identity)


def approval_queue_page():
    st.title('HITL Approval Queue')
    st.write('Review detected RBAC drift and newly proposed policies. Every change requires human sign-off; the AI explains and advises.')

    top_col, scan_col = st.columns([3, 1])
    with scan_col:
        if st.button('Scan for drift now', type='secondary', width='stretch'):
            try:
                res = requests.post(BACKEND_URL + '/drift/scan-now', timeout=30)
                if res.ok:
                    data = res.json()
                    st.success(f"Scan complete: {data.get('findings_count', 0)} drift finding(s)")
                    st.cache_data.clear()
                    st.rerun()
                else:
                    st.error(f"Scan failed: {res.text}")
            except Exception as e:
                st.error(f"Could not trigger scan: {e}")

    queue_data = api('/approval/queue')
    entries = queue_data.get('entries', [])

    crit = sum(1 for e in entries if e.get('risk_tier') == 'CRITICAL')
    high = sum(1 for e in entries if e.get('risk_tier') == 'HIGH')
    low = sum(1 for e in entries if e.get('risk_tier') == 'LOW')

    m1, m2, m3, m4 = st.columns(4)
    m1.metric('Pending approvals', len(entries))
    m2.metric('Critical risk', crit)
    m3.metric('High risk', high)
    m4.metric('Low risk', low)

    if not entries:
        st.success('Approval queue is clean. No pending drifts require review.')
        return

    st.subheader('Pending drift findings and policy proposals')
    for entry in entries:
        qid = entry['id']
        tier = entry.get('risk_tier', 'LOW')
        badge_color = 'red' if tier == 'CRITICAL' else ('orange' if tier == 'HIGH' else 'green')
        sa = entry.get('sa_key', '__CLUSTER__')
        count = entry.get('version_count', 1)

        with st.container(border=True):
            header_col, action_col = st.columns([2.5, 1.5])
            with header_col:
                st.markdown(f"**:{badge_color}[{tier}]** · `{sa}`")
                st.caption(f"Event: {entry.get('event_type', 'DRIFT_DETECTED')} · Created: {timestamp(entry.get('created_at'))} · Accumulated versions: {count}")
                if count > 1:
                    st.info(f"Collapsed: {count} changes accumulated before review. Default view shows net diff.")

            with action_col:
                st.info('Legacy finding · read only. Governed review is being integrated; no changes can be applied here.')

            st.markdown("**LLM Security Explanation**")
            st.write(entry.get('llm_analysis') or 'No LLM analysis available.')

            st.markdown("**Net Diff (Original Baseline vs Latest Live State)**")
            st.json(entry.get('net_diff') or entry.get('diff_summary'), expanded=False)

            chain = entry.get('version_chain') or []
            if chain and len(chain) > 1:
                with st.expander(f"View Full Report ({len(chain)} intermediate changes)"):
                    st.caption('Evolutionary history of changes for this role:')
                    for item in chain:
                        ver = item.get('version')
                        sev = item.get('severity', 'LOW')
                        conf = item.get('confidence', 0.9)
                        ts = timestamp(item.get('timestamp'))
                        st.markdown(f"**Version {ver}** · Severity: `{sev}` · Confidence: `{conf}` · Timestamp: `{ts}`")
                        st.json(item.get('diff_from_prev'), expanded=False)

    with st.expander("Legacy Baseline & Version History"):
        try:
            active_res = requests.get(BACKEND_URL + '/baselines/active', timeout=10)
            if active_res.ok:
                act = active_res.json()
                st.subheader(f"Legacy Recorded Baseline (Version {act.get('version_number', '1')})")
                col_a, col_b = st.columns([3, 1])
                with col_a:
                    st.write(f"**Baseline ID**: `{act.get('baseline_id')}`")
                    st.write(f"**Canonical Hash**: `{act.get('canonical_hash')}`")
                    st.caption(f"Applied at: {timestamp(act.get('applied_at'))} · Approved by: {act.get('approved_by') or 'system'}")
                with col_b:
                    st.caption('Legacy history; approval authority has not been verified. General baseline rollback is retired.')
            else:
                st.info("No active baseline currently recorded.")

            hist_res = requests.get(BACKEND_URL + '/baselines/history', timeout=10)
            if hist_res.ok:
                history = hist_res.json().get('history', [])
                if history:
                    st.markdown("**Version History Audit Trail**")
                    rows = []
                    for h in history:
                        rows.append({
                            "Version": f"v{h.get('version_number')}",
                            "Status": h.get('status'),
                            "Applied At": timestamp(h.get('applied_at')),
                            "Approved By": h.get('approved_by') or "system",
                            "Baseline ID": h.get('baseline_id'),
                            "Canonical Hash": (h.get('canonical_hash') or '')[:16] + "...",
                        })
                    st.dataframe(rows, hide_index=True, width='stretch')
        except Exception as e:
            st.caption(f"Could not load baseline history: {e}")



st.markdown('<div class="brand">GUARDIAN / CLUSTER OBSERVABILITY</div>',unsafe_allow_html=True)
nav_pages=[st.Page(overview,title='All pods',url_path='overview',default=True),st.Page(connections,title='Connections',url_path='connections')]
pod_page=st.Page(pod_workspace,title='Pod workspace',url_path='pod')
approval_page=st.Page(approval_queue_page,title='Approval queue',url_path='approval')
analysis_page=st.Page(analysis_workspace,title='Analysis and review',url_path='analysis')
nav_pages.extend([analysis_page,pod_page,approval_page,st.Page(permissions_page,title='Permissions',url_path='permissions'),st.Page(evidence_page,title='Evidence',url_path='evidence'),st.Page(llm_page,title='LLM review',url_path='review'),st.Page(alerts_page,title='Alerts',url_path='alerts')])
current_page=st.navigation(nav_pages,position='hidden')
links=[]
for item in nav_pages:
    href='/' if item.title=='Overview' else '/'+item.url_path
    selected=' class="active"' if item.title==current_page.title else ''
    links.append('<a href="'+href+'" target="_self"'+selected+'>'+html.escape(item.title)+'</a>')
st.markdown('<style>.guardian-nav{display:flex;gap:6px;flex-wrap:wrap;padding:12px 0 18px;border-bottom:1px solid #24344c;margin-bottom:22px}.guardian-nav a{color:#a9bdd2!important;padding:9px 12px;border-radius:7px;font-size:14px;text-decoration:none}.guardian-nav a:hover{background:#17283c}.guardian-nav a.active{background:#203a56;color:#eaf4ff!important;font-weight:600}</style><nav class="guardian-nav" aria-label="Guardian features">'+''.join(links)+'</nav>',unsafe_allow_html=True)
if current_page.title=='Analysis and review':
    current_page.run()
    st.stop()
refresh_dashboard()
status=api('/telemetry/status');inventory=api('/telemetry/pods');all_pods=inventory.get('pods',[])
bar1,bar2,bar3=st.columns([2,2,1])
bar1.caption('CONNECTED CLUSTER');bar1.write('**'+status.get('cluster','Unknown')+'**')
namespaces=['All namespaces']+sorted({p['namespace'] for p in all_pods})
default_index=namespaces.index('guardian-demo') if 'guardian-demo' in namespaces else 0
chosen_namespace=bar2.selectbox('Namespace',namespaces,index=default_index,key='global_namespace')
namespace=None if chosen_namespace=='All namespaces' else chosen_namespace
if bar3.button('Refresh data',width='stretch'):st.cache_data.clear();st.rerun()
current_page.run()
