import html
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

st.set_page_config(page_title='Guardian · Cluster observability',page_icon='🛡️',layout='wide',initial_sidebar_state='collapsed')
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


def event_table(events,key):
    if not events:
        st.info('No matching observations in the retained sample.');return
    rows=[{'When':timestamp(e.get('timestamp') or e.get('observed_at')),'Pod':e.get('source_pod',{}).get('pod') or 'Shared identity','Activity':event_summary(e),'Source':e.get('source',''),'Result':event_result(e), 'Evidence ID':e['id'][:12]} for e in events]
    st.dataframe(rows,hide_index=True,width='stretch')
    with st.expander('Inspect an observation'):
        chosen=st.selectbox('Observation',list(range(len(events))),format_func=lambda i:rows[i]['When']+' · '+rows[i]['Activity'],key=key+'_event')
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
    for reason in result.get('reasons',[]):st.text('• '+reason)
    st.text('Uncertainty: '+result.get('uncertainty','Not reported'))
    if result.get('next_checks'):
        st.write('**Recommended human checks**')
        for check in result['next_checks']:st.text('• '+check)
    with st.expander('Cited evidence and collection coverage'):
        st.write(result.get('evidence_ids',[]))
        st.json({'attributed_evidence': result.get('evidence',[]), 'shared_identity_evidence': result.get('shared_identity_evidence',[])},expanded=False)
        st.json({'sample':result.get('sample'), 'coverage':result.get('coverage')},expanded=False)
    st.caption('0–2 low concern in the sample · 3–4 needs checking · 5–6 concerning · 7–8 dangerous · 9–10 critical. A low grade does not prove safety. No automated remediation.')


@st.fragment(run_every='10s')
def continuous_assessment(uid):
    data=api('/telemetry/reviews')
    worker=data['worker']
    st.caption('Continuous review: '+worker.get('state','unknown')+' · Checks for changed evidence every '+str(worker['interval_seconds'])+'s after each serial review cycle.'+(' Reviewing '+str(worker['current_pod']) if worker.get('current_pod') else ''))
    result=next((r for r in data['reviews'] if r['uid']==uid),None)
    if result:assessment_view(result)
    else:st.info('Awaiting the first background assessment of this pod. CPU model reviews run one at a time.')


@st.fragment(run_every='10s')
def alert_banner():
    # Cross-namespace alerts remain visible even while investigating one namespace.
    data=api('/telemetry/alerts')
    active=[a for a in data['alerts'] if a['active']]
    if active:
        st.error(str(len(active))+' pod alert(s) need human investigation · '+str(data['unread'])+' unread. Model assessments require verification.')
        for alert in active[:3]:
            label=html.escape(alert['namespace']+'/'+alert['pod'])
            url='/pod?'+urlencode({'namespace':alert['namespace'],'pod':alert['pod']})
            st.markdown('['+label+']('+url+') · severity **'+str(alert['severity'])+'/10**'+(' · acknowledged' if alert['acknowledged'] else ' · UNREAD'))
        st.markdown('[Open Alerts and acknowledge assessments](/alerts)')
    else:
        st.caption('Alerts: '+str(data['unread'])+' unread · Continuous review '+data['worker'].get('state','unknown')+' · In-dashboard notifications only')


def alerts_page():
    st.title('Pod alerts')
    st.write('Persistent local-model assessments. Acknowledgement marks an alert read; it does not revoke permissions or establish that the pod is safe.')
    @st.fragment(run_every='10s')
    def contents():
        data=api('/telemetry/alerts',ns_params())
        st.caption('Alert threshold: '+str(data['worker']['alert_threshold'])+'/10 · Notifications refresh every 10 seconds while this dashboard is open.')
        records=data['alerts']
        if not records:st.info('No alerts have been recorded for this namespace. Check the Reviews below for pending assessments or errors.')
        for alert in sorted(records,key=lambda a:(a['active'],not a['acknowledged'],a['severity']),reverse=True):
            with st.container(border=True):
                st.subheader(alert['namespace']+'/'+alert['pod'])
                st.write(('Active — needs investigation' if alert['active'] else 'Latest valid assessment is below the alert threshold')+' · '+('Acknowledged' if alert['acknowledged'] else ('Unread' if alert['active'] else 'Unacknowledged history')))
                current=next((p for p in all_pods if p.get('uid')==alert['uid']),None)
                if current is None:st.caption('Historical pod instance; this UID is absent from the current inventory.')
                assessment_view(alert)
                url='/pod?'+urlencode({'namespace':alert['namespace'],'pod':alert['pod']})
                st.markdown('[Open pod workspace]('+url+')')
                if not alert['acknowledged'] and st.button('Acknowledge',key='ack_'+alert['id']):
                    response=requests.post(BACKEND_URL+'/telemetry/alerts/'+quote(alert['id'],safe='')+'/acknowledge',json={'version':alert['version']},timeout=15)
                    if response.ok:st.cache_data.clear();st.rerun()
                    else:st.error('Alert changed or acknowledgement failed. Refresh and try again.')
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
    st.subheader('Request a fresh model review')
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
    st.title('Your cluster at a glance')
    st.write('Understand what workloads can do, what they have done, and where the evidence needs attention.')
    events=api('/telemetry/events',ns_params(limit=1000))['events']
    visible=[p for p in all_pods if not namespace or p['namespace']==namespace]
    flagged=[e for e in events if e.get('findings')]
    counts=api('/telemetry/counts',ns_params())
    kinds=counts.get('by_kind',{})
    a,b,c,d=st.columns(4)
    a.metric('Pods',len(visible));b.metric('Network flows',kinds.get('network',0));c.metric('API actions',kinds.get('kubernetes_audit',0));d.metric('Flagged events',counts.get('flagged_events',0))
    st.caption('Counters cover all retained observations in '+(namespace or 'all namespaces')+'. Recent activity and attention lists sample the latest 1,000 records. Counts are observations, not unique connections or risk scores.')
    st.caption('Retention is bounded by '+str(counts.get('max_events',0))+ ' events across the cluster and '+str(counts.get('retention_seconds',0)//86400)+' days, whichever limit is reached first.')
    if not kinds.get('network',0):
        st.info('No retained network observations match this namespace. Choose All namespaces to inspect other workloads, or generate application traffic and click Refresh data. Zero observations do not establish that no communication occurred.')
    left,right=st.columns([1.5,1])
    with left:
        st.subheader('Workloads to inspect')
        pod_counts=Counter((e.get('source_pod',{}).get('namespace'),e.get('source_pod',{}).get('pod')) for e in flagged)
        ordered=sorted(visible,key=lambda p:pod_counts[(p['namespace'],p['pod'])],reverse=True)
        for pod in ordered[:8]:
            with st.container(border=True):
                name,action=st.columns([2,1])
                name.markdown('**'+pod['pod']+'**')
                name.caption(pod['namespace']+' · '+str(pod.get('phase') or 'Unknown')+' · '+str(pod_counts[(pod['namespace'],pod['pod'])])+' flagged observations')
                if action.button('Open pod',key='open_'+pod['namespace']+'/'+pod['pod']):go_pod(pod)
    with right:
        st.subheader('What needs attention')
        counts=Counter(f for e in flagged for f in e.get('findings',[]))
        for flag,count in counts.most_common(7):
            st.write('**'+str(count)+' observations** · '+SIGNALS.get(flag,flag.replace('_',' ').capitalize()))
        if not counts:st.info('No flags in this sample. Check collection coverage before drawing a conclusion.')
        st.subheader('Collection coverage')
        for source,state in status.get('collectors',{}).items():
            state_name=state.get('state','unknown')
            st.write(('🟢 ' if state_name in ('ready','following') else '🟠 ')+source.title()+' · '+state_name)
            if state.get('error'):st.caption(state['error'])
        st.caption('Inventory snapshot: '+timestamp(inventory.get('observed_at')))


def connections():
    st.title('Pod connections')
    st.write('Explore observed communication. Select a node or link for details; open a pod workspace directly from the graph.')
    controls=st.columns([1,2])
    limit=controls[0].selectbox('Network sample', [500,1000,2500,5000],index=1)
    live=controls[1].toggle('Refresh every 10 seconds',value=False)
    @st.fragment(run_every='10s' if live else None)
    def graph_fragment():
        graph=api('/telemetry/graph',ns_params(limit=limit))
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
    with tabs[1]:render_graph(api('/telemetry/graph',{'namespace':ns,'limit':2500}),focus=(ns,pod))
    with tabs[2]:permission_view(identity)
    with tabs[3]:
        st.caption('Execution observed confirms a process event. Exit status describes process termination; kernel return values depend on the traced function. Outcome not captured means no return result was recorded.')
        event_table([e for e in events if e['kind'].startswith('process_')],'runtime')
    with tabs[4]:
        st.subheader('Actions attributed to this pod’s credentials');event_table([e for e in events if e['kind']=='kubernetes_audit'],'api_actions')
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


st.markdown('<div class="brand">GUARDIAN / CLUSTER OBSERVABILITY</div>',unsafe_allow_html=True)
status=api('/telemetry/status');inventory=api('/telemetry/pods');all_pods=inventory.get('pods',[])
bar1,bar2,bar3=st.columns([2,2,1])
bar1.caption('CONNECTED CLUSTER');bar1.write('**'+status.get('cluster','Unknown')+'**')
namespaces=['All namespaces']+sorted({p['namespace'] for p in all_pods})
default_index=namespaces.index('guardian-demo') if 'guardian-demo' in namespaces else 0
chosen_namespace=bar2.selectbox('Namespace',namespaces,index=default_index,key='global_namespace')
namespace=None if chosen_namespace=='All namespaces' else chosen_namespace
if bar3.button('Refresh data',width='stretch'):st.cache_data.clear();st.rerun()
nav_pages=[st.Page(overview,title='Overview',url_path='overview',default=True),st.Page(connections,title='Connections',url_path='connections')]
pod_page=st.Page(pod_workspace,title='Pod workspace',url_path='pod')
nav_pages.extend([pod_page,st.Page(permissions_page,title='Permissions',url_path='permissions'),st.Page(evidence_page,title='Evidence',url_path='evidence'),st.Page(llm_page,title='LLM review',url_path='review'),st.Page(alerts_page,title='Alerts',url_path='alerts')])
current_page=st.navigation(nav_pages,position='hidden')
links=[]
for item in nav_pages:
    href='/' if item.title=='Overview' else '/'+item.url_path
    selected=' class="active"' if item.title==current_page.title else ''
    links.append('<a href="'+href+'" target="_self"'+selected+'>'+html.escape(item.title)+'</a>')
st.markdown('<style>.guardian-nav{display:flex;gap:6px;flex-wrap:wrap;padding:12px 0 18px;border-bottom:1px solid #24344c;margin-bottom:22px}.guardian-nav a{color:#a9bdd2!important;padding:9px 12px;border-radius:7px;font-size:14px;text-decoration:none}.guardian-nav a:hover{background:#17283c}.guardian-nav a.active{background:#203a56;color:#eaf4ff!important;font-weight:600}</style><nav class="guardian-nav" aria-label="Guardian features">'+''.join(links)+'</nav>',unsafe_allow_html=True)
alert_banner()
current_page.run()
