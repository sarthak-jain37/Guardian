"""Authenticated exact-report review, including report-only blocked analyses."""
from datetime import datetime,timedelta,timezone
from uuid import uuid4
import streamlit as st
from backend.app.core.config import BACKEND_URL
from frontend.review_client import ReviewClient


def workspace():
    st.title('Analysis and review')
    st.caption('Analyse a dedicated namespaced Role, inspect evidence and record your review. Cluster changes are disabled.')
    token=st.text_input('Reviewer access token',type='password',key='guardian_review_token',
        help='Use your operator-issued credential. It is kept only in this browser session.')
    if not token:
        st.info('Enter a reviewer credential to open your authorized namespaces.');return
    client=ReviewClient(BACKEND_URL,token)
    try:
        identity=client.call('GET','/governance/me')['principal']
        scopes=[g for g in identity['grants'] if 'read' in g['permissions']]
        if not scopes:st.info('This credential has no readable namespace.');return
        scope=st.selectbox('Authorized cluster / namespace',scopes,
            format_func=lambda g:g['cluster_id']+' / '+g['namespace'])
        params={'cluster_id':scope['cluster_id'],'namespace':scope['namespace']}
        can_review=identity['kind']=='human' and 'review' in scope['permissions']
        st.caption('Signed in as '+identity['actor'])
        if st.button('Refresh reports'):st.rerun()
        if st.checkbox('Start an analysis',key='guardian_show_intake'):
            if can_review:
                progress=client.call('GET','/evidence/status',params=params)['processed_through']
                if progress:st.caption('The observation window ends at the collector watermark: '+progress)
                else:st.caption('No collection watermark is available. Missing coverage will remain visible in the report.')
                roles=client.call('GET','/evidence/roles',params=params)['roles']
                if not roles:st.info('No readable Roles were found in this namespace.')
                else:
                    with st.form('analysis_intake'):
                        role=st.selectbox('Role',roles,format_func=lambda r:r['name'])
                        hours=st.number_input('Observation window (hours)',min_value=1,max_value=2160,value=168)
                        note=st.text_area('Optional workload context',max_chars=2000,
                            help='Describe rare or scheduled work. You do not need to identify unused permissions.')
                        if st.form_submit_button('Queue analysis'):
                            now=datetime.now(timezone.utc)
                            end=min(now,datetime.fromisoformat(progress.replace('Z','+00:00'))) if progress else now
                            result=client.call('POST','/analysis/runs',body={**params,'role_name':role['name'],
                                'window':{'start':(end-timedelta(hours=hours)).isoformat(),'end':end.isoformat()},
                                'idempotency_key':'ui-'+uuid4().hex,'trigger':'initial','context_note':note})
                            st.session_state['guardian_selected_run']=result['run_id'];st.rerun()
            else:st.info('A human credential with review permission is needed to start analyses.')
        runs=client.call('GET','/analysis/runs',params=params)['runs']
        if not runs:st.info('No analyses have been requested in this namespace.');return
        ids=[r['run_id'] for r in runs];by_id={r['run_id']:r for r in runs}
        selected=st.session_state.get('guardian_selected_run')
        run_id=st.selectbox('Analysis',ids,index=ids.index(selected) if selected in ids else 0,
            format_func=lambda rid:by_id[rid]['role_name']+' · revision '+str(by_id[rid]['revision'])+' · '+by_id[rid]['status']+' · '+rid[-8:])
        st.session_state['guardian_selected_run']=run_id
        run=client.call('GET','/analysis/runs/'+run_id)
        st.write('**'+run['role_name']+' · revision '+str(run['revision'])+'**')
        st.caption('Case: '+run['case_id']+' · Requested by '+run['actor']+' · '+run['created_at'])
        if run['error']:st.warning(run['error'])
        if run['status']!='DONE':
            st.info('Analysis status: '+run['status']+'. Refresh to check progress.')
        report=run['report']
        if report:
            st.write('**Analysis result: '+report['status']+'**')
            if report['reason']:st.warning(report['reason'])
            st.caption('Model: '+report['producer']+' / '+run['model_config']['model_name']+
                ' · '+report['model_status']+' · calls '+str(report['model_calls']))
            if report['investigation']:
                st.write(report['investigation']['summary'])
                for uncertainty in report['investigation']['uncertainty']:st.caption(uncertainty)
                for question in report['investigation']['questions']:st.info(question)
            facts=[{'Resource':f['api_group']+'/'+f['resource'],'Verb':f['verb'],'Authorized use':f['authorized_use'],
                'Protected':f['protected'],'Candidate':f['eligible'],'Reasons':', '.join(f['reason_codes'])} for f in report['facts']]
            if facts:st.dataframe(facts,hide_index=True,width='stretch')
            if report['readiness']:
                with st.expander('Readiness checks'):
                    st.dataframe([{'Check':g['gate_id'],'Result':g['result'],'Reasons':', '.join(g['reasons'])}
                        for g in report['readiness']['gates']],hide_index=True,width='stretch')
            if run['proposal']:
                st.subheader('Exact proposed change')
                st.code(run['proposal']['diff'],language='diff')
                st.caption('Preview only. No change has been authorized or applied.')
                with st.expander('Proposed Role and unchanged binding'):st.json(run['proposal'])
            else:st.info('No supported permission removal was proposed. Review the evidence and missing context above.')
            st.write('Report review: **'+str(run['review_state'])+'**')
            st.caption('Review deadline: '+str(run['review_expires']))
            st.button('Approve changes (unavailable)',disabled=True)
            if can_review and run['review_state']=='OPEN':
                with st.form('report_decision_'+run_id):
                    kind=st.selectbox('Review action',['acknowledge','reject','request_context'],
                        format_func=lambda k:{'acknowledge':'Acknowledge report','reject':'Reject report','request_context':'Request context and fresh analysis'}[k])
                    note=st.text_area('Review note or additional context',max_chars=2000)
                    if st.form_submit_button('Record my review'):
                        value=client.call('POST',f'/analysis/runs/{run_id}/decisions',body={'kind':kind,
                            'expected_revision':run['revision'],'expected_report_hash':run['report_hash'],
                            'idempotency_key':'ui-review-'+uuid4().hex,'note':note})
                        if value['successor_run_id']:st.session_state['guardian_selected_run']=value['successor_run_id']
                        st.rerun()
            if run['decision']:
                st.success(run['decision']['kind']+' recorded by '+run['decision']['actor'])
                st.caption('Original analysis is preserved. Review outcome: '+run['decision']['review_outcome'])
        if run['request']:
            with st.expander('Usage coverage, inventory and provenance'):
                evidence=client.call('GET','/evidence/snapshots/'+run['request']['snapshot_id'])
                usage=evidence.get('usage')
                if usage:
                    st.write('Actual query window: '+usage['query_window']['start']+' → '+usage['query_window']['end'])
                    st.caption('Processed through: '+str(usage['processed_through'])+' · '+str(run['retention_state']))
                    st.dataframe([{'Resource':s['request_key']['resource'],'Verb':s['request_key']['verb'],
                        'From':c['interval']['start'],'Until':c['interval']['end'],'Coverage':c['status'],
                        'Reasons':', '.join(c['reason_codes'])} for s in usage['series'] for c in s['coverage']],
                        hide_index=True,width='stretch')
                st.json(evidence,expanded=False)
        with st.expander('Analysis history and exact saved report'):
            st.json(client.call('GET',f'/analysis/runs/{run_id}/history')['history'],expanded=False)
            if report:st.json(report,expanded=False)
            st.caption('Report hash: '+str(run['report_hash']))
        if can_review and run['status'] in ('DONE','FAILED'):
            if st.button('Capture fresh evidence and analyse again'):
                body={k:v for k,v in run['intake'].items() if k not in ('supersedes_run_id','idempotency_key')}
                previous=body['window'];duration=datetime.fromisoformat(previous['end'].replace('Z','+00:00'))-datetime.fromisoformat(previous['start'].replace('Z','+00:00'))
                now=datetime.now(timezone.utc);body.update(window={'start':(now-duration).isoformat(),'end':now.isoformat()},
                    supersedes_run_id=run_id,idempotency_key='ui-refresh-'+uuid4().hex,trigger='manual')
                result=client.call('POST','/analysis/runs',body=body)
                st.session_state['guardian_selected_run']=result['run_id'];st.rerun()
    except (ValueError,KeyError,TypeError) as exc:
        st.error(str(exc) if isinstance(exc,ValueError) else 'The backend returned an incompatible review contract.')
    except Exception:
        st.error('The review backend is unavailable. Check its health and retry.')
