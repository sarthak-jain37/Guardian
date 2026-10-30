"""Scoped backend action reviews, explicit consent and durable outcome display."""
from uuid import uuid4
import streamlit as st


def _post(client,path,body):
    # Positive approval repeats the bounded real checks. It can take longer than
    # browsing a saved report; the server remains the authority on deadlines.
    return client.call('POST',path,body=body,timeout=600)


@st.fragment(run_every='2s')
def _details(client,identifier,identity,can_review):
    review=client.call('GET','/execution/reviews/'+identifier)
    p=review['proposal'];identifier=p['proposal_id'];key='action_'+identifier
    st.caption('Analysis run: '+review['source_run_id']+' · Action: '+identifier)
    st.write('**Governed action: '+p['action']+' · '+review['status']+'**')
    st.caption('Review deadline: '+p['review_expires_at']+
        ' · After approval, execution must start within '+str(p['execution_window_seconds'])+' seconds.')
    st.caption('Approved snapshot: target UID '+p['target']['uid']+' · expected resourceVersion '+p['target']['resource_version'])
    if p['action']=='remediate':st.code(p['diff'],language='diff')
    else:st.info('Adoption records these exact current rules as desired state. It does not change the Role.')
    with st.expander('Exact rules, unchanged binding and approval hash'):
        st.json({'target':p['target'],'result_rules':p['result_rules'],
            'unchanged_binding':p['unchanged_binding'],'approval_hash':p['approval_hash']})
    if review['usage_window']:
        window=review['usage_window']
        st.caption('Action evidence window: '+window['start']+' → '+window['end']+
            ' · Processed through: '+str(review['usage_processed_through']))
    with st.expander('Independent backend checks and verification contract'):
        st.json(review['backend_readiness'])
        st.json(review['verification_contract'])
        st.caption('Source analysis hash: '+review['source_report_hash'])
    for uncertainty in p['uncertainty']:st.warning(uncertainty)
    if review['execution_blockers'] and review['status']=='OPEN':st.info('Current action blockers: '+', '.join(review['execution_blockers']))
    recovery=review['recovery_contract']
    if recovery:
        with st.expander('Exact recovery rules and risks'):
            st.json(recovery)
            st.caption('Recovery can reintroduce the security risks shown here. It restores only this action’s captured rules, '
                'after a repeatable qualifying failure and fresh identity, context, authority and hold checks.')
    if can_review and review['status']=='OPEN':
        with st.form(key):
            positive='approve_remediation' if p['action']=='remediate' else 'adopt_baseline'
            choices=([positive] if review['execution_available'] else [])+['reject','acknowledge','request_context']
            kind=st.selectbox('Governed review action',choices,key=key+'_kind',format_func=lambda v:{
                'approve_remediation':'Approve exact Role change','adopt_baseline':'Adopt exact baseline',
                'reject':'Reject action','acknowledge':'Acknowledge action','request_context':'Add context and analyse again'}[v])
            risk=st.checkbox('I accept the stated residual risks for this exact action',value=False,key=key+'_risk')
            opt=False
            if recovery and recovery['mode']=='optional_advance_exact':
                opt=st.checkbox('Separately authorize one exact recovery if its stated conditions pass',value=False,key=key+'_recovery')
                st.caption('Optional, unchecked by default. Consent expires '+str(recovery['window_seconds'])+
                    ' seconds after approval. It does not authorize general baseline reversion.')
            note=st.text_area('Governed review note',max_chars=2000,key=key+'_note')
            if st.form_submit_button('Record governed decision'):
                writing=kind in ('approve_remediation','adopt_baseline')
                if writing and not risk:st.error('Accept the stated residual risks before approving this exact action.')
                else:
                    consent=bool(opt and kind=='approve_remediation')
                    _post(client,'/governance/reviews/'+identifier+'/decisions',{
                        'kind':kind,'expected_revision':p['revision'],'expected_approval_hash':p['approval_hash'],
                        'idempotency_key':'ui-action-'+uuid4().hex,'note':note,'accept_residual_risk':writing and risk,
                        'opt_in_recovery':consent,'expected_recovery_hash':review['recovery_hash'] if consent else None})
                    st.rerun()
    decision=review['decision']
    if decision:
        st.write('Decision: **'+decision['kind']+'** · '+decision['actor'])
        if decision['kind']=='request_context':
            successor=review.get('context_successor_run_id')
            if successor:
                st.info('Fresh analysis queued: '+successor)
                if st.button('Open revised analysis',key=key+'_context_run'):
                    st.session_state['guardian_selected_run']=successor;st.rerun()
            else:st.info('Context recorded. Waiting for the backend to queue fresh analysis; this status refreshes automatically.')
        st.caption('Execution start deadline: '+str(decision['execution_expires_at'])+
            ' · Forward authority revoked: '+str(decision['revoked']))
        if review['advance_recovery_consent']:
            st.caption('Separate recovery authority expires: '+review['advance_recovery_consent']['expires_at'])
        owner=decision['actor']==identity['actor'] or any('operate' in g['permissions'] for g in identity['grants']
            if (g['cluster_id'],g['namespace'])==(p['target']['cluster_id'],p['target']['namespace']))
        if can_review and owner and decision['kind'] in ('approve_remediation','adopt_baseline'):
            with st.expander('Revoke outstanding authority'):
                with st.form(key+'_revoke'):
                    revoke_kind=st.selectbox('Authority to revoke',['all','forward','recovery'],key=key+'_revoke_kind')
                    reason=st.text_input('Revocation reason',max_chars=2000,key=key+'_revoke_reason')
                    if st.form_submit_button('Revoke selected authority'):
                        if not reason.strip():st.error('Give a reason for revocation.')
                        else:
                            _post(client,'/execution/decisions/'+decision['decision_id']+'/revoke',{'kind':revoke_kind,'reason':reason})
                            st.rerun()
    receipt=review['receipt']
    if decision and decision['kind'] in ('approve_remediation','adopt_baseline'):
        if not receipt or receipt['phase'] in ('requested','applying','verifying'):
            st.info('Approval recorded. Execution is pending or running; completion is not confirmed yet. Status refreshes automatically.')
        if st.button('Refresh execution status',key=key+'_refresh'):st.rerun()
    if receipt:
        st.write('Outcome: **'+receipt['phase']+'** · Apply: '+receipt['apply_status']+
            ' · Verification: '+receipt['verification_status']+' · Recovery: '+receipt['recovery_status'])
        if receipt['phase']=='manual':st.error('Manual intervention is required. Inspect the stored checks before acting.')
        if receipt['phase'] in ('stale','failed'):
            st.error('The approved action was not applied. Reason: '+str(review.get('outcome_reason') or
                'A precondition changed or a check was unavailable; this older receipt has no detailed reason.')+
                ' Prepare a fresh action after resolving the blocker; the old approval will not be replayed.')
        if receipt['phase']=='completed':st.success('Completed: the approved action passed its required verification.')
        if receipt['phase']=='rolled_back':st.warning('The change was applied, then restored under your separate recovery consent. The proposed baseline is not active.')
        st.caption('Baseline activated by this action: '+str(receipt['baseline_activated']))
        if receipt.get('post_resource_version'):st.caption('Confirmed resourceVersion after application: '+receipt['post_resource_version'])
        with st.expander('Durable receipt and verification evidence'):
            st.json(receipt);st.json(review['verification_evidence'])
        if (can_review and receipt['phase']=='manual' and receipt['apply_status']=='confirmed'
                and receipt['verification_status']=='failed' and review['fresh_recovery_hash']):
            with st.form(key+'_fresh'):
                st.warning('This is new human consent for the displayed exact recovery. The backend repeats its trigger and preconditions.')
                consent=st.checkbox('Authorize this exact recovery now',value=False,key=key+'_fresh_consent')
                note=st.text_area('Fresh recovery note',max_chars=2000,key=key+'_fresh_note')
                if st.form_submit_button('Queue fresh recovery'):
                    if not consent:st.error('Explicit recovery consent is required.')
                    else:
                        _post(client,'/execution/actions/'+review['action_key']+'/recovery',{
                            'expected_sequence':receipt['sequence'],'expected_recovery_hash':review['fresh_recovery_hash'],
                            'idempotency_key':'ui-recover-'+uuid4().hex,'note':note})
                        st.rerun()
    with st.expander('Governed action history'):
        st.json(client.call('GET','/governance/reviews/'+identifier+'/history')['history'])


def workspace(client,identity,scope,run):
    params={'cluster_id':scope['cluster_id'],'namespace':scope['namespace']}
    # Older/read-only backends retain the analysis UI when this API is absent.
    try:capabilities=client.call('GET','/execution/capabilities',params=params)
    except ValueError as error:
        if '(404)' in str(error):return
        raise
    st.subheader('Governed actions and outcomes')
    can_review=identity['kind']=='human' and 'review' in scope['permissions']
    enabled=capabilities['execution_available']
    if not enabled:st.info('Execution is disabled for this namespace. An operator must configure the controlled pilot and its real verification profile.')
    if enabled and can_review and run['status']=='DONE':
        action=st.selectbox('Action to prepare',['remediate','adopt_baseline'] if run['proposal'] else ['adopt_baseline'],
            format_func=lambda v:'Prepare exact Role change' if v=='remediate' else 'Prepare explicit baseline adoption')
        if st.button('Queue independent readiness checks'):
            result=_post(client,'/execution/reviews',{'source_run_id':run['run_id'],'expected_report_hash':run['report_hash'],
                'action':action,'idempotency_key':'ui-prepare-'+uuid4().hex})
            st.session_state['guardian_preparation']=(identity['actor'],params,result['preparation_id'])
            st.rerun()
    preparation=st.session_state.get('guardian_preparation')
    if preparation and preparation[:2]==(identity['actor'],params):
        status=client.call('GET','/execution/preparations/'+preparation[2])
        st.caption('Readiness preparation: '+status['status']+' · '+str(status['error'] or 'Refresh to check progress.'))
    reviews=client.call('GET','/execution/reviews',params=params)['reviews']
    reviews=[review for review in reviews if review['source_run_id']==run['run_id']]
    if reviews:
        by_id={r['proposal_id']:r for r in reviews}
        selected=st.selectbox('Governed action',list(by_id),format_func=lambda v:by_id[v]['role_name']+' · '+by_id[v]['action']+
            ' · revision '+str(by_id[v]['revision'])+' · '+by_id[v]['status']+' · '+v[-8:])
        _details(client,selected,identity,can_review)
    else:st.caption('No independently prepared action is available yet.')
    notices=client.call('GET','/execution/notifications',params=params)['notifications']
    with st.expander('Outcome notifications'):
        for notice in notices:
            st.write(notice['message'])
            st.caption('Recipient: '+notice['actor']+' · '+notice['phase']+' · Acknowledged: '+str(notice['acknowledged']))
            if can_review and identity['actor']==notice['actor'] and not notice['acknowledged']:
                if st.button('Acknowledge outcome',key='ack_'+notice['notification_id']):
                    _post(client,'/execution/notifications/'+notice['notification_id']+'/ack',{})
                    st.rerun()
        st.caption('Acknowledging an outcome does not pause monitoring or clear an incident.')
    with st.expander('Approved baseline history'):
        st.json(client.call('GET','/execution/baselines',params=params)['baselines'])
        st.caption('An active baseline is approved desired state. Current observed rules are captured separately.')
    with st.expander('Namespace pause and incident controls'):
        holds=client.call('GET','/governance/holds',params=params)
        st.write('Paused: '+str(holds['pause'])+' · Incident held: '+str(holds['incident']))
        if identity['kind']=='human' and 'operate' in scope['permissions']:
            with st.form('guardian_hold_'+scope['cluster_id']+'_'+scope['namespace']):
                kind=st.selectbox('Control',['pause','incident'])
                active=st.checkbox('Set control active',value=True)
                reason=st.text_input('Control change reason',max_chars=2000)
                if st.form_submit_button('Record control change'):
                    if not reason.strip():st.error('Give a reason for the control change.')
                    else:
                        _post(client,'/governance/holds',{**params,'kind':kind,'active':active,'reason':reason})
                        st.rerun()
        else:st.caption('Changing pause or incident state requires a human operator credential.')
