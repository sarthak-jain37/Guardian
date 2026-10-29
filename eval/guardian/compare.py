"""Offline A/B comparison. Inference never receives evaluator labels or patches."""
import argparse,json,math,time
from datetime import datetime,timedelta
from pathlib import Path
from uuid import uuid4
from agents.guardian.contracts import EvidenceBundle,AnalysisRequest
from agents.guardian.modeling import load_profile
from agents.guardian.policy import build_facts,canonical_hash,operations,rule_dicts
from agents.guardian.runner import configured_model,open_runner,config,export_result
from agents.guardian.evaluate import source_provenance
from eval.guardian.dataset import freeze


def deterministic(e,now):
    facts,gates=build_facts(e,now)
    documents=' '.join(e.context.optional_documents).lower() if e.context else ''
    periodic=any(w in documents for w in ('monthly','infrequent','quarterly','overnight','year-end','rotation','recovery','restore','emergency','scheduled'))
    workflow=any(w in documents for w in ('workflow','routine','fetches','requests','exercise'))
    contextual_defer=periodic and workflow
    selected=[f for f in facts if f['eligible'] and not contextual_defer]
    return {'accepted_removals':[[f['api_group'],f['resource'],f['verb']] for f in selected],
        'raw_removals':[[f['api_group'],f['resource'],f['verb']] for f in selected],
        'status':'proposal' if selected else 'defer','model_calls':0,'model_metrics':None,
        'deterministic_gates':[g.model_dump() for g in gates],'context_rule_deferred':contextual_defer}


def llm(e,directory,profile,anchor):
    started=time.monotonic();model,settings=configured_model(profile.model_dump(mode='json'))
    clock=lambda:anchor+timedelta(seconds=time.monotonic()-started)
    request=AnalysisRequest(case_id='evaluation-'+uuid4().hex,run_id='run-'+uuid4().hex,snapshot_id=e.snapshot_id,
        cluster_id=e.target.cluster_id,target_uid=e.target.uid,baseline_id=e.baseline_id,policy_version=e.policy.policy_version,mode='simulation')
    with open_runner(directory,model=model,evidence=e,clock=clock) as (graph,runtime,store):
        state=graph.invoke({'request':request.model_dump(mode='json')},config(request.run_id));export_result(directory,state,runtime)
        if store.count('action'):raise ValueError('offline_evaluation_must_never_submit_execution')
    accepted=operations(rule_dicts(e.target))-operations(state['proposal']['result_rules']) if state.get('proposal') else set()
    raw=set();results=[];stage_attempts={}
    facts={f['permission_id']:(f['api_group'],f['resource'],f['verb']) for f in state.get('facts',[])}
    invalid=0;emitted=0
    for trace in state['trace']:
        result=trace.get('model_result')
        if not result:continue
        results.append(result);stage_attempts.setdefault(result['stage'],[]).append(trace);response=result.get('response') or {}
        for assessment in response.get('permission_assessments',response.get('decisions',[])):
            emitted+=1;pid=assessment.get('permission_id')
            if pid not in facts:invalid+=1
            elif assessment.get('recommendation',assessment.get('action')) in ('remove','propose_remove'):raw.add(facts[pid])
    return {'accepted_removals':[list(p) for p in sorted(accepted)],'raw_removals':[list(p) for p in sorted(raw)],
        'status':state['status'],'model_calls':state['model_calls'],'lookup_calls':state['lookup_calls'],
        'model_metrics':{'attempted_calls':len(results),'transport_or_schema_errors':sum(r['error'] is not None for r in results),
            'invalid_permission_ids':invalid,'emitted_permission_ids':emitted,'stage_results':results,
            'first_pass_valid_stages':sum(v[0]['outcome']=='validated' for v in stage_attempts.values()),
            'final_valid_stages':sum(v[-1]['outcome']=='validated' for v in stage_attempts.values()),
            'attempted_stages':len(stage_attempts),'repair_calls':state['investigator_repairs']+state['planner_repairs'],
            'semantic_grounding':'requires_independent_human_review','validity_scope':'schema_and_deterministic_domain_validation_not_semantic_grounding'},'config':settings}


def summarize(records,labels):
    indexed={v['case_id']:v for v in labels};groups={}
    for row in records:groups.setdefault(row['arm'],[]).append(row)
    report={}
    for arm,rows in groups.items():
        accepted=correct=unsafe=raw_unsafe=possible=useful=answerable=deferred=defer_total=0;latencies=[];per_category={}
        for row in rows:
            label=indexed[row['case_id']];selected={tuple(p) for p in row['accepted_removals']};raw={tuple(p) for p in row['raw_removals']}
            required={tuple(p) for p in label['required']};optional={tuple(p) for p in label['removable']}
            accepted+=len(selected);correct+=len(selected&optional);unsafe+=len(selected&required);raw_unsafe+=len(raw&required);possible+=len(optional)
            if label['answerable']:answerable+=1;useful+=bool(selected&optional)
            if label['acceptable_deferral']:defer_total+=1;deferred+=not selected
            latencies.append(row['duration_seconds']);bucket=per_category.setdefault(label['category'],{'runs':0,'unsafe_accepted':0,'useful':0})
            bucket['runs']+=1;bucket['unsafe_accepted']+=len(selected&required);bucket['useful']+=bool(selected&optional)
        latencies.sort()
        quantile=lambda q:latencies[max(0,math.ceil(len(latencies)*q)-1)]
        families={r['case_id'] for r in rows}
        failed_families=sum(any(set(map(tuple,r['accepted_removals'])) & set(map(tuple,indexed[f]['required'])) for r in rows if r['case_id']==f) for f in families)
        def wilson(successes,total):
            if not total:return None
            z=1.96;p=successes/total;den=1+z*z/total
            center=(p+z*z/(2*total))/den;radius=z*((p*(1-p)/total+z*z/(4*total*total))**.5)/den
            return [max(0,center-radius),min(1,center+radius)]
        report[arm]={'runs':len(rows),'families':len({r['case_id'] for r in rows}),
            'accepted_removals':accepted,'correct_removals':correct,'labeled_removable':possible,
            'removal_precision':correct/accepted if accepted else None,'removal_recall':correct/possible if possible else None,
            'unsafe_raw_permissions':raw_unsafe,'unsafe_accepted_permissions':unsafe,
            'useful_proposal_coverage':useful/answerable if answerable else None,'answerable_runs':answerable,
            'appropriate_deferral':deferred/defer_total if defer_total else None,'deferral_runs':defer_total,
            'latency_p50_seconds':quantile(.5),'latency_p95_seconds':quantile(.95),'model_calls':sum(r['model_calls'] for r in rows),
            'categories':per_category,'grounding_accuracy':None,'human_review_effort':None,'live_functional_outcome':None,
            'unsafe_family_fraction_95pct_wilson':wilson(failed_families,len(families)),
            'validity_and_repairs':None if arm=='deterministic' else {name:sum(r.get('model_metrics',{}).get(name,0) for r in rows if r.get('model_metrics')) for name in ('first_pass_valid_stages','final_valid_stages','attempted_stages','repair_calls','invalid_permission_ids','emitted_permission_ids')},
            'latency_scope':'active_arm_implementation_path_excluding_human_waiting; A rules/report construction; B graph/checkpoints/inference',
            'uncertainty':'descriptive synthetic-family results; repeated runs are not independent families; human labels unreviewed unless attested'}
    return report


def run(dataset,output,arm,*,profile=None,split='development',repeats=1,case_ids=None,attestation=None):
    dataset=Path(dataset);output=Path(output)
    if output.exists():raise ValueError('evaluation_output_must_be_new')
    manifest=json.loads((dataset/'manifest.json').read_text())
    if split=='held_out':
        if repeats<3:raise ValueError('held_out_requires_three_repetitions')
        if not attestation:raise ValueError('held_out_requires_two_independent_human_label_reviews')
        review=json.loads(Path(attestation).read_text())
        if review.get('dataset_hash')!=manifest['dataset_hash'] or len(set(review.get('reviewers',[])))<2 or review.get('reconciled') is not True:raise ValueError('label_review_attestation_invalid')
    if arm=='llm' and (profile is None or profile.provider=='scripted'):raise ValueError('comparison_requires_real_model_profile')
    output.mkdir(parents=True);records=[];anchor=datetime.fromisoformat(manifest['anchor'])
    entries=[e for e in manifest['families'] if e['split']==split and (not case_ids or e['case_id'] in case_ids)]
    if not entries:raise ValueError('evaluation_selection_empty')
    for entry in entries:
        evidence=EvidenceBundle.model_validate_json((dataset/'runtime'/(entry['case_id']+'.json')).read_text())
        if canonical_hash(evidence.model_dump(mode='json'))!=entry['evidence_hash']:raise ValueError('frozen_runtime_input_changed')
        for repeat in range(repeats):
            start=time.monotonic();directory=output/(entry['case_id']+'-'+str(repeat+1))
            try:result=deterministic(evidence,anchor) if arm=='deterministic' else llm(evidence,directory,profile,anchor)
            except Exception as error:result={'accepted_removals':[],'raw_removals':[],'status':'error','error':type(error).__name__,'model_calls':0,'model_metrics':None}
            row={'case_id':entry['case_id'],'arm':arm,'repeat':repeat+1,'input_hash':entry['evidence_hash'],
                'duration_seconds':time.monotonic()-start,**result}
            records.append(row)
            # Freeze each output before the evaluator opens any labels.
            (output/(entry['case_id']+'-'+str(repeat+1)+'.json')).write_text(json.dumps(row,indent=2))
            print(entry['case_id']+' '+arm+' '+row['status'],flush=True)
    labels=json.loads((dataset/'evaluator/labels.json').read_text())
    check={k:v for k,v in manifest.items() if k!='dataset_hash'}
    if canonical_hash({'manifest':check,'labels':labels})!=manifest['dataset_hash']:raise ValueError('frozen_labels_or_manifest_changed')
    report={'schema_version':'guardian.comparison.v1','dataset_hash':manifest['dataset_hash'],'split':split,
        'source_kind':manifest['source_kind'],'source':source_provenance(),'label_status':'review_attested' if attestation else 'provisional',
        'real_model':arm=='llm','cluster_writes_performed':False,'predictions_frozen_before_label_read':True,
        'arms':summarize(records,labels),'errors':sum(r['status']=='error' for r in records),
        'release_selection_eligible':False,'selection_pending':['independent semantic grounding and review-effort assessment','same-family model settings and held-out repetitions','live subset outcomes']}
    (output/'comparison.json').write_text(json.dumps(report,indent=2))
    return report


def main():
    p=argparse.ArgumentParser(description=__doc__);sub=p.add_subparsers(dest='command',required=True)
    f=sub.add_parser('freeze');f.add_argument('--directory',type=Path,required=True)
    r=sub.add_parser('run');r.add_argument('--dataset',type=Path,required=True);r.add_argument('--output',type=Path,required=True)
    r.add_argument('--arm',choices=['deterministic','llm'],required=True);r.add_argument('--profile',type=Path)
    r.add_argument('--split',choices=['development','held_out'],default='development');r.add_argument('--repeats',type=int,default=1)
    r.add_argument('--case',action='append');r.add_argument('--label-review',type=Path)
    a=p.parse_args()
    result=freeze(a.directory) if a.command=='freeze' else run(a.dataset,a.output,a.arm,profile=load_profile(a.profile) if a.profile else None,
        split=a.split,repeats=a.repeats,case_ids=a.case,attestation=a.label_review)
    print(json.dumps(result,indent=2))


if __name__=='__main__':main()
