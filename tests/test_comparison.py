"""Freeze integrity, label separation, fair deterministic behavior and metric denominators."""
import json,tempfile,unittest
from pathlib import Path
from eval.guardian.dataset import freeze,case,ANCHOR
from eval.guardian.compare import deterministic,run,summarize


class ComparisonTests(unittest.TestCase):
    def test_sixty_families_have_disjoint_twenty_forty_split_and_runtime_has_no_labels(self):
        with tempfile.TemporaryDirectory() as temp:
            root=Path(temp)/'frozen';m=freeze(root)
            self.assertEqual(len(m['families']),60)
            self.assertEqual(sum(e['split']=='development' for e in m['families']),20)
            self.assertEqual(sum(e['split']=='held_out' for e in m['families']),40)
            for entry in m['families']:
                raw=(root/'runtime'/(entry['case_id']+'.json')).read_text()
                self.assertFalse(any('"'+key+'"' in raw for key in ['removable','required','expected_patch','answerable','split','category','label_status']))
            with self.assertRaisesRegex(ValueError,'three_repetitions'):run(root,Path(temp)/'held','deterministic',split='held_out')
            with self.assertRaisesRegex(ValueError,'independent'):run(root,Path(temp)/'held','deterministic',split='held_out',repeats=3)

    def test_competent_baseline_handles_schedules_gaps_consumers_and_misleading_name(self):
        for category,index,removes in [('routine',0,True),('rare',1,False),('incomplete',0,False),('shared',0,False),('ambiguous',0,True)]:
            _,e,_=case(category,index);result=deterministic(e,ANCHOR)
            self.assertEqual(bool(result['accepted_removals']),removes,(category,result))
        _,e,_=case('adversarial',0)
        self.assertTrue(deterministic(e,ANCHOR)['accepted_removals'])

    def test_label_free_predictions_freeze_and_metrics_do_not_reward_abstention(self):
        with tempfile.TemporaryDirectory() as temp:
            root=Path(temp)/'frozen';freeze(root)
            report=run(root,Path(temp)/'results','deterministic')
            self.assertTrue(report['predictions_frozen_before_label_read'])
            self.assertEqual(report['arms']['deterministic']['runs'],20)
            self.assertGreater(report['arms']['deterministic']['useful_proposal_coverage'],0)
            labels=json.loads((root/'evaluator/labels.json').read_text());label=next(l for l in labels if l['answerable'])
            result=summarize([{'case_id':label['case_id'],'arm':'abstain','accepted_removals':[],'raw_removals':[],
                'duration_seconds':1,'model_calls':0}],labels)['abstain']
            self.assertEqual(result['useful_proposal_coverage'],0);self.assertIsNone(result['removal_precision'])
            value=json.loads((root/'runtime/case-001.json').read_text());value['revision']=2
            (root/'runtime/case-001.json').write_text(json.dumps(value))
            with self.assertRaisesRegex(ValueError,'runtime_input_changed'):run(root,Path(temp)/'tampered','deterministic')
