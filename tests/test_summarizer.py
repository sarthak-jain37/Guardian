import importlib.util
from pathlib import Path
import unittest
from unittest.mock import patch
from agents.guardian.modeling import ModelConfig


class SummarizerTests(unittest.TestCase):
    def setUp(self):
        spec=importlib.util.spec_from_file_location('guardian_summarizer_test',Path(__file__).resolve().parents[1]/'agents/summarizer.py')
        self.module=importlib.util.module_from_spec(spec);spec.loader.exec_module(self.module)
        self.call=patch.object(self.module,'advisory_completion',return_value={'text':'Insufficient evidence.'}).start()
        self.addCleanup(patch.stopall)

    def test_import_has_no_model_and_default_is_ollama(self):
        self.assertFalse(hasattr(self.module,'local_qwen'))
        self.assertEqual(self.module.advisory_config().provider,'ollama')

    def test_chat_roles_and_untrusted_evidence_preserved(self):
        self.assertEqual(self.module.analyse_document({'id':'evidence-123'}),'Insufficient evidence.')
        messages=self.call.call_args.args[0]
        self.assertEqual([m['role'] for m in messages],['system','user'])
        self.assertIn('untrusted data',messages[0]['content'])
        self.assertIn('evidence-123',messages[1]['content'])

    def test_grading_requests_schema_and_preserves_full_evidence_ids(self):
        self.call.return_value={'evidence_ids':['E1']}
        result=self.module.grade_document({'events':[{'id':'full-id','kind':'process_exec'}]})
        self.assertEqual(result['evidence_ids'],['full-id'])
        schema=self.call.call_args.args[1]
        self.assertIn('severity',schema['properties'])
        self.assertNotIn('maxLength',schema['properties']['uncertainty'])

    def test_overlarge_context_is_rejected_without_silent_truncation(self):
        with self.assertRaises(ValueError):self.module.grade_document({'events':[{'id':'a','description':'x'*20000}]})
        self.call.assert_not_called()

    def test_provider_errors_are_not_presented_as_model_answers(self):
        self.call.side_effect=ValueError('Advisory model output_truncated')
        with self.assertRaises(ValueError):self.module.analyse_document({'events':[]})
