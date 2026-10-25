import importlib.util
from pathlib import Path
import unittest
from unittest.mock import patch


class SummarizerTests(unittest.TestCase):
    def setUp(self):
        with patch('langchain_community.llms.LlamaCpp') as wrapper:
            spec=importlib.util.spec_from_file_location('guardian_summarizer_test',Path(__file__).resolve().parents[1]/'agents/summarizer.py')
            self.module=importlib.util.module_from_spec(spec)
            spec.loader.exec_module(self.module)
        self.model=self.module.local_qwen
        self.model.n_ctx=8192
        self.model.max_tokens=512
        self.model.client.tokenize.return_value=[1]*20
        self.model.client.create_chat_completion.return_value={'choices':[{'message':{'content':'Insufficient evidence to conclude compromise.'}}]}

    def test_chat_template_roles_and_evidence_are_preserved(self):
        response=self.module.analyse_document({'events':[{'id':'evidence-123','http':{'path':'/healthz'}}]})
        self.assertEqual(response,'Insufficient evidence to conclude compromise.')
        messages=self.model.client.create_chat_completion.call_args.kwargs['messages']
        self.assertEqual([m['role'] for m in messages],['system','user'])
        self.assertIn('untrusted data',messages[0]['content'])
        self.assertIn('evidence-123',messages[1]['content'])

    def test_oversized_evidence_fails_before_generation(self):
        self.model.client.tokenize.return_value=[1]*9000
        with self.assertRaises(ValueError):self.module.analyse_document({'events':[]})
        self.model.client.create_chat_completion.assert_not_called()

    def test_incomplete_generation_is_labelled(self):
        self.model.client.create_chat_completion.return_value['choices'][0]['finish_reason']='length'
        response=self.module.analyse_document({'events':[]})
        self.assertIn('may be incomplete',response)

    def test_grading_requests_schema_and_rejects_truncation(self):
        self.model.client.create_chat_completion.return_value={'choices':[{'message':{'content':'{"severity": null}'}}]}
        result=self.module.grade_document({'events':[]})
        self.assertIsNone(result['severity'])
        args=self.model.client.create_chat_completion.call_args.kwargs
        self.assertEqual(args['response_format']['type'],'json_object')
        self.assertIn('severity',args['response_format']['schema']['oneOf'][0]['properties'])
        self.model.client.create_chat_completion.return_value['choices'][0]['finish_reason']='length'
        with self.assertRaises(ValueError):self.module.grade_document({'events':[]})
