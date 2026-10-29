import json
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from agents.guardian.adapters.models import OllamaModelClient, remote_completion, completion_output
from agents.guardian.modeling import ModelConfig


class OllamaTests(unittest.TestCase):
    def setUp(self):
        self.requests=[];self.reply={'done':True,'done_reason':'stop','model':'qwen3.5:4b',
            'message':{'content':'{"answer":"ok"}'},'prompt_eval_count':12,'eval_count':7}
        owner=self
        class Handler(BaseHTTPRequestHandler):
            def do_POST(self):
                owner.requests.append((self.path,json.loads(self.rfile.read(int(self.headers['Content-Length'])))))
                self.send_response(200);self.end_headers();self.wfile.write(json.dumps(owner.reply).encode())
            def log_message(self,*args):pass
        self.server=ThreadingHTTPServer(('127.0.0.1',0),Handler)
        thread=threading.Thread(target=self.server.serve_forever,daemon=True);thread.start()
        self.addCleanup(self.server.server_close);self.addCleanup(self.server.shutdown)
        self.config=ModelConfig(profile='dev-laptop',provider='ollama',model_name='qwen3.5:4b',
            endpoint=f'http://127.0.0.1:{self.server.server_port}',request_timeout_seconds=2)
        self.schema={'type':'object','properties':{'answer':{'type':'string'}},'required':['answer'],'additionalProperties':False}

    def test_native_schema_controls_and_usage_are_preserved(self):
        client=OllamaModelClient(self.config);self.addCleanup(client.close)
        result=client.generate('investigator',[{'role':'user','content':'test'}],self.schema,self.config,timeout_seconds=4)
        self.assertIsNone(result.error);self.assertEqual(result.response,{'answer':'ok'})
        self.assertEqual((result.input_tokens,result.output_tokens),(12,7))
        route,body=self.requests[0]
        self.assertEqual(route,'/api/chat');self.assertEqual(body['format'],self.schema)
        self.assertFalse(body['stream']);self.assertFalse(body['think'])
        self.assertFalse(body['truncate'])
        self.assertFalse(body['shift'])
        self.assertEqual(body['options']['num_ctx'],8192)
        self.assertIsNone(result.resolved_revision)

    def test_truncated_or_incomplete_is_not_valid_json_success(self):
        self.reply['done_reason']='length'
        self.assertEqual(remote_completion(self.config,[],self.schema),{'error':'output_truncated'})
        self.reply['done_reason']='stop';self.reply['done']=False
        self.assertEqual(remote_completion(self.config,[],self.schema),{'error':'output_truncated'})

    def test_invalid_or_oversized_and_unavailable_fail_closed(self):
        self.reply['message']['content']='[]'
        self.assertEqual(completion_output(remote_completion(self.config,[],self.schema),65536)['error'],'invalid_response')
        self.reply['message']['content']='x'*70000
        self.assertEqual(remote_completion(self.config,[],self.schema)['error'],'output_too_large')
        self.server.shutdown()
        client=OllamaModelClient(self.config);self.addCleanup(client.close)
        result=client.generate('investigator',[],self.schema,self.config,timeout_seconds=.1)
        self.assertEqual(result.error,'timeout')

    def test_endpoint_credentials_and_scripted_real_profile_are_rejected(self):
        with self.assertRaises(ValueError):self.config.model_validate({**self.config.model_dump(),'endpoint':'http://token@localhost'})
        with self.assertRaises(ValueError):ModelConfig(profile='dev-laptop',provider='scripted')

    def test_decoding_mirrors_allowed_choices_without_forcing_eligible_removal(self):
        from agents.guardian.contracts import Investigation
        from agents.guardian.modeling import scoped_schema
        from jsonschema import Draft202012Validator
        facts=[{'permission_id':'protected','eligible':False,'evidence_ids':['source-a']},
               {'permission_id':'candidate','eligible':True,'evidence_ids':['source-b']}]
        schema=scoped_schema(Investigation.model_json_schema(),{'facts':facts})
        validator=Draft202012Validator(schema)
        output={'summary':'Evidence assessment','permission_assessments':[
            {'permission_id':'protected','recommendation':'retain','evidence_ids':['source-a'],'reason':'Known usage'},
            {'permission_id':'candidate','recommendation':'retain','evidence_ids':['source-b'],'reason':'Remaining uncertainty'}],
            'uncertainty':[],'questions':[],'context_requests':[]}
        validator.validate(output)
        output['permission_assessments'][1]['recommendation']='propose_remove';validator.validate(output)
        output['permission_assessments'][0]['recommendation']='propose_remove'
        self.assertTrue(list(validator.iter_errors(output)))
