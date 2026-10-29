"""Real child-process behavior checks against a local recording HTTP API."""
import json,os,tempfile,threading,unittest
from pathlib import Path
from http.server import BaseHTTPRequestHandler,ThreadingHTTPServer
from unittest.mock import patch
from demo.workloads.pod_reader import Reader


class DemoWorkloadTests(unittest.TestCase):
    def test_process_restart_exercises_reads_and_distinguishes_denial_from_dependency_failure(self):
        state={'status':200,'reads':0}
        class Handler(BaseHTTPRequestHandler):
            def do_GET(self):
                state['reads']+=1
                self.send_response(state['status']);self.end_headers()
                self.wfile.write(json.dumps({'kind':'Pod','metadata':{'name':'reader'}}).encode())
            def log_message(self,*args):pass
        server=ThreadingHTTPServer(('127.0.0.1',0),Handler)
        thread=threading.Thread(target=server.serve_forever,daemon=True);thread.start()
        try:
            with tempfile.TemporaryDirectory() as temp:
                path=Path(temp);(path/'namespace').write_text('guardian-demo');(path/'token').write_text('test-only-token')
                with patch.dict(os.environ,{'GUARDIAN_SA_DIRECTORY':temp,'POD_NAME':'reader','GUARDIAN_API_URL':f'http://127.0.0.1:{server.server_port}'}):
                    reader=Reader()
                    try:
                        result=reader.check();self.assertEqual(set(result['checks'].values()),{'pass'})
                        self.assertNotEqual(result['process_before'],result['process_after']);self.assertGreaterEqual(state['reads'],3)
                        state['status']=403
                        denied=reader.check();self.assertTrue(denied['dependencies_healthy']);self.assertEqual(set(denied['checks'].values()),{'fail'})
                        state['status']=503
                        outage=reader.check();self.assertFalse(outage['dependencies_healthy']);self.assertEqual(set(outage['checks'].values()),{'unknown'})
                    finally:reader.stop()
        finally:server.shutdown();server.server_close();thread.join()
