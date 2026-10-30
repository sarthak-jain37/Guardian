"""The actual installed Kubernetes SDK against a local HTTP recording boundary."""
import json,threading,unittest
from http.server import BaseHTTPRequestHandler,ThreadingHTTPServer
from kubernetes.client import ApiClient,Configuration
from backend.app.services.kube_transport import api_call


class KubeTransportTests(unittest.TestCase):
    def test_sdk_response_and_per_request_audit_agent_survive_real_wire_transport(self):
        requests=[]
        class Handler(BaseHTTPRequestHandler):
            def do_GET(self):
                requests.append(dict(self.headers));body=json.dumps({'gitVersion':'test-only'}).encode()
                self.send_response(200);self.send_header('Content-Type','application/json');self.send_header('Content-Length',str(len(body)));self.end_headers();self.wfile.write(body)
            def log_message(self,*args):pass
        server=ThreadingHTTPServer(('127.0.0.1',0),Handler);thread=threading.Thread(target=server.serve_forever,daemon=True);thread.start()
        cfg=Configuration();cfg.host=f'http://127.0.0.1:{server.server_port}';cfg.proxy=None
        try:
            with ApiClient(cfg) as api:
                previous=api.user_agent
                result=api_call(api,'/version','GET',user_agent='guardian-audit-probe/test-nonce',_return_http_data_only=False)
                self.assertEqual(result[0]['gitVersion'],'test-only');self.assertEqual(result[1],200)
                self.assertEqual(requests[0]['User-Agent'],'guardian-audit-probe/test-nonce')
                self.assertEqual(api.user_agent,previous)
                api_call(api,'/version','GET',_return_http_data_only=True)
                self.assertEqual(requests[1]['User-Agent'],previous)
        finally:server.shutdown();server.server_close();thread.join()
