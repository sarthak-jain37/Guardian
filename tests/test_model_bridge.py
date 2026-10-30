import json,threading,unittest
from http.server import BaseHTTPRequestHandler,ThreadingHTTPServer
import requests
from scripts.guardian_model_bridge import Broker,relay_once


class ModelBridgeTests(unittest.TestCase):
    def test_authenticated_relay_forwards_actual_json_and_rejects_other_routes(self):
        seen=[]
        class Model(BaseHTTPRequestHandler):
            def do_GET(self):
                seen.append(self.path);body=json.dumps({'models':[{'name':'actual-test-boundary'}]}).encode()
                self.send_response(200);self.send_header('Content-Length',str(len(body)));self.end_headers();self.wfile.write(body)
            def log_message(self,*args):pass
        upstream=ThreadingHTTPServer(('127.0.0.1',0),Model)
        broker=Broker('x'*40).server('127.0.0.1',0)
        for s in (upstream,broker):threading.Thread(target=s.serve_forever,daemon=True).start()
        session=requests.Session();session.trust_env=False;base=f'http://127.0.0.1:{broker.server_port}'
        try:
            self.assertEqual(session.post(base+'/relay/poll',json={},timeout=2).status_code,403)
            self.assertEqual(session.get(base+'/arbitrary-url',timeout=2).status_code,404)
            result={}
            thread=threading.Thread(target=lambda:result.update(value=session.get(base+'/api/tags',timeout=10).json()));thread.start()
            with requests.Session() as relay:
                relay.trust_env=False
                self.assertTrue(relay_once(base,f'http://127.0.0.1:{upstream.server_port}','x'*40,relay))
            thread.join(timeout=10)
            self.assertEqual(result['value']['models'][0]['name'],'actual-test-boundary');self.assertEqual(seen,['/api/tags'])
        finally:
            session.close()
            for s in (broker,upstream):s.shutdown();s.server_close()
