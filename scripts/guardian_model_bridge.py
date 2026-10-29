"""Authenticated laptop-only reverse relay for a host Ollama behind bridge firewall.

The pod accepts only /api/tags and /api/chat. A loopback-connected host relay
forwards their bounded JSON to one fixed real Ollama endpoint. No canned output,
commands, Kubernetes credentials or arbitrary destination URLs are supported.
Use a protected direct model endpoint in the university lab when available.
"""
import argparse,hmac,json,queue,threading,time
from http.server import BaseHTTPRequestHandler,ThreadingHTTPServer
from pathlib import Path
from uuid import uuid4
import requests


class Broker:
    def __init__(self,token):self.token=token;self.jobs=queue.Queue(4);self.pending={};self.lock=threading.Lock()
    def server(self,host='0.0.0.0',port=11434):
        broker=self
        class Handler(BaseHTTPRequestHandler):
            def body(self,limit):
                length=int(self.headers.get('Content-Length','0'))
                if not 0<=length<=limit:raise ValueError('body_limit')
                return json.loads(self.rfile.read(length)) if length else {}
            def send(self,status,value):
                data=json.dumps(value).encode();self.send_response(status);self.send_header('Content-Type','application/json');self.send_header('Content-Length',str(len(data)));self.end_headers()
                try:self.wfile.write(data)
                except (BrokenPipeError,ConnectionResetError):pass
            def dispatch(self):
                if self.path=='/health':self.send(200,{'alive':True});return
                if self.path.startswith('/relay/'):
                    if not hmac.compare_digest(self.headers.get('Authorization',''),'Bearer '+broker.token):self.send(403,{'error':'relay_auth_required'});return
                    body=self.body(2*1024*1024)
                    if self.path=='/relay/poll':
                        try:job=broker.jobs.get(timeout=5)
                        except queue.Empty:self.send(200,{'job':None});return
                        self.send(200,{'job':job});return
                    if self.path=='/relay/result':
                        with broker.lock:pending=broker.pending.get(body['id'])
                        if pending:pending['response']=(body['status'],body['response']);pending['event'].set()
                        self.send(200,{'received':pending is not None});return
                    self.send(404,{});return
                if (self.command,self.path) not in (('GET','/api/tags'),('POST','/api/chat')):self.send(404,{});return
                body=self.body(512*1024) if self.command=='POST' else None
                identifier=uuid4().hex;pending={'event':threading.Event()}
                with broker.lock:broker.pending[identifier]=pending
                try:
                    try:broker.jobs.put_nowait({'id':identifier,'method':self.command,'path':self.path,'body':body})
                    except queue.Full:self.send(503,{'error':'model_queue_full'});return
                    if not pending['event'].wait(190):self.send(504,{'error':'host_relay_unavailable'});return
                    self.send(*pending['response'])
                finally:
                    with broker.lock:broker.pending.pop(identifier,None)
            def do_GET(self):
                try:self.dispatch()
                except (ValueError,KeyError,TypeError):self.send(400,{'error':'invalid_bridge_request'})
            do_POST=do_GET
            def log_message(self,*args):pass
        server=ThreadingHTTPServer((host,port),Handler);server.daemon_threads=True;return server


def relay_once(bridge,model,token,session):
    headers={'Authorization':'Bearer '+token,'Connection':'close'}
    r=session.post(bridge+'/relay/poll',json={},headers=headers,timeout=10);r.raise_for_status();job=r.json()['job']
    if job is None:return False
    if (job['method'],job['path']) not in (('GET','/api/tags'),('POST','/api/chat')):raise ValueError('relay_route_outside_allowlist')
    try:
        r=session.request(job['method'],model+job['path'],json=job['body'],timeout=180)
        if len(r.content)>2*1024*1024:raise ValueError('model_response_too_large')
        status,value=r.status_code,r.json()
    except Exception:status,value=502,{'error':'real_model_unavailable'}
    r=session.post(bridge+'/relay/result',json={'id':job['id'],'status':status,'response':value},headers=headers,timeout=10);r.raise_for_status();return True


def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('command',choices=['serve','relay']);p.add_argument('--token-file',type=Path,required=True)
    p.add_argument('--bridge',default='http://127.0.0.1:19434');p.add_argument('--model',default='http://127.0.0.1:11434')
    a=p.parse_args();token=a.token_file.read_text().strip()
    if len(token)<32:raise ValueError('strong_relay_token_required')
    if a.command=='serve':Broker(token).server().serve_forever();return
    session=requests.Session();session.trust_env=False
    while True:
        try:relay_once(a.bridge.rstrip('/'),a.model.rstrip('/'),token,session)
        except KeyboardInterrupt:raise
        except Exception:print('Model relay disconnected; retrying without replaying a claimed request.',flush=True);time.sleep(2)


if __name__=='__main__':main()
