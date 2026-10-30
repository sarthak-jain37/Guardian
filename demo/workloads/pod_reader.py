"""Disposable reader: real ServiceAccount reads, with an observable process restart.

The parent serves checks; a separate child performs ordinary reads. Every restart
creates a new OS process and exercises its real initialization/read path again.
No permission answer sheet or evaluator labels are exposed to Guardian.
"""
import json,os,ssl,subprocess,sys,threading,time,urllib.request,urllib.error
from datetime import datetime,timezone
from http.server import BaseHTTPRequestHandler,ThreadingHTTPServer


def read_pod():
    root=os.environ.get('GUARDIAN_SA_DIRECTORY','/var/run/secrets/kubernetes.io/serviceaccount')
    namespace=open(root+'/namespace').read().strip();token=open(root+'/token').read().strip()
    host=os.environ.get('GUARDIAN_API_URL','https://'+os.environ.get('KUBERNETES_SERVICE_HOST','kubernetes.default.svc')+':'+os.environ.get('KUBERNETES_SERVICE_PORT','443'))
    request=urllib.request.Request(host+'/api/v1/namespaces/'+namespace+'/pods/'+os.environ['POD_NAME'],headers={'Authorization':'Bearer '+token})
    try:
        context=ssl.create_default_context(cafile=root+'/ca.crt') if host.startswith('https:') else None
        with urllib.request.urlopen(request,context=context,timeout=3) as response:
            value=json.load(response)
        return {'ok':value.get('kind')=='Pod' and value.get('metadata',{}).get('name')==os.environ['POD_NAME'],'code':200}
    except urllib.error.HTTPError as error:return {'ok':False,'code':error.code}
    except Exception:return {'ok':False,'code':None}


class Reader:
    def __init__(self):self.lock=threading.Lock();self.observations=[];self.process=None;self.start()
    def start(self):
        self.process=subprocess.Popen([sys.executable,__file__,'--worker'],stdout=subprocess.PIPE,text=True)
        self.observations=[]
        def collect(process):
            for line in process.stdout:
                try:row=json.loads(line)
                except ValueError:continue
                with self.lock:
                    if self.process is process:self.observations=(self.observations+[row])[-32:]
        threading.Thread(target=collect,args=(self.process,),daemon=True).start()
    def stop(self):
        self.process.terminate()
        try:self.process.wait(timeout=2)
        except subprocess.TimeoutExpired:self.process.kill();self.process.wait()
        self.process.stdout.close()
    def check(self):
        with self.lock:previous_pid=self.process.pid
        self.stop();self.start();deadline=time.monotonic()+10
        while time.monotonic()<deadline:
            with self.lock:rows=list(self.observations)
            if len(rows)>=3:break
            time.sleep(.1)
        with self.lock:rows=list(self.observations)
        # Authorization failure is a real app failure; connection errors remain
        # dependency uncertainty, never a confirmed policy regression.
        healthy=len(rows)>=3 and all(r['code'] is not None and r['code']<500 for r in rows)
        startup=bool(rows and rows[0]['ok']);normal=len(rows)>=3 and all(r['ok'] for r in rows[-2:])
        return {'runner_healthy':self.process.poll() is None,'dependencies_healthy':healthy,
            'checks':{'startup':'pass' if startup else 'fail' if healthy else 'unknown',
                'normal':'pass' if normal else 'fail' if healthy else 'unknown',
                'restart':'pass' if startup and self.process.pid!=previous_pid else 'fail' if healthy else 'unknown'},
            'process_before':previous_pid,'process_after':self.process.pid,'observations':rows}


def main():
    if '--worker' in sys.argv:
        while True:
            print(json.dumps({**read_pod(),'at':datetime.now(timezone.utc).isoformat(),'pid':os.getpid()}),flush=True);time.sleep(.5)
    reader=Reader();check_lock=threading.Lock()
    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            if self.path!='/health':self.send_error(404);return
            self.send_response(200);self.end_headers();self.wfile.write(b'healthy')
        def do_POST(self):
            if self.path!='/check':self.send_error(404);return
            if not check_lock.acquire(blocking=False):self.send_error(409);return
            try:payload=json.dumps(reader.check()).encode()
            finally:check_lock.release()
            self.send_response(200);self.send_header('Content-Type','application/json');self.end_headers();self.wfile.write(payload)
        def log_message(self,*args):pass
    try:ThreadingHTTPServer(('0.0.0.0',8080),Handler).serve_forever()
    finally:reader.stop()


if __name__=='__main__':main()
