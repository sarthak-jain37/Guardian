"""Run local Guardian services; retry each failed process independently.

Run with the repository virtualenv. This is a local Minikube development launcher,
not an in-cluster production deployment. Stop with SIGTERM or Ctrl+C.
"""
import argparse
import json
import logging
import os
from pathlib import Path
import signal
import subprocess
import time

from dotenv import load_dotenv


class Service:
    def __init__(self, name, command, output, directory):
        self.name, self.command = name, command
        self.output, self.directory = output, directory
        self.process = None
        self.retry_at = 0
        self.failures = 0
        self.started_at = 0

    def tick(self, now):
        if self.process is not None:
            code = self.process.poll()
            if code is None:
                return
            if now - self.started_at > 60:
                self.failures = 0
            self.failures += 1
            delay = min(60, 2 ** min(self.failures, 6))
            logging.warning('%s exited (%s); retry in %ss', self.name, code, delay)
            self.process = None
            self.retry_at = now + delay
        if now < self.retry_at:
            return
        try:
            with self.output.open('ab', buffering=0) as stdout, (self.directory / (self.name + '.stderr.log')).open('ab', buffering=0) as stderr:
                self.process = subprocess.Popen(self.command, stdout=stdout, stderr=stderr, start_new_session=True)
            self.started_at = now
            logging.info('Started %s pid=%s', self.name, self.process.pid)
        except OSError:
            logging.exception('Could not launch %s; retry in 60s', self.name)
            self.retry_at = now + 60

    def stop(self):
        if self.process is not None and self.process.poll() is None:
            try:
                os.killpg(self.process.pid, signal.SIGTERM)
            except ProcessLookupError:
                pass

    def reap(self):
        if self.process is None:
            return
        try:
            self.process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            try:
                os.killpg(self.process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            self.process.wait()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--context', required=True, help='Explicit kubectl context')
    parser.add_argument('--profile', required=True, help='Minikube Docker container name')
    parser.add_argument('--log-dir', required=True, type=Path)
    args = parser.parse_args()
    repo = Path(__file__).resolve().parents[1]
    load_dotenv(repo / '.env')
    os.environ.setdefault('POD_REVIEW_ENABLED', 'true')
    os.environ.setdefault('POD_REVIEW_INTERVAL', '120')
    os.environ.setdefault('POD_INVENTORY_INTERVAL', '10')
    os.chdir(repo)
    directory = args.log_dir.resolve()
    directory.mkdir(parents=True, exist_ok=True, mode=0o700)
    # Prevent a second launcher from appending to the same exports or binding ports.
    import fcntl
    lock = (directory / 'services.lock').open('w')
    fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
    logging.basicConfig(level=logging.INFO, format='%(asctime)s %(levelname)s %(message)s')
    python = str(repo / '.venv/bin/python')
    kubectl = ['kubectl', '--context', args.context, '-n', 'kube-system']
    def export_path(variable):
        value = os.environ.get(variable)
        if not value:
            raise ValueError(f'{variable} must be set in .env')
        path = Path(value).resolve()
        path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        return path
    specs = [
        ('hubble-forward', kubectl + ['port-forward', 'svc/hubble-relay', '4245:80'], None),
        ('audit-export', ['docker', 'exec', args.profile, 'tail', '-n', '+1', '-F', '/var/log/guardian-e2e-audit/audit.log'], export_path('POD_AUDIT_EXPORT_PATH')),
        ('tetragon-export', kubectl + ['logs', '-l', 'app.kubernetes.io/name=tetragon', '-c', 'export-stdout', '--follow', '--since=30s', '--max-log-requests=100'], export_path('TETRAGON_EXPORT_PATH')),
        ('hubble-export', ['hubble', 'observe', '--server', 'localhost:4245', '--follow', '--output', 'json'], export_path('HUBBLE_EXPORT_PATH')),
        ('backend', [python, '-m', 'uvicorn', 'backend.app.main:app', '--host', '127.0.0.1', '--port', '8000'], None),
        ('frontend', [python, '-m', 'streamlit', 'run', 'frontend/main.py', '--server.address', '127.0.0.1', '--server.port', '8501', '--server.headless', 'true', '--browser.gatherUsageStats', 'false'], None),
    ]
    services = [Service(name, command, output or directory / (name + '.log'), directory) for name, command, output in specs]
    stopping = False
    def stop(signum, frame):
        nonlocal stopping
        stopping = True
    signal.signal(signal.SIGTERM, stop)
    signal.signal(signal.SIGINT, stop)
    os.umask(0o077)
    try:
        while not stopping:
            for service in services:
                service.tick(time.monotonic())
            state = {s.name: s.process.pid if s.process else None for s in services}
            temporary = directory / 'processes.json.tmp'
            temporary.write_text(json.dumps(state, indent=2))
            temporary.replace(directory / 'processes.json')
            time.sleep(1)
    finally:
        for service in services:
            service.stop()
        for service in services:
            service.reap()
        (directory / 'processes.json').write_text('{}\n')
        lock.close()


if __name__ == '__main__':
    main()
