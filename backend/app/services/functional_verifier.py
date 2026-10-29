"""Bounded operator-selected functional harness; no model-chosen command/URL."""
import hashlib
import json
import os
import selectors
import signal
import subprocess
import time
from pathlib import Path
from agents.guardian.policy import canonical_hash
from backend.app.models.execution import FunctionalProof


class FunctionalVerifier:
    maximum_bytes=65536

    def __init__(self,governance):
        self.db=governance
        with self.db._connect() as db:
            db.executescript('''CREATE TABLE IF NOT EXISTS functional_checks (
                check_id TEXT PRIMARY KEY,payload TEXT NOT NULL,recorded_at TEXT NOT NULL);
                CREATE TRIGGER IF NOT EXISTS functional_checks_no_update BEFORE UPDATE ON functional_checks
                  BEGIN SELECT RAISE(ABORT,'immutable_verification'); END;
                CREATE TRIGGER IF NOT EXISTS functional_checks_no_delete BEFORE DELETE ON functional_checks
                  BEGIN SELECT RAISE(ABORT,'immutable_verification'); END;''')

    def profile_hash(self,profile):
        for name,expected in profile.artifact_hashes.items():
            path=Path(name)
            if not path.is_file() or hashlib.sha256(path.read_bytes()).hexdigest()!=expected:
                raise ValueError('functional_profile_artifact_changed')
        return canonical_hash(profile.model_dump(mode='json'))

    def check(self,profile,evidence,phase):
        digest=self.profile_hash(profile)
        request={'schema_version':'guardian.functional-request.v1','phase':phase,
            'cluster_id':evidence.target.cluster_id,'namespace':evidence.target.namespace,
            'target_uid':evidence.target.uid,'workload_uid':profile.workload_uid,'image_digest':profile.image_digest,
            'subject':evidence.subject.model_dump(mode='json')}
        # The environment allowlist and executable/artifact digests are operator
        # configuration included in review. Exit 0 alone never means pass.
        environment={key:os.environ[key] for key in profile.environment_keys if key in os.environ}
        environment.update(PATH='/usr/bin:/bin',LANG='C.UTF-8',PYTHONNOUSERSITE='1')
        started=self.db.now();deadline=time.monotonic()+profile.timeout_seconds
        process=subprocess.Popen(profile.argv,stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.DEVNULL,
            env=environment,start_new_session=True)
        output=bytearray()
        try:
            process.stdin.write(json.dumps(request).encode());process.stdin.close()
            with selectors.DefaultSelector() as selector:
                selector.register(process.stdout,selectors.EVENT_READ)
                while selector.get_map():
                    remaining=deadline-time.monotonic()
                    if remaining<=0:raise TimeoutError('functional_probe_timeout')
                    for selected,_ in selector.select(min(remaining,.5)):
                        chunk=os.read(selected.fileobj.fileno(),min(4096,self.maximum_bytes+1-len(output)))
                        if not chunk:selector.unregister(selected.fileobj);continue
                        output.extend(chunk)
                        if len(output)>self.maximum_bytes:raise ValueError('functional_probe_output_too_large')
            process.wait(timeout=max(.01,deadline-time.monotonic()))
            if process.returncode!=0:raise ValueError('functional_runner_unavailable')
            proof=FunctionalProof.model_validate_json(output)
            if ((proof.phase,proof.workload_uid,proof.image_digest)!=(phase,profile.workload_uid,profile.image_digest)
                    or proof.completed_at>self.db.now() or proof.started_at<started):
                raise ValueError('functional_proof_scope_or_time_mismatch')
            payload={'profile_hash':digest,'proof':proof.model_dump(mode='json')}
            identifier='check-'+canonical_hash(payload).split(':')[1]
            with self.db.transaction() as db:
                db.execute('INSERT OR IGNORE INTO functional_checks VALUES (?,?,?)',
                    (identifier,json.dumps(payload,sort_keys=True),self.db.now().isoformat()))
            return {'check_id':identifier,'profile_hash':digest,**proof.model_dump(mode='json')}
        finally:
            if process.poll() is None:
                os.killpg(process.pid,signal.SIGKILL);process.wait(timeout=5)
            process.stdout.close()
