"""Validated model assessments and Redis-backed, advisory pod alerts."""
import asyncio
import hashlib
import json
import logging
import os
import time
from datetime import datetime, timezone
from typing import Literal
from pydantic import BaseModel, ConfigDict, Field, StrictInt, model_validator
from backend.app.services.pod_review import review_context

logger = logging.getLogger(__name__)


class Grade(BaseModel):
    model_config = ConfigDict(extra='forbid')
    status: Literal['assessed', 'insufficient_evidence']
    severity: StrictInt | None = Field(ge=0, le=10)
    reasons: list[str] = Field(min_length=1, max_length=5)
    evidence_ids: list[str] = Field(max_length=12)
    uncertainty: str = Field(min_length=1, max_length=2000)
    next_checks: list[str] = Field(max_length=5)

    @model_validator(mode='after')
    def consistent(self):
        if (self.status == 'assessed') != (self.severity is not None):
            raise ValueError('An assessment requires a score; insufficient evidence requires null')
        if self.status == 'assessed' and not self.evidence_ids:
            raise ValueError('A score requires cited observations')
        return self


def validate_grade(raw, document):
    grade = Grade.model_validate(raw)
    attributed = {e['id'] for e in document.get('events', [])}
    shared = {e['id'] for e in document.get('shared_identity_events', [])}
    if not set(grade.evidence_ids) <= attributed | shared:
        raise ValueError('Model cited evidence outside this review')
    if grade.status == 'assessed' and not set(grade.evidence_ids) & attributed:
        raise ValueError('A pod score requires attributed evidence, not only shared identity')
    return grade.model_dump()


def fingerprint(document):
    stable = {k: document.get(k) for k in ('pod', 'containers', 'permission_points', 'boundaries')}
    stable['grading_configuration'] = {'rubric':'severity-v1', 'model':os.getenv('MODEL_PATH',''), 'context':os.getenv('LLM_CONTEXT_SIZE','8192'), 'output_tokens':os.getenv('LLM_GRADE_MAX_TOKENS','512')}
    stable['events'] = [e['id'] for e in document.get('events', [])]
    stable['shared'] = [e['id'] for e in document.get('shared_identity_events', [])]
    # Collection error changes matter, but moving collection timestamps do not.
    stable['coverage'] = {k: {'state': v.get('state'), 'error': v.get('error')} for k, v in document.get('coverage', {}).items()}
    return hashlib.sha256(json.dumps(stable, sort_keys=True).encode()).hexdigest()


def material_signals(document):
    context = json.dumps({k: document.get(k) for k in ('pod','containers','permission_points','boundaries')}, sort_keys=True)
    return sorted({'context:' + hashlib.sha256(context.encode()).hexdigest()} | {json.dumps({'kind': e.get('kind'), 'findings': e.get('findings', []),
                              'binary': e.get('process', {}).get('binary'), 'function': e.get('function_name'),
                              'verb': e.get('verb'), 'target': e.get('target'), 'outcome': e.get('outcome'),
                              'http': e.get('http'), 'paths': e.get('runtime', {}).get('file_paths')}, sort_keys=True)
                   for e in document.get('events', []) if e.get('findings')})


class PodGrader:
    def __init__(self, telemetry, infer=None):
        self.telemetry, self.redis = telemetry, telemetry.redis
        self.prefix = telemetry.prefix + ':grading'
        self.interval = max(10, int(os.getenv('POD_REVIEW_INTERVAL', '60')))
        self.threshold = max(1, min(10, int(os.getenv('POD_ALERT_THRESHOLD', '7'))))
        self.sample = max(3, min(30, int(os.getenv('POD_REVIEW_EVENT_LIMIT', '8'))))
        self.enabled = os.getenv('POD_REVIEW_ENABLED', 'true').lower() == 'true'
        self.ttl = telemetry.ttl
        self.lock = asyncio.Lock()
        self.state_lock = asyncio.Lock()
        self.infer = infer
        self.health = {'enabled': self.enabled, 'state': 'starting' if self.enabled else 'disabled',
                       'interval_seconds': self.interval, 'alert_threshold': self.threshold,
                       'notification': 'In-dashboard only; no external messages', 'current_pod': None}

    async def get(self, collection, uid):
        raw = await self.redis.get(self.prefix + ':' + collection + ':' + uid)
        return json.loads(raw) if raw else None

    async def put(self, collection, uid, record):
        now = time.time()
        async with self.redis.pipeline(transaction=True) as pipe:
            pipe.set(self.prefix + ':' + collection + ':' + uid, json.dumps(record), ex=self.ttl)
            pipe.zadd(self.prefix + ':' + collection, {uid: now})
            pipe.zremrangebyscore(self.prefix + ':' + collection, '-inf', now - self.ttl)
            await pipe.execute()

    async def records(self, collection, namespace=None):
        uids = await self.redis.zrevrange(self.prefix + ':' + collection, 0, -1)
        if not uids:
            return []
        values = await self.redis.mget([self.prefix + ':' + collection + ':' + uid for uid in uids])
        return [r for raw in values if raw and (r := json.loads(raw)) and (not namespace or r['namespace'] == namespace)]

    async def inventory_matches(self, uid, namespace, pod):
        snapshot = json.loads(await self.redis.get(self.telemetry.prefix + ':inventory') or '{}')
        return any(p.get('uid') == uid and p['namespace'] == namespace and p['pod'] == pod for p in snapshot.get('pods', []))

    async def review(self, document, force=False):
        async with self.lock:
            identity = document['pod']
            uid, namespace, pod = identity['uid'], identity['namespace'], identity['pod']
            previous = await self.get('reviews', uid)
            signature = fingerprint(document)
            if not force and previous and previous.get('fingerprint') == signature and previous.get('status') != 'error':
                return previous
            self.health.update(state='reviewing', current_pod=namespace + '/' + pod)
            now = datetime.now(timezone.utc).isoformat()
            record = {'cluster': document['cluster'], 'namespace': namespace, 'pod': pod, 'uid': uid,
                      'review_started_at': now, 'reviewed_at': now, 'fingerprint': signature, 'sample': document['sample'],
                      'coverage': document['coverage'], 'evidence': document.get('events', []),
                      'shared_identity_evidence': document.get('shared_identity_events', []), 'model_assessment': True,
                      'remediation_enabled': False, 'scoring_enabled': True}
            try:
                if not document.get('events'):
                    raw = {'status': 'insufficient_evidence', 'severity': None, 'reasons': ['No attributed observations available.'],
                           'evidence_ids': [], 'uncertainty': 'Missing telemetry does not establish safety.', 'next_checks': ['Check collection coverage.']}
                else:
                    infer = self.infer
                    if infer is None:
                        from agents.summarizer import grade_document
                        infer = grade_document
                    raw = await asyncio.to_thread(infer, document)
                record.update(validate_grade(raw, document))
            except Exception as exc:
                logger.exception('Pod model assessment failed for %s/%s', namespace, pod)
                record.update(status='error', severity=None, reasons=['Local model review could not be validated.'],
                              evidence_ids=[], uncertainty='No valid grade was produced. Previous alerts remain available.',
                              next_checks=['Inspect model configuration, context size and service logs.'], error_type=type(exc).__name__)
            record['reviewed_at'] = datetime.now(timezone.utc).isoformat()
            if not await self.inventory_matches(uid, namespace, pod):
                self.health.update(state='idle', current_pod=None)
                return {**record, 'status': 'superseded', 'severity': None}
            async with self.state_lock:
                await self.put('reviews', uid, record)
                await self.update_alert(uid, record, document)
            self.health.update(state='idle', current_pod=None, last_reviewed_at=record['reviewed_at'])
            return record

    async def update_alert(self, uid, record, document):
        old = await self.get('alerts', uid)
        if record['status'] != 'assessed':
            return  # Errors and missing evidence never resolve an existing alert.
        dangerous = record['severity'] >= self.threshold
        if not dangerous and not old:
            return
        signals = material_signals(document)
        reopen = dangerous and (not old or not old.get('active') or record['severity'] > old['severity']
                                or bool(set(signals) - set(old.get('material_signals', []))))
        alert = {**record, 'id': uid, 'active': dangerous, 'threshold': self.threshold,
                 'material_signals': signals, 'first_seen': old['first_seen'] if old else record['reviewed_at'],
                 'acknowledged': False if reopen else (old or {}).get('acknowledged', False),
                 'version': (old or {}).get('version', 0) + 1}
        await self.put('alerts', uid, alert)

    async def acknowledge(self, uid, version):
        # The same lock protects against acknowledging over a newly raised alert.
        async with self.state_lock:
            record = await self.get('alerts', uid)
            if not record:
                return None
            if record['version'] != version:
                raise ValueError('Alert changed; refresh before acknowledging')
            record.update(acknowledged=True, acknowledged_at=datetime.now(timezone.utc).isoformat())
            await self.put('alerts', uid, record)
            return record

    async def run(self):
        if not self.enabled:
            return
        while True:
            try:
                snapshot = json.loads(await self.redis.get(self.telemetry.prefix + ':inventory') or '{}')
                self.health.pop('error', None)
                self.health.update(state='scanning', last_scan_at=datetime.now(timezone.utc).isoformat())
                # Serial inference avoids competing model requests. Every current pod is visited.
                for pod in snapshot.get('pods', []):
                    try:
                        document = await review_context(self.telemetry, pod['namespace'], pod['pod'], self.sample)
                        if document:
                            await self.review(document)
                    except asyncio.CancelledError:
                        raise
                    except Exception:
                        logger.exception('Could not review pod %s/%s; continuing cycle', pod['namespace'], pod['pod'])
                        self.health['error'] = 'One or more pod reviews failed; check service logs'
                self.health.update(state='waiting', current_pod=None)
            except asyncio.CancelledError:
                raise
            except Exception:
                logger.exception('Continuous pod review failed')
                self.health.update(state='error', current_pod=None, error='Review cycle failed; retrying next cycle')
            await asyncio.sleep(self.interval)
