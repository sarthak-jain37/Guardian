"""Collector loop: tail -> parse -> commit(batch + checkpoint) -> coverage heartbeat."""
from __future__ import annotations

import json
import logging
import time

import redis

from .config import Config
from .coverage import Coverage, load_policy
from .normalize import extract, parse_us
from .store import Store
from .tailer import Tailer

log = logging.getLogger('guardian.audit')


def now_us() -> int:
    return time.time_ns() // 1000


class Collector:
    def __init__(self, cfg: Config, r):
        self.cfg, self.r = cfg, r
        self.store = Store(r, cfg)
        self.cov = Coverage(r, cfg.cluster_id, cfg.source_id)
        self.tailer = Tailer(cfg.audit_log_path, cfg.source_id)
        self.policy_ref, self.policy_reasons = load_policy(cfg.policy_path)
        mode = self.tailer.start(self.store.load_checkpoint())
        self.need_start, self.gap_from = self.cov.on_startup(mode, self.policy_ref, self.policy_reasons)
        self.secret_bodies_seen = 0
        self._hb = self._pol = 0.0
        log.info('collector start mode=%s need_start=%s', mode, self.need_start)

    def _parse(self, lines):
        usage, rbac, bad, max_ts, min_ts = [], [], 0, None, None
        for raw in lines:
            raw = raw.strip()
            if not raw:
                continue
            try:
                entry = json.loads(raw)
            except ValueError:
                bad += 1
                continue
            sts = parse_us(entry.get('stageTimestamp')) if isinstance(entry, dict) else None
            if sts:
                max_ts = sts if max_ts is None else max(max_ts, sts)
                min_ts = sts if min_ts is None else min(min_ts, sts)
            ex = extract(entry)
            usage += ex.usage
            if ex.rbac:
                rbac.append(ex.rbac)
            self.secret_bodies_seen += ex.secret_body_seen   # never stored; only counted + logged
        return usage, rbac, bad, min_ts, max_ts

    def _commit(self, usage, rbac, batch):
        delay = 1.0
        while True:                                          # file position is only advanced after success
            try:
                pipe = self.r.pipeline(transaction=False)
                for ev in usage:
                    self.store.apply_usage(pipe, ev, batch.segment_ref)
                for ev in rbac:
                    self.store.apply_rbac(pipe, ev)
                self.store.save_checkpoint(pipe, batch.position)
                pipe.execute()
                return
            except redis.RedisError as e:
                log.warning('redis error, retrying same batch: %s', e)
                time.sleep(delay)
                delay = min(delay * 2, 30)

    def step(self) -> bool:
        batch = self.tailer.read_batch()
        usage, rbac, bad, min_ts, max_ts = self._parse(batch.lines)
        if batch.position and (batch.lines or batch.notices):
            self._commit(usage, rbac, batch)
        now, lag = now_us(), self.cfg.safety_lag_s * 1_000_000
        if self.need_start:
            if min_ts or (batch.at_eof and self.tailer.offset == 0 and self.tailer.fh):
                self.cov.begin(min(min_ts, now) if min_ts else now, self.policy_ref, self.policy_reasons, self.gap_from)
                self.need_start = False
        else:
            if bad:
                self.cov.record_defect('malformed_log_line', bad, now)
            if 'truncated' in batch.notices:
                self.cov.record_defect('log_truncated', None, now)
            if time.monotonic() - self._hb >= self.cfg.heartbeat_s:
                caught_up = batch.at_eof and not batch.lines
                cand = now - lag if caught_up else (max_ts - lag if max_ts else None)
                if cand:
                    self.cov.heartbeat(min(cand, now - lag))
                    self._hb = time.monotonic()
            if time.monotonic() - self._pol >= 60:
                self._pol = time.monotonic()
                ref, reasons = load_policy(self.cfg.policy_path)
                if (ref, reasons) != (self.policy_ref, self.policy_reasons):
                    self.policy_ref, self.policy_reasons = ref, reasons
                    self.cov.policy_changed(ref, reasons)
        if self.secret_bodies_seen:
            log.error('Secret request/response bodies present in audit log (%d): fix the audit policy; bodies are NOT stored',
                      self.secret_bodies_seen)
            self.secret_bodies_seen = 0
        return bool(batch.lines or batch.notices)

    def run_forever(self):
        while True:
            try:
                if not self.step():
                    time.sleep(self.cfg.poll_s)
            except Exception:
                log.exception('unexpected error in collector loop')
                time.sleep(2)


if __name__ == '__main__':
    logging.basicConfig(level=logging.INFO, format='%(asctime)s %(levelname)s %(name)s %(message)s')
    cfg = Config.from_env()
    Collector(cfg, redis.Redis(host=cfg.redis_host, port=cfg.redis_port, decode_responses=True)).run_forever()
