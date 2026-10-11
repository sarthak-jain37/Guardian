"""Coverage ledger: what time ranges the collector provably observed, per apiserver source."""
from __future__ import annotations

import hashlib
import json

from .normalize import SA_PREFIX

COMPLETE = 'complete_for_declared_scope'


def load_policy(path: str | None) -> tuple[str, list[str]]:
    """Return (policy_ref, reason_codes). Any reason code downgrades coverage to 'partial'."""
    if not path:
        return 'policy:unverified', ['audit_policy_unverified']
    try:
        data = open(path, 'rb').read()
    except OSError:
        return 'policy:unreadable', ['audit_policy_unreadable']
    ref = 'policy:sha256:' + hashlib.sha256(data).hexdigest()[:16]
    try:
        import yaml
        doc = yaml.safe_load(data) or {}
    except Exception:
        return ref, ['audit_policy_unparsable']
    reasons = []
    if 'ResponseComplete' in (doc.get('omitStages') or []):
        reasons.append('policy_omits_ResponseComplete')
    for i, rule in enumerate(doc.get('rules') or []):
        if 'ResponseComplete' in (rule.get('omitStages') or []):
            reasons.append(f'rule{i}_omits_ResponseComplete')
        if rule.get('level') == 'None' and _may_hide_sa(rule):
            reasons.append(f'rule{i}_level_none_may_hide_serviceaccounts')
    return ref, reasons[:32]


def _may_hide_sa(rule: dict) -> bool:
    if rule.get('nonResourceURLs') and not rule.get('resources'):
        return False
    users, groups = rule.get('users') or [], rule.get('userGroups') or []
    if not users and not groups:
        return True
    return any(u.startswith(SA_PREFIX) for u in users) or any(g.startswith('system:serviceaccounts') for g in groups)


class Coverage:
    """One open segment [start, watermark] per source; closed segments live in a zset keyed by start."""

    def __init__(self, r, cluster: str, source: str):
        self.r = r
        self.open_key, self.closed_key, self.ver_key = f'covopen:{cluster}:{source}', f'cov:{cluster}:{source}', f'cv:{cluster}'
        self.wm = 0

    def get_open(self):
        return self.r.hgetall(self.open_key) or None

    def on_startup(self, mode: str, policy_ref: str, reasons: list[str]) -> tuple[bool, int | None]:
        """Returns (need_start, gap_from_us). need_start: open a new segment at the first observed event."""
        cur = self.get_open()
        if cur is None:
            return True, None
        self.wm = int(cur['wm'])
        same = cur['policy'] == policy_ref and json.loads(cur['reasons']) == reasons
        if mode == 'resumed' and same:
            return False, None                       # contiguous: events during downtime are replayed from the file
        self._close()
        if mode == 'resumed':
            self.open(self.wm, policy_ref, reasons)
            return False, None
        return True, self.wm                         # unrecoverable: [wm, first event) becomes an 'unavailable' gap

    def open(self, start_us: int, policy_ref: str, reasons: list[str]):
        self.r.hset(self.open_key, mapping={'start': start_us, 'wm': start_us, 'policy': policy_ref,
                                            'reasons': json.dumps(reasons),
                                            'status': COMPLETE if not reasons else 'partial'})
        self.r.incr(self.ver_key)
        self.wm = start_us

    def add_closed(self, start, end, status, reasons, policy_ref, lost):
        if end <= start:
            return
        m = json.dumps({'start': start, 'end': end, 'status': status, 'reasons': reasons,
                        'policy': [policy_ref], 'lost': lost}, sort_keys=True)
        self.r.zadd(self.closed_key, {m: start})
        self.r.incr(self.ver_key)

    def _close(self):
        cur = self.get_open()
        if not cur:
            return
        self.add_closed(int(cur['start']), int(cur['wm']), cur['status'], json.loads(cur['reasons']), cur['policy'], 0)
        self.r.delete(self.open_key)

    def begin(self, start_us, policy_ref, reasons, gap_from=None):
        if gap_from is not None:
            self.add_closed(gap_from, start_us, 'unavailable', ['collector_gap_unrecoverable'], policy_ref, None)
        self.open(start_us, policy_ref, reasons)

    def heartbeat(self, candidate_us: int):
        if candidate_us > self.wm:
            self.wm = candidate_us
            self.r.hset(self.open_key, 'wm', candidate_us)

    def record_defect(self, reason: str, lost: int | None, now_us: int):
        """Known loss somewhere in (watermark, now]: mark that span partial and continue."""
        cur = self.get_open()
        if not cur:
            return
        pol, reasons = cur['policy'], json.loads(cur['reasons'])
        wm = int(cur['wm'])
        self._close()
        self.add_closed(wm, max(now_us, wm + 1), 'partial', sorted(set(reasons + [reason])), pol, lost)
        self.open(max(now_us, wm + 1), pol, reasons)

    def policy_changed(self, policy_ref, reasons):
        cur = self.get_open()
        if cur and (cur['policy'] != policy_ref or json.loads(cur['reasons']) != reasons):
            wm = int(cur['wm'])
            self._close()
            self.open(wm, policy_ref, reasons)


def load_segments(r, cluster: str, source: str, lo: int, hi: int) -> list[dict]:
    segs = [d for d in map(json.loads, r.zrangebyscore(f'cov:{cluster}:{source}', '-inf', hi)) if d['end'] > lo]
    o = r.hgetall(f'covopen:{cluster}:{source}')
    if o and int(o['wm']) > int(o['start']):
        segs.append({'start': int(o['start']), 'end': int(o['wm']), 'status': o['status'],
                     'reasons': json.loads(o['reasons']), 'policy': [o['policy']], 'lost': 0})
    return segs


def merge_coverage(per_source: dict[str, list[dict]], lo: int, hi: int, now_us: int, floor_us: int):
    """Split [lo,hi) at every boundary; an interval is complete only if EVERY expected source is complete."""
    pts = {lo, hi}
    for segs in per_source.values():
        for s in segs:
            pts.update(t for t in (s['start'], s['end']) if lo < t < hi)
    pts.update(t for t in (floor_us, now_us) if lo < t < hi)
    pts = sorted(pts)
    last_end = {src: max((s['end'] for s in segs), default=None) for src, segs in per_source.items()}
    out = []
    for a, b in zip(pts, pts[1:]):
        if b <= floor_us:
            out.append(dict(a=a, b=b, status='unavailable', reasons=['beyond_aggregate_retention'],
                            sources=[], policy=[], health=[], lost=None))
            continue
        reasons, sources, policy, health, statuses, lost, have_lost = set(), [], set(), [], [], 0, False
        for src, segs in per_source.items():
            cov = [s for s in segs if s['start'] <= a and s['end'] >= b]
            if not cov:
                statuses.append('unavailable')
                if a >= now_us:
                    reasons.add('future_interval')
                elif last_end[src] is not None and a >= last_end[src]:
                    reasons.add(f'not_yet_processed:{src}')
                else:
                    reasons.add(f'no_collection_record:{src}')
                continue
            w = next((s for s in cov if s['status'] != COMPLETE), cov[0])
            statuses.append(w['status'])
            sources.append(src)
            reasons.update(w['reasons'])
            policy.update(w.get('policy', []))
            health.append(f"coverage:{src}:{w['start']}")
            if w.get('lost') is not None:
                lost, have_lost = lost + w['lost'], True
        status = (COMPLETE if all(s == COMPLETE for s in statuses) else
                  'unavailable' if all(s == 'unavailable' for s in statuses) else 'partial')
        out.append(dict(a=a, b=b, status=status, reasons=sorted(reasons)[:32], sources=sources[:32],
                        policy=sorted(policy)[:32], health=health[:32], lost=lost if have_lost else None))
    merged = []
    for s in out:                                    # coalesce neighbours that differ only by interval
        if merged and merged[-1]['b'] == s['a'] and all(merged[-1][k] == s[k] for k in s if k not in ('a', 'b')):
            merged[-1]['b'] = s['b']
        else:
            merged.append(s)
    ends = list(last_end.values())
    processed = None if (not ends or any(e is None for e in ends)) else min(ends)
    return merged, processed
