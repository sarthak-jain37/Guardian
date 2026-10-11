"""Read path: build a guardian.usage-summary.v1 document for one subject and a set of request keys."""
from __future__ import annotations

import json
import time
import uuid

from . import AGGREGATION_VERSION, COLLECTOR_VERSION
from .config import Config
from .coverage import load_segments, merge_coverage
from .normalize import HOUR_US, from_us, key_id, parse_sa
from .schema import (CarriedAuthorization, Counts, CoverageSlice, RequestKey, Subject, UsageBucket,
                     UsageSeries, UsageSummary, Window)

MAX_BUCKETS, MAX_CARRIED = 2200, 1000


def _subject(r, cluster, username, warnings) -> Subject:
    raw = r.hget(f'sj:{cluster}:{username}', 'json')
    d = json.loads(raw) if raw else {}
    uids = r.smembers(f'sju:{cluster}:{username}')
    sa = parse_sa(username)
    if len(uids) > 1:      # same name, different uid => ServiceAccount was deleted/recreated; history is mixed
        warnings.append(f'multiple_uids_observed:{len(uids)}')
    uid = next(iter(uids)) if len(uids) == 1 else None
    return Subject(username=username, kind='service_account' if sa else ('user' if username else 'unknown'),
                   namespace=sa[0] if sa else None, name=sa[1] if sa else None, uid=uid,
                   uid_status='verified' if uid else 'unknown', groups=d.get('groups', [])[:128],
                   identity_evidence_refs=[f"audit:{d['evidence']}"] if d.get('evidence') else [])


def _series(r, cluster, username, rk: RequestKey, lo, hi, coverage, warnings) -> tuple[UsageSeries, bool]:
    kid = key_id(rk)
    if rk.name_resolution == 'any_name':    # RBAC rule without resourceNames: aggregate every observed name
        from .normalize import family_id
        ids = sorted(r.smembers(f'ukf:{cluster}:{username}:{family_id(rk)}'))
    else:
        ids = [kid]
    # buckets
    targets = []
    for i in ids:
        for b in r.zrangebyscore(f'ubi:{cluster}:{username}:{i}', lo, hi - 1):
            targets.append((int(b), f'ub:{cluster}:{username}:{i}:{b}', f'ubr:{cluster}:{username}:{i}:{b}'))
    pipe = r.pipeline(transaction=False)
    for _, bk, ek in targets:
        pipe.hgetall(bk)
        pipe.smembers(ek)
    res = pipe.execute()
    agg: dict[int, dict] = {}
    for n, (b, _, _) in enumerate(targets):
        h, ev = res[2 * n], res[2 * n + 1]
        if not h:
            continue
        a = agg.setdefault(b, dict(c=dict.fromkeys(Counts.model_fields, 0), first=None, last=None, ev=set()))
        for f in a['c']:
            a['c'][f] += int(h.get(f, 0))
        if 'first' in h:
            a['first'] = int(h['first']) if a['first'] is None else min(a['first'], int(h['first']))
            a['last'] = int(h['last']) if a['last'] is None else max(a['last'], int(h['last']))
        a['ev'] |= set(ev)
    truncated = False
    buckets = []
    for b in sorted(agg):
        a = agg[b]
        buckets.append(UsageBucket(
            bucket_start=from_us(b), interval=Window(start=from_us(b), end=from_us(b + HOUR_US)),
            counts=Counts(**{k: max(0, v) for k, v in a['c'].items()}),
            first_request_at=from_us(a['first']) if a['first'] else None,
            last_request_at=from_us(a['last']) if a['last'] else None,
            evidence_refs=sorted(a['ev'])[:32]))
    if len(buckets) > MAX_BUCKETS:
        buckets, truncated = buckets[:MAX_BUCKETS], True
        warnings.append(f'buckets_truncated:{kid}')
    # requests that began before the window and may still be running into it
    carried = []
    for i in ids:
        cidx = f'cyi:{cluster}:{username}:{i}'
        aids = list(r.smembers(cidx))
        p = r.pipeline(transaction=False)
        for a in aids:
            p.hgetall(f'cy:{cluster}:{a}:{i}')
        for a, h in zip(aids, p.execute()):
            if not h:
                r.srem(cidx, a)                       # expired
                continue
            started, done = int(h['started']), int(h['done']) if 'done' in h else None
            if started < lo and (done is None or done >= lo):
                carried.append(CarriedAuthorization(
                    request_ref=a, request_started_at=from_us(started), authorized_at=from_us(int(h['auth'])),
                    last_observed_at=from_us(int(h['last'])), completed_at=from_us(done) if done else None,
                    evidence_refs=[f'audit:{a}', h['ev']]))
    carried.sort(key=lambda c: c.request_started_at, reverse=True)
    if len(carried) > MAX_CARRIED:
        carried, truncated = carried[:MAX_CARRIED], True
        warnings.append(f'carried_truncated:{kid}')
    return UsageSeries(request_key_id=kid, request_key=rk, buckets=buckets, coverage=coverage,
                       carried_authorized_requests=carried), truncated


def build_usage_summary(r, cfg: Config, username: str, window_start_us: int, window_end_us: int,
                        requested_keys: list[RequestKey], now_us: int | None = None) -> UsageSummary:
    """Window must be hour-aligned (boundary_mode='exact'): hourly aggregates can't be split honestly."""
    if window_start_us % HOUR_US or window_end_us % HOUR_US or window_start_us >= window_end_us:
        raise ValueError('window must be hour-aligned UTC with start < end (boundary_mode=exact)')
    if not 1 <= len(requested_keys) <= 256:
        raise ValueError('1..256 request keys required')
    now_us = now_us or time.time_ns() // 1000
    cluster, warnings = cfg.cluster_id, []
    floor = (now_us - cfg.agg_ttl_s * 1_000_000) // HOUR_US * HOUR_US + HOUR_US
    per_source = {s: load_segments(r, cluster, s, window_start_us, window_end_us) for s in cfg.sources}
    merged, processed = merge_coverage(per_source, window_start_us, window_end_us, now_us, floor)
    slices = [CoverageSlice(interval=Window(start=from_us(m['a']), end=from_us(m['b'])), status=m['status'],
                            reason_codes=m['reasons'], source_ids=m['sources'], audit_policy_refs=m['policy'],
                            health_evidence_refs=m['health'], known_lost_events=m['lost']) for m in merged]
    truncated = False
    if len(slices) > 5000:
        slices, truncated = slices[:5000], True
        warnings.append('coverage_truncated')
    subject = _subject(r, cluster, username, warnings)
    series = []
    for rk in requested_keys:
        s, t = _series(r, cluster, username, rk, window_start_us, window_end_us, slices, warnings)
        series.append(s)
        truncated |= t
    ids = [s.request_key_id for s in series]
    rev = max(1, int(r.get(f'sv:{cluster}:{username}') or 0) + int(r.get(f'cv:{cluster}') or 0))
    cursors = []
    for s in cfg.sources:
        raw = r.get(f'ckpt:{cluster}:{s}')
        if raw:
            p = json.loads(raw)
            cursors.append(f"cursor:{s}:{p['inode']}:{p['offset']}")
    return UsageSummary(
        schema_version='guardian.usage-summary.v1',
        summary_id='us_' + uuid.uuid5(uuid.NAMESPACE_URL, f'{cluster}|{username}|{window_start_us}|{window_end_us}|{sorted(ids)}|{rev}').hex,
        revision=rev, cluster_id=cluster, subject=subject,
        query_window=Window(start=from_us(window_start_us), end=from_us(window_end_us)),
        generated_at=from_us(now_us), processed_through=from_us(processed) if processed else None,
        bucket_resolution='PT1H', boundary_mode='exact', collector_version=COLLECTOR_VERSION,
        aggregation_version=AGGREGATION_VERSION, source_cursor_refs=cursors[:128], requested_key_ids=ids,
        series=series, truncated=truncated, warnings=sorted(set(warnings))[:128])
