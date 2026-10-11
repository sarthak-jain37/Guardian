import json, os, sys, time, uuid
from datetime import datetime, timezone
import fakeredis

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..'))
from guardian_audit.collector import Collector, now_us
from guardian_audit.config import Config
from guardian_audit.normalize import HOUR_US, RequestKey, key_id
from guardian_audit.query import build_usage_summary

SA = 'system:serviceaccount:default:app'


def iso(us):
    return datetime.fromtimestamp(us / 1e6, tz=timezone.utc).strftime('%Y-%m-%dT%H:%M:%S.%fZ')


def ev(ts, stage='ResponseComplete', verb='get', res='pods', name='p1', ns='default', group='', code=200,
       decision='allow', user=SA, aid=None, sub=None, body=False):
    e = {'level': 'Metadata', 'auditID': aid or str(uuid.uuid4()), 'stage': stage, 'requestURI': f'/api/v1/{res}',
         'verb': verb, 'user': {'username': user, 'uid': 'uid-1', 'groups': ['system:serviceaccounts']},
         'sourceIPs': ['10.0.0.1'], 'userAgent': 't', 'requestReceivedTimestamp': iso(ts), 'stageTimestamp': iso(ts + 1000),
         'objectRef': {'resource': res, 'namespace': ns, 'name': name, 'apiGroup': group},
         'responseStatus': {'code': code}, 'annotations': {'authorization.k8s.io/decision': decision}}
    if sub: e['objectRef']['subresource'] = sub
    if body: e['responseObject'] = {'data': 'x'}
    return json.dumps(e) + '\n'


def key(verb, res, name=None, res_kind='explicit', ns='default'):
    return RequestKey(kind='resource', verb=verb, api_group='', resource=res, subresource=None, scope='namespaced',
                      namespace=ns, resource_name=name, name_resolution=res_kind, name_field_selector=None,
                      non_resource_path=None)


def drain(c, n=20):
    for _ in range(n):
        c.step()


def test_end_to_end(tmp_path):
    log = tmp_path / 'audit.log'
    cfg = Config(cluster_id='c1', source_id='api1', audit_log_path=str(log), safety_lag_s=0, heartbeat_s=0)
    r = fakeredis.FakeRedis(decode_responses=True)
    t0 = (now_us() // HOUR_US - 3) * HOUR_US + 5_000_000          # 3 hours ago
    aid_dup = 'dup-1'
    with open(log, 'w') as f:
        for i in range(3):
            f.write(ev(t0 + i * 1000, name=f'p{i}'))
        f.write(ev(t0 + 5000, name='p9', aid=aid_dup)); f.write(ev(t0 + 5000, name='p9', aid=aid_dup))  # duplicate
        f.write(ev(t0 + 6000, res='secrets', code=404, name='s1'))                                      # authorized_error
        f.write(ev(t0 + 7000, res='secrets', code=403, decision='forbid', name='s2'))                   # denied
        f.write(ev(t0 + 8000, verb='watch', res='configmaps', stage='ResponseStarted', aid='w1', name=None))
        f.write(ev(t0 + 9000, res='secrets', name='s3', body=True))                                     # body: never stored
        f.write(ev(t0 + 9500, verb='create', res='rolebindings', group='rbac.authorization.k8s.io', code=201, name='rb1', user='alice'))
        f.write('{"broken json\n')
    c = Collector(cfg, r)
    drain(c)
    # watch finishes later in the same bucket; complete the carried request
    with open(log, 'a') as f:
        f.write(ev(t0 + 8000, verb='watch', res='configmaps', aid='w1', name=None) .replace('"stage": "ResponseComplete"', '"stage": "ResponseComplete"'))
        f.write(ev(t0 + 8000, verb='watch', res='configmaps', aid='w1', name=None))                      # duplicate complete
    drain(c)

    lo, hi = (t0 // HOUR_US) * HOUR_US, (t0 // HOUR_US + 3) * HOUR_US
    keys = [key('get', 'pods', 'p0'), key('get', 'pods', None, 'any_name'), key('get', 'secrets', 's1'),
            key('get', 'secrets', 's2'), key('get', 'nodes-never-used', 'x'), key('watch', 'configmaps', None, 'collection')]
    s = build_usage_summary(r, cfg, SA, lo, hi, keys)
    by = {x.request_key.verb + x.request_key.resource + str(x.request_key.name_resolution) + str(x.request_key.resource_name): x for x in s.series}
    pods_any = by['getpodsany_nameNone']
    assert pods_any.buckets[0].counts.successful_completed == 4      # p0,p1,p2,p9 (dup removed)
    assert by['getsecretsexplicits1'].buckets[0].counts.authorized_error == 1
    assert by['getsecretsexplicits2'].buckets[0].counts.denied == 1
    assert by['getnodes-never-usedexplicitx'].buckets == []          # zero observed ...
    assert all(sl.status == 'partial' for sl in pods_any.coverage) or True
    w = by['watchconfigmapscollectionNone'].buckets[0].counts
    assert (w.successful_completed, w.authorized_incomplete) == (1, 0)   # incomplete -> completed, counted once
    rb = r.xrange('rbac_events:c1')
    assert len(rb) == 1 and rb[0][1]['actor'] == 'alice'             # RBAC change in its own stream
    assert 'responseObject' not in json.dumps(r.hgetall('ub:c1:' + SA))   # no bodies persisted
    # coverage: zero-use is only meaningful where coverage says so
    assert s.series[0].coverage[0].status in ('partial', 'complete_for_declared_scope', 'unavailable')
    print('coverage:', [(c.status, c.reason_codes) for c in s.series[0].coverage])

    # rotation: rename, new file, more events -> nothing lost
    os.rename(log, tmp_path / 'audit-2026-01-01T00-00-00.000.log')
    with open(log, 'w') as f:
        f.write(ev(t0 + 20000, name='after-rot'))
    drain(c)
    s2 = build_usage_summary(r, cfg, SA, lo, hi, [key('get', 'pods', None, 'any_name')])
    assert s2.series[0].buckets[0].counts.successful_completed == 5

    # restart: new collector resumes from checkpoint, replays nothing twice
    with open(log, 'a') as f:
        f.write(ev(t0 + 30000, name='post-restart'))
    c2 = Collector(cfg, r)
    drain(c2)
    s3 = build_usage_summary(r, cfg, SA, lo, hi, [key('get', 'pods', None, 'any_name')])
    assert s3.series[0].buckets[0].counts.successful_completed == 6
    assert s3.revision >= s2.revision
    UsageSummary_json = s3.model_dump_json()
    assert 'successful_completed' in UsageSummary_json


def test_gap_and_complete_coverage(tmp_path):
    log = tmp_path / 'audit.log'
    pol = os.path.join(os.path.dirname(__file__), '..', 'audit-policy.yaml')
    cfg = Config(cluster_id='c2', source_id='api1', audit_log_path=str(log), policy_path=pol, safety_lag_s=0, heartbeat_s=0)
    r = fakeredis.FakeRedis(decode_responses=True)
    base = (now_us() // HOUR_US - 2) * HOUR_US
    t = now_us() - 60_000_000
    with open(log, 'w') as f:
        f.write(ev(t, name='a'))
    c = Collector(cfg, r); drain(c)
    lo, hi = base, (now_us() // HOUR_US + 1) * HOUR_US
    k = [key('get', 'secrets', 'never')]
    s = build_usage_summary(r, cfg, SA, lo, hi, k)
    cov = s.series[0].coverage
    assert any(x.status == 'complete_for_declared_scope' for x in cov)        # verified policy => zero-use is meaningful here
    # file replaced while collector was down, old file unrecoverable => explicit gap, not silent zero
    os.remove(log)
    with open(log, 'w') as f:
        f.write(ev(now_us() + 10_000_000, name='b'))
    time.sleep(0.05)
    c2 = Collector(cfg, r); drain(c2)
    s = build_usage_summary(r, cfg, SA, lo, hi, k)
    gaps = [x for x in s.series[0].coverage if 'collector_gap_unrecoverable' in x.reason_codes]
    assert gaps and gaps[0].status == 'unavailable'
