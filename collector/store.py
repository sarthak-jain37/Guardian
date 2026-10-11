"""Redis write path. Every event is applied by one Lua script => dedupe + counters + indexes are atomic,
so replays after a crash/rotation/restart are idempotent (at-least-once read, exactly-once effect)."""
from __future__ import annotations

import json

from .normalize import HOUR_US, UsageEvent
from .tailer import Position

# KEYS: 1 dd  2 dd_complete  3 bucket  4 bucket_idx  5 bucket_evidence  6 subject_keys  7 family_keys
#       8 keydefs  9 subject  10 subject_uids  11 version  12 carry  13 carry_idx
# ARGV: 1 dedupe_ttl 2 agg_ttl 3 carry_ttl 4 stage 5 outcome 6 ts_us 7 bucket_us 8 key_id 9 keydef_json
#       10 subject_json 11 uid 12 audit_id 13 stage_ts_us 14 evidence_ref
LUA_USAGE = """
if not redis.call('SET', KEYS[1], '1', 'NX', 'EX', tonumber(ARGV[1])) then return 0 end
local stage, outcome, ts = ARGV[4], ARGV[5], tonumber(ARGV[6])
local started = (stage == 'ResponseStarted' and outcome == 'authorized_incomplete')
if started and redis.call('EXISTS', KEYS[2]) == 1 then return 2 end   -- Complete already seen (out of order)
if started then
  redis.call('HINCRBY', KEYS[3], 'authorized_incomplete', 1)
  redis.call('HSET', KEYS[12], 'bk', KEYS[3], 'started', ARGV[6], 'auth', ARGV[13], 'last', ARGV[13], 'ev', ARGV[14])
  redis.call('EXPIRE', KEYS[12], tonumber(ARGV[3]))
  redis.call('SADD', KEYS[13], ARGV[12])
else
  if redis.call('EXISTS', KEYS[12]) == 1 then            -- move the pending 'incomplete' to its final outcome
    redis.call('HINCRBY', redis.call('HGET', KEYS[12], 'bk'), 'authorized_incomplete', -1)
    redis.call('HSET', KEYS[12], 'done', ARGV[13])
  end
  redis.call('HINCRBY', KEYS[3], outcome, 1)
end
local f = redis.call('HGET', KEYS[3], 'first')
if (not f) or tonumber(f) > ts then redis.call('HSET', KEYS[3], 'first', ARGV[6]) end
local l = redis.call('HGET', KEYS[3], 'last')
if (not l) or tonumber(l) < ts then redis.call('HSET', KEYS[3], 'last', ARGV[6]) end
redis.call('ZADD', KEYS[4], 'NX', tonumber(ARGV[7]), ARGV[7])
redis.call('SADD', KEYS[5], ARGV[14])
redis.call('SADD', KEYS[6], ARGV[8])
redis.call('SADD', KEYS[7], ARGV[8])
redis.call('HSETNX', KEYS[8], ARGV[8], ARGV[9])
redis.call('HSET', KEYS[9], 'json', ARGV[10])
if ARGV[11] ~= '' then redis.call('SADD', KEYS[10], ARGV[11]) end
redis.call('INCR', KEYS[11])
local ttl = tonumber(ARGV[2])
for _, i in ipairs({3, 4, 5}) do redis.call('EXPIRE', KEYS[i], ttl) end
return 1
"""

LUA_RBAC = """
if not redis.call('SET', KEYS[1], '1', 'NX', 'EX', tonumber(ARGV[1])) then return 0 end
local up = table.unpack or unpack
local f = {}
for i = 3, #ARGV do f[#f + 1] = ARGV[i] end
redis.call('XADD', KEYS[2], 'MAXLEN', '~', tonumber(ARGV[2]), '*', up(f))
return 1
"""


class Store:
    def __init__(self, r, cfg):
        self.r, self.cfg = r, cfg
        self.cluster = cfg.cluster_id
        self._usage = r.register_script(LUA_USAGE)
        self._rbac = r.register_script(LUA_RBAC)
        self.ckpt_key = f'ckpt:{cfg.cluster_id}:{cfg.source_id}'

    def apply_usage(self, pipe, ev: UsageEvent, evidence_ref: str):
        c, u, k = self.cluster, ev.username, ev.key_id
        bucket = ev.ts_us - ev.ts_us % HOUR_US
        keys = [f'dd:{c}:{ev.audit_id}:{ev.stage}:{k}', f'dd:{c}:{ev.audit_id}:ResponseComplete:{k}',
                f'ub:{c}:{u}:{k}:{bucket}', f'ubi:{c}:{u}:{k}', f'ubr:{c}:{u}:{k}:{bucket}',
                f'uki:{c}:{u}', f'ukf:{c}:{u}:{ev.family_id}', f'kd:{c}', f'sj:{c}:{u}', f'sju:{c}:{u}',
                f'sv:{c}:{u}', f'cy:{c}:{ev.audit_id}:{k}', f'cyi:{c}:{u}:{k}']
        args = [self.cfg.dedupe_ttl_s, self.cfg.agg_ttl_s, self.cfg.carry_ttl_s, ev.stage, ev.outcome,
                ev.ts_us, bucket, k, ev.key.model_dump_json(), json.dumps(ev.subject), ev.subject['uid'],
                ev.audit_id, ev.stage_ts_us, evidence_ref]
        self._usage(keys=keys, args=args, client=pipe)

    def apply_rbac(self, pipe, ev: dict):
        c = self.cluster
        flat = [x for kv in ev.items() for x in (kv[0], str(kv[1]))]
        self._rbac(keys=[f'dd:{c}:{ev["audit_id"]}:rbac', f'rbac_events:{c}'],
                   args=[self.cfg.dedupe_ttl_s, self.cfg.rbac_stream_maxlen, *flat], client=pipe)

    def save_checkpoint(self, pipe, pos: Position):
        pipe.set(self.ckpt_key, json.dumps(pos.to_dict()))

    def load_checkpoint(self) -> Position | None:
        raw = self.r.get(self.ckpt_key)
        return Position(**json.loads(raw)) if raw else None
