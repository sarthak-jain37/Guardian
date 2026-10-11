import os
import socket
from dataclasses import dataclass


@dataclass(frozen=True)
class Config:
    cluster_id: str = 'default'
    source_id: str = socket.gethostname()          # one id per kube-apiserver audit file
    expected_sources: tuple[str, ...] = ()         # all apiservers that must be covered (HA); empty = just this one
    audit_log_path: str = '/var/log/kubernetes/audit/audit.log'
    policy_path: str | None = None                 # mount the apiserver audit policy read-only to verify it
    redis_host: str = 'guardian-redis'
    redis_port: int = 6379
    dedupe_ttl_s: int = 86_400                     # must exceed max replay window (restart/rotation re-reads)
    agg_ttl_s: int = 120 * 86_400                  # hourly-aggregate retention; coverage never claims older data
    carry_ttl_s: int = 7 * 86_400
    safety_lag_s: int = 90                         # > apiserver request timeout; watermark = now - lag
    poll_s: float = 0.2
    heartbeat_s: float = 5.0
    rbac_stream_maxlen: int = 100_000

    @property
    def sources(self) -> tuple[str, ...]:
        return self.expected_sources or (self.source_id,)

    @classmethod
    def from_env(cls) -> 'Config':
        e = os.environ
        d = cls()
        return cls(
            cluster_id=e.get('CLUSTER_ID', d.cluster_id),
            source_id=e.get('SOURCE_ID', d.source_id),
            expected_sources=tuple(x for x in e.get('EXPECTED_SOURCES', '').split(',') if x),
            audit_log_path=e.get('AUDIT_LOG_PATH', d.audit_log_path),
            policy_path=e.get('AUDIT_POLICY_PATH') or None,
            redis_host=e.get('REDIS_HOST', d.redis_host),
            redis_port=int(e.get('REDIS_PORT', d.redis_port)),
            dedupe_ttl_s=int(e.get('DEDUPE_TTL_S', d.dedupe_ttl_s)),
            agg_ttl_s=int(e.get('AGG_TTL_S', d.agg_ttl_s)),
            safety_lag_s=int(e.get('SAFETY_LAG_S', d.safety_lag_s)),
        )
