"""Independent collector; no inference or Kubernetes mutation credentials needed."""
import argparse
import json
import time
from pathlib import Path
from backend.app.models.evidence import CollectionPolicy
from backend.app.services.governance_store import GovernanceStore
from backend.app.services.usage_store import UsageStore
from backend.app.services.usage_collector import AuditFollower
from backend.app.services.evidence_archive import EvidenceArchive


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--database',required=True)
    parser.add_argument('--source-policy',type=Path,required=True)
    parser.add_argument('--audit-policy',type=Path,required=True)
    parser.add_argument('--audit-log',type=Path,required=True)
    parser.add_argument('--archive-directory',type=Path)
    parser.add_argument('--archive-keys',type=Path)
    parser.add_argument('--once',action='store_true')
    parser.add_argument('--poll-seconds',type=int,choices=range(1,11),default=2,
        help='audit/probe poll interval; default 2s leaves room inside the evidence freshness budget')
    parser.add_argument('--retention-days',type=int,choices=(90,365),default=90)
    parser.add_argument('--prune',action='store_true',help='apply acknowledged hot/archive retention; never touches control-plane files')
    args=parser.parse_args()
    usage=UsageStore(GovernanceStore(args.database))
    policy=usage.register(CollectionPolicy.model_validate_json(args.source_policy.read_text()),args.audit_policy.read_bytes())
    archive=EvidenceArchive(usage,args.archive_directory,args.archive_keys,retention_days=args.retention_days) if args.archive_directory and args.archive_keys else None
    follower=AuditFollower(usage,policy.source_id,args.audit_log)
    # Read-only /version probes must themselves appear in the configured audit sink.
    # A live API response without its captured audit record does not establish coverage.
    from backend.app.services.kubernetes_service import KubernetesService
    k8s=KubernetesService()
    sealed=time.monotonic()
    try:
        while True:
            status=follower.poll();follower.probe(k8s.api_client)
            if archive and (args.once or time.monotonic()-sealed>=3600 or archive.pending_bytes()>=100*1024*1024):
                archive.seal();sealed=time.monotonic()
                if args.prune:archive.prune_hot();archive.delete_expired()
            print(json.dumps(status),flush=True)
            if args.once:break
            time.sleep(args.poll_seconds)
    finally:
        follower.close();k8s.api_client.close()


if __name__=='__main__':main()
