"""Backfill retained pod evidence from local JSONL exports without changing global cursors."""
import argparse
import asyncio
import json
import os
from datetime import datetime, timezone
from pathlib import Path
import sys
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from backend.app.core.config import REDIS_URL
from backend.app.services.telemetry import Telemetry, normalize
from redis.asyncio import Redis

async def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--namespace',required=True)
    args=parser.parse_args()
    redis=Redis.from_url(REDIS_URL,decode_responses=True,socket_timeout=60)
    service=Telemetry(redis)
    count=0
    # Original evidence snapshots can outlive the global recent-event list.
    for collection in ('reviews','alerts'):
        ids=await redis.zrange(service.prefix+':grading:'+collection,0,-1)
        for uid in ids:
            raw=await redis.get(service.prefix+':grading:'+collection+':'+uid)
            if not raw:continue
            record=json.loads(raw)
            for event in record.get('evidence',[])+record.get('shared_identity_evidence',[]):
                await service.archive(event)
    needle=args.namespace.encode()
    for source,variable in [('audit','POD_AUDIT_EXPORT_PATH'),('hubble','HUBBLE_EXPORT_PATH'),('tetragon','TETRAGON_EXPORT_PATH')]:
        path=os.getenv(variable)
        if not path:continue
        recovered=0
        with open(path,'rb') as stream:
            for line in stream:
                if needle not in line:continue
                try:
                    event=normalize(json.loads(line),source,service.cluster)
                    if not event:continue
                    namespaces={e.get('namespace') for e in (event.get('source_pod',{}),event.get('destination_pod',{}),event.get('target',{}))}
                    if args.namespace not in namespaces:continue
                    stamp=event.get('timestamp')
                    if not stamp:continue
                    when=datetime.fromisoformat(stamp.replace('Z','+00:00'))
                    if datetime.now(timezone.utc).timestamp()-when.timestamp()>service.ttl:continue
                    event['observed_at']=when.isoformat()
                    event['findings']=service.findings(event)
                    await service.archive(event)
                    recovered+=1
                except (ValueError,TypeError,KeyError):continue
        print(source, recovered,'retained records replayed',flush=True)
        count+=recovered
    print('Total:',count,flush=True)
    await redis.aclose()

if __name__=='__main__':asyncio.run(main())
