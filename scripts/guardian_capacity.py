"""Measure current storage and disclose the assumptions behind retention estimates."""
import argparse,json,shutil,sqlite3
from pathlib import Path
from datetime import datetime


def measure(directory,database,*,days=90):
    directory=Path(directory);disk=shutil.disk_usage(directory)
    files=[p for p in directory.rglob('*') if p.is_file() and not p.is_symlink()]
    size=sum(p.stat().st_size for p in files)
    with sqlite3.connect('file:'+str(Path(database).resolve())+'?mode=ro',uri=True) as db:
        count,encoded,start,end=db.execute('SELECT count(*),COALESCE(sum(length(payload)),0),MIN(received_at),MAX(received_at) FROM audit_raw').fetchone()
    duration=(datetime.fromisoformat(end)-datetime.fromisoformat(start)).total_seconds() if count>1 else 0
    projected=(encoded/duration*86400*days*1.3) if duration>=86400 else None
    return {'schema_version':'guardian.capacity.v1','raw_records':count,'hot_encoded_bytes':encoded,'measured_seconds':duration,
        'state_bytes':size,'filesystem_total_bytes':disk.total,'filesystem_free_bytes':disk.free,
        'filesystem_used_fraction':disk.used/disk.total,'storage_alert':disk.used/disk.total>=.8,
        'retention_days':days,'projected_encoded_retention_with_30pct_headroom':projected,
        'projection_status':'insufficient_representative_measurement' if projected is None else 'linear_estimate_not_collected_history',
        'excluded_costs':['archive replication','backup retention','database indices','growth and burst variation']}


def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--directory',type=Path,required=True);p.add_argument('--database',type=Path,required=True);p.add_argument('--retention-days',type=int,choices=[90,365],default=90)
    a=p.parse_args();print(json.dumps(measure(a.directory,a.database,days=a.retention_days),indent=2))


if __name__=='__main__':main()
