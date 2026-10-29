"""Quiesced, encrypted single-host pilot backups and fail-closed new-path restore.

Stop backend, collector and worker first. The backup key is kept separately.
Large deployments should use their approved encrypted volume/object-store backup.
"""
import argparse,hashlib,io,json,os,shutil,sqlite3,tarfile,tempfile,time
from datetime import datetime,timezone
from contextlib import closing
from pathlib import Path,PurePosixPath
from cryptography.fernet import Fernet

LIMIT=256*1024*1024


def sha(path):
    with Path(path).open('rb') as f:return hashlib.file_digest(f,'sha256').hexdigest()


def create(roots,destination,key_file,*,quiesced=False):
    if not quiesced:raise ValueError('stop_backend_collector_and_worker_then_assert_quiesced')
    target=Path(destination)
    if target.exists():raise ValueError('backup_destination_exists')
    cipher=Fernet(Path(key_file).read_bytes().strip());started=time.monotonic();now=datetime.now(timezone.utc).isoformat()
    with tempfile.TemporaryDirectory() as tmp:
        stage=Path(tmp);manifest={'schema_version':'guardian.backup.v1','created_at':now,'quiesced':True,'files':{}}
        total=0
        for label,root in roots.items():
            if not label.isidentifier():raise ValueError('invalid_root_label')
            root=Path(root).resolve()
            if not root.is_dir():raise ValueError('backup_root_missing')
            for source in sorted(root.rglob('*')):
                if source.is_symlink():raise ValueError('backup_symlinks_forbidden')
                if not source.is_file() or source.name.endswith(('-wal','-shm','.lock')):continue
                relative=Path(label)/source.relative_to(root);out=stage/relative;out.parent.mkdir(parents=True,exist_ok=True)
                total+=source.stat().st_size
                if total>LIMIT:raise ValueError('pilot_backup_exceeds_256MiB_use_approved_volume_backup')
                if source.suffix in ('.sqlite3','.sqlite'):
                    with closing(sqlite3.connect('file:'+str(source)+'?mode=ro',uri=True)) as original,closing(sqlite3.connect(out)) as snapshot:
                        original.backup(snapshot)
                        if snapshot.execute('PRAGMA integrity_check').fetchone()[0]!='ok':raise ValueError('sqlite_integrity_failed')
                else:shutil.copyfile(source,out)
                manifest['files'][relative.as_posix()]={'sha256':sha(out),'bytes':out.stat().st_size}
        (stage/'manifest.json').write_text(json.dumps(manifest,sort_keys=True))
        data=io.BytesIO()
        with tarfile.open(fileobj=data,mode='w:gz') as tar:
            for p in sorted(stage.rglob('*')):
                if p.is_file():tar.add(p,arcname=p.relative_to(stage).as_posix(),recursive=False)
        if len(data.getvalue())>LIMIT:raise ValueError('compressed_backup_exceeds_limit')
        ciphertext=cipher.encrypt(data.getvalue())
        target.parent.mkdir(parents=True,exist_ok=True,mode=0o700)
        fd=os.open(target,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600)
        with os.fdopen(fd,'wb') as f:f.write(ciphertext);f.flush();os.fsync(f.fileno())
        if cipher.decrypt(target.read_bytes())!=data.getvalue():raise ValueError('backup_readback_failed')
    return {'schema_version':'guardian.backup-result.v1','created_at':now,'files':len(manifest['files']),
        'plaintext_bytes':total,'ciphertext_bytes':target.stat().st_size,'sha256':sha(target),'duration_seconds':time.monotonic()-started}


def invalidate(root):
    """Restored authority cannot resume automatically, even with enabled policy."""
    root=Path(root);(root/'restore-required').write_text('Reconcile surviving live/audit records and reissue credentials before enabling execution.\n')
    for path in root.rglob('*'):
        if path.suffix not in ('.sqlite3','.sqlite') or not path.is_file():continue
        with closing(sqlite3.connect(path)) as db,db:
            tables={r[0] for r in db.execute("SELECT name FROM sqlite_master WHERE type='table'")}
            if 'review_state' in tables:
                (path.parent/'restore-required').write_text('Restore reconciliation is required.\n')
                db.execute("UPDATE review_state SET status='EXPIRED' WHERE status='OPEN'")
            if 'execution_authorities' in tables and 'execution_revocations' in tables:
                db.execute("INSERT INTO execution_revocations(decision_id,kind,actor,reason,recorded_at) SELECT decision_id,'all','restore-custodian','backup_restore_invalidates_authority',? FROM execution_authorities",(datetime.now(timezone.utc).isoformat(),))
            if 'outbox' in tables:db.execute("UPDATE outbox SET status='ACKED' WHERE status!='ACKED'")
            if 'analysis_runs' in tables:db.execute("UPDATE analysis_runs SET status='FAILED',error='restored_run_requires_fresh_intake',lease_token=NULL,lease_until=NULL WHERE status NOT IN ('DONE','FAILED')")
    # Also place the guard beside every governed ledger, where the runtime checks.
    for path in root.rglob('governance.sqlite3'):(path.parent/'restore-required').write_text('Restore reconciliation is required.\n')


def restore(source,destination,key_file):
    source=Path(source);target=Path(destination);started=time.monotonic()
    if target.exists():raise ValueError('restore_requires_new_nonexistent_directory')
    if source.stat().st_size>LIMIT*2:raise ValueError('backup_too_large')
    plaintext=Fernet(Path(key_file).read_bytes().strip()).decrypt(source.read_bytes())
    if len(plaintext)>LIMIT:raise ValueError('backup_too_large')
    with tarfile.open(fileobj=io.BytesIO(plaintext),mode='r:gz') as tar:
        members=tar.getmembers()
        if len(members)>100000 or sum(m.size for m in members)>LIMIT:raise ValueError('expanded_backup_too_large')
        for member in members:
            name=PurePosixPath(member.name)
            if not member.isfile() or name.is_absolute() or '..' in name.parts:raise ValueError('unsafe_backup_member')
        records={m.name:m for m in members}
        if len(records)!=len(members):raise ValueError('duplicate_backup_member')
        manifest=json.load(tar.extractfile(records['manifest.json']))
        if manifest.get('schema_version')!='guardian.backup.v1' or set(records)!=set(manifest['files'])|{'manifest.json'}:raise ValueError('backup_manifest_mismatch')
        # Verify every byte before exposing a usable restore directory.
        for name,entry in manifest['files'].items():
            data=tar.extractfile(records[name]).read()
            if len(data)!=entry['bytes'] or hashlib.sha256(data).hexdigest()!=entry['sha256']:raise ValueError('backup_checksum_failed')
        target.mkdir(parents=True,mode=0o700)
        (target/'restore-required').write_text('Restore in progress; execution is disabled.\n')
        for name in manifest['files']:
            path=target/name;path.parent.mkdir(parents=True,exist_ok=True,mode=0o700)
            path.write_bytes(tar.extractfile(records[name]).read());path.chmod(0o600)
    invalidate(target)
    return {'schema_version':'guardian.restore-result.v1','backup_created_at':manifest['created_at'],
        'duration_seconds':time.monotonic()-started,'files':len(manifest['files']),'execution_enabled':False,
        'authority_invalidated':True,'reconciliation_required':True,'evidence_loss_since_snapshot':'must_be_measured_against_surviving_records'}


def main():
    p=argparse.ArgumentParser(description=__doc__);sub=p.add_subparsers(dest='command',required=True)
    key=sub.add_parser('keygen');key.add_argument('--key-file',type=Path,required=True)
    backup=sub.add_parser('create');backup.add_argument('--root',action='append',required=True,help='label=/absolute/quiesced/directory');backup.add_argument('--quiesced',action='store_true')
    recover=sub.add_parser('restore');recover.add_argument('--source',type=Path,required=True)
    for child in (backup,recover):child.add_argument('--destination',type=Path,required=True);child.add_argument('--key-file',type=Path,required=True)
    args=p.parse_args();os.umask(0o077)
    if args.command=='keygen':
        args.key_file.parent.mkdir(parents=True,exist_ok=True,mode=0o700)
        with args.key_file.open('xb') as f:f.write(Fernet.generate_key()+b'\n')
        print('Backup key created; keep a separate protected recovery copy.');return
    result=create(dict(r.split('=',1) for r in args.root),args.destination,args.key_file,quiesced=args.quiesced) if args.command=='create' else restore(args.source,args.destination,args.key_file)
    print(json.dumps(result,indent=2))


if __name__=='__main__':main()
