"""Private encrypted audit segments, verified catalogs, pins and bounded restore.

A local persistent archive volume is the initial storage adapter. Its durability,
encrypted backups and independent copy are deployment requirements, not assumed.
"""
import gzip
import hashlib
import json
import os
import tempfile
from datetime import timedelta
from pathlib import Path
from uuid import uuid4

from cryptography.fernet import Fernet, InvalidToken
from backend.app.services.audit_usage import iso, timestamp
from backend.app.services.governance_store import digest, encode, GovernanceStore
from backend.app.services.usage_store import UsageStore


class EvidenceArchive:
    def __init__(self, usage, root, key_file, *, retention_days=90):
        if retention_days not in (90,365): raise ValueError('unsupported_retention_profile')
        self.usage,self.db,self.root,self.days=usage,usage.db,Path(root).resolve(),retention_days
        self.root.mkdir(parents=True,exist_ok=True,mode=0o700)
        raw=Path(key_file).read_bytes()
        if len(raw)>16384: raise ValueError('archive_key_registry_too_large')
        keys=json.loads(raw)
        self.active=keys['active']
        self.keys={name:Fernet(value.encode()) for name,value in keys['keys'].items()}
        if self.active not in self.keys:raise ValueError('active_archive_key_unavailable')
        with self.db._connect() as db:
            db.executescript('''
            CREATE TABLE IF NOT EXISTS archive_segments (
              segment_id TEXT PRIMARY KEY, key_id TEXT NOT NULL, ciphertext_hash TEXT NOT NULL,
              compressed_hash TEXT NOT NULL, plaintext_hash TEXT NOT NULL,
              manifest TEXT NOT NULL, created_at TEXT NOT NULL, retained_until TEXT NOT NULL);
            CREATE TABLE IF NOT EXISTS archive_members (
              segment_id TEXT NOT NULL, raw_ref TEXT NOT NULL UNIQUE, cluster_id TEXT NOT NULL, audit_id TEXT,
              PRIMARY KEY(segment_id,raw_ref));
            CREATE INDEX IF NOT EXISTS archive_audit ON archive_members(cluster_id,audit_id);
            CREATE TABLE IF NOT EXISTS archive_pins (
              case_id TEXT NOT NULL, summary_id TEXT NOT NULL, retained_until TEXT NOT NULL,
              PRIMARY KEY(case_id,summary_id));
            CREATE TABLE IF NOT EXISTS archive_coverage (
              segment_id TEXT NOT NULL, coverage_id TEXT NOT NULL, PRIMARY KEY(segment_id,coverage_id));
            CREATE TABLE IF NOT EXISTS archive_tombstones (
              segment_id TEXT PRIMARY KEY, deleted_at TEXT NOT NULL, reason TEXT NOT NULL);
            ''')

    def path(self,segment_id):
        if not segment_id.startswith('segment-') or len(segment_id)!=40 or not all(c in '0123456789abcdef' for c in segment_id[8:]):
            raise ValueError('invalid_archive_id')
        return self.root/(segment_id+'.jsonl.gz.fernet')

    def pending_bytes(self):
        with self.db._connect() as db:
            return db.execute('''SELECT COALESCE(SUM(length(payload)),0) FROM audit_raw r
                WHERE NOT EXISTS (SELECT 1 FROM archive_members a WHERE a.raw_ref=r.raw_ref)''').fetchone()[0]

    def seal(self,*,maximum_bytes=100*1024*1024):
        """Catalog acknowledgement follows fsync, decryption and checksum checks."""
        with self.db._connect() as db:
            rows=db.execute('''SELECT r.* FROM audit_raw r LEFT JOIN archive_members a USING(raw_ref)
                WHERE a.raw_ref IS NULL ORDER BY r.received_at LIMIT 50000''').fetchall()
            selected=[];size=0
            for row in rows:
                size+=len(row['payload'].encode())
                if size>maximum_bytes:break
                selected.append(dict(row))
            if not selected:return None
            sources=[dict(row) for row in db.execute('SELECT * FROM evidence_sources')]
            times=[]
            for row in selected:
                value=json.loads(row['payload'])
                for name in ('requestReceivedTimestamp','stageTimestamp'):
                    try:times.append(timestamp(value[name]))
                    except (KeyError,ValueError):pass
            left=min(times) if times else timestamp(selected[0]['received_at'])
            right=max(times) if times else timestamp(selected[-1]['received_at'])
            coverage=[dict(row) for row in db.execute('SELECT * FROM evidence_coverage WHERE start<=? AND end>=?',(iso(right),iso(left)))]
            gaps=[dict(row) for row in db.execute('SELECT * FROM evidence_gaps WHERE start<=? AND end>=?',(iso(right),iso(left)))]
        package={'schema_version':'guardian.audit-archive.v1','raw':selected,'sources':sources,'coverage':coverage,'gaps':gaps}
        plaintext=encode(package).encode()
        compressed=gzip.compress(plaintext,mtime=0)
        ciphertext=self.keys[self.active].encrypt(compressed)
        identifier='segment-'+uuid4().hex
        target=self.path(identifier)
        descriptor,temporary=tempfile.mkstemp(dir=self.root,prefix='.pending-')
        try:
            with os.fdopen(descriptor,'wb') as output:
                output.write(ciphertext);output.flush();os.fsync(output.fileno())
            os.replace(temporary,target)
            directory=os.open(self.root,os.O_DIRECTORY)
            try:os.fsync(directory)
            finally:os.close(directory)
        finally:
            if os.path.exists(temporary):os.unlink(temporary)
        if self.keys[self.active].decrypt(target.read_bytes())!=compressed:raise ValueError('archive_readback_failed')
        now=self.usage.clock()
        manifest={'schema_version':'guardian.archive-manifest.v1','segment_id':identifier,'key_id':self.active,
            'source_ids':sorted({r['source_id'] for r in selected}),'raw_count':len(selected),
            'received_start':min(r['received_at'] for r in selected),'received_end':max(r['received_at'] for r in selected),
            'event_start':iso(left),'event_end':iso(right),
            'parser_version':'guardian.audit-collector.v1','retention_days':self.days,
            'compression':'gzip','encryption':'fernet','availability':'available'}
        hashes=[hashlib.sha256(value).hexdigest() for value in (ciphertext,compressed,plaintext)]
        with self.db.transaction() as db:
            # Recheck membership under the writer lock; concurrent sealing cannot
            # duplicate a catalog member or discard the acknowledged original.
            if any(db.execute('SELECT 1 FROM archive_members WHERE raw_ref=?',(r['raw_ref'],)).fetchone() for r in selected):
                target.unlink();return None
            db.execute('INSERT INTO archive_segments VALUES (?,?,?,?,?,?,?,?)',
                (identifier,self.active,*hashes,encode(manifest),iso(now),iso(right+timedelta(days=self.days))))
            db.executemany('INSERT INTO archive_members VALUES (?,?,?,?)',
                [(identifier,r['raw_ref'],r['cluster_id'],r['audit_id']) for r in selected])
            db.executemany('INSERT INTO archive_coverage VALUES (?,?)',[(identifier,c['coverage_id']) for c in coverage])
        return {**manifest,'ciphertext_sha256':hashes[0],'compressed_sha256':hashes[1],'plaintext_sha256':hashes[2]}

    def read(self,segment_id):
        with self.db._connect() as db:
            row=db.execute('SELECT * FROM archive_segments WHERE segment_id=?',(segment_id,)).fetchone()
            if row is None:raise ValueError('archive_not_found')
            if db.execute('SELECT 1 FROM archive_tombstones WHERE segment_id=?',(segment_id,)).fetchone():
                raise ValueError('archive_expired')
            pinned=db.execute('''SELECT 1 FROM archive_members a JOIN summary_requests r
                ON r.cluster_id=a.cluster_id AND r.audit_id=a.audit_id JOIN archive_pins p USING(summary_id)
                WHERE a.segment_id=? AND p.retained_until>=? LIMIT 1''',(segment_id,iso(self.usage.clock()))).fetchone()
            pinned=pinned or db.execute('''SELECT 1 FROM archive_coverage a JOIN summary_coverage c USING(coverage_id)
                JOIN archive_pins p USING(summary_id) WHERE a.segment_id=? AND p.retained_until>=? LIMIT 1''',
                (segment_id,iso(self.usage.clock()))).fetchone()
            if timestamp(row['retained_until'])<self.usage.clock() and not pinned:raise ValueError('archive_expired')
        try:
            data=self.path(segment_id).read_bytes()
            if len(data)>160*1024*1024 or hashlib.sha256(data).hexdigest()!=row['ciphertext_hash']:
                raise ValueError('archive_checksum_failed')
            compressed=self.keys[row['key_id']].decrypt(data)
            if hashlib.sha256(compressed).hexdigest()!=row['compressed_hash']:raise ValueError('archive_checksum_failed')
            import io
            with gzip.GzipFile(fileobj=io.BytesIO(compressed)) as source:
                plaintext=source.read(200*1024*1024+1)
            if len(plaintext)>200*1024*1024 or hashlib.sha256(plaintext).hexdigest()!=row['plaintext_hash']:
                raise ValueError('archive_checksum_failed')
            return json.loads(plaintext)
        except (OSError,KeyError,InvalidToken):
            raise ValueError('archive_restore_failed') from None

    def pin(self,case_id,summary_id,retained_until):
        with self.db.transaction() as db:
            if not db.execute('SELECT 1 FROM usage_summaries WHERE summary_id=?',(summary_id,)).fetchone():
                raise ValueError('unknown_summary')
            db.execute('INSERT INTO archive_pins VALUES (?,?,?) ON CONFLICT(case_id,summary_id) DO UPDATE SET retained_until=MAX(retained_until,excluded.retained_until)',
                       (case_id,summary_id,iso(retained_until)))

    def prune_hot(self,days=7,index_days=90):
        now=self.usage.clock()
        with self.db.transaction() as db:
            # Only acknowledged, still-readable segments qualify for raw pruning.
            segments=db.execute('SELECT DISTINCT a.segment_id FROM archive_members a JOIN audit_raw r USING(raw_ref) WHERE r.received_at<?',
                                (iso(now-timedelta(days=days)),)).fetchall()
        for segment in segments:self.read(segment['segment_id'])
        with self.db.transaction() as db:
            count=db.execute('DELETE FROM audit_raw WHERE received_at<? AND raw_ref IN (SELECT raw_ref FROM archive_members)',
                             (iso(now-timedelta(days=days)),)).rowcount
            cutoff=now-timedelta(days=index_days)
            candidates=db.execute('''SELECT DISTINCT cluster_id FROM audit_requests WHERE started_at<?''',(iso(cutoff),)).fetchall()
            for row in candidates:
                sources=db.execute('SELECT source_id FROM evidence_sources WHERE cluster_id=?',(row['cluster_id'],)).fetchall()
                for source in sources:
                    oldest=db.execute('SELECT MIN(started_at) FROM audit_requests WHERE cluster_id=?',(row['cluster_id'],)).fetchone()[0]
                    if oldest and timestamp(oldest)<cutoff:
                        self.usage._gap(db,source['source_id'],timestamp(oldest),cutoff,'hot_index_expired_restore_archive')
            # Keep ongoing authorized requests so carried watches survive retention.
            db.execute('''DELETE FROM audit_stages WHERE (cluster_id,audit_id) IN
                (SELECT cluster_id,audit_id FROM audit_requests WHERE started_at<? AND json_extract(payload,'$.completed_at') IS NOT NULL)''',(iso(cutoff),))
            db.execute("DELETE FROM audit_requests WHERE started_at<? AND json_extract(payload,'$.completed_at') IS NOT NULL",(iso(cutoff),))
            db.execute('DELETE FROM usage_hours WHERE hour<?',(iso(cutoff.replace(minute=0,second=0,microsecond=0)),))
        return {'raw_pruned':count,'index_cutoff':iso(cutoff)}

    def restore(self,query,*,maximum_segments=32):
        """Access control is enforced by the calling Evidence API, never an LLM path."""
        with self.db._connect() as db:
            segments=db.execute('''SELECT DISTINCT a.segment_id FROM archive_members a JOIN archive_segments s USING(segment_id)
                WHERE a.cluster_id=? AND json_extract(s.manifest,'$.event_start')<?
                AND json_extract(s.manifest,'$.event_end')>=? ORDER BY s.created_at LIMIT ?''',
                (query.cluster_id,iso(query.window.end),iso(query.window.start),maximum_segments+1)).fetchall()
            # Earlier started/ongoing watches need their authorization stage too.
            carried=db.execute('''SELECT DISTINCT a.segment_id FROM archive_members a JOIN audit_requests r
                ON r.cluster_id=a.cluster_id AND r.audit_id=a.audit_id WHERE r.cluster_id=? AND r.username=?
                AND r.started_at<? AND (json_extract(r.payload,'$.completed_at') IS NULL
                OR json_extract(r.payload,'$.completed_at')>?) LIMIT ?''',
                (query.cluster_id,query.subject.username,iso(query.window.start),iso(query.window.start),maximum_segments+1)).fetchall()
            segments=[{'segment_id':identifier} for identifier in sorted({r['segment_id'] for r in [*segments,*carried]})]
        if len(segments)>maximum_segments:return {'status':'partial','reasons':['archive_query_requires_smaller_window']}
        if not segments:return {'status':'expired','reasons':['no_retained_archive']}
        try:
            packages=[self.read(row['segment_id']) for row in segments]
            related={r['audit_id'] for package in packages for r in package['raw'] if r['audit_id']}
            with self.db._connect() as db:
                expanded={r['segment_id'] for r in segments}
                for audit in related:
                    expanded.update(r[0] for r in db.execute('SELECT segment_id FROM archive_members WHERE cluster_id=? AND audit_id=?',(query.cluster_id,audit)))
                if len(expanded)>maximum_segments:return {'status':'partial','reasons':['archive_query_requires_smaller_window']}
            original={r['segment_id'] for r in segments}
            packages.extend(self.read(identifier) for identifier in expanded-original)
            segments=[{'segment_id':identifier} for identifier in sorted(expanded)]
            with tempfile.TemporaryDirectory(prefix='guardian-restore-') as directory:
                store=UsageStore(GovernanceStore(Path(directory)/'restore.sqlite3',clock=self.usage.clock),clock=self.usage.clock)
                with store.db.transaction() as db:
                    for package in packages:
                        for source in package['sources']:
                            db.execute('INSERT OR IGNORE INTO evidence_sources VALUES (?,?,?,?,?)',tuple(source[k] for k in
                                ('source_id','cluster_id','namespace','declaration','audit_policy')))
                        for coverage in package['coverage']:
                            db.execute('INSERT OR IGNORE INTO evidence_coverage VALUES (?,?,?,?,?,?,?,?)',tuple(coverage[k] for k in
                                ('coverage_id','source_id','start','end','status','reasons','cursor_ref','processed_through')))
                        for gap in package['gaps']:
                            db.execute('INSERT OR IGNORE INTO evidence_gaps VALUES (?,?,?,?,?)',tuple(gap[k] for k in
                                ('gap_id','source_id','start','end','reason')))
                for package in packages:
                    for index,raw in enumerate(package['raw']):
                        store.ingest(raw['source_id'],'restore-'+raw['raw_ref'],[(index,json.loads(raw['payload']))],index+1)
                summary=store.query(query)
                # Persist a new immutable reconstruction; never overwrite the case's original.
                with self.db.transaction() as db:
                    db.execute('INSERT OR IGNORE INTO usage_summaries VALUES (?,?,?,?,?)',
                        (summary.summary_id,'archive:'+digest(query.model_dump(mode='json')),summary.revision,summary.model_dump_json(),iso(self.usage.clock())))
                    with store.db._connect() as restored:
                        db.executemany('INSERT OR IGNORE INTO summary_requests VALUES (?,?,?)',
                            [tuple(r) for r in restored.execute('SELECT summary_id,cluster_id,audit_id FROM summary_requests WHERE summary_id=?',(summary.summary_id,))])
                        db.executemany('INSERT OR IGNORE INTO summary_coverage VALUES (?,?)',
                            [tuple(r) for r in restored.execute('SELECT summary_id,coverage_id FROM summary_coverage WHERE summary_id=?',(summary.summary_id,))])
                status='available' if not summary.truncated and all(c.status=='complete_for_declared_scope' for s in summary.series for c in s.coverage) else 'partial'
                return {'status':status,'summary':summary.model_dump(mode='json'),'segment_ids':[r['segment_id'] for r in segments]}
        except (ValueError,OSError) as error:
            if str(error)=='archive_expired':return {'status':'expired','reasons':['archive_retention_expired']}
            return {'status':'restore_failed','reasons':['archive_integrity_or_key_failure']}

    def delete_expired(self):
        now=self.usage.clock();deleted=[]
        with self.db.transaction() as db:
            rows=db.execute('SELECT segment_id FROM archive_segments WHERE retained_until<?',(iso(now),)).fetchall()
            for row in rows:
                identifier=row['segment_id']
                pinned=db.execute('''SELECT 1 FROM archive_members a JOIN summary_requests r
                    ON r.cluster_id=a.cluster_id AND r.audit_id=a.audit_id JOIN archive_pins p USING(summary_id)
                    WHERE a.segment_id=? AND p.retained_until>=? LIMIT 1''',(identifier,iso(now))).fetchone()
                if pinned:continue
                if db.execute('''SELECT 1 FROM archive_coverage a JOIN summary_coverage c USING(coverage_id)
                    JOIN archive_pins p USING(summary_id) WHERE a.segment_id=? AND p.retained_until>=? LIMIT 1''',
                    (identifier,iso(now))).fetchone():continue
                # Tombstone first; a crash before unlink leaves inaccessible retained bytes,
                # not an available reference to missing evidence.
                db.execute('INSERT OR IGNORE INTO archive_tombstones VALUES (?,?,?)',(identifier,iso(now),'retention_expired'))
                deleted.append(identifier)
        for identifier in deleted:self.path(identifier).unlink(missing_ok=True)
        return deleted
