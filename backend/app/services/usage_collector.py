"""Bounded read-only audit follower with transactional file cursors and probes."""
import base64
import json
import os
from datetime import timedelta
from pathlib import Path
from uuid import uuid4

from contracts.usage_summary_v1 import Window
from backend.app.services.kube_transport import api_call
from backend.app.services.audit_usage import iso, timestamp


class AuditFollower:
    maximum_line=1024*1024

    def __init__(self,usage,source_id,path):
        self.usage,self.source_id,self.path=usage,source_id,Path(path)
        self.stream=None;self.generation=None
        with usage.db._connect() as db:
            self.policy,_=usage.source(db,source_id)
            cursor=db.execute('SELECT * FROM evidence_cursors WHERE source_id=?',(source_id,)).fetchone()
            self.saved=dict(cursor) if cursor else None

    def close(self):
        if self.stream:self.stream.close();self.stream=None

    def lost(self,reason):
        with self.usage.db._connect() as db:
            since=db.execute('SELECT MAX(confirmed_at) FROM collector_probes WHERE source_id=?',(self.source_id,)).fetchone()[0]
        now=self.usage.clock()
        self.usage.gap(self.source_id,timestamp(since)-timedelta(seconds=self.policy.maximum_lag_seconds) if since else now-timedelta(seconds=self.policy.maximum_lag_seconds),now,reason)

    def open(self):
        stream=self.path.open('rb')
        stat=os.fstat(stream.fileno());generation=f'{stat.st_dev}:{stat.st_ino}'
        if self.saved:
            if self.saved['generation']==generation and stat.st_size>=self.saved['offset']:
                stream.seek(self.saved['offset'])
            else:self.lost('source_rotated_or_truncated_across_restart')
        self.stream,self.generation=stream,generation;self.saved=None

    def poll(self):
        try:
            if self.stream is None:self.open()
            stat=os.fstat(self.stream.fileno())
            if stat.st_size<self.stream.tell():
                self.lost('source_truncated');self.stream.seek(0)
                self.generation=f'{stat.st_dev}:{stat.st_ino}:reset:{uuid4().hex}'
            rows=[];bytes_read=0
            while len(rows)<4096 and bytes_read<4*1024*1024:
                position=self.stream.tell();line=self.stream.readline(self.maximum_line+1)
                if not line:break
                if not line.endswith(b'\n') and len(line)<=self.maximum_line:
                    self.stream.seek(position);break
                bytes_read+=len(line)
                try:
                    if len(line)>self.maximum_line:raise ValueError('line_too_large')
                    value=json.loads(line)
                    if not isinstance(value,dict):raise ValueError('audit_object_required')
                except (ValueError,UnicodeError):
                    value={'ingestion_error':'unparseable_or_oversized_line','original_bytes_base64':base64.b64encode(line).decode()}
                    self.lost('unparseable_or_oversized_line')
                rows.append((position,value))
            offset=self.stream.tell()
            self.usage.ingest(self.source_id,self.generation,rows,offset)
            for _,value in rows:self.confirm_probe(value)
            # Drain a renamed file through its open descriptor before switching.
            live=self.path.stat()
            drained=os.fstat(self.stream.fileno())
            if (live.st_dev,live.st_ino)!=(stat.st_dev,stat.st_ino) and self.stream.tell()>=drained.st_size:
                self.close();self.saved=None
            return {'state':'following','records':len(rows),'offset':offset,'generation':self.generation}
        except OSError:
            self.lost('audit_source_unavailable')
            return {'state':'unavailable','records':0}

    def probe(self,client):
        nonce=uuid4().hex
        with self.usage.db.transaction() as db:
            db.execute('INSERT INTO collector_probes VALUES (?,?,?,NULL)',(nonce,self.source_id,iso(self.usage.clock())))
        try:
            result=api_call(client,'/version','GET',user_agent='guardian-audit-probe/'+nonce,
                auth_settings=['BearerToken'],response_type='object',_return_http_data_only=False,_request_timeout=(5,10))
            if result[1]!=200:raise ValueError('probe_failed')
        except Exception:
            self.lost('audit_probe_failed')
            return False
        return True

    def confirm_probe(self,event):
        agent=event.get('userAgent','')
        if not agent.startswith('guardian-audit-probe/') or event.get('stage')!='ResponseComplete':return
        if event.get('requestURI')!='/version' or event.get('responseStatus',{}).get('code')!=200:return
        nonce=agent.partition('/')[2]
        with self.usage.db.transaction() as db:
            row=db.execute('SELECT * FROM collector_probes WHERE nonce=? AND source_id=?',(nonce,self.source_id)).fetchone()
            if row is None or row['confirmed_at']:return
            at=timestamp(event['requestReceivedTimestamp'])
            if at<timestamp(row['requested_at']) or at>self.usage.clock():return
            previous=db.execute('SELECT MAX(confirmed_at) FROM collector_probes WHERE source_id=?',(self.source_id,)).fetchone()[0]
            db.execute('UPDATE collector_probes SET confirmed_at=? WHERE nonce=?',(iso(at),nonce))
        if previous and timestamp(previous)<at:
            lag=timedelta(seconds=self.policy.maximum_lag_seconds)
            left,right=timestamp(previous)-lag,at-lag
            self.usage.health(self.source_id,Window(start=left,end=right),right,
                f'probe:{nonce}:cursor:{self.generation}:{self.stream.tell()}')
