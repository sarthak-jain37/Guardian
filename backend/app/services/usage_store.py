"""Replay-safe request index, hourly counters and immutable exact UsageSummary.

Counts, late-stage correction, raw capture and cursor progress commit together.
Coverage is independent health/policy evidence; no event timestamp creates it.
"""
import json
from datetime import datetime, timedelta, timezone

from contracts.usage_summary_v1 import UsageSummary, Window
from backend.app.models.evidence import CollectionPolicy, UsageQuery
from backend.app.services.audit_usage import OUTCOMES, STAGES, iso, matches, normalize, timestamp
from backend.app.services.governance_store import LedgerError, digest, encode


def policy_covers(policy, key, subject):
    """Evaluate ordered audit rules conservatively for this exact query scope."""
    resource = key.resource + ('/'+key.subresource if key.subresource else '')
    for rule in policy.get('rules',[]):
        if rule.get('users') and subject.username not in rule['users']: continue
        if rule.get('userGroups') and not set(rule['userGroups']) & set(subject.groups): continue
        if rule.get('verbs') and key.verb not in rule['verbs']: continue
        if rule.get('namespaces') and key.namespace not in rule['namespaces']: continue
        if rule.get('nonResourceURLs'): continue
        resources = rule.get('resources')
        if resources:
            selected = []
            for spec in resources:
                if spec.get('group','') != key.api_group: continue
                if not any(r in ('*',resource) or r==key.resource+'/*' and key.subresource
                           for r in spec.get('resources',[])): continue
                selected.append(spec)
            if not selected: continue
            if any(s.get('resourceNames') for s in selected):
                return False  # A name-specific earlier exclusion can hide part of any_name.
        omitted = set(policy.get('omitStages',[])) | set(rule.get('omitStages',[]))
        return rule.get('level') in ('Metadata','Request','RequestResponse') and 'ResponseComplete' not in omitted and (
            key.verb!='watch' or 'ResponseStarted' not in omitted)
    return False


class UsageStore:
    def __init__(self, database, *, clock=None, maximum_requests=50000):
        self.db = database
        self.clock = clock or database.now
        self.maximum = maximum_requests
        with self.db._connect() as db:
            db.executescript('''
            CREATE TABLE IF NOT EXISTS evidence_sources (
              source_id TEXT PRIMARY KEY, cluster_id TEXT NOT NULL, namespace TEXT NOT NULL,
              declaration TEXT NOT NULL, audit_policy TEXT NOT NULL);
            CREATE TABLE IF NOT EXISTS audit_raw (
              raw_ref TEXT PRIMARY KEY, cluster_id TEXT NOT NULL, source_id TEXT NOT NULL,
              audit_id TEXT, received_at TEXT NOT NULL, payload TEXT NOT NULL);
            CREATE INDEX IF NOT EXISTS raw_audit ON audit_raw(cluster_id,audit_id);
            CREATE TABLE IF NOT EXISTS audit_requests (
              cluster_id TEXT NOT NULL, audit_id TEXT NOT NULL, username TEXT NOT NULL, uid TEXT NOT NULL,
              started_at TEXT NOT NULL, hour TEXT NOT NULL, key_hash TEXT NOT NULL,
              outcome TEXT NOT NULL, conflict INTEGER NOT NULL, payload TEXT NOT NULL,
              PRIMARY KEY(cluster_id,audit_id));
            CREATE INDEX IF NOT EXISTS request_window ON audit_requests(cluster_id,username,started_at);
            CREATE TABLE IF NOT EXISTS audit_stages (
              cluster_id TEXT NOT NULL, audit_id TEXT NOT NULL, stage TEXT NOT NULL,
              content_hash TEXT NOT NULL, payload TEXT NOT NULL, PRIMARY KEY(cluster_id,audit_id,stage));
            CREATE TABLE IF NOT EXISTS usage_hours (
              cluster_id TEXT NOT NULL, username TEXT NOT NULL, uid TEXT NOT NULL,
              key_hash TEXT NOT NULL, hour TEXT NOT NULL, outcome TEXT NOT NULL, count INTEGER NOT NULL,
              PRIMARY KEY(cluster_id,username,uid,key_hash,hour,outcome));
            CREATE TABLE IF NOT EXISTS evidence_cursors (
              source_id TEXT PRIMARY KEY, generation TEXT NOT NULL, offset INTEGER NOT NULL,
              updated_at TEXT NOT NULL);
            CREATE TABLE IF NOT EXISTS evidence_coverage (
              coverage_id TEXT PRIMARY KEY, source_id TEXT NOT NULL, start TEXT NOT NULL, end TEXT NOT NULL,
              status TEXT NOT NULL, reasons TEXT NOT NULL, cursor_ref TEXT NOT NULL, processed_through TEXT NOT NULL);
            CREATE INDEX IF NOT EXISTS coverage_window ON evidence_coverage(source_id,start,end);
            CREATE TABLE IF NOT EXISTS evidence_gaps (
              gap_id TEXT PRIMARY KEY, source_id TEXT NOT NULL, start TEXT NOT NULL, end TEXT NOT NULL, reason TEXT NOT NULL);
            CREATE TABLE IF NOT EXISTS usage_summaries (
              summary_id TEXT PRIMARY KEY, query_hash TEXT NOT NULL, revision INTEGER NOT NULL,
              payload TEXT NOT NULL, created_at TEXT NOT NULL);
            CREATE TABLE IF NOT EXISTS summary_requests (
              summary_id TEXT NOT NULL, cluster_id TEXT NOT NULL, audit_id TEXT NOT NULL,
              PRIMARY KEY(summary_id,cluster_id,audit_id));
            CREATE TABLE IF NOT EXISTS summary_coverage (
              summary_id TEXT NOT NULL, coverage_id TEXT NOT NULL, PRIMARY KEY(summary_id,coverage_id));
            CREATE TABLE IF NOT EXISTS collector_probes (
              nonce TEXT PRIMARY KEY, source_id TEXT NOT NULL, requested_at TEXT NOT NULL, confirmed_at TEXT);
            ''')
            for table in ('usage_summaries','evidence_coverage','evidence_gaps','evidence_sources'):
                for operation in ('UPDATE','DELETE'):
                    db.execute(f"CREATE TRIGGER IF NOT EXISTS {table}_no_{operation} BEFORE {operation} ON {table} BEGIN SELECT RAISE(ABORT,'immutable_evidence'); END")

    def register(self, declaration, audit_policy):
        import hashlib
        import yaml
        declaration = CollectionPolicy.model_validate(declaration)
        raw = audit_policy if isinstance(audit_policy,bytes) else audit_policy.encode()
        if hashlib.sha256(raw).hexdigest()!=declaration.approved_policy_sha256:
            raise ValueError('audit_policy_hash_mismatch')
        parsed = yaml.safe_load(raw)
        if not isinstance(parsed,dict) or parsed.get('kind')!='Policy':
            raise ValueError('invalid_audit_policy')
        with self.db.transaction() as db:
            old = db.execute('SELECT declaration,audit_policy FROM evidence_sources WHERE source_id=?',(declaration.source_id,)).fetchone()
            values = (encode(declaration.model_dump(mode='json')),encode(parsed))
            if old and tuple(old)!=values:
                raise ValueError('source_policy_is_immutable_register_new_source_id')
            db.execute('INSERT OR IGNORE INTO evidence_sources VALUES (?,?,?,?,?)',
                (declaration.source_id,declaration.cluster_id,declaration.namespace,*values))
        return declaration

    @staticmethod
    def source(db, source_id):
        row = db.execute('SELECT * FROM evidence_sources WHERE source_id=?',(source_id,)).fetchone()
        if row is None: raise ValueError('unknown_audit_source')
        return CollectionPolicy.model_validate_json(row['declaration']),json.loads(row['audit_policy'])

    @staticmethod
    def counter(db, cluster, request, delta):
        hour = iso(timestamp(request['started_at']).replace(minute=0,second=0,microsecond=0))
        args = (cluster,request['subject']['username'],request['subject']['uid'] or '',digest(request['key']),hour,request['outcome'],delta)
        db.execute('''INSERT INTO usage_hours VALUES (?,?,?,?,?,?,?) ON CONFLICT(cluster_id,username,uid,key_hash,hour,outcome)
                      DO UPDATE SET count=count+excluded.count''',args)

    def ingest(self, source_id, generation, records, offset):
        """records=(line start byte offset, original audit object); offset includes consumed bytes."""
        if len(records)>4096 or type(offset) is not int or offset<0:
            raise ValueError('audit_batch_out_of_bounds')
        with self.db.transaction() as db:
            declaration,_ = self.source(db,source_id)
            prior = db.execute('SELECT * FROM evidence_cursors WHERE source_id=?',(source_id,)).fetchone()
            if prior and prior['generation']==generation and offset<prior['offset']:
                raise ValueError('cursor_regression')
            now = self.clock()
            for position,event in records:
                raw_ref = 'raw-'+digest([source_id,generation,position]).split(':')[1]
                payload = encode(event)
                old_raw = db.execute('SELECT payload FROM audit_raw WHERE raw_ref=?',(raw_ref,)).fetchone()
                if old_raw and old_raw['payload']!=payload:
                    raise ValueError('source_cursor_content_conflict')
                db.execute('INSERT OR IGNORE INTO audit_raw VALUES (?,?,?,?,?,?)',
                    (raw_ref,declaration.cluster_id,source_id,event.get('auditID'),iso(now),payload))
                try:
                    request = normalize(event,declaration.resource_scopes)
                    if timestamp(request['observed_at'])>now:
                        raise ValueError('audit_event_from_future')
                except (ValueError,KeyError,TypeError):
                    earliest=db.execute('SELECT MIN(start) FROM evidence_coverage WHERE source_id=?',(source_id,)).fetchone()[0]
                    left=timestamp(earliest) if earliest else now-timedelta(seconds=declaration.maximum_lag_seconds)
                    try:left=min(left,timestamp(event['requestReceivedTimestamp']))
                    except (KeyError,ValueError,TypeError):pass
                    self._gap(db,source_id,left,now,'invalid_audit_record')
                    continue
                cluster,audit = declaration.cluster_id,request['audit_id']
                old = db.execute('SELECT * FROM audit_requests WHERE cluster_id=? AND audit_id=?',(cluster,audit)).fetchone()
                stage = db.execute('SELECT * FROM audit_stages WHERE cluster_id=? AND audit_id=? AND stage=?',
                                   (cluster,audit,request['stage'])).fetchone()
                stage_hash = digest(request)
                conflict = bool(old and (old['conflict'] or json.loads(old['payload'])['identity_hash']!=request['identity_hash']))
                if stage and stage['content_hash']!=stage_hash:
                    prior_stage=json.loads(stage['payload'])
                    # A real API-server watch can emit ResponseStarted again
                    # with a later timestamp. Keep one request, earliest known
                    # authorization and latest observation; changed identity or
                    # outcome still quarantines the request.
                    stable=('identity_hash','stage','outcome')
                    if all(prior_stage[k]==request[k] for k in stable):
                        request['observed_at']=max(prior_stage['observed_at'],request['observed_at'])
                        auth=[v for v in (prior_stage['authorized_at'],request['authorized_at']) if v]
                        request['authorized_at']=min(auth) if auth else None
                        completed=[v for v in (prior_stage['completed_at'],request['completed_at']) if v]
                        request['completed_at']=max(completed) if completed else None
                        stage_hash=digest(request)
                        db.execute('UPDATE audit_stages SET content_hash=?,payload=? WHERE cluster_id=? AND audit_id=? AND stage=?',
                            (stage_hash,encode(request),cluster,audit,request['stage']))
                    else:conflict=True
                db.execute('INSERT OR IGNORE INTO audit_stages VALUES (?,?,?,?,?)',
                           (cluster,audit,request['stage'],stage_hash,encode(request)))
                stages = [json.loads(row[0]) for row in db.execute('SELECT payload FROM audit_stages WHERE cluster_id=? AND audit_id=?',(cluster,audit))]
                current = max(stages,key=lambda value:STAGES[value['stage']])
                authorized = [s['authorized_at'] for s in stages if s['authorized_at']]
                current['authorized_at'] = min(authorized) if authorized else None
                current['observed_at'] = max(s['observed_at'] for s in stages)
                # Contradictory same-request outcomes are quarantined, not whichever line arrived last.
                if any(s['outcome']=='denied' for s in stages) and any(s['authorized_at'] for s in stages):
                    conflict = True
                if conflict:
                    current = json.loads(old['payload']) if old else current
                    current['outcome']='unknown'
                    affected=[current['key'],request['key']]
                    if any((key.get('api_group') or '')+'/'+(key.get('resource') or '') in declaration.resources
                            and key.get('namespace') in (None,declaration.namespace) for key in affected):
                        self._gap(db,source_id,timestamp(current['started_at']),max(now,timestamp(current['started_at'])+timedelta(microseconds=1)),
                                  'conflicting_audit_identity_or_outcome')
                if old: self.counter(db,cluster,json.loads(old['payload']),-1)
                self.counter(db,cluster,current,1)
                hour = iso(timestamp(current['started_at']).replace(minute=0,second=0,microsecond=0))
                db.execute('INSERT OR REPLACE INTO audit_requests VALUES (?,?,?,?,?,?,?,?,?,?)',
                    (cluster,audit,current['subject']['username'],current['subject']['uid'] or '',current['started_at'],
                     hour,digest(current['key']),current['outcome'],int(conflict),encode(current)))
            db.execute('INSERT INTO evidence_cursors VALUES (?,?,?,?) ON CONFLICT(source_id) DO UPDATE SET generation=excluded.generation,offset=excluded.offset,updated_at=excluded.updated_at',
                       (source_id,generation,offset,iso(now)))

    @staticmethod
    def _gap(db, source_id, start, end, reason):
        if end<=start: end=start+timedelta(microseconds=1)
        identifier = digest([source_id,iso(start),iso(end),reason])
        db.execute('INSERT OR IGNORE INTO evidence_gaps VALUES (?,?,?,?,?)',(identifier,source_id,iso(start),iso(end),reason))

    def gap(self,source_id,start,end,reason):
        with self.db.transaction() as db:
            self.source(db,source_id)
            self._gap(db,source_id,start,end,reason)

    def health(self,source_id,window,processed_through,cursor_ref,*,healthy=True):
        """Collector-owned verified probe interval, never an HTTP/model assertion."""
        window = Window.model_validate(window)
        with self.db.transaction() as db:
            policy,_ = self.source(db,source_id)
            if window.end>processed_through or processed_through>self.clock():
                raise ValueError('invalid_collector_watermark')
            complete = healthy and policy.completeness_attested
            row = (digest([source_id,window.model_dump(mode='json'),cursor_ref,complete]),source_id,
                iso(window.start),iso(window.end),'complete_for_declared_scope' if complete else 'partial',
                encode([] if complete else ['source_health_or_attestation_unavailable']),cursor_ref,iso(processed_through))
            db.execute('INSERT OR IGNORE INTO evidence_coverage VALUES (?,?,?,?,?,?,?,?)',row)

    def _coverage(self,db,query,key,progress,identity_uncertain):
        start,end=query.window.start,query.window.end
        rows = db.execute('''SELECT c.*,s.declaration,s.audit_policy FROM evidence_coverage c JOIN evidence_sources s USING(source_id)
              WHERE s.cluster_id=? AND s.namespace=? AND c.start<? AND c.end>?''',
              (query.cluster_id,query.namespace,iso(end),iso(start))).fetchall()
        gaps = db.execute('''SELECT g.* FROM evidence_gaps g JOIN evidence_sources s USING(source_id)
              WHERE s.cluster_id=? AND s.namespace=? AND g.start<? AND g.end>?''',
              (query.cluster_id,query.namespace,iso(end),iso(start))).fetchall()
        points={start,end}
        for row in [*rows,*gaps]:
            points.update((max(start,timestamp(row['start'])),min(end,timestamp(row['end']))))
        if progress and start<progress<end: points.add(progress)
        result=[]
        for left,right in zip(sorted(points),sorted(points)[1:]):
            applicable=[]
            for row in rows:
                declaration=CollectionPolicy.model_validate_json(row['declaration'])
                resource=(key.api_group or '')+'/'+key.resource+('/'+key.subresource if key.subresource else '')
                if (timestamp(row['start'])<=left and right<=timestamp(row['end'])
                    and resource in declaration.resources and policy_covers(json.loads(row['audit_policy']),key,query.subject)):
                    applicable.append(row)
            lost=any(timestamp(g['start'])<right and timestamp(g['end'])>left for g in gaps)
            good=[r for r in applicable if r['status']=='complete_for_declared_scope' and timestamp(r['processed_through'])>=right]
            complete=bool(good) and not lost and not identity_uncertain
            reasons=[] if complete else (['source_gap'] if lost else ['identity_unresolved'] if identity_uncertain else ['coverage_unavailable'])
            chosen=good if complete else applicable
            result.append({'interval':{'start':left,'end':right},'status':'complete_for_declared_scope' if complete else 'unavailable',
                'reason_codes':reasons,'source_ids':sorted({r['source_id'] for r in chosen})[:32],
                'audit_policy_refs':sorted({CollectionPolicy.model_validate_json(r['declaration']).audit_policy_ref for r in chosen})[:32],
                'health_evidence_refs':[r['coverage_id'] for r in chosen][:32],'known_lost_events':0 if complete else None})
        return result

    def query(self,query,*,persist=True):
        query=UsageQuery.model_validate(query.model_dump(mode='json') if isinstance(query,UsageQuery) else query)
        now=self.clock()
        if query.window.end>now: raise ValueError('query_ends_in_future')
        with self.db.transaction() as db:
            records=db.execute('''SELECT * FROM audit_requests WHERE cluster_id=? AND username=? AND started_at<?
                AND (started_at>=? OR (json_extract(payload,'$.authorized_at') IS NOT NULL AND
                    (json_extract(payload,'$.completed_at') IS NULL OR json_extract(payload,'$.completed_at')>?)))
                ORDER BY started_at DESC LIMIT ?''',(query.cluster_id,query.subject.username,iso(query.window.end),
                    iso(query.window.start),iso(query.window.start),self.maximum+1)).fetchall()
            truncated=len(records)>self.maximum
            records=records[:self.maximum]
            # Unknown/recreated historical identity is not filled using today's SA UID.
            uncertain=any(r['uid']!= (query.subject.uid or '') for r in records)
            records=[json.loads(r['payload']) for r in records if r['uid']==(query.subject.uid or '')]
            health=db.execute('''SELECT MAX(processed_through) FROM evidence_coverage c JOIN evidence_sources s USING(source_id)
                WHERE s.cluster_id=? AND s.namespace=?''',(query.cluster_id,query.namespace)).fetchone()[0]
            progress=timestamp(health) if health else None
            series=[]; selected=set()
            for key_id,key in query.keys.items():
                observations=[r for r in records if matches(r['key'],key)]
                buckets=[]; left=query.window.start
                while left<query.window.end:
                    hour=left.replace(minute=0,second=0,microsecond=0)
                    right=min(hour+timedelta(hours=1),query.window.end)
                    rows=[r for r in observations if left<=timestamp(r['started_at'])<right]
                    counts={category:sum(r['outcome']==category for r in rows) for category in OUTCOMES}
                    times=sorted(timestamp(r['started_at']) for r in rows)
                    selected.update(r['audit_id'] for r in rows)
                    buckets.append({'bucket_start':hour,'interval':{'start':left,'end':right},'counts':counts,
                        'first_request_at':times[0] if times else None,'last_request_at':times[-1] if times else None,
                        'evidence_refs':['audit:'+r['audit_id'] for r in rows[:32]]})
                    left=right
                carried=[]
                for r in observations:
                    if timestamp(r['started_at'])>=query.window.start or not r['authorized_at']:continue
                    if timestamp(r['authorized_at'])>=query.window.end:continue
                    if r['completed_at'] and timestamp(r['completed_at'])<=query.window.start:continue
                    carried.append({'request_ref':'audit:'+r['audit_id'],'request_started_at':r['started_at'],
                        'authorized_at':r['authorized_at'],'last_observed_at':r['observed_at'],
                        'completed_at':r['completed_at'],'evidence_refs':['audit:'+r['audit_id']]})
                    selected.add(r['audit_id'])
                if len(carried)>1000: truncated=True
                series.append({'request_key_id':key_id,'request_key':key,'buckets':buckets,
                    'coverage':self._coverage(db,query,key,progress,uncertain),'carried_authorized_requests':carried[:1000]})
            query_hash=digest(query.model_dump(mode='json'))
            revision=db.execute('SELECT COALESCE(MAX(revision),0)+1 FROM usage_summaries WHERE query_hash=?',(query_hash,)).fetchone()[0]
            value=UsageSummary(schema_version='guardian.usage-summary.v1',summary_id='usage-'+digest([query_hash,revision,iso(now)]).split(':')[1],
                revision=revision,cluster_id=query.cluster_id,subject=query.subject,query_window=query.window,
                generated_at=now,processed_through=progress,bucket_resolution='PT1H',boundary_mode='exact',
                collector_version='guardian.audit-collector.v1',aggregation_version='guardian.request-index.v1',
                source_cursor_refs=sorted({r['cursor_ref'] for r in db.execute('SELECT cursor_ref FROM evidence_coverage c JOIN evidence_sources s USING(source_id) WHERE s.cluster_id=?',(query.cluster_id,))})[:128],
                requested_key_ids=list(query.keys),series=series,truncated=truncated,
                warnings=['request_index_capacity_exceeded'] if truncated else [])
            if persist:
                db.execute('INSERT INTO usage_summaries VALUES (?,?,?,?,?)',
                    (value.summary_id,query_hash,revision,value.model_dump_json(),iso(now)))
                db.executemany('INSERT OR IGNORE INTO summary_requests VALUES (?,?,?)',
                    [(value.summary_id,query.cluster_id,audit) for audit in selected])
                db.executemany('INSERT OR IGNORE INTO summary_coverage VALUES (?,?)',
                    [(value.summary_id,ref) for s in value.series for c in s.coverage for ref in c.health_evidence_refs])
            return value
