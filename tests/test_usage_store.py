import hashlib
import json
import tempfile
import unittest
from unittest.mock import patch
from copy import deepcopy
from datetime import datetime,timedelta,timezone
from pathlib import Path

from contracts.usage_summary_v1 import Subject, RequestKey, Window
from backend.app.models.evidence import CollectionPolicy, UsageQuery
from backend.app.services.governance_store import GovernanceStore
from backend.app.services.usage_store import UsageStore
from backend.app.services.audit_usage import normalize

START=datetime(2026,10,29,8,58,tzinfo=timezone.utc)
POLICY=b'''apiVersion: audit.k8s.io/v1
kind: Policy
rules:
- level: Metadata
  resources:
  - group: ""
    resources: [pods, secrets, configmaps]
- level: Metadata
  nonResourceURLs: [/version]
'''


def subject(uid='sa-uid'):
    return Subject(username='system:serviceaccount:guardian-demo:reader',kind='service_account',
        namespace='guardian-demo',name='reader',uid=uid,uid_status='verified',
        groups=['system:authenticated','system:serviceaccounts','system:serviceaccounts:guardian-demo'],
        identity_evidence_refs=['inventory-sa'])


def key(resource='pods',verb='get',namespace='guardian-demo'):
    return RequestKey(kind='resource',verb=verb,api_group='',resource=resource,subresource=None,
        scope='namespaced',namespace=namespace,resource_name=None,name_resolution='any_name',name_field_selector=None,non_resource_path=None)


def event(identifier='request',*,at=30,stage='ResponseComplete',code=200,decision=None,resource='pods',verb='get',uid='sa-uid',namespace='guardian-demo'):
    row={'auditID':identifier,'stage':stage,'requestReceivedTimestamp':(START+timedelta(seconds=at)).isoformat(),
        'stageTimestamp':(START+timedelta(seconds=at+1)).isoformat(),'user':{
            'username':subject().username,'uid':uid,'groups':subject().groups},'verb':verb,
        'objectRef':{'resource':resource,'namespace':namespace,'name':'one'},
        'requestURI':'/api/v1/namespaces/'+namespace+'/'+resource+'/one','responseStatus':{'code':code}}
    if decision: row['annotations']={'authorization.k8s.io/decision':decision}
    return row


class UsageTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup)
        self.now=START+timedelta(minutes=10)
        self.db=GovernanceStore(Path(self.temp.name)/'state.sqlite3',clock=lambda:self.now)
        self.store=UsageStore(self.db)
        self.policy=CollectionPolicy(cluster_id='lab',source_id='audit',namespace='guardian-demo',audit_policy_ref='policy-1',
            resources=['/pods','/secrets','/configmaps'],resource_scopes={'/pods':'namespaced','/secrets':'namespaced','/configmaps':'namespaced'},
            approved_policy_sha256=hashlib.sha256(POLICY).hexdigest(),completeness_attested=True)
        self.store.register(self.policy,POLICY)
        self.store.health('audit',Window(start=START,end=self.now),self.now,'verified-heartbeat:1')
        self.offset=0

    def ingest(self,*events,source='audit'):
        rows=[]
        for e in events:
            rows.append((self.offset,e));self.offset+=1
        self.store.ingest(source,'generation',rows,self.offset)

    def query(self,**changes):
        values={'cluster_id':'lab','namespace':'guardian-demo','subject':subject(),
            'window':Window(start=START,end=self.now),'keys':{'pods':key(),'secrets':key('secrets')}}
        values.update(changes)
        return self.store.query(UsageQuery(**values))

    def test_stage_replay_and_duplicate_sources_count_one_request_and_correct_original_hour(self):
        started=event(stage='ResponseStarted',verb='watch')
        self.ingest(started,deepcopy(started))
        complete=deepcopy(started);complete['stage']='ResponseComplete';complete['stageTimestamp']=(START+timedelta(minutes=8)).isoformat()
        self.ingest(complete)
        other=self.policy.model_copy(update={'source_id':'second'})
        self.store.register(other,POLICY)
        self.ingest(complete,source='second')
        report=self.query(keys={'watch':key(verb='watch')})
        self.assertEqual(sum(b.counts.successful_completed for b in report.series[0].buckets),1)
        self.assertEqual(sum(b.counts.authorized_incomplete for b in report.series[0].buckets),0)
        with self.db._connect() as db:
            self.assertEqual(db.execute("SELECT SUM(count) FROM usage_hours WHERE outcome='successful_completed'").fetchone()[0],1)
            self.assertEqual(db.execute('SELECT count(*) FROM audit_requests').fetchone()[0],1)

    def test_authorized_errors_denials_and_unknown_http_errors_remain_distinct(self):
        self.ingest(event('allowed-error',code=404,decision='allow'),event('denied',code=403,decision='forbid'),event('unknown',code=403),event('created',code=201))
        counts=self.query().series[0].buckets[0].counts
        self.assertEqual(counts.model_dump(),dict(successful_completed=1,authorized_error=1,authorized_incomplete=0,denied=1,unknown=1))

    def test_exact_half_open_partial_hour_boundaries_and_explicit_quiet_zero_series(self):
        self.ingest(event('before',at=9),event('inside',at=10),event('end',at=61))
        report=self.query(window=Window(start=START+timedelta(seconds=10),end=START+timedelta(seconds=61)))
        self.assertEqual(report.series[0].buckets[0].counts.successful_completed,1)
        self.assertEqual(report.series[1].buckets[0].counts.total(),0)
        self.assertTrue(all(c.status=='complete_for_declared_scope' for s in report.series for c in s.coverage))

    def test_carried_watch_protects_access_without_becoming_a_new_start(self):
        self.ingest(event('watch',stage='ResponseStarted',verb='watch',at=10))
        report=self.query(window=Window(start=START+timedelta(minutes=3),end=self.now),keys={'watch':key(verb='watch')})
        self.assertEqual(sum(b.counts.total() for b in report.series[0].buckets),0)
        self.assertEqual(len(report.series[0].carried_authorized_requests),1)
        self.assertIsNone(report.series[0].carried_authorized_requests[0].completed_at)

    def test_missing_coverage_and_recorded_source_gap_never_become_zero_evidence(self):
        empty=self.query(window=Window(start=START-timedelta(days=1),end=START))
        self.assertTrue(all(c.status=='unavailable' for s in empty.series for c in s.coverage))
        self.store.gap('audit',START+timedelta(seconds=10),START+timedelta(seconds=20),'rotation_loss')
        report=self.query()
        self.assertTrue(any(c.status=='unavailable' for c in report.series[0].coverage))
        self.assertEqual(report.series[0].buckets[0].counts.total(),0)

    def test_case_and_namespace_and_resource_restrictions_are_not_merged(self):
        self.ingest(event('other-ns',namespace='other'),event('pods'),event('secrets',resource='secrets'))
        report=self.query()
        self.assertEqual(sum(b.counts.successful_completed for b in report.series[0].buckets),1)
        self.assertEqual(sum(b.counts.successful_completed for b in report.series[1].buckets),1)

    def test_impersonation_and_unknown_or_recreated_uid_are_preserved(self):
        e=event();e['impersonatedUser']=e['user'];e['user']={'username':'admin','uid':'admin-uid'}
        self.ingest(e)
        self.assertEqual(self.query().series[0].buckets[0].counts.successful_completed,1)
        self.ingest(event('unknown-uid',uid=''))
        self.assertTrue(any(c.status=='unavailable' for c in self.query().series[0].coverage))
        self.assertTrue(any(c.status=='unavailable' for c in self.query(subject=subject('new-uid')).series[0].coverage))

    def test_conflicting_identity_is_quarantined_and_late_stage_cannot_overwrite_it(self):
        first=event();self.ingest(first)
        altered=deepcopy(first);altered['objectRef']['resource']='secrets'
        self.ingest(altered)
        report=self.query()
        self.assertEqual(report.series[0].buckets[0].counts.unknown,1)
        self.assertTrue(any(c.status=='unavailable' for c in report.series[0].coverage))

    def test_audit_policy_first_matching_exclusion_blocks_coverage(self):
        import yaml
        policy=yaml.safe_load(POLICY);policy['rules'].insert(0,{'level':'None','resources':[{'group':'','resources':['secrets']}]})
        from backend.app.services.usage_store import policy_covers
        self.assertFalse(policy_covers(policy,key('secrets'),subject()))
        self.assertTrue(policy_covers(policy,key('pods'),subject()))

    def test_cursor_replay_is_atomic_and_rejects_changed_bytes_at_same_position(self):
        e=event();self.store.ingest('audit','same',[(0,e)],1)
        self.store.ingest('audit','same',[(0,e)],1)
        changed=event(code=404)
        with self.assertRaisesRegex(ValueError,'source_cursor_content_conflict'):
            self.store.ingest('audit','same',[(0,changed)],2)
        with self.db._connect() as db:
            self.assertEqual(db.execute('SELECT offset FROM evidence_cursors').fetchone()[0],1)
            self.assertEqual(db.execute('SELECT count(*) FROM audit_raw').fetchone()[0],1)

    def test_summary_corrections_create_immutable_revisions_and_capacity_is_disclosed(self):
        first=self.query()
        self.ingest(event())
        second=self.query()
        self.assertGreater(second.revision,first.revision)
        with self.db._connect() as db:
            old=db.execute('SELECT payload FROM usage_summaries WHERE summary_id=?',(first.summary_id,)).fetchone()[0]
            self.assertEqual(json.loads(old)['series'][0]['buckets'][0]['counts']['successful_completed'],0)
        self.store.maximum=1
        self.ingest(event('second'))
        self.assertTrue(self.query().truncated)

class RepeatedAuditStageTests(unittest.TestCase):
    setUp=UsageTests.setUp
    ingest=UsageTests.ingest
    # Exercise the real server behavior without duplicating the inherited suite.
    def test_repeated_response_started_with_new_timestamp_is_one_authorized_watch(self):
        from copy import deepcopy
        first=event('repeated-watch',stage='ResponseStarted',verb='watch')
        second=deepcopy(first);second['stageTimestamp']=(START+timedelta(seconds=35)).isoformat()
        self.ingest(first,second)
        with self.db._connect() as db:
            row=db.execute("SELECT conflict,payload FROM audit_requests WHERE audit_id='repeated-watch'").fetchone()
            self.assertFalse(row['conflict']);value=json.loads(row['payload'])
            self.assertEqual(__import__('datetime').datetime.fromisoformat(value['authorized_at']),__import__('datetime').datetime.fromisoformat(first['stageTimestamp']));self.assertEqual(__import__('datetime').datetime.fromisoformat(value['observed_at']),__import__('datetime').datetime.fromisoformat(second['stageTimestamp']))
            self.assertEqual(db.execute("SELECT sum(count) FROM usage_hours WHERE outcome='authorized_incomplete'").fetchone()[0],1)

    def test_unrelated_rbac_identity_conflict_does_not_claim_a_pod_coverage_gap(self):
        first=event('rbac-unrelated',resource='roles',verb='watch',namespace='')
        first['objectRef']['apiGroup']='rbac.authorization.k8s.io'
        second=__import__('copy').deepcopy(first);second['user']['uid']='another-uid'
        self.ingest(first,second)
        with self.db._connect() as db:
            self.assertTrue(db.execute("SELECT conflict FROM audit_requests WHERE audit_id='rbac-unrelated'").fetchone()[0])
            self.assertEqual(db.execute('SELECT count(*) FROM evidence_gaps').fetchone()[0],0)


class CoverageHistoryTests(unittest.TestCase):
    setUp=UsageTests.setUp
    query=UsageTests.query

    def test_long_probe_history_does_not_revalidate_policy_per_interval(self):
        # A long-running collector produces thousands of adjacent health rows.
        # The query must keep explicit gaps while decoding each source once per
        # permission, rather than quadratically inside its writer transaction.
        self.now=START+timedelta(hours=14)
        for number in range(1000):
            left=START+timedelta(seconds=number*50)
            self.store.health('audit',Window(start=left,end=left+timedelta(seconds=50)),
                self.now,f'probe:{number}')
        gap_start=START+timedelta(hours=5)
        gap_end=gap_start+timedelta(seconds=10)
        self.store.gap('audit',gap_start,gap_end,'collector_restart')
        with patch.object(CollectionPolicy,'model_validate_json',
                wraps=CollectionPolicy.model_validate_json) as validate_source:
            report=self.query(window=Window(start=START-timedelta(days=7),end=self.now))
        self.assertLessEqual(validate_source.call_count,2)
        for series in report.series:
            self.assertEqual(series.coverage[0].status,'unavailable')
            self.assertTrue(any(c.status=='complete_for_declared_scope' for c in series.coverage))
            inside=[c for c in series.coverage if c.interval.start<gap_end and c.interval.end>gap_start]
            self.assertTrue(inside)
            self.assertTrue(all(c.status=='unavailable' and 'source_gap' in c.reason_codes for c in inside))
