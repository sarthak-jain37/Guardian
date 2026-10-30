import json
import unittest
from datetime import timedelta
from pathlib import Path
from unittest.mock import MagicMock
from backend.app.services.usage_collector import AuditFollower
from backend.app.services.audit_usage import iso
from tests.test_usage_store import START,event
import tests.test_usage_store as fixture


class CollectorTests(unittest.TestCase):
    setUp=fixture.UsageTests.setUp
    query=fixture.UsageTests.query

    def test_restart_and_partial_line_are_replay_safe(self):
        path=Path(self.temp.name)/'audit.log'
        encoded=json.dumps(event()).encode()
        path.write_bytes(encoded[:50])
        follower=AuditFollower(self.store,'audit',path)
        self.assertEqual(follower.poll()['records'],0)
        with path.open('ab') as out:out.write(encoded[50:]+b'\n')
        self.assertEqual(follower.poll()['records'],1);follower.close()
        follower=AuditFollower(self.store,'audit',path)
        self.assertEqual(follower.poll()['records'],0);follower.close()
        self.assertEqual(self.query().series[0].buckets[0].counts.successful_completed,1)

    def test_quiet_coverage_requires_confirmed_audit_probes_and_not_just_api_success(self):
        path=Path(self.temp.name)/'audit.log';path.write_text('')
        follower=AuditFollower(self.store,'audit',path)
        client=MagicMock();client.call_api.return_value=({},200,{})
        self.assertTrue(follower.probe(client))
        with self.db._connect() as db:
            first=db.execute('SELECT nonce FROM collector_probes').fetchone()[0]
        self.assertIsNone(self.probe_confirmed(first))
        before=event('health1',at=600);before['stageTimestamp']=before['requestReceivedTimestamp'];before.pop('objectRef');before.update(requestURI='/version',userAgent='guardian-audit-probe/'+first)
        with path.open('a') as out:out.write(json.dumps(before)+'\n')
        follower.poll();self.assertIsNotNone(self.probe_confirmed(first))
        self.now+=timedelta(seconds=30);follower.probe(client)
        with self.db._connect() as db:
            second=db.execute('SELECT nonce FROM collector_probes WHERE confirmed_at IS NULL').fetchone()[0]
        after=event('health2',at=630);after['stageTimestamp']=after['requestReceivedTimestamp'];after.pop('objectRef');after.update(requestURI='/version',userAgent='guardian-audit-probe/'+second)
        with path.open('a') as out:out.write(json.dumps(after)+'\n')
        follower.poll();follower.close()
        with self.db._connect() as db:
            count=db.execute("SELECT count(*) FROM evidence_coverage WHERE cursor_ref LIKE 'probe:%'").fetchone()[0]
        self.assertEqual(count,1)

    def probe_confirmed(self,nonce):
        with self.db._connect() as db:return db.execute('SELECT confirmed_at FROM collector_probes WHERE nonce=?',(nonce,)).fetchone()[0]

    def test_lost_or_truncated_source_is_visible(self):
        path=Path(self.temp.name)/'audit.log';path.write_text(json.dumps(event())+'\n')
        follower=AuditFollower(self.store,'audit',path);follower.poll()
        path.write_text('bad\n');follower.poll();follower.close()
        self.assertTrue(any(c.status=='unavailable' for c in self.query().series[0].coverage))
