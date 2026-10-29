import json
import unittest
from datetime import timedelta
from pathlib import Path
from cryptography.fernet import Fernet
from backend.app.services.evidence_archive import EvidenceArchive
from backend.app.models.evidence import UsageQuery
from contracts.usage_summary_v1 import Window
from tests.test_usage_store import START, event, subject, key
import tests.test_usage_store as usage_fixture


class ArchiveTests(unittest.TestCase):
    setUp=usage_fixture.UsageTests.setUp
    ingest=usage_fixture.UsageTests.ingest
    query=usage_fixture.UsageTests.query

    def archive(self):
        keyfile=Path(self.temp.name)/'keys.json'
        keyfile.write_text(json.dumps({'active':'key-1','keys':{'key-1':Fernet.generate_key().decode()}}))
        return EvidenceArchive(self.store,Path(self.temp.name)/'archive',keyfile)

    def test_encrypted_archive_readback_and_restore_after_hot_index_expiry(self):
        self.ingest(event('sensitive-original-marker'))
        summary=self.query()
        archive=self.archive();manifest=archive.seal()
        data=archive.path(manifest['segment_id']).read_bytes()
        self.assertNotIn(b'sensitive-original-marker',data)
        self.assertEqual(archive.read(manifest['segment_id'])['raw'][0]['audit_id'],'sensitive-original-marker')
        archive.pin('case-one',summary.summary_id,self.now+timedelta(days=365))
        self.now+=timedelta(days=100)
        archive.prune_hot()
        query=UsageQuery(cluster_id='lab',namespace='guardian-demo',subject=subject(),
            window=Window(start=START,end=START+timedelta(minutes=10)),keys={'pods':key()})
        self.assertTrue(any(c.status=='unavailable' for c in self.store.query(query).series[0].coverage))
        restored=archive.restore(query)
        self.assertEqual(restored['status'],'available',restored)
        self.assertEqual(restored['summary']['series'][0]['buckets'][0]['counts']['successful_completed'],1)
        self.assertEqual(archive.delete_expired(),[])

    def test_corruption_and_missing_key_fail_closed(self):
        self.ingest(event());archive=self.archive();manifest=archive.seal()
        path=archive.path(manifest['segment_id']);original=path.read_bytes();path.write_bytes(original[:-1]+b'x')
        with self.assertRaisesRegex(ValueError,'archive_checksum_failed'):archive.read(manifest['segment_id'])
        path.write_bytes(original);archive.keys={}
        with self.assertRaisesRegex(ValueError,'archive_restore_failed'):archive.read(manifest['segment_id'])

    def test_expiry_has_a_tombstone_and_does_not_return_quiet_zero(self):
        self.ingest(event());archive=self.archive();manifest=archive.seal()
        self.now+=timedelta(days=91)
        self.assertEqual(archive.delete_expired(),[manifest['segment_id']])
        self.assertFalse(archive.path(manifest['segment_id']).exists())
        query=UsageQuery(cluster_id='lab',namespace='guardian-demo',subject=subject(),
            window=Window(start=START,end=START+timedelta(minutes=10)),keys={'pods':key()})
        self.assertEqual(archive.restore(query)['status'],'expired')

    def test_raw_hot_pruning_requires_acknowledged_readable_archive(self):
        self.ingest(event());archive=self.archive();self.now+=timedelta(days=8)
        self.assertEqual(archive.prune_hot()['raw_pruned'],0)
        manifest=archive.seal()
        archive.path(manifest['segment_id']).unlink()
        with self.assertRaisesRegex(ValueError,'archive_restore_failed'):archive.prune_hot()
        with self.db._connect() as db:self.assertEqual(db.execute('SELECT count(*) FROM audit_raw').fetchone()[0],1)

    def test_path_traversal_is_rejected(self):
        archive=self.archive()
        with self.assertRaises(ValueError):archive.path('../../outside')
