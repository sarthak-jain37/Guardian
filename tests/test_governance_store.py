"""Real SQLite transactions and graph-produced publications; no cluster/model."""
import copy
import sqlite3
import tempfile
import unittest
import subprocess
import sys
from contextlib import contextmanager
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import patch

from fastapi import HTTPException
from pydantic import ValidationError

from agents.guardian.contracts import AnalysisRequest
from agents.guardian.fixtures import demo_evidence
from agents.guardian.governance import GovernedDecision
from agents.guardian.runner import config, open_runner
from agents.guardian.work import WorkItem
from backend.app.core.auth import Principal
from backend.app.models.governance import DecisionInput, DeliveryClaim, HoldInput, ReviewPublication
from backend.app.services.governance_store import GovernanceStore, LedgerError

NOW = datetime(2026, 10, 29, tzinfo=timezone.utc)


def publication():
    evidence = demo_evidence(now=NOW).model_copy(update={'source_mode': 'captured'})
    request = AnalysisRequest(case_id='case-one', run_id='run-one', snapshot_id=evidence.snapshot_id,
        cluster_id=evidence.target.cluster_id, target_uid=evidence.target.uid, mode='preview')
    with tempfile.TemporaryDirectory() as directory:
        with open_runner(directory, evidence=evidence, clock=lambda: NOW) as (graph, runtime, store):
            state = graph.invoke({'request': request.model_dump(mode='json')}, config(request.run_id))
            return ReviewPublication(proposal=state['proposal'], report=store.get_report(request.run_id))


def principal(actor, kind, cluster, namespace, permissions):
    return Principal(actor=actor, kind=kind, grants=[{
        'cluster_id': cluster, 'namespace': namespace, 'permissions': permissions}])


class GovernanceStoreTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.template = publication()

    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.path = Path(self.directory.name) / 'ledger.sqlite3'
        self.now = NOW
        self.store = GovernanceStore(self.path, clock=lambda: self.now)
        self.pub = self.template.model_copy(deep=True)
        p = self.pub.proposal
        self.worker = principal('worker', 'service', p.target.cluster_id, p.target.namespace, ['read','publish','deliver'])
        self.reviewer = principal('alice', 'human', p.target.cluster_id, p.target.namespace, ['read','review','operate'])
        self.store.publish_review(self.pub, self.worker)
        self.decision = DecisionInput(kind='reject', expected_revision=1,
            expected_approval_hash=p.approval_hash, idempotency_key='request-one', note='Keep this grant')

    def decide(self, **changes):
        return self.store.record_decision(self.pub.proposal.proposal_id,
            self.decision.model_copy(update=changes), self.reviewer)

    def claim(self, actor=None, **changes):
        p = self.pub.proposal
        claim = DeliveryClaim(cluster_id=p.target.cluster_id, namespace=p.target.namespace, **changes)
        return self.store.claim_deliveries(claim, actor or self.worker)

    def test_publication_replay_is_immutable_and_restart_preserves_original(self):
        first = self.store.get_review(self.pub.proposal.proposal_id, self.reviewer)
        self.now += timedelta(hours=1)
        reopened = GovernanceStore(self.path, clock=lambda: self.now)
        repeated = reopened.publish_review(self.pub, self.worker)
        self.assertEqual(first, repeated)
        altered = self.pub.model_copy(deep=True)
        altered.proposal.diff = 'a new change'
        with self.assertRaisesRegex(LedgerError, 'immutable_review_conflict'):
            reopened.publish_review(altered, self.worker)
        self.assertEqual(len(reopened.history(self.pub.proposal.proposal_id, self.reviewer)), 1)

    def test_decision_is_authoritative_and_atomically_delivered_once_across_restart(self):
        value = self.decide()
        self.assertEqual(GovernedDecision.model_validate(value).actor, 'alice')
        self.assertFalse(value['simulation'])
        self.assertIsNone(value['execution_expires_at'])
        self.store = GovernanceStore(self.path, clock=lambda: self.now)
        self.now += timedelta(days=2)
        self.assertEqual(self.decide(), value)  # Replay returns history; grants no new authority.
        work = self.claim()[0]
        item = WorkItem.model_validate(work['work'])
        self.assertEqual(item.decision_id, value['decision_id'])
        self.assertEqual(item.kind, 'resume')
        self.assertNotIn('actor', work['work'])
        self.assertEqual(self.claim(), [])
        self.assertEqual([e['kind'] for e in self.store.history(self.pub.proposal.proposal_id, self.reviewer)],
                         ['review_published', 'decision_recorded', 'resume_claimed'])

    def test_conflicting_idempotency_and_second_decision_cannot_overwrite(self):
        first = self.decide()
        for changes, code in [({'kind':'acknowledge'}, 'idempotency_conflict'),
                              ({'note':'changed'}, 'idempotency_conflict'),
                              ({'idempotency_key':'different-request'}, 'review_not_open')]:
            with self.subTest(changes=changes), self.assertRaisesRegex(LedgerError, code):
                self.decide(**changes)
        self.assertEqual(self.store.get_decision(first['decision_id'], self.worker), first)

    def test_concurrent_identical_decisions_and_deliveries_are_deduplicated(self):
        with ThreadPoolExecutor(max_workers=4) as pool:
            results = list(pool.map(lambda _: self.decide(), range(8)))
        self.assertEqual(len({r['decision_id'] for r in results}), 1)
        with ThreadPoolExecutor(max_workers=4) as pool:
            claims = list(pool.map(lambda _: self.claim(), range(8)))
        self.assertEqual(sum(len(c) for c in claims), 1)

    def test_competing_reviewers_cannot_both_decide(self):
        bob = self.reviewer.model_copy(update={'actor':'bob'})
        def run(who):
            try:
                return self.store.record_decision(self.pub.proposal.proposal_id, self.decision, who)
            except LedgerError as error:
                return error.code
        with ThreadPoolExecutor(max_workers=2) as pool:
            results = list(pool.map(run, [self.reviewer, bob]))
        self.assertEqual(sum(isinstance(result, dict) for result in results), 1)
        self.assertIn('review_not_open', results)

    def test_wrong_revision_hash_expiry_and_unsupported_authority_fail_closed(self):
        for changes in ({'expected_revision':2}, {'expected_approval_hash':'forged'}):
            with self.assertRaisesRegex(LedgerError, 'review_revision_or_hash_changed'):
                self.decide(**changes)
        for kind in ('approve_remediation', 'adopt_baseline'):
            with self.assertRaisesRegex(LedgerError, 'governed_executor_unavailable'):
                self.decide(kind=kind, accept_residual_risk=True)
        with self.assertRaises(ValidationError):
            DecisionInput.model_validate({**self.decision.model_dump(), 'actor':'admin'})
        with self.assertRaises(ValidationError):
            DecisionInput.model_validate({**self.decision.model_dump(), 'authority':'standing_policy'})
        self.now += timedelta(days=1)
        with self.assertRaisesRegex(LedgerError, 'review_expired'):
            self.decide()
        history = self.store.history(self.pub.proposal.proposal_id, self.reviewer)
        self.assertEqual(history[-1]['kind'], 'review_expired')
        self.assertEqual(self.claim(), [])

    def test_server_clock_sets_review_deadline_and_replay_cannot_extend_it(self):
        record = self.store.get_review(self.pub.proposal.proposal_id, self.reviewer)
        self.assertEqual(datetime.fromisoformat(record['review_expires_at']), NOW + timedelta(hours=24))
        self.now += timedelta(hours=23)
        self.assertEqual(self.store.publish_review(self.pub, self.worker)['review_expires_at'], record['review_expires_at'])

    def test_service_self_review_and_wrong_scope_are_rejected(self):
        with self.assertRaises(HTTPException):
            self.store.record_decision(self.pub.proposal.proposal_id, self.decision, self.worker)
        wrong = principal('mallory','human','other',self.pub.proposal.target.namespace,['read','review'])
        for action in (lambda: self.store.get_review(self.pub.proposal.proposal_id, wrong),
                       lambda: self.store.record_decision(self.pub.proposal.proposal_id, self.decision, wrong)):
            with self.assertRaises(HTTPException) as error:
                action()
            self.assertEqual(error.exception.status_code, 403)

    def test_failed_transaction_cannot_leave_decision_without_delivery(self):
        with patch.object(self.store, 'event', side_effect=RuntimeError('simulated process failure')):
            with self.assertRaises(RuntimeError):
                self.decide()
        with sqlite3.connect(self.path) as db:
            self.assertEqual(db.execute('SELECT count(*) FROM decisions').fetchone()[0], 0)
            self.assertEqual(db.execute('SELECT count(*) FROM outbox').fetchone()[0], 0)
        self.assertEqual(self.store.get_review(self.pub.proposal.proposal_id, self.reviewer)['status'], 'OPEN')
        self.decide()
        self.assertEqual(len(self.claim()), 1)

    def test_process_exit_before_outbox_insert_cannot_commit_a_partial_decision(self):
        script = """
import os, sqlite3, sys
db = sqlite3.connect(sys.argv[1])
db.execute('BEGIN IMMEDIATE')
db.execute("UPDATE review_state SET status='RESOLVED' WHERE proposal_id=?", (sys.argv[2],))
db.execute('INSERT INTO decisions VALUES (?,?,?,?,?,?,?)', ('crashed',sys.argv[2],'alice','crash-key','hash','{}',''))
os._exit(17)
"""
        result = subprocess.run([sys.executable, '-c', script, str(self.path), self.pub.proposal.proposal_id],
                                capture_output=True, timeout=10)
        self.assertEqual(result.returncode, 17, result.stderr)
        self.store = GovernanceStore(self.path, clock=lambda: self.now)
        with sqlite3.connect(self.path) as db:
            self.assertEqual(db.execute('SELECT count(*) FROM decisions').fetchone()[0], 0)
            self.assertEqual(db.execute('SELECT count(*) FROM outbox').fetchone()[0], 0)
        self.assertEqual(self.store.get_review(self.pub.proposal.proposal_id, self.reviewer)['status'], 'OPEN')
        self.decide()
        self.assertEqual(len(self.claim()), 1)

    def test_clock_is_read_after_transaction_lock_before_accepting_decision(self):
        original = self.store.transaction
        @contextmanager
        def delayed():
            with original() as db:
                self.now += timedelta(days=1)
                yield db
        with patch.object(self.store, 'transaction', delayed):
            with self.assertRaisesRegex(LedgerError, 'review_expired'):
                self.decide()
        self.assertEqual(self.claim(), [])

    def test_delivery_expiry_and_fencing_prevent_old_ack_or_duplicate_claim(self):
        self.decide()
        old = self.claim(lease_seconds=10)[0]
        self.now += timedelta(seconds=10)
        with self.assertRaisesRegex(LedgerError, 'delivery_lease_expired'):
            self.store.acknowledge_delivery(old['delivery_id'], old['lease_token'], self.worker)
        new = self.claim()[0]
        self.assertEqual(old['work'], new['work'])
        self.assertEqual(new['attempt'], 2)
        with self.assertRaisesRegex(LedgerError, 'delivery_lease_mismatch'):
            self.store.acknowledge_delivery(old['delivery_id'], old['lease_token'], self.worker)
        result = self.store.acknowledge_delivery(new['delivery_id'], new['lease_token'], self.worker)
        self.assertEqual(result['status'], 'ACKED')
        self.assertEqual(self.store.acknowledge_delivery(new['delivery_id'], new['lease_token'], self.worker), result)
        self.assertEqual(self.claim(), [])

    def test_queue_backpressure_rolls_back_decision_without_losing_history(self):
        self.store.queue_capacity = 1
        self.decide()
        other = self.pub.model_copy(deep=True)
        other.proposal.proposal_id = 'other-proposal'
        other.proposal.case_id = other.report.case_id = 'other-case'
        other.proposal.run_id = other.report.run_id = 'other-run'
        self.store.publish_review(other, self.worker)
        request = self.decision.model_copy(update={'idempotency_key':'another-request'})
        with self.assertRaisesRegex(LedgerError, 'resume_queue_full'):
            self.store.record_decision(other.proposal.proposal_id, request, self.reviewer)
        self.assertEqual(self.store.get_review(other.proposal.proposal_id, self.reviewer)['status'], 'OPEN')

    def test_new_revision_preserves_old_review_and_decisions(self):
        successor = self.pub.model_copy(deep=True)
        successor.proposal.proposal_id = 'proposal-two'
        successor.proposal.revision = 2
        successor.proposal.run_id = successor.report.run_id = 'run-two'
        self.store.publish_review(successor, self.worker)
        old = self.store.get_review(self.pub.proposal.proposal_id, self.reviewer)
        self.assertEqual(old['status'], 'SUPERSEDED')
        self.assertEqual(old['proposal'], self.pub.proposal.model_dump(mode='json'))
        with self.assertRaisesRegex(LedgerError, 'review_not_open'):
            self.decide()

    def test_immutable_tables_reject_sql_update_and_delete(self):
        self.decide()
        with sqlite3.connect(self.path) as db:
            for table in ('reviews','decisions','events'):
                with self.subTest(table=table), self.assertRaisesRegex(sqlite3.IntegrityError, 'immutable_governance_record'):
                    db.execute('DELETE FROM '+table)

    def test_review_listing_and_history_are_bounded_without_losing_access_to_events(self):
        p = self.pub.proposal
        rows = self.store.list_reviews(p.target.cluster_id, p.target.namespace, self.reviewer)
        self.assertEqual(rows[0]['proposal_id'], p.proposal_id)
        self.assertNotIn('report', rows[0])
        with self.store.transaction() as db:
            for number in range(105):
                self.store.event(db, p.proposal_id, 'test_history', 'backend', self.now, number=number)
        first = self.store.history(p.proposal_id, self.reviewer)
        self.assertEqual(len(first), 100)
        rest = self.store.history(p.proposal_id, self.reviewer, after_sequence=first[-1]['sequence'])
        self.assertEqual(len(rest), 6)
        self.assertTrue(all(r['sequence'] > first[-1]['sequence'] for r in rest))

    def test_pause_and_incident_records_are_independent_and_operator_owned(self):
        p = self.pub.proposal
        for kind in ('pause', 'incident'):
            request = HoldInput(cluster_id=p.target.cluster_id, namespace=p.target.namespace,
                                kind=kind, active=True, reason='Investigating this namespace')
            with self.assertRaises(HTTPException):
                self.store.record_hold(request, self.worker)
            self.store.record_hold(request, self.reviewer)
        self.assertTrue(self.store.get_holds(p.target.cluster_id, p.target.namespace, self.worker)['incident'])
        self.store.record_hold(HoldInput(cluster_id=p.target.cluster_id, namespace=p.target.namespace,
            kind='pause', active=False, reason='Pause cleared by operator'), self.reviewer)
        current = self.store.get_holds(p.target.cluster_id, p.target.namespace, self.worker)
        self.assertFalse(current['pause'])
        self.assertTrue(current['incident'])
