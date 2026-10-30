import tempfile
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

from fastapi import FastAPI
from fastapi.testclient import TestClient

from backend.app.api.routes.governance import router
from backend.app.core.auth import Authenticator
from backend.app.core.body_limit import GovernanceBodyLimit, MAX_GOVERNANCE_BODY_BYTES
from backend.app.services.governance_store import GovernanceStore
from scripts.guardian_auth import issue, revoke
from tests.test_governance_store import NOW, principal, publication


class GovernanceApiTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.pub = publication()

    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        root = Path(self.directory.name)
        self.path = root / 'reviewers.auth.json'
        p = self.pub.proposal
        self.worker = principal('model-worker', 'service', p.target.cluster_id, p.target.namespace, ['read','publish','deliver'])
        self.reviewer = principal('alice', 'human', p.target.cluster_id, p.target.namespace, ['read','review','operate'])
        self.worker_token = issue(self.path, self.worker)
        self.reviewer_token = issue(self.path, self.reviewer)
        self.app = FastAPI()
        self.app.add_middleware(GovernanceBodyLimit)
        self.app.state.authenticator = Authenticator(self.path)
        self.app.state.governance = GovernanceStore(root/'ledger.sqlite3', clock=lambda: NOW)
        self.app.state.k8s = MagicMock()
        self.app.include_router(router)
        self.client = TestClient(self.app)
        self.url = '/governance/reviews/'+p.proposal_id
        self.request = {'kind':'reject','expected_revision':p.revision,'expected_approval_hash':p.approval_hash,
                        'idempotency_key':'api-request-one'}

    def headers(self, token=None):
        return {'Authorization':'Bearer '+(token or self.reviewer_token)}

    def publish(self):
        return self.client.post('/governance/reviews', json=self.pub.model_dump(mode='json'),
                                headers=self.headers(self.worker_token))

    def test_all_governance_surfaces_require_authentication(self):
        requests = [('get','/governance/me',None), ('get',self.url,None),
                    ('get','/governance/reviews?cluster_id=x&namespace=y',None),
                    ('get',self.url+'/history',None), ('get','/governance/decisions/unknown',None),
                    ('post',self.url+'/decisions',self.request),
                    ('post','/governance/reviews',self.pub.model_dump(mode='json')),
                    ('post','/governance/holds',{'cluster_id':'x','namespace':'y','kind':'pause','active':True,'reason':'test'}),
                    ('post','/governance/deliveries/claim',{'cluster_id':'x','namespace':'y'}),
                    ('post','/governance/deliveries/d/ack',{'lease_token':'t'})]
        for method, url, body in requests:
            with self.subTest(url=url):
                kwargs = {'json':body} if body else {}
                response = getattr(self.client, method)(url, **kwargs)
                self.assertEqual(response.status_code, 401, response.text)

    def test_authenticated_publication_review_and_delivery_workflow(self):
        response = self.publish()
        self.assertEqual(response.status_code, 200, response.text)
        self.assertFalse(response.json()['execution_available'])
        self.assertEqual(self.client.get(self.url, headers=self.headers()).json()['schema_version'], 'guardian.review-record.v1')
        decision = self.client.post(self.url+'/decisions',json=self.request,headers=self.headers())
        self.assertEqual(decision.status_code, 200, decision.text)
        value = decision.json()
        self.assertEqual(value['actor'], 'alice')
        self.assertEqual(value['authority'], 'human')
        self.assertEqual(self.client.post(self.url+'/decisions',json=self.request,headers=self.headers()).json(), value)
        p = self.pub.proposal
        response = self.client.post('/governance/deliveries/claim',headers=self.headers(self.worker_token),
            json={'cluster_id':p.target.cluster_id,'namespace':p.target.namespace})
        delivery = response.json()['deliveries'][0]
        self.assertEqual(delivery['work']['decision_id'], value['decision_id'])
        ack = self.client.post('/governance/deliveries/'+delivery['delivery_id']+'/ack',
            headers=self.headers(self.worker_token),json={'lease_token':delivery['lease_token']})
        self.assertEqual(ack.json()['status'], 'ACKED')
        self.assertEqual(self.client.get('/governance/decisions/'+value['decision_id'], headers=self.headers()).json(), value)
        self.assertEqual(self.app.state.k8s.mock_calls, [])

    def test_body_cannot_supply_actor_authority_deadline_or_recovery_consent(self):
        self.publish()
        for key, value in [('actor','admin'), ('authority','standing_policy'),
                           ('execution_expires_at','2099-01-01T00:00:00Z'), ('recovery_authorized',True)]:
            response = self.client.post(self.url+'/decisions', json={**self.request,key:value}, headers=self.headers())
            self.assertEqual(response.status_code, 422, response.text)
        for kind in ('approve_remediation','adopt_baseline'):
            response = self.client.post(self.url+'/decisions',json={**self.request,'kind':kind,'accept_residual_risk':True},headers=self.headers())
            self.assertEqual(response.status_code, 503)
            self.assertEqual(response.json()['detail'], 'governed_executor_unavailable')
        self.assertEqual(self.app.state.k8s.mock_calls, [])

    def test_credentials_cannot_cross_scope_or_self_approve(self):
        self.publish()
        response = self.client.post(self.url+'/decisions',json=self.request,headers=self.headers(self.worker_token))
        self.assertEqual(response.status_code, 403)
        response = self.client.post('/governance/reviews',json=self.pub.model_dump(mode='json'),headers=self.headers())
        self.assertEqual(response.status_code, 403)
        outsider = issue(self.path, principal('other','human','other-cluster','other-namespace',['read','review']))
        self.assertEqual(self.client.get(self.url,headers=self.headers(outsider)).status_code, 403)
        self.assertEqual(self.client.post(self.url+'/decisions',json=self.request,headers=self.headers(outsider)).status_code, 403)

    def test_cli_issued_registry_contains_only_digests_and_revokes_immediately(self):
        self.assertNotIn(self.reviewer_token, self.path.read_text())
        self.assertEqual(self.path.stat().st_mode & 0o777, 0o600)
        self.assertEqual(self.client.get('/governance/me',headers=self.headers()).status_code, 200)
        import hashlib
        self.assertTrue(revoke(self.path, hashlib.sha256(self.reviewer_token.encode()).hexdigest()))
        self.assertEqual(self.client.get('/governance/me',headers=self.headers()).status_code, 401)

    def test_failed_registry_update_preserves_existing_credentials(self):
        before = self.path.read_bytes()
        with patch('scripts.guardian_auth.MAX_REGISTRY_BYTES', 1):
            with self.assertRaisesRegex(ValueError, 'credential_registry_too_large'):
                issue(self.path, self.reviewer)
        self.assertEqual(self.path.read_bytes(), before)
        self.assertEqual(self.client.get('/governance/me',headers=self.headers()).status_code, 200)

    def test_storage_failure_is_closed_and_does_not_expose_database_details(self):
        import sqlite3
        self.publish()
        with patch.object(self.app.state.governance,'record_decision',side_effect=sqlite3.OperationalError('/private/db/path')):
            result = self.client.post(self.url+'/decisions',json=self.request,headers=self.headers())
        self.assertEqual(result.status_code, 503)
        self.assertNotIn('/private', result.text)

    def test_oversized_body_is_rejected_before_json_parsing_with_or_without_content_length(self):
        for content in (b'x' * (MAX_GOVERNANCE_BODY_BYTES + 1),
                        iter([b'x' * MAX_GOVERNANCE_BODY_BYTES, b'x'])):
            response = self.client.post('/governance/reviews', content=content, headers=self.headers(self.worker_token))
            self.assertEqual(response.status_code, 413)
            self.assertEqual(response.json()['detail'], 'governance_body_too_large')
