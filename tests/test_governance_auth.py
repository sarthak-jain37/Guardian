import hashlib
import json
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

from fastapi import FastAPI, HTTPException
from fastapi.testclient import TestClient
from pydantic import ValidationError

from backend.app.core.auth import Authenticated, Authenticator, Principal


class AuthenticationTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.path = Path(self.directory.name) / 'auth.json'
        self.token = 'test-credential-' + 'a' * 40
        self.principal = {'actor': 'alice', 'kind': 'human', 'grants': [
            {'cluster_id': 'lab', 'namespace': 'demo', 'permissions': ['read', 'review']}]}
        self.registry = {'schema_version': 'guardian.auth.v1', 'credentials': [{
            'token_sha256': hashlib.sha256(self.token.encode()).hexdigest(), 'principal': self.principal,
            'expires_at': (datetime.now(timezone.utc) + timedelta(hours=1)).isoformat()}]}
        self.write()
        app = FastAPI()
        app.state.authenticator = Authenticator(self.path)
        @app.get('/review')
        def review(principal: Authenticated):
            principal.require('review', 'lab', 'demo')
            return {'actor': principal.actor}
        self.app = app
        self.client = TestClient(app)

    def write(self):
        self.path.write_text(json.dumps(self.registry))

    def request(self, token=None):
        return self.client.get('/review', headers={'Authorization': 'Bearer ' + (token or self.token)})

    def test_authentication_is_required_and_actor_is_server_derived(self):
        self.assertEqual(self.client.get('/review?actor=admin').status_code, 401)
        self.assertEqual(self.request('wrong-token-' + 'x' * 40).status_code, 401)
        self.assertEqual(self.request().json(), {'actor': 'alice'})

    def test_expiry_revocation_and_scope_change_take_effect_without_restart(self):
        self.registry['credentials'][0]['expires_at'] = (datetime.now(timezone.utc) - timedelta(seconds=1)).isoformat()
        self.write()
        self.assertEqual(self.request().status_code, 401)
        self.registry['credentials'][0]['expires_at'] = (datetime.now(timezone.utc) + timedelta(hours=1)).isoformat()
        self.registry['credentials'][0]['principal']['grants'][0]['namespace'] = 'other'
        self.write()
        self.assertEqual(self.request().status_code, 403)
        self.registry['credentials'] = []
        self.write()
        self.assertEqual(self.request().status_code, 401)

    def test_missing_or_corrupt_registry_never_opens_access(self):
        self.path.write_text('{')
        self.assertEqual(self.request().status_code, 503)
        self.path.unlink()
        self.assertEqual(self.request().status_code, 503)
        self.app.state.authenticator = None
        self.assertEqual(self.request().status_code, 503)

    def test_service_identity_cannot_be_configured_as_reviewer_or_operator(self):
        for permission in ('review', 'operate'):
            value = {**self.principal, 'kind': 'service', 'grants': [
                {'cluster_id': 'lab', 'namespace': 'demo', 'permissions': [permission]}]}
            with self.assertRaises(ValidationError):
                Principal.model_validate(value)
        with self.assertRaises(ValidationError):
            Principal.model_validate({**self.principal, 'grants': [
                {'cluster_id': '*', 'namespace': 'demo', 'permissions': ['review']}]})

    def test_scope_is_exact_and_does_not_imply_other_permissions(self):
        principal = Principal.model_validate(self.principal)
        for permission, cluster, namespace in [('operate','lab','demo'), ('review','other','demo'), ('review','lab','other')]:
            with self.assertRaises(HTTPException) as error:
                principal.require(permission, cluster, namespace)
            self.assertEqual(error.exception.status_code, 403)
