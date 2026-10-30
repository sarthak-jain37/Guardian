import tempfile
import unittest
from pathlib import Path
from unittest.mock import MagicMock
from fastapi import FastAPI
from fastapi.testclient import TestClient
from backend.app.api.routes.evidence import router
from backend.app.core.auth import Authenticator, Principal
from scripts.guardian_auth import issue
from backend.app.models.evidence import UsageQuery
from contracts.usage_summary_v1 import Window
from tests.test_usage_store import START,subject,key
import tests.test_usage_store as fixture


class EvidenceApiTests(unittest.TestCase):
    setUp=fixture.UsageTests.setUp

    def client(self,namespace='guardian-demo'):
        app=FastAPI();app.include_router(router);app.state.usage=self.store;app.state.evidence_archive=None
        app.state.evidence_inventory=MagicMock()
        principal=Principal(actor='reader',kind='human',grants=[{'cluster_id':'lab','namespace':namespace,'permissions':['read']}])
        path=Path(self.temp.name)/'auth.json';token=issue(path,principal)
        app.state.authenticator=Authenticator(path)
        return TestClient(app),{'Authorization':'Bearer '+token},app

    def payload(self):
        return UsageQuery(cluster_id='lab',namespace='guardian-demo',subject=subject(),
            window=Window(start=START,end=self.now),keys={'pods':key()}).model_dump(mode='json')

    def test_evidence_queries_require_authentication_and_exact_namespace(self):
        client,headers,app=self.client('other')
        self.assertEqual(client.post('/evidence/usage',json=self.payload()).status_code,401)
        self.assertEqual(client.post('/evidence/usage',json=self.payload(),headers=headers).status_code,403)
        app.state.evidence_inventory.load.assert_not_called()

    def test_missing_archive_is_explicit_and_usage_is_strict_contract(self):
        client,headers,app=self.client()
        response=client.post('/evidence/usage',json=self.payload(),headers=headers)
        self.assertEqual(response.status_code,200,response.text)
        self.assertEqual(response.json()['schema_version'],'guardian.usage-summary.v1')
        self.assertEqual(client.post('/evidence/archive-query',json=self.payload(),headers=headers).status_code,503)
