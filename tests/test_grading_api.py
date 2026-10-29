import unittest
from unittest.mock import AsyncMock, patch
from fastapi import FastAPI
from fastapi.testclient import TestClient
from backend.app.api.routes.telemetry import router


class GradingAPITests(unittest.TestCase):
    def setUp(self):
        app=FastAPI();app.include_router(router)
        self.grader=AsyncMock();self.grader.health={'enabled':True,'state':'waiting'}
        app.state.pod_grader=self.grader
        self.permissions=AsyncMock();app.state.permission_proposals=self.permissions
        app.state.telemetry=AsyncMock()
        self.client=TestClient(app)

    def test_alert_unread_count_and_namespace(self):
        self.grader.records.return_value=[{'active':True,'acknowledged':False},{'active':True,'acknowledged':True},{'active':False,'acknowledged':False}]
        result=self.client.get('/telemetry/alerts?namespace=app')
        self.assertEqual(result.json()['unread'],1)
        self.grader.records.assert_awaited_once_with('alerts','app')

    def test_ack_conflict_missing_and_success(self):
        self.grader.acknowledge.side_effect=ValueError('Alert changed')
        self.assertEqual(self.client.post('/telemetry/alerts/u/acknowledge',json={'version':1}).status_code,409)
        self.grader.acknowledge.side_effect=None
        self.grader.acknowledge.return_value=None
        self.assertEqual(self.client.post('/telemetry/alerts/u/acknowledge',json={'version':1}).status_code,404)
        self.grader.acknowledge.return_value={'acknowledged':True}
        self.assertTrue(self.client.post('/telemetry/alerts/u/acknowledge',json={'version':1}).json()['acknowledged'])
        self.assertEqual(self.client.post('/telemetry/alerts/u/acknowledge',json={'version':0}).status_code,422)

    def test_manual_review_uses_same_grading_path(self):
        self.grader.review.return_value={'status':'assessed','severity':8,'reasons':['Investigate'],'uncertainty':'Uncertain','evidence_ids':['id']}
        with patch('backend.app.api.routes.telemetry.review_context',new=AsyncMock(return_value={'pod':{},'events':[]})):
            result=self.client.post('/telemetry/pods/app/client/review',json={'event_limit':8,'question':'Explain this pod'})
        self.assertEqual(result.status_code,200)
        self.assertEqual(result.json()['severity'],8)
        self.grader.review.assert_awaited_once()
        self.assertTrue(self.grader.review.call_args.kwargs['force'])
        self.assertEqual(self.grader.review.call_args.args[0]['operator_question'],'Explain this pod')

    def test_permission_decisions_require_the_new_governance_boundary(self):
        for decision in ('apply', 'reject', 'accept'):
            response=self.client.post('/telemetry/permission-proposals/id/decision',json={
                'decision':decision,'actor':'operator','note':'Keep current grants'})
            self.assertEqual(response.status_code,410)
        self.permissions.decide.assert_not_awaited()

    def test_retired_route_cannot_reach_legacy_service_even_when_it_would_fail(self):
        self.permissions.decide.side_effect=ValueError('Already decided')
        response=self.client.post('/telemetry/permission-proposals/id/decision',json={'decision':'accept','actor':'operator'})
        self.assertEqual(response.status_code,410)
        self.permissions.decide.assert_not_awaited()
