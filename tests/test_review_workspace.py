"""Run the actual Streamlit review controls against the real scoped ASGI API."""
import unittest
from unittest.mock import patch
from streamlit.testing.v1 import AppTest
import tests.test_analysis as fixture


class ReviewWorkspaceTests(unittest.TestCase):
    def setUp(self):
        fixture.AnalysisTests.setUp(self)
        from backend.app.api.routes.governance import router
        self.client.app.include_router(router)
        self.client.app.state.k8s=self.k8s
        self.client.app.state.usage=self.store
    intake=fixture.AnalysisTests.intake
    queued=fixture.AnalysisTests.queued
    run_job=fixture.AnalysisTests.run_job

    def request(self,method,url,params=None,json=None,headers=None,**kwargs):
        path='/'+url.split('/',3)[3]
        return self.client.request(method,path,params=params,json=json,headers=headers)

    def test_authenticated_report_controls_record_server_identity_without_legacy_monitoring(self):
        run,job=self.run_job()
        app=AppTest.from_string('from frontend.analysis_workspace import workspace\nworkspace()')
        with patch('frontend.review_client.requests.request',side_effect=self.request):
            app.run();self.assertFalse(app.exception)
            self.assertEqual(len(app.selectbox),0)
            app.text_input[0].set_value(self.human_token).run()
            self.assertFalse(app.exception)
            approve=[b for b in app.button if b.label.startswith('Approve')]
            self.assertEqual(len(approve),0)
            self.assertTrue(any('Actual query window' in m.value for m in app.markdown))
            action=[s for s in app.selectbox if s.label=='Review action'][0]
            action.select('acknowledge')
            submit=[b for b in app.button if b.label=='Record my review'][0]
            submit.click().run()
            self.assertFalse(app.exception)
        saved=self.analysis.get(run['run_id'],self.human)
        self.assertEqual(saved['decision']['actor'],'alice')
        self.assertEqual(saved['decision']['kind'],'acknowledge')
        self.assertFalse(saved['decision']['execution_authorized'])

    def test_scope_failure_is_shown_and_never_reads_another_namespace_report(self):
        app=AppTest.from_string('from frontend.analysis_workspace import workspace\nworkspace()')
        with patch('frontend.review_client.requests.request',side_effect=self.request):
            app.run();app.text_input[0].set_value('invalid-token-value-with-enough-characters').run()
            self.assertFalse(app.exception);self.assertEqual(len(app.error),1)
            self.assertIn('401',app.error[0].value)

    def test_analyse_again_uses_collector_watermark_instead_of_uncovered_now(self):
        from datetime import timedelta
        run,job=self.run_job();self.now+=timedelta(seconds=30)
        app=AppTest.from_string('from frontend.analysis_workspace import workspace\nworkspace()')
        with patch('frontend.review_client.requests.request',side_effect=self.request):
            app.run();app.text_input[0].set_value(self.human_token).run()
            next(b for b in app.button if b.label=='Capture fresh evidence and analyse again').click().run()
            self.assertFalse(app.exception);self.assertFalse(app.error)
        latest=self.analysis.list('lab','guardian-demo',self.human)[0]
        successor=self.analysis.get(latest['run_id'],self.human)
        self.assertEqual(successor['revision'],2)
        self.assertEqual(successor['intake']['window']['end'],run['intake']['window']['end'])
