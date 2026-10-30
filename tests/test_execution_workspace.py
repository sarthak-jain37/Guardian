"""Actual Streamlit action consent controls against authenticated backend state."""
import unittest
from unittest.mock import patch
from streamlit.testing.v1 import AppTest
import tests.test_execution as execution_fixture
import tests.test_review_workspace as review_fixture


class ExecutionWorkspaceTests(unittest.TestCase):
    intake=execution_fixture.ExecutionTests.intake
    queued=execution_fixture.ExecutionTests.queued
    run_job=execution_fixture.ExecutionTests.run_job
    prepared=execution_fixture.ExecutionTests.prepared
    advance=execution_fixture.ExecutionTests.advance
    request=review_fixture.ReviewWorkspaceTests.request
    setUp=execution_fixture.ExecutionTests.setUp

    def open(self):
        app=AppTest.from_string('from frontend.analysis_workspace import workspace\nworkspace()')
        app.run();app.text_input[0].set_value(self.human_token).run()
        self.assertFalse(app.exception)
        self.assertFalse(app.error)
        return app

    def button(self,app,label):return next(b for b in app.button if b.label==label)
    def checkbox(self,app,label):return next(c for c in app.checkbox if c.label==label)

    def test_risk_and_recovery_are_separate_unchecked_choices_and_outcome_ack_keeps_monitoring(self):
        run,review=self.prepared()
        with patch('frontend.review_client.requests.request',side_effect=self.request):
            app=self.open()
            risk=self.checkbox(app,'I accept the stated residual risks for this exact action')
            recovery=self.checkbox(app,'Separately authorize one exact recovery if its stated conditions pass')
            self.assertFalse(risk.value);self.assertFalse(recovery.value)
            self.button(app,'Record governed decision').click().run()
            self.assertTrue(any('Accept the stated residual risks' in e.value for e in app.error))
            self.assertIsNone(self.execution.review_detail(review['proposal_id'],self.human)['decision'])
            self.checkbox(app,'I accept the stated residual risks for this exact action').check()
            self.button(app,'Record governed decision').click().run()
            self.assertFalse(app.exception);self.assertFalse(app.error)
            decision=self.execution.review_detail(review['proposal_id'],self.human)['decision']
            self.assertEqual(decision['actor'],'alice');self.assertIsNone(decision['recovery_authority_id'])
            self.assertEqual(self.driver.applies,[])
            self.execution.execute_next()
            self.button(app,'Refresh reports').click().run()
            self.assertTrue(any('completed' in m.value and 'Outcome' in m.value for m in app.markdown))
            self.button(app,'Acknowledge outcome').click().run()
            self.assertTrue(self.execution.notifications('lab','guardian-demo',self.human)[0]['acknowledged'])
            self.assertFalse(self.db.get_holds('lab','guardian-demo',self.human)['pause'])
        self.assertEqual(len(self.driver.applies),1)
        self.assertEqual(self.analysis.get(run['run_id'],self.human)['report'],run['report'])

    def test_explicit_recovery_consent_reaches_backend_and_verified_rollback_display(self):
        run,review=self.prepared()
        with patch('frontend.review_client.requests.request',side_effect=self.request):
            app=self.open()
            self.checkbox(app,'I accept the stated residual risks for this exact action').check()
            self.checkbox(app,'Separately authorize one exact recovery if its stated conditions pass').check()
            self.button(app,'Record governed decision').click().run()
            self.assertFalse(app.exception);self.assertFalse(app.error)
            decision=self.execution.review_detail(review['proposal_id'],self.human)['decision']
            self.assertIsNotNone(decision['recovery_authority_id'])
            self.verifier.fail_post=True;self.execution.execute_next()
            self.button(app,'Refresh reports').click().run()
            self.assertFalse(app.exception)
            self.assertTrue(any('rolled_back' in m.value and 'Outcome' in m.value for m in app.markdown))
            self.assertTrue(any('restored under your recovery authorization' in m.value for m in app.markdown))
        self.assertEqual(len(self.driver.applies),2)

    def test_disabled_executor_explains_capability_and_offers_no_positive_action(self):
        run,review=self.prepared()
        self.execution.policy=self.execution.policy.model_copy(update={'enabled':False})
        with patch('frontend.review_client.requests.request',side_effect=self.request):
            app=self.open()
            self.assertTrue(any('Execution is disabled' in m.value for m in app.info))
            actions=next(s for s in app.selectbox if s.label=='Governed review action')
            self.assertNotIn('Approve exact Role change',actions.options)
            self.assertFalse(any(b.label=='Queue independent readiness checks' for b in app.button))
        self.assertEqual(self.driver.applies,[])

    def test_approval_pending_and_stopped_outcome_are_explicit(self):
        run,review=self.prepared()
        with patch('frontend.review_client.requests.request',side_effect=self.request):
            app=self.open()
            self.checkbox(app,'I accept the stated residual risks for this exact action').check()
            self.button(app,'Record governed decision').click().run()
            self.assertTrue(any('completion is not confirmed yet' in m.value for m in app.info))
            self.advance(301)
            self.execution.execute_next()
            self.button(app,'Refresh execution status').click().run()
            self.assertFalse(app.exception)
            self.assertTrue(any('was not applied' in m.value and 'execution_start_deadline_expired' in m.value for m in app.error))
            self.assertEqual(self.driver.applies,[])

    def test_governed_context_links_to_queued_successor_analysis(self):
        run,review=self.prepared()
        with patch('frontend.review_client.requests.request',side_effect=self.request):
            app=self.open()
            next(s for s in app.selectbox if s.label=='Governed review action').select('request_context')
            next(t for t in app.text_area if t.label=='Governed review note').set_value('Please recheck the observed pod reads.')
            self.button(app,'Record governed decision').click().run()
            self.execution.execute_next()
            self.button(app,'Refresh reports').click().run()
            successor=self.execution.review_detail(review['proposal_id'],self.human)['context_successor_run_id']
            self.assertIsNotNone(successor)
            self.button(app,'Open revised analysis').click().run()
            self.assertFalse(app.exception);self.assertFalse(app.error)
            self.assertTrue(any(successor in c.value for c in app.caption))
            self.assertEqual(self.driver.applies,[])
