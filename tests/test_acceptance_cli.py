import json
import unittest
from pathlib import Path
from unittest.mock import Mock,patch
from scripts.guardian_acceptance import run
import tests.test_execution as fixture


class AcceptanceCliTests(unittest.TestCase):
    setUp=fixture.ExecutionTests.setUp
    intake=fixture.ExecutionTests.intake
    queued=fixture.ExecutionTests.queued
    run_job=fixture.ExecutionTests.run_job
    prepared=fixture.ExecutionTests.prepared
    approve=fixture.ExecutionTests.approve
    execute=fixture.ExecutionTests.execute
    advance=fixture.ExecutionTests.advance

    def test_resume_reports_completed_action_without_creating_or_approving_another(self):
        source,review=self.prepared();decision=self.approve(review)
        self.assertEqual(self.execute(review,decision).phase,'completed')
        directory=Path(self.temp.name)/'cli';directory.mkdir()
        (directory/'intake.json').write_text(json.dumps(source))
        (directory/'review.json').write_text(json.dumps(review))
        token=Path(self.temp.name)/'token';token.write_text(self.human_token)
        session=Mock();session.headers={}
        def request(method,url,json=None,**kwargs):
            path='/'+url.split('/',3)[3]
            if path=='/ready':
                response=Mock();response.json.return_value={'ready':True,'execution_enabled':True};return response
            return self.client.request(method,path,json=json,headers=session.headers)
        session.request.side_effect=request
        with patch('scripts.guardian_acceptance.requests.Session',return_value=session):
            result=run('http://backend',token,directory,resume=True,follow_approval=True,cluster='lab',role='reader')
        self.assertTrue(result['human_approval_recorded']);self.assertTrue(result['target_writes_by_guardian'])
        self.assertTrue(result['live_execution_verified']);self.assertEqual(result['execution_receipt']['phase'],'completed')
        self.assertTrue(all(call.args[0]=='GET' for call in session.request.call_args_list))
        self.assertEqual(len(self.driver.applies),1)
