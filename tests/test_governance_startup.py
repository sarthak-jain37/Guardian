import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

from fastapi.testclient import TestClient


class GovernanceStartupTests(unittest.TestCase):
    def test_actual_application_startup_captures_observation_without_adopting_legacy_state(self):
        with patch('logging.basicConfig'):
            from backend.app import main
        observed = {'r': {'kind': 'Role', 'metadata': {'name':'r','namespace':'demo'}, 'rules':[]}}
        redis = AsyncMock()
        k8s = MagicMock()
        k8s.get_rbac_state.return_value = observed
        telemetry = MagicMock()
        telemetry.start.return_value = []
        grader = MagicMock()
        grader.run = AsyncMock()
        proposals = MagicMock()
        proposals.recover_interrupted = AsyncMock()
        proposals.tasks = set()
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'governance.sqlite3'
            with patch.dict(os.environ, {'GUARDIAN_GOVERNANCE_DB':str(path), 'GUARDIAN_AUTH_FILE':''}), \
                 patch.object(main.Redis, 'from_url', return_value=redis), \
                 patch.object(main, 'KubernetesService', return_value=k8s), \
                 patch.object(main, 'Telemetry', return_value=telemetry), \
                 patch.object(main, 'PodGrader', return_value=grader), \
                 patch.object(main, 'refresh_inventory', new=AsyncMock()), \
                 patch.object(main, 'run_pipeline', new=AsyncMock()), \
                 patch('backend.app.services.permission_proposals.PermissionProposals', return_value=proposals):
                with TestClient(main.app) as client:
                    self.assertFalse(client.get('/').json()['execution_enabled'])
                    self.assertEqual(client.get('/governance/me').status_code, 401)
                    self.assertTrue(path.exists())
            self.assertEqual(redis.hset.await_count, 0)
            redis.delete.assert_not_awaited()
            snapshots = [call for call in redis.set.await_args_list if call.args[0] == 'rbac:current']
            self.assertEqual(len(snapshots), 1)
            self.assertEqual(json.loads(snapshots[0].args[1]), observed)
            k8s.apply_state.assert_not_called()
            k8s.revert_to_baseline.assert_not_called()
            self.assertEqual(main.app.state.governance.execution_available, False)
