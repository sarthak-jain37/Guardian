import sys
import unittest
from datetime import datetime, timezone
from unittest.mock import AsyncMock, MagicMock, patch

# Mock agents.summarizer if llama_cpp is not installed in the environment
if "agents.summarizer" not in sys.modules:
    mock_summarizer = MagicMock()
    mock_summarizer.analyse_document = MagicMock(return_value="mock analysis")
    sys.modules["agents.summarizer"] = mock_summarizer

from backend.app.services.event_processor import process_events


class TestEventProcessorIntegration(unittest.TestCase):

    @patch("backend.app.services.event_processor.get_latest_event_timestamp")
    @patch("backend.app.services.event_processor.get_last_processed_timestamp")
    @patch("backend.app.services.event_processor.run_apply_script")
    @patch("backend.app.services.event_processor.save_rbac_state")
    @patch("backend.app.services.event_processor.set_last_processed_timestamp")
    @patch("backend.app.services.event_processor.scan_dangerous_permissions")
    @patch("backend.app.services.event_processor.save_dangerous_permissions")
    async def _run_apply_event_test(
        self,
        mock_save_danger,
        mock_scan_danger,
        mock_set_last,
        mock_save_rbac,
        mock_run_apply,
        mock_get_last,
        mock_get_latest,
    ):
        mock_redis = MagicMock()
        mock_k8s = MagicMock()

        # Simulate a new apply event
        apply_time = datetime(2026, 9, 10, 10, 0, tzinfo=timezone.utc)
        mock_get_latest.side_effect = lambda data, fields: apply_time if "apply" in fields[0] else None
        mock_get_last.return_value = None 

        fake_baseline = {"Role_default_admin": {"kind": "Role", "metadata": {"name": "admin"}, "rules": []}}
        mock_run_apply.return_value = fake_baseline
        mock_scan_danger.return_value = [{"role_name": "admin", "severity": "CRITICAL"}]

        await process_events({}, mock_redis, mock_k8s)

        mock_run_apply.assert_called_once_with(mock_k8s)
        mock_scan_danger.assert_called_once_with(fake_baseline)
        mock_save_danger.assert_called_once_with(mock_scan_danger.return_value, mock_redis)

    def test_apply_event_triggers_scan(self):
        import asyncio
        asyncio.run(self._run_apply_event_test())

    @patch("backend.app.services.event_processor.get_latest_event_timestamp")
    @patch("backend.app.services.event_processor.get_last_processed_timestamp")
    @patch("backend.app.services.event_processor.get_rbac_state")
    @patch("backend.app.services.event_processor.run_modify_script")
    @patch("backend.app.services.event_processor.save_rbac_state")
    @patch("backend.app.services.event_processor.set_last_processed_timestamp")
    @patch("backend.app.services.event_processor.scan_dangerous_permissions")
    @patch("backend.app.services.event_processor.save_dangerous_permissions")
    async def _run_modify_event_test(
        self,
        mock_save_danger,
        mock_scan_danger,
        mock_set_last,
        mock_save_rbac,
        mock_run_modify,
        mock_get_rbac,
        mock_get_last,
        mock_get_latest,
    ):
        mock_redis = MagicMock()
        mock_k8s = MagicMock()

        # Simulate a new modify event
        modify_time = datetime(2026, 9, 10, 10, 0, tzinfo=timezone.utc)
        mock_get_latest.side_effect = lambda data, fields: modify_time if "edit" in fields[0] else None
        mock_get_last.return_value = None

        fake_current = {"Role_default_mod": {"kind": "Role", "metadata": {"name": "mod"}, "rules": []}}
        mock_run_modify.return_value = (fake_current, {})
        mock_scan_danger.return_value = []

        await process_events({}, mock_redis, mock_k8s)

        mock_scan_danger.assert_called_once_with(fake_current)
        mock_save_danger.assert_called_once_with([], mock_redis)

    def test_modify_event_triggers_scan(self):
        import asyncio
        asyncio.run(self._run_modify_event_test())

    @patch("backend.app.services.event_processor.get_latest_event_timestamp")
    @patch("backend.app.services.event_processor.get_last_processed_timestamp")
    @patch("backend.app.services.event_processor.scan_dangerous_permissions")
    async def _run_no_event_test(
        self,
        mock_scan_danger,
        mock_get_last,
        mock_get_latest,
    ):
        mock_redis = MagicMock()
        mock_k8s = MagicMock()

        # No events
        mock_get_latest.return_value = None
        mock_get_last.return_value = None

        await process_events({}, mock_redis, mock_k8s)

        mock_scan_danger.assert_not_called()

    def test_no_event_does_not_trigger_scan(self):
        import asyncio
        asyncio.run(self._run_no_event_test())


if __name__ == "__main__":
    unittest.main()
