import unittest
from backend.app.services.pod_review import event_result


class EventResultTests(unittest.TestCase):
    def test_execution_does_not_claim_completion(self):
        self.assertEqual(event_result({'kind': 'process_exec'}), 'Execution observed')

    def test_zero_exit_status_is_preserved(self):
        self.assertEqual(event_result({'kind': 'process_exit', 'status': 0}), 'Exit status: 0')

    def test_exit_signal_and_missing_status(self):
        self.assertEqual(event_result({'kind': 'process_exit', 'signal': 'SIGKILL'}), 'Signal: SIGKILL')
        self.assertEqual(event_result({'kind': 'process_exit'}), 'Exit observed; status not captured')

    def test_kernel_return_values_are_not_generalized_as_success(self):
        for value in (0, -13, 7):
            event = {'kind': 'process_kprobe', 'runtime': {'return_value': {'int_arg': value}}}
            self.assertEqual(event_result(event), 'Kernel return value: ' + str(value))

    def test_missing_return_is_explicit(self):
        self.assertEqual(event_result({'kind': 'process_kprobe', 'runtime': {}}), 'Outcome not captured')

    def test_existing_network_and_api_results(self):
        self.assertEqual(event_result({'kind': 'network', 'verdict': 'DROPPED'}), 'DROPPED')
        self.assertEqual(event_result({'kind': 'kubernetes_audit', 'outcome': 'denied'}), 'denied')
