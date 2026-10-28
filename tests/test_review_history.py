import unittest
from backend.app.services.pod_review import summarize_history

class HistoryTests(unittest.TestCase):
    def test_all_events_counted_and_lifecycle_separate(self):
        record={'events':[{'id':str(i),'kind':'network','verdict':'FORWARDED','timestamp':'2026-10-29T00:00:00Z'} for i in range(25)],
                'shared_identity_audit_events':[{'id':'shared'}],
                'actions_affecting_pod':[{'verb':'delete','actor':'human'}]}
        summary=summarize_history(record)
        self.assertEqual(summary['attributed_observations'],25)
        self.assertEqual(summary['network_outcomes'],{'FORWARDED':25})
        self.assertEqual(summary['actions_affecting_pod'],{'delete by human':1})
        self.assertEqual(summary['shared_identity_observations'],1)
