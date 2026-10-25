import json
import re
import unittest
from unittest.mock import patch
from frontend.graph_view import render_graph, safe_graph_json


class GraphViewTests(unittest.TestCase):
    def test_telemetry_strings_cannot_close_the_script(self):
        payload={'label':'</script><img src=x onerror=alert(1)> & text'}
        encoded=safe_graph_json(payload)
        self.assertNotIn('<',encoded)
        self.assertEqual(json.loads(encoded),payload)

    @patch('frontend.graph_view.st.iframe')
    def test_pod_graph_only_contains_exact_pod_and_neighbors(self,iframe):
        graph={'nodes':[{'id':'a','namespace':'app','pod':'client'}, {'id':'b','namespace':'app','pod':'server'}, {'id':'c','namespace':'other','pod':'client'}, {'id':'d','namespace':'other','pod':'server'}], 'edges':[{'source':'a','target':'b'},{'source':'c','target':'d'}]}
        render_graph(graph,focus=('app','client'))
        content=iframe.call_args.args[0]
        selected=json.loads(re.search(r'const raw=(.*?);\nconst appURL',content).group(1))
        self.assertEqual({n['id'] for n in selected['nodes']},{'a','b'})
        self.assertEqual(len(selected['edges']),1)
        self.assertEqual(len(graph['nodes']),4)
