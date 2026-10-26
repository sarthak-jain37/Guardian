import json
import os
from pathlib import Path
import streamlit as st

ASSETS=Path(__file__).parent/'assets'


def safe_graph_json(value):
    return json.dumps(value).replace('<',r'\u003c').replace('>',r'\u003e').replace('&',r'\u0026')


def render_graph(graph, focus=None):
    graph={'nodes':list(graph.get('nodes',[])), 'edges':list(graph.get('edges',[]))}
    if focus:
        ids={n['id'] for n in graph['nodes'] if n.get('namespace')==focus[0] and n.get('pod')==focus[1]}
        graph['edges']=[e for e in graph['edges'] if e['source'] in ids or e['target'] in ids]
        neighbors=ids|{e[k] for e in graph['edges'] for k in ('source','target')}
        graph['nodes']=[n for n in graph['nodes'] if n['id'] in neighbors]
    html=(ASSETS/'network.html').read_text()
    html=html.replace('__VENDOR__',(ASSETS/'vis-network.min.js').read_text())
    html=html.replace('__APP_URL__',safe_graph_json(os.getenv('FRONTEND_URL','http://127.0.0.1:8501')))
    html=html.replace('__GRAPH_DATA__',safe_graph_json(graph))
    st.iframe(html,height='content',width='stretch')
