import json
from pathlib import Path
from deepagents import create_deep_agent
from langchain_core.tools import tool
from langchain_community.llms import LlamaCpp

def load_json(file_path: str):
    path = Path(file_path)

    if not path.exists():
        raise FileNotFoundError(f"File not found: {file_path}")
    try:
        with path.open('r', encoding='utf-8') as file:
            data = json.load(file)
        print("File loaded")
    except ValueError as e:
        print(f"{e}")

    return json.dumps(
        data,
        indent=2,
        ensure_ascii=False
    )

@tool
def get_document() -> str:
    document = load_json("data.json")
    return document


local_qwen = LlamaCpp(
    model_path="/path/to/qwen2.5-7b-instruct-Q4_K_M.gguf",
    temperature=0.2,
    verbose=False,
)


agent = create_deep_agent(
    model=local_qwen,
    tools=[get_document],
)


response = agent.invoke(
    {
        "messages": [
            {
                "role": "user",
                "content": (
                    "Use the get_document tool to read the document. "
                    "Summarize ONLY the contents of that document. "
                    "Do not use outside knowledge. "
                    "Do not add information that is not present in the document."
                ),
            }
        ]
    }
)



