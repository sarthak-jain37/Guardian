import json

from langchain_community.llms import LlamaCpp


local_qwen = LlamaCpp(
    model_path="/path/to/qwen2.5-7b-instruct-Q4_K_M.gguf",
    temperature=0.2,
    verbose=False,
)


def analyse_document(document: dict) -> str:

    document_json = json.dumps(
        document,
        indent=2,
        ensure_ascii=False,
    )

    prompt = f"""
Analyze ONLY the JSON document below.

Rules:
- Do not invent information.
- Do not assume facts that are not present.
- Do not use outside knowledge.
- Do not add information that is not present in the document.

JSON DOCUMENT:

{document_json}
"""

    response = local_qwen.invoke(prompt)

    return response