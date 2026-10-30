# Local model runtime

The default laptop profile is `agents/guardian/config/dev-laptop.toml`: native
Ollama, `qwen3.5:4b`, 8192 context, 2048 output tokens, temperature zero, seed 17,
concurrency one. Inference remains local and weights still need downloading. The local smoke run
downloaded them to ignored `data/ollama-models`; use that same path below to reuse
them. An existing Ollama service can keep its configured storage path.

```bash
OLLAMA_MODELS="$PWD/data/ollama-models" OLLAMA_NUM_PARALLEL=1 OLLAMA_MAX_LOADED_MODELS=1 OLLAMA_MAX_QUEUE=4 ollama serve
ollama pull qwen3.5:4b
.venv/bin/python -m scripts.guardian_model_smoke
```

Set `GUARDIAN_MODEL_PROFILE` to a reviewed TOML profile for both backend intake
and advisory monitoring. Each analysis job pins that complete configuration and
its graph checkpoint pins its fingerprint. A restarted worker cannot silently
substitute another model/profile. Optional profiles `dev-llama-cpp.toml` and
`lab.toml` retain llama.cpp/vLLM; replace their operator placeholders before use.
`MODEL_PATH` alone no longer selects the default runtime.

Ollama uses `/api/chat`, schema `format`, `stream=false`, `think=false`, `num_ctx`
and `num_predict`, with input truncation and context shifting explicitly disabled.
Use a server supporting those native fields (tested Ollama 0.40.3). An actual
over-context request was rejected with HTTP 400. Responses must complete with `done=true` and `done_reason=stop`;
provider, schema, byte, deadline and domain validation still apply. Errors and
truncation become explicit failed/blocked analysis rather than partial success.
Provider startup and requests run in a killable process under one deadline.
Requested revision and resolved revision remain distinct; a mutable model tag is
not reported as a verified digest. Pin deployment weights/digests in private
deployment configuration.
The provider enum addition is backward compatible for existing saved profiles;
older consumers must negotiate Ollama support before accepting new profiles.

Advisory monitoring uses the same lazy provider transport and profile. Importing
the API, collector or summarizer initializes no model. Advisory requests have
finite input/output/deadline bounds and a bounded local lock; omitted examples
are disclosed while aggregate history counts remain. Advisory severity cannot
authorize changes. Set `POD_REVIEW_ENABLED=false` to reserve laptop inference for
the dedicated analysis worker during the demo; otherwise Ollama also serializes
requests with `OLLAMA_NUM_PARALLEL=1`.

On 29 October 2026 the real local `qwen3.5:4b` transport/schema smoke passed:
5.426 seconds including startup, 46 input and 25 output tokens. It used synthetic
minimal input and made no cluster writes. This checks connectivity/structured
output, not project evaluation quality, workload suitability or live acceptance.
Repeat on each laptop. The broader project demo continues to label synthetic,
recording-backend and live-model results separately.

The integrated graph also passed real local investigator/planner smoke checks on
synthetic development evidence; see `docs/analysis.md` for the scope and observed
rejected output. [Native chat API](https://docs.ollama.com/api/chat) and
[structured output](https://docs.ollama.com/capabilities/structured-outputs), and
[ChatRequest controls](https://pkg.go.dev/github.com/ollama/ollama/api#ChatRequest) describe
the transport fields; independent Guardian validators enforce the domain rules.
