# 0003: Model, bounded evidence and worker contracts

Status: orchestration implementation in progress; component acceptance pending.

Phase 3 versions model profiles/prompts and records strict ModelResult envelopes.
Real providers accept messages, output schema and validated ModelConfig. Raw
dictionary responses remain supported only by the explicit ScriptedModelClient
test adapter, including its adversarial test subclasses. A real provider cannot
silently become scripted inference. External errors are represented by stable
codes to avoid storing credential-bearing exception text.

The lazy provider process gives initialization and inference one shared deadline.
The vLLM adapter uses a configured endpoint, bounded response reads and JSON Schema
output. It rejects endpoint redirects. Requested model revision and observed
resolved model/revision remain distinct; an unavailable resolved revision stays
null. Input/output bytes are bounded without silent truncation. The configured
context size is not a claim about an unverified remote server's actual capacity.
The initial worker supports one concurrent job and a finite queue per process.

Graph/state/report versions advance to v5. Prompt/output-schema versions join the
required compatibility stamp; the model configuration fingerprint enters the
checkpoint, model result and remediation approval hash. Changing configuration
cannot resume an interrupted model call, and cached analysis from a different
configuration is reanalyzed. Old pending contracts require a fresh revision.

The profile examples require an explicitly selected local file or lab endpoint
and pinned requested revision. They do not select a final lab model, establish
hardware allocation or claim a real university inference run. Collector,
authenticated ledger/outbox, real verification and execution remain backend-owned.

Transport references: [vLLM structured output](https://docs.vllm.ai/en/latest/features/structured_outputs/)
and [LangGraph interrupts](https://docs.langchain.com/oss/python/langgraph/interrupts).
