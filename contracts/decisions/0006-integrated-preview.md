# 0006: Integrated evidence, Ollama and nonwriting report review

Status: local producer/consumer and UI integration verified; action acceptance pending.

The existing strict UsageSummary/EvidenceBundle/AnalysisRequest/Report/Proposal
contracts now cross real serialized scoped backend/worker ports. Immutable evidence
and final reports share the operator-owned governance database; checkpoints are
separate private worker files. Model/repair/lookup reservations commit before use,
remain spent after crashes, and are fenced by server-owned active deadlines/leases.

The laptop profile uses native Ollama Qwen3.5 4B. Existing model-config v2 inputs
remain valid; the provider enum adds Ollama. Older consumers need capability
negotiation for that provider. Prompt v4 and validator v2 meaning are unchanged.
Runtime schema narrowing now reflects the same validator's known permission/target
IDs, citations and inadmissible removals for every provider. It never forces an
eligible removal or supplies evaluation answers; output-schema hashes record the
actual decoder schema. Existing saved profiles/config fingerprints are preserved;
new jobs pin their reviewed profile and saved checkpoints reject a different one.

Phase 3 runs preview graphs with unknown execution verification and no executor or
baseline port. Final blocked/no-proposal reports support independent authenticated
human acknowledge/reject/context review outside the execution interrupt. Context
review atomically records a decision and queues a fresh capture/analysis revision;
it cannot reuse old authority. Analysis status and report-review outcome remain
separate. Optional exact proposals are blocked previews, not an action request.
Positive approval/adoption remains unavailable. Existing governed decision/outbox
records remain proposal-oriented; attaching real execution consumers is Phase 4.

Local acceptance evidence: tests/test_usage_store.py, test_usage_collector.py,
test_evidence_inventory.py, test_evidence_archive.py, test_evidence_api.py,
test_analysis.py, test_ollama.py and test_review_workspace.py. The actual provider
also produced a valid investigation/no-removal for incomplete readiness and a valid
investigation/plan/exact blocked preview for synthetic candidate evidence. Those
functional smokes are unscored and do not establish live workload or held-out
benchmark acceptance. Preflight/action/receipt/recovery acceptance stays pending.
