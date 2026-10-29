# Frozen comparison and acceptance protocol

The evaluation package is `eval/guardian`. It is deliberately absent from the
runtime image and from model tool allowlists. It defines 60 synthetic families,
20 development and 40 held-out, across routine narrowing, rare workflows,
ambiguous names/context, incomplete evidence, shared/alternate grants and
adversarial inputs. These are constructed evidence families, not 60 independent
live applications. Their labels are provisional until two humans independently
review behavior/intent and reconcile ambiguity. Variants remain within a family.

`freeze` creates a neutral-ID runtime directory, a separate evaluator directory
and a manifest binding both by hash. The actual model receives only strict
EvidenceBundle-derived prompts and approved scoped tools. No expected patch,
required/removable labels, split/category or evaluator filenames enter inference.
Model outputs are saved before the runner reads labels. Modified runtime inputs,
manifest or labels invalidate the run. The graph never requests a real mutation
in this offline comparison.

## Arms and metrics

Arm A runs the same deterministic facts/gates plus a declared conservative rule
for ordinary documentation that describes unexercised periodic/recovery work. It
handles coverage gaps, consumers, observed use, dependencies and misleading names;
it is not a zero-count-only strawman. Arm B uses the same frozen evidence and
gates with the actual two-stage model graph. Model-generated raw advice and
accepted proposals are measured separately. Both start with identical grants;
no arm receives an already-narrowed policy from the other.

Active-path latency includes A's rule/report construction and B's graph,
checkpoints and inference; it excludes human waiting and subsequent execution.
It is not pure decoder latency. Record hardware, warm/cold/queue conditions,
profile/model revision, source/prompt/schema versions, repetitions and failures.
This laptop run does not control the machine's other workloads, and cannot select
an H100 model. Only the tested 4B setting is currently measured; no bigger-model
fit or superiority claim is made.

Reports include raw/accepted required removals, removal precision/recall with
numerators/denominators, useful proposal coverage, appropriate deferral, permission
ID validity, first/final deterministic-domain/schema stage validity, repair calls,
p50/p95 latency, calls and per-category outcomes. Repeated runs count as repeated
measurements of one family. A family-level Wilson interval makes small-sample
uncertainty explicit. An empty proposal has undefined removal precision and zero
usefulness on answerable cases; abstention cannot manufacture success.

Semantic grounding, context-question utility, blind human review effort and live
functional/effective-access outcomes require actual reviewed observations. They
remain N/A until measured. A valid ID/schema does not establish that a cited fact
supports the model's claim. The comparison does not use an LLM as sole judge.

The original validator v2 development run exposed two accepted removals contrary
to rare-workflow documentation. Those results are retained. Validator v3 now puts
the declared conservative English workflow-cue rule in the shared gates, before
model interpretation and backend approval. Older saved analyses cannot silently
acquire this new validator; they need fresh analysis/review. This is a development
safety fix, not evidence of passing a held-out benchmark. Languages/phrasing beyond
the declared rule still require human/context validation; it is not a general
natural-language proof of dependencies.

## Reproduce development measurements

```bash
.venv/bin/python -m eval.guardian.compare freeze --directory data/evaluation/frozen
.venv/bin/python -m eval.guardian.compare run \
  --dataset data/evaluation/frozen --output data/evaluation/A-dev \
  --arm deterministic
.venv/bin/python -m eval.guardian.compare run \
  --dataset data/evaluation/frozen --output data/evaluation/B-dev \
  --arm llm --profile /PRIVATE/actual-model.toml
```

For a small matched development smoke, pass the same `--case case-001 --case
case-011 --case case-051 --repeats 3` to both arms. Preserve a fresh output path for
each run. The real model profile requires a real provider; scripted responses are
rejected for measured comparison. Ordinary repository protocol tests remain CPU
only and explicitly use recording adapters.

## Held-out university run

Freeze the metric definitions/selection rule and input/label hash before opening
held-out results. Two independent humans review the evaluator labels against the
specified behavior, document disagreements and provide a private attestation:

```json
{
  "dataset_hash": "<exact frozen manifest hash>",
  "reviewers": ["actual first reviewer", "actual second reviewer"],
  "reconciled": true
}
```

Names are a custodian's attestation, not a cryptographic identity system. Never
fill them with invented reviewers. Any corrected label changes the dataset hash
and requires a new freeze/review before scoring. The runner requires the matching
attestation and at least three repetitions for held-out runs:

```bash
.venv/bin/python -m eval.guardian.compare run \
  --dataset data/evaluation/frozen --output data/evaluation/A-held \
  --arm deterministic --split held_out --repeats 3 --label-review /PRIVATE/review.json
.venv/bin/python -m eval.guardian.compare run \
  --dataset data/evaluation/frozen --output data/evaluation/B-held-4b \
  --arm llm --profile /PRIVATE/lab-4b.toml --split held_out --repeats 3 \
  --label-review /PRIVATE/review.json
```

Repeat B with the approved actual same-family medium/larger settings when lab
allocation permits. Pin model digests/quantization and keep context/decoding/gates
comparable. Changes of family/quantization are confounds. Test a smaller live
subset with actual app behavior and fresh human approvals; synthetic offline
results cannot substitute for that. Counterbalance report order for blind human
ratings/time, then add the semantic grounding/question-utility review.

Selection requires no accepted known-required removal, demonstrated nonempty
useful narrowing and then comparable grounded quality/review effort/latency. The
runner deliberately does not stamp release selection complete without those
external assessments. If B does not improve A, report it and retain A as viable.
A failed held-out safety criterion requires a fix and a genuinely separated new
evaluation; do not quietly tune to held-out answers and rerun the same test.

See `project-report.md` and `release/` for actual development measurements and
remaining acceptance gates. No held-out/lab result has been invented.
