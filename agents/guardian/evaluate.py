"""Reproducible development evaluation; evaluator labels never enter model input.

This is not the team's held-out benchmark or a live deployment acceptance test.
Captured producer exports run in preview mode and have no invented ground truth.
"""

import argparse
import json
import subprocess
import time
from pathlib import Path
from uuid import uuid4

from .adapters.pod_context import attach_pod_context
from .contracts import AnalysisRequest, EvidenceBundle, utc_now
from .fixtures import demo_evidence
from .modeling import ModelConfig, load_profile
from .policy import canonical_hash, operations
from .runner import config, configured_model, export_result, open_runner
from .versions import current_versions

SCENARIOS = ("complete", "coverage-gap", "monthly", "missing-usage")


def score_development(scenario, state):
    """Private evaluator expectation, outside the evidence/model payload."""
    selected = set()
    if state.get("proposal"):
        selected = operations(state["evidence"]["target"]["rules"]) - operations(state["proposal"]["result_rules"])
    expected = {("", "secrets", "get")} if scenario == "complete" else set()
    useful = bool(selected) if scenario == "complete" else None
    passed = (state["status"] == "PENDING_REVIEW" and selected == expected) if scenario == "complete" else (
        state["status"] == "BLOCKED" and not selected)
    return {"scope": "development_fixture_only", "passed": passed,
            "useful_narrowing": useful, "accepted_unexpected_removals": len(selected - expected),
            "selected_operations": [list(op) for op in sorted(selected)],
            "expected_operations": [list(op) for op in sorted(expected)]}


def source_provenance():
    root = Path(__file__).resolve().parents[2]
    files = sorted([*root.joinpath("agents/guardian").rglob("*.py"),
                    *root.joinpath("agents/guardian/config").glob("*.toml"),
                    *root.joinpath("contracts").rglob("*.py"), root / "contracts/compatibility.json",
                    *[root / "backend/app/services" / name for name in
                      ("permission_scanner.py", "pod_evidence.py", "runtime_evidence.py", "telemetry.py")],
                    root / "pyproject.toml", root / "uv.lock"])
    hashes = {str(path.relative_to(root)): canonical_hash(path.read_text()) for path in files}
    try:
        commit = subprocess.run(["git", "rev-parse", "HEAD"], cwd=root, check=True, capture_output=True, text=True).stdout.strip()
        dirty = bool(subprocess.run(["git", "status", "--porcelain"], cwd=root, check=True,
                                    capture_output=True, text=True).stdout.strip())
    except (OSError, subprocess.CalledProcessError):
        commit, dirty = None, None
    return {"commit": commit, "working_tree_dirty": dirty, "source_hash": canonical_hash(hashes), "source_files": hashes}


def evaluate_case(directory, evidence, settings, scenario=None):
    directory = Path(directory)
    directory.mkdir(parents=True, exist_ok=False)
    model, saved_settings = configured_model(settings)
    request = AnalysisRequest(case_id="evaluation-" + uuid4().hex[:12], run_id="run-" + uuid4().hex[:12],
                              snapshot_id=evidence.snapshot_id, cluster_id=evidence.target.cluster_id,
                              target_uid=evidence.target.uid, baseline_id=evidence.baseline_id,
                              policy_version=evidence.policy.policy_version,
                              mode="simulation" if evidence.source_mode == "fixture" else "preview")
    (directory / "evidence.json").write_text(evidence.model_dump_json(indent=2))
    (directory / "run.json").write_text(json.dumps({"run_id": request.run_id, "producer": model.producer,
                                                    "model_config": saved_settings}, indent=2))
    started = time.monotonic()
    with open_runner(directory, model=model, evidence=evidence) as (graph, runtime, store):
        state = graph.invoke({"request": request.model_dump(mode="json")}, config(request.run_id))
        export_result(directory, state, runtime)
        execution_requests = store.count("action")
    scoring = score_development(scenario, state) if scenario else None
    results = [t["model_result"] for t in state["trace"] if t.get("model_result")]
    return {"case": scenario or "captured-preview", "run_id": request.run_id,
            "evidence_hash": canonical_hash(evidence.model_dump(mode="json")), "source_mode": evidence.source_mode,
            "producer": model.producer, "status": state["status"], "reason": state.get("reason"),
            "model_status": state["model_status"], "model_calls": state["model_calls"], "lookup_calls": state["lookup_calls"],
            "execution_requests": execution_requests, "duration_seconds": time.monotonic() - started,
            "stages": [{k: result[k] for k in ("stage", "producer", "requested_model", "requested_revision",
                                                "resolved_model", "resolved_revision", "duration_seconds",
                                                "input_tokens", "output_tokens", "error")} for result in results],
            "scoring": scoring, "report": str((directory / "result.json").resolve())}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--directory", type=Path, required=True, help="new/empty output directory")
    parser.add_argument("--profile", type=Path)
    parser.add_argument("--scenario", choices=("all", *SCENARIOS), default="all")
    parser.add_argument("--evidence", type=Path, help="actual sanitized EvidenceBundle; preview only")
    parser.add_argument("--pod-context", type=Path, help="main's supplemental pod-evidence JSON export")
    parser.add_argument("--pod-name")
    parser.add_argument("--pod-uid")
    args = parser.parse_args(argv)
    if args.directory.exists() and any(args.directory.iterdir()):
        parser.error("preserve_previous_evaluation_use_fresh_directory")
    settings = load_profile(args.profile).model_dump(mode="json") if args.profile else ModelConfig().model_dump(mode="json")
    if args.pod_context and (not args.evidence or not args.pod_name or not args.pod_uid):
        parser.error("pod_context_requires_captured_evidence_and_exact_pod_identity")
    if args.evidence:
        if args.evidence.stat().st_size > 2097152:
            parser.error("evidence_export_too_large")
        evidence = EvidenceBundle.model_validate_json(args.evidence.read_text())
        if evidence.source_mode != "captured":
            parser.error("external_export_must_be_captured")
        if args.pod_context:
            if args.pod_context.stat().st_size > 131072:
                parser.error("pod_context_export_too_large")
            evidence = attach_pod_context(evidence, json.loads(args.pod_context.read_text()),
                                          cluster_id=evidence.target.cluster_id, pod_name=args.pod_name,
                                          pod_uid=args.pod_uid, now=utc_now())
        cases = [("captured-preview", evidence)]
    else:
        # Build each frozen fixture just before inference so previous slow cases
        # cannot make a later case stale before it even starts.
        cases = [(name, None) for name in (SCENARIOS if args.scenario == "all" else (args.scenario,))]
    args.directory.mkdir(parents=True, exist_ok=True)
    provenance = source_provenance()
    results = []
    for name, evidence in cases:
        print("Evaluating " + name, flush=True)
        results.append(evaluate_case(args.directory / name, evidence or demo_evidence(name), settings,
                                     scenario=None if evidence else name))
    summary = {"schema_version": "guardian.development-evaluation.v1", "source": provenance,
               "versions": current_versions("per-case-policy").model_dump(mode="json"),
               "profile_hash": ModelConfig.model_validate(settings).fingerprint(),
               "split": "captured_unscored" if args.evidence else "synthetic_development",
               "held_out_evaluation": False, "cluster_writes_performed": False,
               "cases": results, "passed": None if args.evidence else all(r["execution_requests"] == 0 and
                   r["scoring"]["passed"] for r in results)}
    (args.directory / "evaluation.json").write_text(json.dumps(summary, indent=2) + "\n")
    view = {**summary, "source": {k: v for k, v in provenance.items() if k != "source_files"}}
    print(json.dumps(view, indent=2))
    if summary["passed"] is False:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
