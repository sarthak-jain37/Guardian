"""One-command local phase 1–5 development demo; no cluster writes or live claims."""

import argparse
import json
import subprocess
import sys
from pathlib import Path

from .contracts import AnalysisRequest
from .evaluate import source_provenance
from .fixtures import demo_evidence
from .schemas import export_schemas
from .work import WorkItem


def run_demo(directory, *, run_tests=True):
    from jsonschema import Draft202012Validator

    directory = Path(directory).resolve()
    if directory.exists() and any(directory.iterdir()):
        raise ValueError("preserve_previous_demo_use_fresh_directory")
    directory.mkdir(parents=True, exist_ok=True)
    root = Path(__file__).resolve().parents[2]

    def command(module, arguments, log=None):
        result = subprocess.run([sys.executable, "-m", module, *map(str, arguments)], cwd=root,
                                capture_output=True, text=True, timeout=120)
        if log:
            (directory / log).write_text(result.stdout + result.stderr)
        if result.returncode:
            raise RuntimeError("demo_command_failed: " + module + ("; inspect " + log if log else ""))
        return result.stdout

    def cli(case, *arguments):
        value = command("agents.guardian.runner", ["--directory", directory / case, *arguments])
        return json.JSONDecoder().raw_decode(value)[0]

    def decision(case, kind):
        stored = cli(case, "decide", kind)
        return cli(case, "resume", "--decision-id", stored["decision_id"]), stored["decision_id"]

    summary = {"schema_version": "guardian.local-demo.v1", "source": source_provenance(),
               "scope": "synthetic_development_and_recording_backend_contract_tests",
               "cluster_writes_performed": False, "lab_acceptance": False,
               "tests_run": run_tests, "checks": {}}
    if run_tests:
        print("Running repository tests (including governed outcome contracts)", flush=True)
        command("unittest", ["discover", "-s", "tests", "-q"], log="tests.log")
    schemas = export_schemas()
    for schema in schemas.values():
        Draft202012Validator.check_schema(schema)
    (directory / "schemas.json").write_text(json.dumps(schemas, indent=2))
    summary["schemas_validated"] = len(schemas)
    for case, kind, expected, count in [("reject", "reject", "REJECTED", 0),
                                       ("approve", "approve_remediation", "EXECUTION_REQUESTED", 1),
                                       ("acknowledge", "acknowledge", "NO_CHANGE", 0)]:
        print("Checking " + case, flush=True)
        first = cli(case, "start")
        assert first["status"] == "PENDING_REVIEW" and first["model_calls"] == 2
        restarted = cli(case, "status")
        assert restarted["status"] == "PENDING_REVIEW" and restarted["model_calls"] == 2
        result, stored_id = decision(case, kind)
        assert result["status"] == expected and result["execution_requests"] == count
        repeated = cli(case, "resume", "--decision-id", stored_id)
        assert repeated["execution_requests"] == count
        if count:
            assert all(result["receipt"][key] is False for key in
                       ("cluster_write_performed", "verification_performed", "baseline_activated"))
        summary["checks"][case] = {"status": result["status"], "execution_requests": count}
    print("Checking adoption and context revision", flush=True)
    adoption = cli("adoption", "start", "--intent", "adopt_baseline", "--scenario", "missing-usage")
    assert adoption["model_calls"] == 0 and adoption["status"] == "PENDING_REVIEW"
    adopted, _ = decision("adoption", "adopt_baseline")
    assert adopted["status"] == "EXECUTION_REQUESTED" and not adopted["receipt"]["baseline_activated"]
    summary["checks"]["adoption"] = {"status": adopted["status"], "model_calls": 0, "baseline_activated": False}
    original = cli("context", "start")
    closed, _ = decision("context", "request_context")
    assert closed["status"] == "STALE" and closed["revision_request"]
    successor = cli("context", "next")
    assert successor["status"] == "PENDING_REVIEW" and successor["revision"] == 2
    assert successor["run_id"] != original["run_id"] and successor["execution_requests"] == 0
    summary["checks"]["context"] = successor
    for scenario in ("coverage-gap", "monthly", "missing-usage"):
        result = cli(scenario, "start", "--scenario", scenario)
        assert result["status"] == "BLOCKED" and result["execution_requests"] == 0
        summary["checks"][scenario] = {"status": result["status"], "reason": result["reason"]}
    cli("forged", "start")
    forged = cli("forged", "resume", "--decision-id", "invented-decision")
    assert forged["status"] == "STALE" and forged["execution_requests"] == 0
    summary["checks"]["forged_decision"] = {"status": "STALE", "execution_requests": 0}
    print("Checking standalone worker and duplicate delivery", flush=True)
    worker_dir = directory / "worker"
    worker_dir.mkdir()
    evidence = demo_evidence()
    request = AnalysisRequest(case_id="demo-worker", run_id="demo-worker-run", snapshot_id=evidence.snapshot_id,
                              cluster_id=evidence.target.cluster_id, target_uid=evidence.target.uid)
    (worker_dir / "evidence.json").write_text(evidence.model_dump_json())
    work_file = worker_dir / "work.json"
    work_file.write_text(WorkItem(work_id="analysis", run_id=request.run_id, kind="analyze", request=request).model_dump_json())
    worker_args = ["--directory", worker_dir, "--item", work_file]
    for _ in range(2):
        outcome = json.loads(command("agents.guardian.worker", worker_args))
        assert not outcome["failures"] and outcome["outcomes"][0]["model_calls"] == 2
        assert outcome["outcomes"][0]["waiting_for_review"]
    stored = cli("worker", "decide", "reject")
    work_file.write_text(WorkItem(work_id="review", run_id=request.run_id, kind="resume",
                                 decision_id=stored["decision_id"]).model_dump_json())
    outcome = json.loads(command("agents.guardian.worker", worker_args))
    assert not outcome["failures"] and outcome["outcomes"][0]["status"] == "REJECTED"
    summary["checks"]["worker"] = outcome["outcomes"][0]
    print("Running development evaluation", flush=True)
    command("agents.guardian.evaluate", ["--directory", directory / "evaluation"], log="evaluation.log")
    evaluation = json.loads((directory / "evaluation/evaluation.json").read_text())
    assert evaluation["passed"]
    summary["checks"]["development_evaluation"] = {"passed": True, "split": evaluation["split"]}
    summary["passed"] = True
    (directory / "demo-summary.json").write_text(json.dumps(summary, indent=2) + "\n")
    return summary


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--directory", required=True, type=Path)
    parser.add_argument("--skip-tests", action="store_true", help="skip unit tests already run separately")
    args = parser.parse_args(argv)
    summary = run_demo(args.directory, run_tests=not args.skip_tests)
    # Exact file hashes remain in the artifact; keep terminal output readable.
    view = {**summary, "source": {k: v for k, v in summary["source"].items() if k != "source_files"}}
    print(json.dumps(view, indent=2))


if __name__ == "__main__":
    main()
