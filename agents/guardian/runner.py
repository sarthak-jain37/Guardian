"""Command-line module demo. Decisions and execution are local test records."""

import argparse
import json
from contextlib import contextmanager
from pathlib import Path
from uuid import uuid4

from langgraph.checkpoint.sqlite import SqliteSaver
from langgraph.types import Command

from .adapters.local import (FixtureEvidencePort, LocalTestStore, PreviewVerificationPort,
                             RecordingExecutor, SimulatedVerificationPort)
from .adapters.models import LlamaCppModelClient, ScriptedModelClient
from .contracts import AnalysisRequest, EvidenceBundle, utc_now
from .fixtures import demo_evidence
from .graph import Runtime, build_graph, report


@contextmanager
def open_runner(directory, model=None, evidence=None, clock=utc_now):
    directory = Path(directory)
    directory.mkdir(parents=True, exist_ok=True)
    store = LocalTestStore(directory / "test-records.sqlite", clock=clock)
    if evidence is None:
        evidence = EvidenceBundle.model_validate_json((directory / "evidence.json").read_text())
    adapter = FixtureEvidencePort(evidence)
    runtime = Runtime(adapter, model or ScriptedModelClient(), store,
                      SimulatedVerificationPort() if evidence.source_mode == "fixture" else PreviewVerificationPort(),
                      RecordingExecutor(store), clock=clock, budget=store)
    with SqliteSaver.from_conn_string(str(directory / "checkpoints.sqlite")) as saver:
        try:
            yield build_graph(runtime, saver), runtime, store
        finally:
            store.close()
            if hasattr(runtime.model, "close"):
                runtime.model.close()


def config(run_id):
    return {"configurable": {"thread_id": run_id}, "recursion_limit": 32}


def export_result(directory, state, runtime):
    directory = Path(directory)
    payload = report(state, runtime)
    payload.update(proposal=state.get("proposal"), receipt=state.get("receipt"))
    (directory / "result.json").write_text(json.dumps(payload, indent=2) + "\n")
    if state.get("proposal"):
        (directory / "role-preview.yaml").write_text(state["proposal"]["role_yaml"])
        (directory / "binding-preview.json").write_text(json.dumps(state["proposal"]["unchanged_binding"], indent=2) + "\n")
    return payload


def main(argv=None):
    parser = argparse.ArgumentParser(description="Guardian LangGraph module demo; no Kubernetes writes")
    parser.add_argument("--directory", default="personal_docs/guardian-demo", help="durable local state/output directory")
    sub = parser.add_subparsers(dest="command", required=True)
    start = sub.add_parser("start")
    start.add_argument("--scenario", choices=["complete", "coverage-gap", "monthly", "missing-usage"], default="complete")
    start.add_argument("--evidence", type=Path, help="strict EvidenceBundle JSON capture; preview only")
    start.add_argument("--model", choices=["scripted", "llama-cpp"], default="scripted")
    start.add_argument("--model-path", required=False, help="GGUF path; defaults to MODEL_PATH environment variable")
    start.add_argument("--timeout", type=int, default=180)
    start.add_argument("--threads", type=int, default=4)
    sub.add_parser("status")
    decision = sub.add_parser("decide")
    decision.add_argument("kind", choices=["approve_remediation", "reject", "acknowledge", "request_context"])
    resume = sub.add_parser("resume")
    resume.add_argument("--decision-id", required=True)
    sub.add_parser("schema")
    args = parser.parse_args(argv)
    if args.command == "schema":
        from contracts.usage_summary_v1 import UsageSummary
        print(json.dumps({"evidence": EvidenceBundle.model_json_schema(), "usage": UsageSummary.model_json_schema()}, indent=2))
        return
    directory = Path(args.directory)
    directory.mkdir(parents=True, exist_ok=True)
    if args.command == "start":
        if (directory / "run.json").exists():
            parser.error("directory already contains a run; choose a fresh directory to preserve history")
        if args.evidence:
            evidence = EvidenceBundle.model_validate_json(args.evidence.read_text())
            if evidence.source_mode != "captured":
                parser.error("external export must be labeled captured; simulation accepts built-in fixtures only")
        else:
            evidence = demo_evidence(args.scenario)
        request = AnalysisRequest(case_id=f"case-{uuid4().hex[:12]}", run_id=f"run-{uuid4().hex[:12]}",
                                  snapshot_id=evidence.snapshot_id, cluster_id=evidence.target.cluster_id,
                                  target_uid=evidence.target.uid, mode="preview" if args.evidence else "simulation")
        (directory / "evidence.json").write_text(evidence.model_dump_json(indent=2))
        if args.model == "llama-cpp":
            import os
            from dotenv import load_dotenv
            load_dotenv()
            model_path = args.model_path or os.environ.get("MODEL_PATH")
            if not model_path:
                parser.error("llama-cpp needs --model-path or MODEL_PATH")
            model = LlamaCppModelClient(model_path, timeout_seconds=args.timeout, threads=args.threads)
        else:
            model = ScriptedModelClient()
        with open_runner(directory, model, evidence) as (graph, runtime, store):
            (directory / "run.json").write_text(json.dumps({"run_id": request.run_id, "producer": model.producer}))
            state = graph.invoke({"request": request.model_dump(mode="json")}, config(request.run_id))
            export_result(directory, state, runtime)
            print(json.dumps({"run_id": request.run_id, "status": state["status"], "mode": request.mode,
                              "producer": model.producer, "model_calls": state["model_calls"], "reason": state.get("reason"),
                              "proposal_id": state["proposal"]["proposal_id"] if state.get("proposal") else None,
                              "output": str((directory / "result.json").resolve()), "execution_requests": store.count("action")}, indent=2))
            if state.get("proposal"):
                print(state["proposal"]["diff"])
        return
    run = json.loads((directory / "run.json").read_text())
    with open_runner(directory) as (graph, runtime, store):
        runtime.model.producer = run["producer"]
        state = graph.get_state(config(run["run_id"])).values
        if args.command == "status":
            print(json.dumps({"run_id": run["run_id"], "status": state["status"], "reason": state.get("reason"),
                              "simulation": state["request"]["mode"] == "simulation", "model_calls": state["model_calls"],
                              "execution_requests": store.count("action"), "pending_proposal": state.get("proposal")}, indent=2))
        elif args.command == "decide":
            if state["status"] != "PENDING_REVIEW":
                parser.error("run is not waiting for review")
            decision = store.record_test_decision(state["proposal"]["proposal_id"], args.kind)
            print(json.dumps({"decision_id": decision.decision_id, "kind": decision.kind, "simulation": True}, indent=2))
        else:
            if not graph.get_state(config(run["run_id"])).next:
                print(json.dumps({"status": state["status"], "message": "run already ended; duplicate resume ignored",
                                  "execution_requests": store.count("action")}, indent=2))
                return
            state = graph.invoke(Command(resume=args.decision_id), config(run["run_id"]))
            export_result(directory, state, runtime)
            print(json.dumps({"status": state["status"], "reason": state.get("reason"),
                              "receipt": state.get("receipt"), "execution_requests": store.count("action")}, indent=2))


if __name__ == "__main__":
    main()
