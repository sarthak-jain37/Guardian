"""Command-line module demo. Decisions and execution are local test records."""

import argparse
import json
from contextlib import contextmanager
from pathlib import Path
from uuid import uuid4

from langgraph.checkpoint.sqlite import SqliteSaver
from langgraph.types import Command

from .adapters.local import (FixtureEvidencePort, LocalTestStore, PreviewVerificationPort,
                             RecordingBaselinePort, RecordingExecutor, SimulatedVerificationPort)
from .adapters.models import LlamaCppModelClient, ScriptedModelClient, VllmModelClient
from .modeling import ModelConfig, load_profile
from .contracts import AnalysisRequest, EvidenceBundle, utc_now
from .fixtures import demo_evidence
from .graph import Runtime, build_graph, report
from .policy import canonical_hash
from .revisions import renew_review
from .versions import IncompatibleRunError, require_compatible_state


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
                      RecordingExecutor(store), clock=clock, budget=store, baseline=RecordingBaselinePort(store))
    with SqliteSaver.from_conn_string(str(directory / "checkpoints.sqlite")) as saver:
        try:
            yield build_graph(runtime, saver), runtime, store
        finally:
            store.close()
            if hasattr(runtime.model, "close"):
                runtime.model.close()


def config(run_id):
    return {"configurable": {"thread_id": run_id}, "recursion_limit": 32}


def configured_model(settings):
    settings = dict(settings)
    if "profile" not in settings:
        provider = settings.get("provider")
        if provider == "scripted":
            settings = ModelConfig().model_dump(mode="json")
        elif provider == "llama-cpp":
            import os
            from dotenv import load_dotenv
            load_dotenv()
            path = settings.get("model_path") or os.environ.get("MODEL_PATH")
            if not path:
                raise ValueError("llama-cpp needs --model-path or MODEL_PATH")
            settings = ModelConfig(profile="dev-laptop", provider="llama-cpp", model_name=Path(path).name,
                                   model_path=str(Path(path).expanduser().resolve()),
                                   request_timeout_seconds=settings.get("timeout", 180),
                                   threads=settings.get("threads", 4)).model_dump(mode="json")
        else:
            raise ValueError("unsupported_model_provider")
    config = ModelConfig.model_validate(settings)
    if config.provider == "scripted":
        model = ScriptedModelClient()
        model.config = config
    elif config.provider == "llama-cpp":
        model = LlamaCppModelClient(config.model_path, config=config)
    else:
        model = VllmModelClient(config)
    return model, config.model_dump(mode="json")


def start_successor(graph, ticket):
    next_config = config(ticket.request.run_id)
    existing = graph.get_state(next_config)
    if not existing.values:
        return graph.invoke({"request": ticket.request.model_dump(mode="json")}, next_config)
    require_compatible_state(existing.values)
    if existing.next and not any(task.interrupts for task in existing.tasks):
        return graph.invoke(None, next_config)
    return existing.values


def export_result(directory, state, runtime):
    directory = Path(directory)
    payload = report(state, runtime)
    payload.update(proposal=state.get("proposal"), receipt=state.get("receipt"), revision_request=state.get("revision_request"))
    # Hash the arbitrary external run ID before using it as a directory name.
    history = directory / "runs" / canonical_hash(state["request"]["run_id"]).split(":")[1][:24]
    history.mkdir(parents=True, exist_ok=True)
    for output in (directory, history):
        (output / "result.json").write_text(json.dumps(payload, indent=2) + "\n")
        if state.get("proposal"):
            (output / "role-preview.yaml").write_text(state["proposal"]["role_yaml"])
            (output / "binding-preview.json").write_text(json.dumps(state["proposal"]["unchanged_binding"], indent=2) + "\n")
        else:
            (output / "role-preview.yaml").unlink(missing_ok=True)
            (output / "binding-preview.json").unlink(missing_ok=True)
    if state.get("evidence"):
        (history / "evidence.json").write_text(json.dumps(state["evidence"], indent=2) + "\n")
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
    start.add_argument("--intent", choices=["analyze", "adopt_baseline"], default="analyze")
    start.add_argument("--profile", type=Path, help="strict TOML model/worker profile")
    sub.add_parser("status")
    sub.add_parser("renew", help="request a fresh revision after unused review/approval expiry")
    sub.add_parser("next", help="run the recorded successor revision; never carries old authority")
    decision = sub.add_parser("decide")
    decision.add_argument("kind", choices=["approve_remediation", "adopt_baseline", "reject", "acknowledge", "request_context"])
    resume = sub.add_parser("resume")
    resume.add_argument("--decision-id", required=True)
    sub.add_parser("schema")
    args = parser.parse_args(argv)
    if args.command == "schema":
        from .schemas import export_schemas
        print(json.dumps(export_schemas(), indent=2))
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
                                  target_uid=evidence.target.uid, baseline_id=evidence.baseline_id,
                                  policy_version=evidence.policy.policy_version,
                                  intent=args.intent,
                                  mode="preview" if args.evidence else "simulation")
        (directory / "evidence.json").write_text(evidence.model_dump_json(indent=2))
        try:
            settings = load_profile(args.profile).model_dump(mode="json") if args.profile else {
                "provider": args.model, "model_path": args.model_path, "timeout": args.timeout, "threads": args.threads}
            model, model_config = configured_model(settings)
        except ValueError as exc:
            parser.error(str(exc))
        with open_runner(directory, model, evidence) as (graph, runtime, store):
            (directory / "run.json").write_text(json.dumps({"run_id": request.run_id, "producer": model.producer,
                                                          "model_config": model_config}))
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
    model = None
    if args.command == "next":
        model_config = run.get("model_config")
        if model_config is None:
            if run["producer"] != "scripted-test":
                parser.error("saved_model_configuration_missing: cannot substitute scripted inference")
            model_config = {"provider": "scripted"}
        try:
            model, model_config = configured_model(model_config)
        except ValueError as exc:
            parser.error(str(exc))
    with open_runner(directory, model=model) as (graph, runtime, store):
        if args.command != "next":
            runtime.model.producer = run["producer"]
        state = graph.get_state(config(run["run_id"])).values
        try:
            require_compatible_state(state)
        except IncompatibleRunError as exc:
            if args.command != "status":
                parser.error(str(exc))
            print(json.dumps({"run_id": run["run_id"], "status": state.get("status"),
                              "compatible": False, "reason": str(exc),
                              "execution_requests": store.count("action")}, indent=2))
            return
        if args.command == "status":
            print(json.dumps({"run_id": run["run_id"], "status": state["status"], "reason": state.get("reason"),
                              "simulation": state["request"]["mode"] == "simulation", "model_calls": state["model_calls"],
                              "execution_requests": store.count("action"), "pending_proposal": state.get("proposal")}, indent=2))
        elif args.command == "renew":
            try:
                ticket = renew_review(graph, runtime, config(run["run_id"]))
            except (LookupError, ValueError) as exc:
                parser.error(str(exc))
            export_result(directory, graph.get_state(config(run["run_id"])).values, runtime)
            print(json.dumps(ticket.model_dump(mode="json"), indent=2))
        elif args.command == "next":
            if not state.get("revision_request"):
                parser.error("no successor revision is recorded")
            ticket = store.get_revision(state["revision_request"]["revision_request_id"])
            state = start_successor(graph, ticket)
            (directory / "run.json").write_text(json.dumps({"run_id": ticket.request.run_id, "producer": runtime.model.producer,
                                                          "model_config": model_config}))
            export_result(directory, state, runtime)
            print(json.dumps({"run_id": ticket.request.run_id, "revision": ticket.request.revision,
                              "status": state["status"], "model_calls": state["model_calls"],
                              "reuse_analysis": ticket.reuse_analysis, "execution_requests": store.count("action")}, indent=2))
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
                              "receipt": state.get("receipt"), "revision_request": state.get("revision_request"),
                              "execution_requests": store.count("action")}, indent=2))


if __name__ == "__main__":
    main()
