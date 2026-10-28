"""Single-job worker boundary, separate from API requests and audit ingestion."""

import argparse
import json
from collections import deque
from contextlib import contextmanager
from pathlib import Path
from queue import Queue
from typing import Protocol

from langgraph.types import Command

from .modeling import load_profile
from .runner import config, configured_model, export_result, open_runner, start_successor
from .versions import require_compatible_state
from .work import WorkItem, WorkOutcome
from .reconciliation import reconcile_run


class WorkQueuePort(Protocol):
    """Backend owns durable leases, outbox delivery and retry scheduling."""
    def receive(self) -> WorkItem | None: ...
    def acknowledge(self, work_id: str, outcome: WorkOutcome) -> None: ...
    def fail(self, work_id: str, error_code: str) -> None: ...


class RecordingWorkQueue:
    """Bounded in-memory test adapter; not a durable backend queue."""
    def __init__(self, limit=8):
        if type(limit) is not int or not 1 <= limit <= 64:
            raise ValueError("invalid_queue_limit")
        self.pending = Queue(maxsize=limit)
        self.completed = deque(maxlen=limit)
        self.failed = deque(maxlen=limit)

    def submit(self, item):
        self.pending.put_nowait(WorkItem.model_validate(item))

    def receive(self):
        from queue import Empty
        try:
            return self.pending.get_nowait()
        except Empty:
            return None

    def acknowledge(self, work_id, outcome):
        self.completed.append(outcome)
        self.pending.task_done()

    def fail(self, work_id, error_code):
        self.failed.append({"work_id": work_id, "error_code": error_code})
        self.pending.task_done()


def process_work(graph, runtime, item):
    item = WorkItem.model_validate(item.model_dump(mode="json") if isinstance(item, WorkItem) else item)
    cfg = config(item.run_id)
    snapshot = graph.get_state(cfg)
    if item.kind == "reconcile":
        state = reconcile_run(graph, runtime, cfg)
    elif item.kind == "revision":
        ticket = runtime.review.get_revision(item.revision_request_id)
        if ticket.request.run_id != item.run_id:
            raise ValueError("revision_delivery_scope_mismatch")
        state = start_successor(graph, ticket)
    elif not snapshot.values:
        if item.kind != "analyze":
            raise ValueError("unknown_worker_run")
        state = graph.invoke({"request": item.request.model_dump(mode="json")}, cfg)
    else:
        require_compatible_state(snapshot.values)
        if item.kind == "analyze" and snapshot.values["request"] != item.request.model_dump(mode="json"):
            raise ValueError("conflicting_analysis_delivery")
        interrupted = any(task.interrupts for task in snapshot.tasks)
        if item.kind == "resume" and interrupted:
            state = graph.invoke(Command(resume=item.decision_id), cfg)
        elif snapshot.next and not interrupted:
            if item.kind == "resume" and snapshot.values.get("decision_id") != item.decision_id:
                raise ValueError("conflicting_resume_delivery")
            state = graph.invoke(None, cfg)
        else:
            state = snapshot.values
    saved = graph.get_state(cfg)
    return WorkOutcome(work_id=item.work_id, run_id=item.run_id, status=state["status"],
                       waiting_for_review=any(task.interrupts for task in saved.tasks),
                       model_calls=state["model_calls"], lookup_calls=state["lookup_calls"])


def run_worker(queue, session_factory, max_jobs=1):
    if type(max_jobs) is not int or not 1 <= max_jobs <= 64:
        raise ValueError("worker_batch_out_of_bounds")
    outcomes = []
    for _ in range(max_jobs):
        item = queue.receive()
        if item is None:
            break
        try:
            with session_factory(item) as (graph, runtime, _):
                outcome = process_work(graph, runtime, item)
            # Waiting for a reviewer completes this delivery and releases the
            # model/session. A later decision arrives as a separate queued job.
            queue.acknowledge(item.work_id, outcome)
            outcomes.append(outcome)
        except Exception as exc:
            queue.fail(item.work_id, type(exc).__name__)
    return outcomes


@contextmanager
def local_session(directory, settings):
    import fcntl
    directory = Path(directory)
    directory.mkdir(parents=True, exist_ok=True)
    with (directory / "worker.lock").open("a") as lock:
        try:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as exc:
            raise ValueError("worker_directory_busy") from exc
        model, settings = configured_model(settings)
        with open_runner(directory, model=model) as session:
            yield session


def main(argv=None):
    parser = argparse.ArgumentParser(description="Guardian worker test/file handoff; no production queue or cluster writes")
    parser.add_argument("--directory", type=Path, required=True)
    parser.add_argument("--item", type=Path, required=True)
    parser.add_argument("--profile", type=Path)
    args = parser.parse_args(argv)
    with args.item.open("rb") as source:
        raw = source.read(65537)
    if len(raw) > 65536:
        parser.error("work_item_too_large")
    item = WorkItem.model_validate_json(raw)
    manifest = args.directory / "run.json"
    if args.profile:
        settings = load_profile(args.profile).model_dump(mode="json")
    elif manifest.exists():
        saved = json.loads(manifest.read_text())
        settings = saved.get("model_config")
        if settings is None:
            parser.error("saved_model_configuration_missing")
    else:
        settings = {"provider": "scripted"}
    model, settings = configured_model(settings)
    if hasattr(model, "close"):
        model.close()
    queue = RecordingWorkQueue(settings["queue_limit"])
    queue.submit(item)

    @contextmanager
    def session_factory(job):
        with local_session(args.directory, settings) as session:
            yield session
            graph, runtime, _ = session
            state = graph.get_state(config(job.run_id)).values
            export_result(args.directory, state, runtime)
            manifest.write_text(json.dumps({"run_id": job.run_id, "producer": runtime.model.producer,
                                            "model_config": settings}))

    outcomes = run_worker(queue, session_factory)
    print(json.dumps({"outcomes": [o.model_dump(mode="json") for o in outcomes], "failures": list(queue.failed)}, indent=2))
    if queue.failed:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
