"""Durable local test records behind ports, not the team's production ledger."""

import json
import sqlite3
from datetime import timedelta
from pathlib import Path

from ..contracts import AnalysisRequest, ApprovalDecision, EvidenceBundle, Proposal, RevisionRequest, utc_now
from ..policy import canonical_hash
from ..lifecycle import ProposalStatus
from ..evidence_tools import AccessResult, ToolResult


class LocalTestStore:
    authoritative = False
    def __init__(self, path: str | Path, clock=utc_now):
        Path(path).parent.mkdir(parents=True, exist_ok=True)
        self.connection = sqlite3.connect(str(path))
        self.connection.execute("CREATE TABLE IF NOT EXISTS records (kind TEXT, id TEXT, payload TEXT, PRIMARY KEY(kind,id))")
        self.connection.execute("CREATE TABLE IF NOT EXISTS model_calls (run_id TEXT, number INTEGER, stage TEXT, PRIMARY KEY(run_id,number))")
        self.connection.commit()
        self.clock = clock

    def close(self):
        self.connection.close()

    def put_once(self, kind: str, identifier: str, payload: dict) -> dict:
        encoded = json.dumps(payload, sort_keys=True)
        with self.connection:
            self.connection.execute("INSERT OR IGNORE INTO records VALUES (?,?,?)", (kind, identifier, encoded))
        return self.get(kind, identifier)

    def get(self, kind: str, identifier: str) -> dict:
        row = self.connection.execute("SELECT payload FROM records WHERE kind=? AND id=?", (kind, identifier)).fetchone()
        if row is None:
            raise LookupError(f"unknown {kind} ID")
        return json.loads(row[0])

    def count(self, kind: str) -> int:
        return self.connection.execute("SELECT count(*) FROM records WHERE kind=?", (kind,)).fetchone()[0]

    def model_call_count(self, run_id: str) -> int:
        return self.connection.execute("SELECT count(*) FROM model_calls WHERE run_id=?", (run_id,)).fetchone()[0]

    def begin_action(self, action_key):
        # A crash after reservation is uncertain: replay may only reconcile.
        with self.connection:
            cursor = self.connection.execute("INSERT OR IGNORE INTO records VALUES (?,?,?)",
                                             ("action_dispatch", action_key, "{}"))
        return cursor.rowcount == 1

    def model_repair_count(self, run_id, stage):
        return self.connection.execute("SELECT count(*) FROM records WHERE kind='model_repair' AND id=?",
                                       (canonical_hash([run_id, stage]),)).fetchone()[0]

    def reserve_model_call(self, run_id: str, stage: str, limit: int, repair=False) -> int:
        # Commit the budget before inference, so a crashed call still consumes capacity.
        with self.connection:
            self.connection.execute("BEGIN IMMEDIATE")
            number = self.model_call_count(run_id) + 1
            if number > limit:
                raise ValueError("model_budget_exhausted")
            if repair:
                if self.model_repair_count(run_id, stage):
                    raise ValueError("stage_repair_budget_exhausted")
                self.connection.execute("INSERT INTO records VALUES (?,?,?)",
                                        ("model_repair", canonical_hash([run_id, stage]), "{}"))
            self.connection.execute("INSERT INTO model_calls VALUES (?,?,?)", (run_id, number, stage))
        return number

    def reserve_lookup_batch(self, run_id, batch_key, requests, rounds, calls):
        with self.connection:
            self.connection.execute("BEGIN IMMEDIATE")
            try:
                existing = self.get("lookup_batch", batch_key)
            except LookupError:
                existing = None
            if existing is not None:
                if existing["run_id"] != run_id or [c["request"] for c in existing["calls"]] != requests:
                    raise ValueError("lookup_reservation_mismatch")
                return existing
            previous = [json.loads(row[0]) for row in self.connection.execute("SELECT payload FROM records WHERE kind='lookup_batch'")]
            previous = [r for r in previous if r["run_id"] == run_id]
            count = sum(len(r["calls"]) for r in previous)
            if len(previous) >= rounds or count + len(requests) > calls:
                raise ValueError("lookup_budget_exhausted")
            result = {"run_id": run_id, "round": len(previous) + 1, "total_calls": count + len(requests),
                      "calls": [{"request": r, "started": False, "result": None} for r in requests]}
            self.connection.execute("INSERT INTO records VALUES (?,?,?)", ("lookup_batch", batch_key, json.dumps(result)))
        return result

    def begin_lookup(self, batch_key, index):
        with self.connection:
            self.connection.execute("BEGIN IMMEDIATE")
            batch = self.get("lookup_batch", batch_key)
            entry = batch["calls"][index]
            if entry["result"] is not None:
                return entry["result"]
            if entry["started"]:
                raise ValueError("lookup_outcome_uncertain_after_restart")
            entry["started"] = True
            self.connection.execute("UPDATE records SET payload=? WHERE kind='lookup_batch' AND id=?", (json.dumps(batch), batch_key))
        return None

    def complete_lookup(self, batch_key, index, result):
        with self.connection:
            batch = self.get("lookup_batch", batch_key)
            entry = batch["calls"][index]
            if not entry["started"] or (entry["result"] is not None and entry["result"] != result):
                raise ValueError("lookup_result_conflict")
            entry["result"] = result
            self.connection.execute("UPDATE records SET payload=? WHERE kind='lookup_batch' AND id=?", (json.dumps(batch), batch_key))

    def finalize_run(self, run_id: str, result: dict):
        return self.put_once("outcome", run_id, result)

    def publish_report(self, run_id, report):
        return self.put_once("analysis", run_id, report)

    def get_report(self, run_id):
        return self.get("analysis", run_id)

    def get_proposal_status(self, proposal_id):
        try:
            return self.get("proposal_status", proposal_id)["status"]
        except LookupError:
            return self.get_proposal(proposal_id).status

    def project_proposal(self, proposal_id, status, reason):
        status = ProposalStatus(status).value
        projection = {"proposal_id": proposal_id, "status": status, "reason": reason}
        with self.connection:
            current = self.connection.execute("SELECT payload FROM records WHERE kind='proposal_status' AND id=?", (proposal_id,)).fetchone()
            if current and json.loads(current[0])["status"] in ("EXPIRED", "SUPERSEDED", "REJECTED", "BLOCKED"):
                return json.loads(current[0])
            self.connection.execute("INSERT OR IGNORE INTO records VALUES (?,?,?)",
                                    ("proposal_transition", canonical_hash(projection), json.dumps(projection)))
            self.connection.execute("INSERT OR REPLACE INTO records VALUES (?,?,?)",
                                    ("proposal_status", proposal_id, json.dumps(projection)))
        return projection

    def get_proposal_decision(self, proposal_id):
        try:
            return self.get_decision(f"test-decision-{proposal_id}")
        except LookupError:
            return None

    def get_revision(self, revision_request_id):
        return RevisionRequest.model_validate(self.get("revision", revision_request_id))

    def get_successor(self, proposal_id):
        try:
            successor = self.get("successor", proposal_id)
        except LookupError:
            return None
        return self.get_revision(successor["revision_request_id"])

    def request_revision(self, request):
        p = self.get_proposal(request.source_proposal_id)
        if (request.source_run_id != p.run_id or request.source_revision != p.revision
                or request.source_approval_hash != p.approval_hash or request.request.case_id != p.case_id
                or request.request.mode != ("simulation" if p.simulation else "preview")):
            raise ValueError("revision_source_mismatch")
        # This adapter is a test ledger only. Its atomic successor/projection
        # records exercise the port contract the backend owner will implement.
        with self.connection:
            self.connection.execute("BEGIN IMMEDIATE")
            existing = self.connection.execute("SELECT payload FROM records WHERE kind='successor' AND id=?", (p.proposal_id,)).fetchone()
            if existing:
                previous = self.get_revision(json.loads(existing[0])["revision_request_id"])
                if previous.reason != request.reason:
                    raise ValueError("revision_already_requested")
                return previous
            d = self.get_proposal_decision(p.proposal_id)
            if request.reason == "revision_requested":
                if d is None or d.kind != "request_context" or d.revoked:
                    raise ValueError("context_revision_requires_stored_decision")
            elif request.reason == "review_window_expired":
                if d is not None or self.clock() < p.review_expires_at:
                    raise ValueError("review_not_expired_or_decided")
            else:
                if (d is None or d.revoked or d.kind not in ("approve_remediation", "adopt_baseline")
                        or d.execution_expires_at is None or self.clock() < d.execution_expires_at):
                    raise ValueError("unused_approval_not_expired")
            if any(json.loads(row[0]).get("proposal_id") == p.proposal_id
                   for row in self.connection.execute("SELECT payload FROM records WHERE kind IN ('action','adoption')")):
                raise ValueError("action_already_started")
            projection = {"proposal_id": p.proposal_id,
                          "status": "SUPERSEDED" if request.reason == "revision_requested" else "EXPIRED",
                          "reason": request.reason}
            for kind, identifier, payload in [
                ("revision", request.revision_request_id, request.model_dump(mode="json")),
                ("successor", p.proposal_id, {"revision_request_id": request.revision_request_id}),
                ("proposal_transition", canonical_hash(projection), projection)]:
                self.connection.execute("INSERT INTO records VALUES (?,?,?)", (kind, identifier, json.dumps(payload)))
            self.connection.execute("INSERT OR REPLACE INTO records VALUES (?,?,?)",
                                    ("proposal_status", p.proposal_id, json.dumps(projection)))
        return request

    def publish(self, proposal: Proposal, report: dict) -> Proposal:
        stored = self.put_once("proposal", proposal.proposal_id, proposal.model_dump(mode="json"))
        # Publication retries may have a different clock; content identity must still agree.
        if stored["approval_hash"] != proposal.approval_hash:
            raise ValueError("proposal revision cannot change after publication")
        self.put_once("report", proposal.proposal_id, report)
        return Proposal.model_validate(stored)

    def get_proposal(self, proposal_id: str) -> Proposal:
        return Proposal.model_validate(self.get("proposal", proposal_id))

    def get_decision(self, decision_id: str) -> ApprovalDecision:
        return ApprovalDecision.model_validate(self.get("decision", decision_id))

    def record_test_decision(self, proposal_id: str, kind: str) -> ApprovalDecision:
        proposal = self.get_proposal(proposal_id)
        if not proposal.simulation or self.get_proposal_status(proposal_id) != "PENDING_APPROVAL":
            raise ValueError("local test decisions require a ready simulated proposal")
        now = self.clock()
        if now >= proposal.review_expires_at:
            raise ValueError("review_window_expired")
        if ((kind == "adopt_baseline" and proposal.action != "adopt_baseline") or
                (kind == "approve_remediation" and proposal.action != "remediate")):
            raise ValueError("decision_kind_does_not_match_proposal")
        decision = ApprovalDecision(decision_id=f"test-decision-{proposal_id}", proposal_id=proposal_id,
                                    revision=proposal.revision, kind=kind, authority="human",
                                    actor="local-demo-reviewer", simulation=True,
                                    approval_hash=proposal.approval_hash, policy_version=proposal.policy_version,
                                    target_uid=proposal.target.uid, approved_at=now,
                                    execution_expires_at=now + timedelta(seconds=proposal.execution_window_seconds)
                                    if kind in ("approve_remediation", "adopt_baseline") else None)
        payload = self.put_once("decision", decision.decision_id, decision.model_dump(mode="json"))
        if payload["kind"] != kind:
            raise ValueError("conflicting_decision")
        return ApprovalDecision.model_validate(payload)


class FixtureEvidencePort:
    def __init__(self, evidence: EvidenceBundle):
        self.evidence = evidence
        self.context_fetches = 0

    def load(self, request: AnalysisRequest) -> EvidenceBundle:
        if (request.snapshot_id, request.cluster_id, request.target_uid) != (
                self.evidence.snapshot_id, self.evidence.target.cluster_id, self.evidence.target.uid):
            raise ValueError("request and snapshot scope disagree")
        if request.mode == "simulation" and self.evidence.source_mode != "fixture":
            raise ValueError("captured evidence cannot enter simulation review")
        return self.evidence.model_copy(deep=True)

    def current(self, request: AnalysisRequest) -> EvidenceBundle:
        # Current refresh may have a new snapshot ID/version. The immutable load
        # path stays exact; the graph decides whether refreshed facts are stale.
        return self.evidence.model_copy(deep=True)

    def fetch_context(self, request, lookup) -> EvidenceBundle:
        if lookup.subject_id != self.evidence.subject.username or lookup.tool != "get_workload_context":
            raise ValueError("lookup outside allowed case")
        self.context_fetches += 1
        return self.load(request)

    def lookup(self, request, lookup, *, timeout_seconds):
        e = self.evidence
        base = {"tool": lookup.tool, "case_id": request.case_id, "subject_id": e.subject.username,
                "target_uid": e.target.uid, "evidence_refs": ["fixture-tool-source"], "reasons": []}
        if e.source_mode != "fixture" and lookup.tool in ("get_failure_history", "check_access"):
            return ToolResult(**{**base, "status": "unavailable", "reasons": ["backend_tool_unavailable"]})
        if lookup.tool == "get_failure_history":
            return ToolResult(**base, status="available", failures=[])
        if lookup.tool == "check_access":
            return ToolResult(**base, status="available", access=AccessResult(
                permission_id=lookup.permission_id, allowed=None, denied=None, evaluation_error="fixture_check_not_performed"))
        evidence = self.fetch_context(request, lookup) if lookup.tool == "get_workload_context" else self.current(request)
        return ToolResult(**base, status="available", evidence=evidence)


class SimulatedVerificationPort:
    simulation_only = True
    def check_adoption(self, evidence):
        if evidence.source_mode != "fixture":
            raise ValueError("simulated checks accept fixtures only")
        return [{"gate_id": "simulated_adoption_preconditions", "result": "pass", "reasons": []}]

    def check(self, evidence, result_rules):
        if evidence.source_mode != "fixture":
            raise ValueError("simulated checks accept fixtures only")
        return [{"gate_id": name, "result": "pass", "reasons": []}
                for name in ["simulated_dry_run", "simulated_functional_profile", "simulated_pause_and_authorization", "simulated_failure_history"]]


class PreviewVerificationPort:
    simulation_only = True
    def check_adoption(self, evidence):
        return [{"gate_id": "backend_adoption", "result": "unknown", "reasons": ["governance_unavailable"]}]

    def check(self, evidence, result_rules):
        return [{"gate_id": "backend_readiness", "result": "unknown", "reasons": ["verification_unavailable"]}]


class RecordingExecutor:
    """No Kubernetes calls and no mutation credentials, even for test approvals."""
    simulation_only = True

    def __init__(self, store: LocalTestStore):
        self.store = store

    def request(self, proposal_id, decision_id, action_key):
        proposal = self.store.get_proposal(proposal_id)
        decision = self.store.get_decision(decision_id)
        now = self.store.clock()
        if (self.store.get_proposal_status(proposal_id) not in ("PENDING_APPROVAL", "APPROVED")
                or proposal.action != "remediate" or not proposal.simulation or not decision.simulation or decision.revoked
                or decision.kind != "approve_remediation" or decision.proposal_id != proposal_id
                or decision.approval_hash != proposal.approval_hash
                or decision.revision != proposal.revision or decision.target_uid != proposal.target.uid
                or decision.policy_version != proposal.policy_version
                or decision.approved_at < proposal.published_at or decision.approved_at >= proposal.review_expires_at
                or decision.approved_at > now
                or decision.execution_expires_at is None or now >= decision.execution_expires_at):
            raise ValueError("invalid_test_authority")
        expected_key = canonical_hash([proposal_id, decision_id, proposal.approval_hash])
        if action_key != expected_key:
            raise ValueError("invalid_action_key")
        receipt = {"action_key": action_key, "proposal_id": proposal_id, "decision_id": decision_id,
                   "simulation": True, "status": "recorded_only", "cluster_write_performed": False,
                   "verification_performed": False, "baseline_activated": False, "recorded_at": now.isoformat()}
        return self.store.put_once("action", action_key, receipt)


class RecordingBaselinePort:
    """Record a test adoption request; never activate a real baseline."""
    simulation_only = True

    def __init__(self, store):
        self.store = store

    def adopt_approved_snapshot(self, proposal_id, decision_id, action_key):
        p = self.store.get_proposal(proposal_id)
        d = self.store.get_decision(decision_id)
        now = self.store.clock()
        if (self.store.get_proposal_status(proposal_id) not in ("PENDING_APPROVAL", "APPROVED")
                or p.action != "adopt_baseline" or not p.simulation or not d.simulation
                or d.kind != "adopt_baseline" or d.revoked or d.proposal_id != p.proposal_id
                or d.revision != p.revision or d.approval_hash != p.approval_hash
                or d.target_uid != p.target.uid or d.policy_version != p.policy_version
                or d.approved_at < p.published_at or d.approved_at >= p.review_expires_at
                or d.approved_at > now or d.execution_expires_at is None or now >= d.execution_expires_at
                or action_key != canonical_hash([proposal_id, decision_id, p.approval_hash])):
            raise ValueError("invalid_test_adoption_authority")
        receipt = {"action_key": action_key, "proposal_id": proposal_id, "decision_id": decision_id,
                   "simulation": True, "status": "recorded_only", "cluster_write_performed": False,
                   "baseline_activated": False, "snapshot_hash": p.evidence_hash, "recorded_at": now.isoformat()}
        return self.store.put_once("adoption", action_key, receipt)
