"""Durable local test records behind ports, not the team's production ledger."""

import json
import sqlite3
from datetime import timedelta
from pathlib import Path

from ..contracts import AnalysisRequest, ApprovalDecision, EvidenceBundle, Proposal, utc_now
from ..policy import canonical_hash


class LocalTestStore:
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

    def reserve_model_call(self, run_id: str, stage: str, limit: int) -> int:
        # Commit the budget before inference, so a crashed call still consumes capacity.
        with self.connection:
            self.connection.execute("BEGIN IMMEDIATE")
            number = self.model_call_count(run_id) + 1
            if number > limit:
                raise ValueError("model_budget_exhausted")
            self.connection.execute("INSERT INTO model_calls VALUES (?,?,?)", (run_id, number, stage))
        return number

    def finalize_run(self, run_id: str, result: dict):
        return self.put_once("outcome", run_id, result)

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
        if not proposal.simulation or proposal.status != "PENDING_APPROVAL":
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
        return self.load(request)

    def fetch_context(self, request, lookup) -> EvidenceBundle:
        if lookup.subject_id != self.evidence.subject.username or lookup.tool != "get_workload_context":
            raise ValueError("lookup outside allowed case")
        self.context_fetches += 1
        return self.load(request)


class SimulatedVerificationPort:
    def check_adoption(self, evidence):
        if evidence.source_mode != "fixture":
            raise ValueError("simulated checks accept fixtures only")
        return [{"gate_id": "simulated_adoption_preconditions", "result": "pass", "reasons": []}]

    def check(self, evidence, result_rules):
        if evidence.source_mode != "fixture":
            raise ValueError("simulated checks accept fixtures only")
        return [{"gate_id": name, "result": "pass", "reasons": []}
                for name in ["simulated_dry_run", "simulated_functional_profile", "simulated_pause_and_authorization"]]


class PreviewVerificationPort:
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
        if (proposal.action != "remediate" or not proposal.simulation or not decision.simulation or decision.revoked
                or decision.kind != "approve_remediation" or decision.proposal_id != proposal_id
                or decision.approval_hash != proposal.approval_hash
                or decision.revision != proposal.revision or decision.target_uid != proposal.target.uid
                or decision.policy_version != proposal.policy_version
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
        if (p.action != "adopt_baseline" or not p.simulation or not d.simulation
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
