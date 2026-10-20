"""Bounded StateGraph with one side-effect-free durable review interrupt."""

from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Callable

from langgraph.graph import END, START, StateGraph
from langgraph.types import interrupt

from .contracts import (AnalysisReport, AnalysisRequest, ApprovalDecision, ChangePlan, EvidenceBundle, Gate,
                        Investigation, Proposal, ReadinessAssessment, utc_now, validate_request_evidence)
from .policy import (build_facts, canonical_hash, global_gates, render, risk_findings,
                     validate_investigation, validate_plan)
from .ports import BaselinePort, BudgetPort, EvidencePort, ExecutionPort, ModelClient, ReviewPort, VerificationPort
from .review import adoption_gates, adoption_proposal, checked_gates
from .state import GuardianState
from .versions import GRAPH_VERSION, current_versions, require_compatible_state


@dataclass
class Runtime:
    evidence: EvidencePort
    model: ModelClient
    review: ReviewPort
    verification: VerificationPort
    execution: ExecutionPort
    clock: Callable = utc_now
    budget: BudgetPort | None = None
    baseline: BaselinePort | None = None


def event(state, node, **details):
    return state.get("trace", []) + [{"node": node, **details}]


def bundle(state):
    return EvidenceBundle.model_validate(state["evidence"])


def report(state, runtime):
    return AnalysisReport.model_validate({"graph_version": GRAPH_VERSION, "versions": state["versions"],
            "case_id": state["request"]["case_id"], "run_id": state["request"]["run_id"],
            "mode": state["request"]["mode"],
            "producer": "deterministic" if state["request"].get("intent") == "adopt_baseline" else runtime.model.producer,
            "status": state.get("status"), "reason": state.get("reason"),
            "facts": state.get("facts", []), "security_risk": state.get("risk", []),
            "investigation": state.get("investigation"), "plan": state.get("plan"),
            "readiness": state.get("readiness"),
            "model_status": state.get("model_status"), "model_calls": state.get("model_calls", 0),
            "lookup_calls": state.get("lookup_calls", 0), "trace": state.get("trace", [])}).model_dump(mode="json")


def build_graph(runtime: Runtime, checkpointer):
    def accept_case(state, config):
        if state.get("started_at") is not None:
            require_compatible_state(state)
        req = AnalysisRequest.model_validate(state["request"])
        if config.get("configurable", {}).get("thread_id") != req.run_id:
            raise ValueError("run_id must equal checkpoint thread_id")
        return {"request": req.model_dump(mode="json"), "status": "ANALYZING", "reason": None,
                "versions": current_versions(req.policy_version).model_dump(mode="json"),
                "started_at": runtime.clock().isoformat(), "model_calls": 0, "lookup_rounds": 0,
                "lookup_calls": 0, "investigator_repairs": 0, "planner_repairs": 0,
                "model_status": "not_called", "investigation": None, "plan": None,
                "proposal": None, "receipt": None, "readiness": None,
                "trace": event(state, "accept_case", graph_version=GRAPH_VERSION)}

    def load_evidence(state):
        require_compatible_state(state)
        try:
            request = AnalysisRequest.model_validate(state["request"])
            raw = runtime.evidence.load(request)
            evidence = EvidenceBundle.model_validate(raw.model_dump(mode="json") if isinstance(raw, EvidenceBundle) else raw)
            validate_request_evidence(request, evidence)
        except (LookupError, ValueError, TypeError) as exc:
            return {"status": "BLOCKED", "reason": f"invalid_evidence: {str(exc)[:250]}",
                    "trace": event(state, "load_evidence", outcome="invalid_or_unavailable")}
        return {"evidence": evidence.model_dump(mode="json"),
                "trace": event(state, "load_evidence", source_mode=evidence.source_mode,
                               baseline_present=evidence.baseline_id is not None)}

    def facts_node(state):
        facts, gates = build_facts(bundle(state), runtime.clock())
        return {"facts": facts, "trace": event(state, "build_facts", gates=[g.model_dump() for g in gates])}

    def assess_risk(state):
        return {"risk": risk_findings(bundle(state)), "trace": event(state, "assess_risk")}

    def prepare_adoption(state):
        e = bundle(state)
        req = AnalysisRequest.model_validate(state["request"])
        gates = adoption_gates(e, runtime.verification, runtime.clock())
        simulation = req.mode == "simulation"
        transport = simulation and runtime.baseline is not None and runtime.baseline.simulation_only
        gates.append(Gate(gate_id="adoption_transport", result="pass" if transport else "unknown",
                          reasons=[] if transport else ["production_governance_unavailable"]))
        proposal = adoption_proposal(req, e, state["versions"], gates, runtime.clock())
        ready = proposal.status == "PENDING_APPROVAL"
        return {"proposal": proposal.model_dump(mode="json"),
                "status": "PENDING_REVIEW" if ready else "BLOCKED",
                "reason": None if ready else "adoption_readiness_incomplete",
                "trace": event(state, "prepare_adoption", review_ready=ready)}

    def model_stage(state, stage):
        e = bundle(state)
        count = runtime.budget.model_call_count(state["request"]["run_id"]) if runtime.budget else state["model_calls"]
        repairs_key = "investigator_repairs" if stage == "investigator" else "planner_repairs"
        output_type = Investigation if stage == "investigator" else ChangePlan
        elapsed = (runtime.clock() - datetime.fromisoformat(state["started_at"])).total_seconds()
        if count >= e.policy.model_calls or elapsed >= e.policy.active_run_timeout_seconds:
            return {"model_status": "budget_exhausted", "model_calls": count, "retry_stage": False, "status": "BLOCKED",
                    "reason": "model_budget_exhausted", "trace": event(state, stage, outcome="budget_exhausted")}
        payload = {"stage": stage, "facts": state["facts"], "deterministic_risk": state["risk"],
                   "target_uid": e.target.uid, "workload_context": e.context.model_dump(mode="json") if e.context else None,
                   "evidence_policy": e.policy.model_dump(),
                   "observation_window": e.usage.query_window.model_dump(mode="json") if e.usage else None,
                   "allowed_lookup": {"tool": "get_workload_context", "subject_id": e.subject.username},
                   "remaining_lookup_rounds": e.policy.lookup_rounds - state["lookup_rounds"],
                   "previous_validation_error": state.get("reason") if state.get("retry_stage") else None}
        if stage == "planner":
            payload["investigation"] = state["investigation"]
        if runtime.budget:
            count = runtime.budget.reserve_model_call(state["request"]["run_id"], stage, e.policy.model_calls) - 1
        try:
            output = output_type.model_validate(runtime.model.generate(stage, payload, output_type.model_json_schema()))
            if stage == "investigator":
                validate_investigation(output, state["facts"], e)
            else:
                validate_plan(output, state["facts"], Investigation.model_validate(state["investigation"]), e)
        except Exception as exc:
            retry = state[repairs_key] < 1 and count + 1 < e.policy.model_calls
            # This boundary contains no interrupt; GraphInterrupt is never swallowed here.
            return {"model_calls": count + 1, repairs_key: state[repairs_key] + int(retry),
                    "model_status": f"{stage}_failed", "retry_stage": retry,
                    "reason": f"{type(exc).__name__}: {str(exc)[:300]}",
                    "status": "ANALYZING" if retry else "BLOCKED",
                    "trace": event(state, stage, outcome="invalid_or_unavailable", repair=retry,
                                   model_attempt=getattr(runtime.model, "attempts", [])[-1:])}
        key = "investigation" if stage == "investigator" else "plan"
        return {key: output.model_dump(mode="json"), "model_calls": count + 1,
                "model_status": f"{stage}_valid", "retry_stage": False, "reason": None,
                "trace": event(state, stage, outcome="validated", producer=runtime.model.producer,
                               model_attempt=getattr(runtime.model, "attempts", [])[-1:],
                               metadata=getattr(runtime.model, "metadata", [])[-1:] if runtime.model.producer != "scripted-test" else [])}

    def investigate_context(state):
        return model_stage(state, "investigator")

    def investigation_route(state):
        if state["retry_stage"]:
            return "investigate_context"
        if state["status"] == "BLOCKED":
            return "finalize"
        requests = state["investigation"]["context_requests"]
        policy = bundle(state).policy
        if requests and state["lookup_rounds"] < policy.lookup_rounds and state["lookup_calls"] + len(requests) <= policy.lookup_calls:
            return "fetch_context"
        return "select_strategy"

    def fetch_context(state):
        from .contracts import ContextLookup
        e = bundle(state)
        req = AnalysisRequest.model_validate(state["request"])
        requests = state["investigation"]["context_requests"]
        try:
            for lookup in requests:
                refreshed = runtime.evidence.fetch_context(req, ContextLookup.model_validate(lookup))
                # Context lookup cannot change grants, usage, baseline, policy or authority.
                unchanged = ["target", "subject", "binding", "usage", "baseline_id", "policy", "source_mode"]
                if any(getattr(refreshed, key) != getattr(e, key) for key in unchanged):
                    raise ValueError("context lookup changed non-context evidence")
                e = refreshed
        except Exception as exc:
            return {"status": "BLOCKED", "reason": f"context_lookup_failed: {type(exc).__name__}",
                    "lookup_calls": state["lookup_calls"] + len(requests),
                    "lookup_rounds": state["lookup_rounds"] + 1,
                    "trace": event(state, "fetch_context", outcome="failed")}
        return {"evidence": e.model_dump(mode="json"), "lookup_calls": state["lookup_calls"] + len(requests),
                "lookup_rounds": state["lookup_rounds"] + 1, "trace": event(state, "fetch_context", outcome="loaded")}

    def select_strategy(state):
        assessment = state["investigation"]
        eligible = {f["permission_id"] for f in state["facts"] if f["eligible"]}
        suggested = {a["permission_id"] for a in assessment["permission_assessments"] if a["recommendation"] == "propose_remove"}
        if not suggested & eligible:
            has_unknown = any(set(f["reason_codes"]) - {"observed_use", "known_dependency"} for f in state["facts"])
            return {"status": "BLOCKED" if has_unknown else "NO_CHANGE",
                    "reason": "no_supported_removal" if has_unknown else "no_change",
                    "trace": event(state, "select_strategy", supported_candidates=0)}
        return {"trace": event(state, "select_strategy", supported_candidates=len(suggested & eligible))}

    def plan_change(state):
        return model_stage(state, "planner")

    def render_and_validate(state):
        e = bundle(state)
        plan = ChangePlan.model_validate(state["plan"])
        removed = {d.permission_id for d in plan.decisions if d.action == "remove"}
        if not removed:
            return {"status": "NO_CHANGE", "reason": "planner_retained_all", "trace": event(state, "render_and_validate")}
        rendered = render(e, removed)
        gates = global_gates(e, runtime.clock())
        current_facts, _ = build_facts(e, runtime.clock())
        eligible = {f["permission_id"] for f in current_facts if f["eligible"]}
        gates.append(Gate(gate_id="removal_evidence", result="pass" if removed <= eligible else "fail",
                          reasons=[] if removed <= eligible else ["removal_no_longer_eligible"]))
        gates.extend(checked_gates(runtime.verification.check(e, rendered["result_rules"]), "verification_unavailable"))
        ready = all(g.result == "pass" for g in gates)
        req = AnalysisRequest.model_validate(state["request"])
        simulation = req.mode == "simulation"
        if simulation and (e.source_mode != "fixture" or not runtime.execution.simulation_only):
            raise ValueError("simulation cannot use captured evidence or real executor")
        # Captured/live previews cannot acquire executable authority through local checks.
        ready = ready and simulation
        gates.append(Gate(gate_id="execution_transport", result="pass" if simulation else "unknown",
                          reasons=[] if simulation else ["production_governance_unavailable"]))
        readiness = ReadinessAssessment(
            policy_version=e.policy.policy_version, evidence_revision=e.revision, gates=gates,
            allowed_removal_ids=sorted(eligible),
            protected_permission_ids=sorted(f["permission_id"] for f in current_facts if f["protected"]),
            residual_uncertainties=state["investigation"]["uncertainty"], execution_ready=ready)
        now = runtime.clock()
        evidence_hash = canonical_hash(e.model_dump(mode="json"))
        candidate_hash = canonical_hash({"target_uid": e.target.uid, "namespace": e.target.namespace,
                                        "strategy": plan.strategy_id, "rules": rendered["result_rules"]})
        approval_hash = canonical_hash({"candidate": candidate_hash, "evidence": evidence_hash,
                                       "patch": rendered["patch"], "policy": e.policy.model_dump(),
                                       "verification": plan.verification_profile_id, "recovery_authorized": False,
                                       "uncertainty": state["investigation"]["uncertainty"],
                                       "versions": state["versions"], "simulation": simulation})
        proposal = Proposal(proposal_id=f"proposal-{req.run_id}-r{req.revision}", case_id=req.case_id, run_id=req.run_id,
                            revision=req.revision, simulation=simulation, status="PENDING_APPROVAL" if ready else "BLOCKED",
                            target=e.target, unchanged_binding=e.binding, evidence_hash=evidence_hash, candidate_hash=candidate_hash,
                            approval_hash=approval_hash, policy_version=e.policy.policy_version,
                            removed_permission_ids=sorted(removed), gates=gates,
                            uncertainty=state["investigation"]["uncertainty"], published_at=now,
                            review_expires_at=now + timedelta(seconds=e.policy.review_window_seconds),
                            execution_window_seconds=e.policy.execution_window_seconds,
                            verification_profile_id=plan.verification_profile_id, **rendered)
        return {"proposal": proposal.model_dump(mode="json"), "readiness": readiness.model_dump(mode="json"),
                "status": "PENDING_REVIEW" if ready else "BLOCKED",
                "reason": None if ready else "readiness_incomplete",
                "trace": event(state, "render_and_validate", execution_ready=ready, simulation=simulation)}

    def publish_review(state):
        p = runtime.review.publish(Proposal.model_validate(state["proposal"]), report(state, runtime))
        return {"proposal": p.model_dump(mode="json"), "trace": event(state, "publish_review", proposal_id=p.proposal_id)}

    def await_review(state):
        # No model invocation, publication or database write belongs in this node.
        decision_id = interrupt({"proposal_id": state["proposal"]["proposal_id"], "simulation": state["proposal"]["simulation"],
                                 "action": state["proposal"]["action"],
                                 "approval_hash": state["proposal"]["approval_hash"],
                                 "review_expires_at": state["proposal"]["review_expires_at"],
                                 "message": "Resume with a stored local TEST decision ID only."})
        return {"decision_id": decision_id, "trace": event(state, "await_review", outcome="resumed")}

    def revalidate(state):
        try:
            if not isinstance(state.get("decision_id"), str):
                raise ValueError("resume_requires_decision_id")
            proposal = runtime.review.get_proposal(state["proposal"]["proposal_id"])
            decision: ApprovalDecision = runtime.review.get_decision(state["decision_id"])
            now = runtime.clock()
            if (decision.proposal_id != proposal.proposal_id or decision.revision != proposal.revision
                    or decision.approval_hash != proposal.approval_hash or decision.target_uid != proposal.target.uid
                    or decision.policy_version != proposal.policy_version or decision.revoked
                    or decision.authority != "human" or not proposal.simulation or not decision.simulation
                    or decision.approved_at < proposal.published_at
                    or decision.approved_at >= proposal.review_expires_at or decision.approved_at > now):
                raise ValueError("invalid_or_revoked_decision")
            if decision.kind in ("reject", "acknowledge", "request_context"):
                status = {"reject": "REJECTED", "acknowledge": "NO_CHANGE", "request_context": "STALE"}[decision.kind]
                return {"status": status, "reason": "revision_requested" if decision.kind == "request_context" else decision.kind,
                        "trace": event(state, "revalidate", decision_kind=decision.kind)}
            if decision.execution_expires_at is None or now >= decision.execution_expires_at:
                raise ValueError("execution_window_expired")
            expected_kind = "adopt_baseline" if proposal.action == "adopt_baseline" else "approve_remediation"
            if decision.kind != expected_kind:
                raise ValueError("decision_kind_does_not_match_proposal")
            req = AnalysisRequest.model_validate(state["request"])
            current = runtime.evidence.current(req)
            if canonical_hash(current.model_dump(mode="json")) != proposal.evidence_hash:
                raise ValueError("material_evidence_changed")
            if proposal.action == "adopt_baseline":
                gates = adoption_gates(current, runtime.verification, now)
                if (runtime.baseline is None or not runtime.baseline.simulation_only
                        or any(g.result != "pass" for g in gates)):
                    raise ValueError("current_adoption_readiness_failed")
                return {"status": "EXECUTION_REQUESTED", "reason": None,
                        "trace": event(state, "revalidate", decision_kind=decision.kind, outcome="simulated_adoption_authority_valid")}
            facts, gates = build_facts(current, now)
            eligible = {f["permission_id"] for f in facts if f["eligible"]}
            if not set(proposal.removed_permission_ids) <= eligible or any(g.result != "pass" for g in gates):
                raise ValueError("current_readiness_failed")
            checks = checked_gates(runtime.verification.check(current, [r.model_dump(exclude_defaults=True) for r in proposal.result_rules]),
                                   "verification_unavailable")
            if any(g.result != "pass" for g in checks):
                raise ValueError("backend_readiness_failed")
            return {"status": "EXECUTION_REQUESTED", "reason": None,
                    "trace": event(state, "revalidate", decision_kind=decision.kind, outcome="simulated_authority_valid")}
        except (LookupError, ValueError, TypeError) as exc:
            return {"status": "STALE", "reason": str(exc)[:300], "trace": event(state, "revalidate", outcome="blocked")}

    def request_execution(state):
        proposal = state["proposal"]
        key = canonical_hash([proposal["proposal_id"], state["decision_id"], proposal["approval_hash"]])
        try:
            receipt = runtime.execution.request(proposal["proposal_id"], state["decision_id"], key)
        except (LookupError, ValueError) as exc:
            return {"status": "STALE", "reason": str(exc), "trace": event(state, "request_execution", outcome="blocked")}
        return {"receipt": receipt, "trace": event(state, "request_execution", outcome="recorded_only")}

    def commit_baseline_adoption(state):
        p = state["proposal"]
        key = canonical_hash([p["proposal_id"], state["decision_id"], p["approval_hash"]])
        try:
            if runtime.baseline is None:
                raise ValueError("adoption_port_unavailable")
            receipt = runtime.baseline.adopt_approved_snapshot(p["proposal_id"], state["decision_id"], key)
        except (LookupError, ValueError) as exc:
            return {"status": "STALE", "reason": str(exc), "trace": event(state, "commit_baseline_adoption", outcome="blocked")}
        return {"receipt": receipt, "trace": event(state, "commit_baseline_adoption", outcome="recorded_only")}

    def finalize(state):
        require_compatible_state(state)
        if state.get("proposal"):
            runtime.review.publish(Proposal.model_validate(state["proposal"]), report(state, runtime))
        runtime.review.finalize_run(state["request"]["run_id"], report(state, runtime))
        return {"trace": event(state, "finalize", status=state["status"])}

    graph = StateGraph(GuardianState)

    def compatible_node(function):
        def checked(state):
            require_compatible_state(state)
            return function(state)
        return checked

    for name, function in [("accept_case", accept_case), ("load_evidence", load_evidence),
                           ("build_facts", facts_node), ("assess_risk", assess_risk),
                           ("prepare_adoption", prepare_adoption),
                           ("investigate_context", investigate_context), ("fetch_context", fetch_context),
                           ("select_strategy", select_strategy), ("plan_change", plan_change),
                           ("render_and_validate", render_and_validate), ("publish_review", publish_review),
                           ("await_review", await_review), ("revalidate", revalidate),
                           ("request_execution", request_execution), ("commit_baseline_adoption", commit_baseline_adoption),
                           ("finalize", finalize)]:
        # Guard direct Command resume and crash recovery, not only CLI callers.
        graph.add_node(name, function if name in ("accept_case", "load_evidence", "finalize") else compatible_node(function))
    graph.add_edge(START, "accept_case")
    graph.add_edge("accept_case", "load_evidence")
    graph.add_conditional_edges("load_evidence", lambda s: "finalize" if s["status"] == "BLOCKED" else "build_facts",
                                ["finalize", "build_facts"])
    graph.add_edge("build_facts", "assess_risk")
    graph.add_conditional_edges("assess_risk", lambda s: "prepare_adoption" if s["request"]["intent"] == "adopt_baseline" else "investigate_context",
                                ["prepare_adoption", "investigate_context"])
    graph.add_conditional_edges("prepare_adoption", lambda s: "publish_review" if s["status"] == "PENDING_REVIEW" else "finalize",
                                ["publish_review", "finalize"])
    graph.add_conditional_edges("investigate_context", investigation_route,
                                ["investigate_context", "fetch_context", "select_strategy", "finalize"])
    graph.add_conditional_edges("fetch_context", lambda s: "finalize" if s["status"] == "BLOCKED" else "build_facts",
                                ["finalize", "build_facts"])
    graph.add_conditional_edges("select_strategy", lambda s: "finalize" if s["status"] in ("BLOCKED", "NO_CHANGE") else "plan_change",
                                ["finalize", "plan_change"])
    graph.add_conditional_edges("plan_change", lambda s: "plan_change" if s["retry_stage"] else "finalize" if s["status"] == "BLOCKED" else "render_and_validate",
                                ["plan_change", "finalize", "render_and_validate"])
    graph.add_conditional_edges("render_and_validate", lambda s: "publish_review" if s["status"] == "PENDING_REVIEW" else "finalize",
                                ["publish_review", "finalize"])
    graph.add_edge("publish_review", "await_review")
    graph.add_edge("await_review", "revalidate")
    graph.add_conditional_edges("revalidate", lambda s: ("commit_baseline_adoption" if s["proposal"]["action"] == "adopt_baseline" else "request_execution")
                                if s["status"] == "EXECUTION_REQUESTED" else "finalize",
                                ["request_execution", "commit_baseline_adoption", "finalize"])
    graph.add_edge("request_execution", "finalize")
    graph.add_edge("commit_baseline_adoption", "finalize")
    graph.add_edge("finalize", END)
    return graph.compile(checkpointer=checkpointer)
