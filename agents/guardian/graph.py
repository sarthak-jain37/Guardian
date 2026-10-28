"""Bounded StateGraph with one side-effect-free durable review interrupt."""

from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Callable

from langgraph.graph import END, START, StateGraph
from langgraph.types import interrupt

from .contracts import (AnalysisReport, AnalysisRequest, ApprovalDecision, ChangePlan, ContextLookup, EvidenceBundle, Gate,
                        Investigation, Proposal, ReadinessAssessment, utc_now, validate_request_evidence)
from .policy import (build_facts, canonical_hash, global_gates, render, risk_findings,
                     validate_investigation, validate_plan)
from .ports import BaselinePort, BudgetPort, EvidencePort, ExecutionPort, ModelClient, ReviewPort, VerificationPort
from .review import adoption_gates, adoption_proposal, checked_gates
from .revisions import prepare_revision, read_evidence
from .state import GuardianState
from .versions import GRAPH_VERSION, current_versions, require_compatible_state
from .modeling import call_model, model_config, model_input
from .evidence_tools import allowed_lookups, validate_lookup, validate_result
from .governance import (GovernancePort, GovernedDecision, action_key, receipt_status,
                         validate_preflight, validate_receipt)


@dataclass
class Runtime:
    evidence: EvidencePort
    model: ModelClient
    review: ReviewPort
    verification: VerificationPort
    execution: ExecutionPort | None
    clock: Callable = utc_now
    budget: BudgetPort | None = None
    baseline: BaselinePort | None = None
    governance: GovernancePort | None = None


def governed_transport(runtime):
    return (runtime.governance is not None and not runtime.governance.simulation_only
            and getattr(runtime.review, "authoritative", False)
            and not getattr(runtime.verification, "simulation_only", True))


def event(state, node, **details):
    return state.get("trace", []) + [{"node": node, **details}]


def bundle(state):
    return EvidenceBundle.model_validate(state["evidence"])


def report(state, runtime):
    return AnalysisReport.model_validate({"graph_version": GRAPH_VERSION, "versions": state["versions"],
            "case_id": state["request"]["case_id"], "run_id": state["request"]["run_id"],
            "mode": state["request"]["mode"],
            "producer": "deterministic" if state["request"].get("intent") == "adopt_baseline" else state.get("analysis_producer", runtime.model.producer),
            "status": state.get("status"), "reason": state.get("reason"),
            "facts": state.get("facts", []), "security_risk": state.get("risk", []),
            "investigation": state.get("investigation"), "plan": state.get("plan"),
            "readiness": state.get("readiness"),
            "model_status": state.get("model_status"), "model_calls": state.get("model_calls", 0),
            "lookup_calls": state.get("lookup_calls", 0), "trace": state.get("trace", []),
            "execution_outcome": state.get("execution_outcome")}).model_dump(mode="json")


def build_graph(runtime: Runtime, checkpointer):
    if runtime.budget is None:
        raise ValueError("durable_budget_port_required")
    def accept_case(state, config):
        if state.get("started_at") is not None:
            require_compatible_state(state)
            raise ValueError("run_already_started: use a recorded successor revision")
        req = AnalysisRequest.model_validate(state["request"])
        if config.get("configurable", {}).get("thread_id") != req.run_id:
            raise ValueError("run_id must equal checkpoint thread_id")
        return {"request": req.model_dump(mode="json"), "status": "ANALYZING", "reason": None,
                "versions": current_versions(req.policy_version).model_dump(mode="json"),
                "started_at": runtime.clock().isoformat(), "model_calls": 0, "lookup_rounds": 0,
                "lookup_calls": 0, "investigator_repairs": 0, "planner_repairs": 0,
                "model_status": "not_called", "investigation": None, "plan": None,
                "proposal": None, "receipt": None, "readiness": None, "revision_request": None,
                "analysis_producer": runtime.model.producer,
                "model_config_hash": model_config(runtime.model).fingerprint(),
                "tool_results": [],
                "execution_outcome": None, "preflight": None, "recovery_authority_id": None,
                "trace": event(state, "accept_case", graph_version=GRAPH_VERSION)}

    def load_evidence(state):
        require_compatible_state(state)
        try:
            request = AnalysisRequest.model_validate(state["request"])
            ticket = None
            if request.revision_request_id:
                ticket = runtime.review.get_revision(request.revision_request_id)
                if ticket.request != request:
                    raise ValueError("revision_request_does_not_match_intake")
            context_revision = ticket is not None and ticket.reason == "revision_requested"
            raw = runtime.evidence.current(request) if context_revision else runtime.evidence.load(request)
            evidence = read_evidence(raw)
            if context_revision:
                # A context request is an analysis intent. Its answer can arrive
                # after queueing; bind the actual snapshot before fresh analysis.
                source = runtime.review.get_proposal(ticket.source_proposal_id)
                if ((source.target.kind, source.target.namespace, source.target.name, source.target.uid) !=
                        (evidence.target.kind, evidence.target.namespace, evidence.target.name, evidence.target.uid)):
                    raise ValueError("revision_target_scope_changed")
                request = request.model_copy(update={"snapshot_id": evidence.snapshot_id})
            elif ticket is not None and ticket.evidence_hash != canonical_hash(evidence.model_dump(mode="json")):
                raise ValueError("revision_request_does_not_match_current_evidence")
            validate_request_evidence(request, evidence)
        except (LookupError, ValueError, TypeError) as exc:
            return {"status": "BLOCKED", "reason": f"invalid_evidence: {str(exc)[:250]}",
                    "trace": event(state, "load_evidence", outcome="invalid_or_unavailable")}
        return {"request": request.model_dump(mode="json"), "evidence": evidence.model_dump(mode="json"),
                "trace": event(state, "load_evidence", source_mode=evidence.source_mode,
                               baseline_present=evidence.baseline_id is not None)}

    def facts_node(state):
        facts, gates = build_facts(bundle(state), runtime.clock())
        tool_refs = {ref for result in state["tool_results"] for ref in result["evidence_refs"]}
        tool_refs.update(ref for result in state["tool_results"] for failure in result.get("failures", []) for ref in failure["evidence_refs"])
        for fact in facts:
            fact["evidence_ids"] = sorted(set(fact["evidence_ids"]) | tool_refs)
        readiness = ReadinessAssessment(policy_version=bundle(state).policy.policy_version,
                                        evidence_revision=bundle(state).revision, gates=gates,
                                        allowed_removal_ids=[f["permission_id"] for f in facts if f["eligible"]],
                                        protected_permission_ids=[f["permission_id"] for f in facts if f["protected"]],
                                        residual_uncertainties=[], execution_ready=False)
        return {"facts": facts, "readiness": readiness.model_dump(mode="json"),
                "trace": event(state, "build_facts", gates=[g.model_dump() for g in gates])}

    def assess_risk(state):
        return {"risk": risk_findings(bundle(state)), "trace": event(state, "assess_risk")}

    def prepare_adoption(state):
        e = bundle(state)
        req = AnalysisRequest.model_validate(state["request"])
        gates = adoption_gates(e, runtime.verification, runtime.clock())
        simulation = req.mode == "simulation"
        transport = ((simulation and runtime.baseline is not None and runtime.baseline.simulation_only)
                     or (req.mode == "governed" and governed_transport(runtime)))
        gates.append(Gate(gate_id="adoption_transport", result="pass" if transport else "unknown",
                          reasons=[] if transport else ["production_governance_unavailable"]))
        proposal = adoption_proposal(req, e, state["versions"], gates, runtime.clock())
        ready = proposal.status == "PENDING_APPROVAL"
        return {"proposal": proposal.model_dump(mode="json"),
                "status": "PENDING_REVIEW" if ready else "BLOCKED",
                "reason": None if ready else "adoption_readiness_incomplete",
                "trace": event(state, "prepare_adoption", review_ready=ready)}

    def restore_analysis(state):
        ticket = runtime.review.get_revision(state["request"]["revision_request_id"])
        source = runtime.review.get_proposal(ticket.source_proposal_id)
        previous = runtime.review.get_report(ticket.source_run_id)
        if (source.approval_hash != ticket.source_approval_hash or source.case_id != state["request"]["case_id"]
                or previous["versions"] != state["versions"]):
            return {"status": "BLOCKED", "reason": "incompatible_revision_source", "trace": event(state, "restore_analysis", outcome="blocked")}
        hashes = {t["model_result"]["config_hash"] for t in previous["trace"] if t.get("model_result")}
        if hashes and hashes != {state["model_config_hash"]}:
            return {"trace": event(state, "restore_analysis", outcome="reanalyze_configuration_changed")}
        try:
            investigation = Investigation.model_validate(previous["investigation"])
            plan = ChangePlan.model_validate(previous["plan"])
            validate_investigation(investigation, state["facts"], bundle(state))
            validate_plan(plan, state["facts"], investigation, bundle(state))
        except (ValueError, TypeError):
            return {"trace": event(state, "restore_analysis", outcome="reanalyze")}
        return {"investigation": investigation.model_dump(mode="json"), "plan": plan.model_dump(mode="json"),
                "analysis_producer": previous["producer"], "model_status": "analysis_reused",
                "trace": event(state, "restore_analysis", source_run_id=ticket.source_run_id, outcome="reused")}

    def after_risk(state):
        if state["request"]["intent"] == "adopt_baseline":
            return "prepare_adoption"
        ticket_id = state["request"].get("revision_request_id")
        if ticket_id and runtime.review.get_revision(ticket_id).reuse_analysis:
            return "restore_analysis"
        return "investigate_context"

    def model_stage(state, stage):
        e = bundle(state)
        count = runtime.budget.model_call_count(state["request"]["run_id"]) if runtime.budget else state["model_calls"]
        repairs_key = "investigator_repairs" if stage == "investigator" else "planner_repairs"
        output_type = Investigation if stage == "investigator" else ChangePlan
        elapsed = (runtime.clock() - datetime.fromisoformat(state["started_at"])).total_seconds()
        settings = model_config(runtime.model)
        if settings.fingerprint() != state.get("model_config_hash"):
            return {"model_status": "configuration_changed", "model_calls": count, "retry_stage": False,
                    "status": "BLOCKED", "reason": "model_configuration_changed",
                    "trace": event(state, stage, outcome="configuration_changed")}
        active_limit = min(e.policy.active_run_timeout_seconds, settings.active_run_timeout_seconds)
        repairing = state.get("retry_stage", False)
        if repairing and runtime.budget.model_repair_count(state["request"]["run_id"], stage):
            return {"model_status": "repair_exhausted", "model_calls": count, "retry_stage": False, repairs_key: 1,
                    "status": "BLOCKED", "reason": "stage_repair_budget_exhausted",
                    "trace": event(state, stage, outcome="repair_exhausted_after_restart")}
        if count >= e.policy.model_calls or elapsed >= active_limit:
            return {"model_status": "budget_exhausted", "model_calls": count, "retry_stage": False, "status": "BLOCKED",
                    "reason": "model_budget_exhausted", "trace": event(state, stage, outcome="budget_exhausted")}
        payload = {"stage": stage, "facts": state["facts"], "deterministic_risk": state["risk"],
                   "target_uid": e.target.uid, "workload_context": e.context.model_dump(mode="json") if e.context else None,
                   "evidence_policy": e.policy.model_dump(),
                   "observation_window": e.usage.query_window.model_dump(mode="json") if e.usage else None,
                   "allowed_lookup": {"tool": "get_workload_context", "subject_id": e.subject.username},
                   "allowed_lookups": allowed_lookups(AnalysisRequest.model_validate(state["request"]), e, state["facts"]),
                   "tool_results": [{k: v for k, v in r.items() if k != "evidence"} for r in state["tool_results"]],
                   "remaining_lookup_rounds": e.policy.lookup_rounds - state["lookup_rounds"],
                   "previous_validation_error": state.get("reason") if state.get("retry_stage") else None}
        if stage == "planner":
            payload["investigation"] = state["investigation"]
        if runtime.budget:
            count = runtime.budget.reserve_model_call(state["request"]["run_id"], stage, e.policy.model_calls, repair=repairing) - 1
        try:
            result = call_model(runtime.model, stage, payload, output_type.model_json_schema(),
                                min(settings.request_timeout_seconds, active_limit - elapsed))
            if result.error:
                raise ValueError(result.error)
            output = output_type.model_validate(result.response)
            if stage == "investigator":
                validate_investigation(output, state["facts"], e)
                for lookup in output.context_requests:
                    validate_lookup(lookup, AnalysisRequest.model_validate(state["request"]), e, state["facts"])
            else:
                validate_plan(output, state["facts"], Investigation.model_validate(state["investigation"]), e)
        except Exception as exc:
            retry = runtime.budget.model_repair_count(state["request"]["run_id"], stage) < 1 and count + 1 < e.policy.model_calls
            # This boundary contains no interrupt; GraphInterrupt is never swallowed here.
            return {"model_calls": count + 1, repairs_key: runtime.budget.model_repair_count(state["request"]["run_id"], stage),
                    "model_status": f"{stage}_failed", "retry_stage": retry,
                    "reason": f"{type(exc).__name__}: {str(exc)[:300]}",
                    "status": "ANALYZING" if retry else "BLOCKED",
                    "trace": event(state, stage, outcome="invalid_or_unavailable", repair=retry,
                                   model_result=result.model_dump(mode="json") if "result" in locals() else None,
                                   model_input=model_input(stage, payload, output_type.model_json_schema(), runtime.model))}
        key = "investigation" if stage == "investigator" else "plan"
        return {key: output.model_dump(mode="json"), "model_calls": count + 1,
                repairs_key: runtime.budget.model_repair_count(state["request"]["run_id"], stage),
                "model_status": f"{stage}_valid", "retry_stage": False, "reason": None,
                "trace": event(state, stage, outcome="validated", producer=runtime.model.producer,
                               model_result=result.model_dump(mode="json"),
                               model_input=model_input(stage, payload, output_type.model_json_schema(), runtime.model))}

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
        if requests:
            return "lookup_exhausted"
        return "select_strategy"

    def lookup_exhausted(state):
        return {"status": "BLOCKED", "reason": "lookup_budget_exhausted",
                "trace": event(state, "fetch_context", outcome="budget_exhausted")}

    def fetch_context(state):
        e = bundle(state)
        req = AnalysisRequest.model_validate(state["request"])
        requests = state["investigation"]["context_requests"]
        results = list(state["tool_results"])
        batch = None
        try:
            key = canonical_hash([req.run_id, state["lookup_rounds"], requests])
            batch = runtime.budget.reserve_lookup_batch(req.run_id, key, requests, e.policy.lookup_rounds, e.policy.lookup_calls)
            for index, raw_lookup in enumerate(requests):
                lookup = ContextLookup.model_validate(raw_lookup)
                validate_lookup(lookup, req, e, state["facts"])
                raw = runtime.budget.begin_lookup(key, index)
                if raw is None:
                    remaining = min(e.policy.active_run_timeout_seconds, model_config(runtime.model).active_run_timeout_seconds) - (
                        runtime.clock() - datetime.fromisoformat(state["started_at"])).total_seconds()
                    if remaining <= 0:
                        raise ValueError("active_run_timeout")
                    raw = runtime.evidence.lookup(req, lookup, timeout_seconds=min(30, remaining))
                    result = validate_result(raw, lookup, req, e)
                    if len(result.model_dump_json().encode()) > model_config(runtime.model).max_input_bytes:
                        raise ValueError("tool_result_too_large")
                    runtime.budget.complete_lookup(key, index, result.model_dump(mode="json"))
                else:
                    result = validate_result(raw, lookup, req, e)
                e = result.evidence or e
                results.append(result.model_dump(mode="json"))
        except Exception as exc:
            visible = {"lookup_outcome_uncertain_after_restart", "lookup_budget_exhausted", "active_run_timeout",
                       "tool_result_too_large", "lookup_changed_unrelated_evidence", "tool_result_scope_mismatch"}
            reason = str(exc) if type(exc) is ValueError and str(exc) in visible else type(exc).__name__
            return {"status": "BLOCKED", "reason": f"context_lookup_failed: {reason[:200]}",
                    "tool_results": results,
                    "lookup_calls": batch["total_calls"] if batch else state["lookup_calls"],
                    "lookup_rounds": batch["round"] if batch else state["lookup_rounds"],
                    "trace": event(state, "fetch_context", outcome="failed")}
        return {"evidence": e.model_dump(mode="json"), "lookup_calls": batch["total_calls"],
                "lookup_rounds": batch["round"], "tool_results": results,
                "trace": event(state, "fetch_context", outcome="loaded", results=results[-len(requests):])}

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
        candidate_hash = canonical_hash({"target_uid": e.target.uid, "namespace": e.target.namespace,
                                        "strategy": plan.strategy_id, "rules": rendered["result_rules"]})
        gates = global_gates(e, runtime.clock())
        verification = checked_gates(runtime.verification.check(e, rendered["result_rules"]), "verification_unavailable")
        failures = [f for result in state["tool_results"] for f in result.get("failures", [])]
        blocked = any(f["blocks_candidate"] and f["candidate_hash"] == candidate_hash
                      and f["target_uid"] == e.target.uid and f["policy_version"] == e.policy.policy_version
                      and e.context and f["workload_uid"] == e.context.workload_uid and f["image_digest"] == e.context.image_digest
                      for f in failures)
        history_available = (any(r["tool"] == "get_failure_history" and r["status"] == "available" for r in state["tool_results"])
                             or any(g.gate_id in ("failure_history", "simulated_failure_history") and g.result == "pass" for g in verification))
        gates.append(Gate(gate_id="candidate_failure_history", result="fail" if blocked else "pass" if history_available else "unknown",
                          reasons=["prior_candidate_failure"] if blocked else [] if history_available else ["failure_history_unavailable"]))
        current_facts, _ = build_facts(e, runtime.clock())
        eligible = {f["permission_id"] for f in current_facts if f["eligible"]}
        gates.append(Gate(gate_id="removal_evidence", result="pass" if removed <= eligible else "fail",
                          reasons=[] if removed <= eligible else ["removal_no_longer_eligible"]))
        gates.extend(verification)
        ready = all(g.result == "pass" for g in gates)
        req = AnalysisRequest.model_validate(state["request"])
        simulation = req.mode == "simulation"
        if simulation and (e.source_mode != "fixture" or runtime.execution is None or not runtime.execution.simulation_only):
            raise ValueError("simulation cannot use captured evidence or real executor")
        transport = simulation or (req.mode == "governed" and governed_transport(runtime))
        ready = ready and transport
        gates.append(Gate(gate_id="execution_transport", result="pass" if transport else "unknown",
                          reasons=[] if transport else ["production_governance_unavailable"]))
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
                                       "versions": state["versions"], "model_config_hash": state["model_config_hash"],
                                       "simulation": simulation})
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
        runtime.review.publish_report(state["request"]["run_id"], report(state, runtime))
        p = runtime.review.publish(Proposal.model_validate(state["proposal"]), report(state, runtime))
        return {"proposal": p.model_dump(mode="json"), "trace": event(state, "publish_review", proposal_id=p.proposal_id)}

    def await_review(state):
        # No model invocation, publication or database write belongs in this node.
        decision_id = interrupt({"proposal_id": state["proposal"]["proposal_id"], "simulation": state["proposal"]["simulation"],
                                 "action": state["proposal"]["action"],
                                 "approval_hash": state["proposal"]["approval_hash"],
                                 "review_expires_at": state["proposal"]["review_expires_at"],
                                 "message": "Resume with a stored decision ID only; delivery supplies no authority."})
        return {"decision_id": decision_id, "trace": event(state, "await_review", outcome="resumed")}

    def revalidate(state):
        try:
            if not isinstance(state.get("decision_id"), str):
                raise ValueError("resume_requires_decision_id")
            proposal = runtime.review.get_proposal(state["proposal"]["proposal_id"])
            if proposal.model_dump(exclude={"status"}) != Proposal.model_validate(state["proposal"]).model_dump(exclude={"status"}):
                raise ValueError("stored_proposal_content_changed")
            decision = runtime.review.get_decision(state["decision_id"])
            governed = state["request"]["mode"] == "governed" and governed_transport(runtime)
            if governed:
                decision = GovernedDecision.model_validate(decision)
            else:
                decision = ApprovalDecision.model_validate(decision)
            now = runtime.clock()
            proposal_status = runtime.review.get_proposal_status(proposal.proposal_id)
            recovering_context = (proposal_status == "SUPERSEDED" and decision.kind == "request_context"
                                  and runtime.review.get_successor(proposal.proposal_id) is not None)
            if proposal_status not in ("PENDING_APPROVAL", "APPROVED") and not recovering_context:
                raise ValueError("proposal_no_longer_reviewable")
            if (decision.proposal_id != proposal.proposal_id or decision.revision != proposal.revision
                    or decision.approval_hash != proposal.approval_hash or decision.target_uid != proposal.target.uid
                    or decision.policy_version != proposal.policy_version or decision.revoked
                    or decision.decision_id != state["decision_id"]
                    or proposal.approval_hash != state["proposal"]["approval_hash"]
                    or proposal.run_id != state["request"]["run_id"]
                    or decision.authority != "human"
                    or (not governed and (not proposal.simulation or not decision.simulation))
                    or (governed and (proposal.simulation or decision.simulation))
                    or decision.approved_at < proposal.published_at
                    or decision.approved_at >= proposal.review_expires_at or decision.approved_at > now):
                raise ValueError("invalid_or_revoked_decision")
            if decision.kind in ("reject", "acknowledge", "request_context"):
                status = {"reject": "REJECTED", "acknowledge": "NO_CHANGE", "request_context": "STALE"}[decision.kind]
                ticket = prepare_revision(state, runtime, "revision_requested") if decision.kind == "request_context" else None
                return {"status": status, "reason": "revision_requested" if decision.kind == "request_context" else decision.kind,
                        "revision_request": ticket.model_dump(mode="json") if ticket else None,
                        "trace": event(state, "revalidate", decision_kind=decision.kind)}
            if decision.execution_expires_at is None or now >= decision.execution_expires_at:
                raise ValueError("execution_window_expired")
            if decision.execution_expires_at != decision.approved_at + timedelta(seconds=proposal.execution_window_seconds):
                raise ValueError("execution_window_does_not_match_proposal")
            expected_kind = "adopt_baseline" if proposal.action == "adopt_baseline" else "approve_remediation"
            if decision.kind != expected_kind:
                raise ValueError("decision_kind_does_not_match_proposal")
            req = AnalysisRequest.model_validate(state["request"])
            current = read_evidence(runtime.evidence.current(req))
            if canonical_hash(current.model_dump(mode="json")) != proposal.evidence_hash:
                raise ValueError("material_evidence_changed")
            if proposal.action == "adopt_baseline":
                gates = adoption_gates(current, runtime.verification, now)
                if ((not governed and (runtime.baseline is None or not runtime.baseline.simulation_only))
                        or any(g.result != "pass" for g in gates)):
                    raise ValueError("current_adoption_readiness_failed")
                if governed:
                    checked = validate_preflight(runtime.governance.preflight(proposal.proposal_id, decision.decision_id,
                                                  action_key(proposal, decision.decision_id)), proposal, decision, now)
                    return {"status": "EXECUTION_REQUESTED", "reason": None, "preflight": checked.model_dump(mode="json"),
                            "trace": event(state, "revalidate", outcome="backend_preflight_passed")}
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
            if governed:
                checked = validate_preflight(runtime.governance.preflight(proposal.proposal_id, decision.decision_id,
                                              action_key(proposal, decision.decision_id)), proposal, decision, now)
                return {"status": "EXECUTION_REQUESTED", "reason": None, "preflight": checked.model_dump(mode="json"),
                        "recovery_authority_id": decision.recovery_authority_id,
                        "trace": event(state, "revalidate", outcome="backend_preflight_passed")}
            return {"status": "EXECUTION_REQUESTED", "reason": None,
                    "trace": event(state, "revalidate", decision_kind=decision.kind, outcome="simulated_authority_valid")}
        except (LookupError, ValueError, TypeError) as exc:
            reason = str(exc)[:300]
            if state["request"]["mode"] == "governed":
                safe_codes = {"resume_requires_decision_id", "stored_proposal_content_changed", "proposal_no_longer_reviewable",
                              "invalid_or_revoked_decision", "execution_window_expired", "execution_window_does_not_match_proposal",
                              "decision_kind_does_not_match_proposal", "material_evidence_changed",
                              "current_adoption_readiness_failed", "current_readiness_failed", "backend_readiness_failed",
                              "preflight_scope_mismatch", "preflight_expired_or_future", "backend_preflight_blocked",
                              "governance_operation_unavailable", "invalid_governance_record"}
                reason = reason if reason in safe_codes else "governance_revalidation_failed"
            return {"status": "STALE", "reason": reason, "trace": event(state, "revalidate", outcome="blocked")}
        except Exception:
            if state["request"]["mode"] != "governed":
                raise
            return {"status": "STALE", "reason": "governance_revalidation_failed",
                    "trace": event(state, "revalidate", outcome="blocked")}

    def request_execution(state):
        if state["request"]["mode"] == "governed":
            return dispatch_governed(state)
        proposal = state["proposal"]
        key = canonical_hash([proposal["proposal_id"], state["decision_id"], proposal["approval_hash"]])
        try:
            receipt = runtime.execution.request(proposal["proposal_id"], state["decision_id"], key)
        except (LookupError, ValueError) as exc:
            return {"status": "STALE", "reason": str(exc), "trace": event(state, "request_execution", outcome="blocked")}
        return {"receipt": receipt, "trace": event(state, "request_execution", outcome="recorded_only")}

    def commit_baseline_adoption(state):
        if state["request"]["mode"] == "governed":
            return dispatch_governed(state)
        p = state["proposal"]
        key = canonical_hash([p["proposal_id"], state["decision_id"], p["approval_hash"]])
        try:
            if runtime.baseline is None:
                raise ValueError("adoption_port_unavailable")
            receipt = runtime.baseline.adopt_approved_snapshot(p["proposal_id"], state["decision_id"], key)
        except (LookupError, ValueError) as exc:
            return {"status": "STALE", "reason": str(exc), "trace": event(state, "commit_baseline_adoption", outcome="blocked")}
        return {"receipt": receipt, "trace": event(state, "commit_baseline_adoption", outcome="recorded_only")}

    def dispatch_governed(state):
        proposal = Proposal.model_validate(state["proposal"])
        key = action_key(proposal, state["decision_id"])
        try:
            if not governed_transport(runtime):
                raise ValueError("governance_unavailable")
            # Replays first recover a durable receipt; expiry does not prevent
            # reconciliation of an already-issued action.
            receipt = runtime.governance.get_receipt(key)
            if receipt is None:
                if not runtime.budget.begin_action(key):
                    raise ValueError("dispatch_outcome_unknown")
                if datetime.fromisoformat(state["preflight"]["expires_at"]) <= runtime.clock():
                    return {"status": "STALE", "reason": "preflight_expired",
                            "trace": event(state, "request_execution", outcome="blocked")}
                receipt = runtime.governance.request(proposal.proposal_id, state["decision_id"], key, proposal.action)
            receipt = validate_receipt(receipt, proposal, state["decision_id"], runtime.clock(),
                                       previous=state.get("execution_outcome"),
                                       recovery_authority_id=state.get("recovery_authority_id"))
            runtime.governance.record_outcome(proposal.run_id, receipt)
        except Exception:
            # No automatic retry of a possibly-issued request, and no raw backend
            # response/credential is copied into checkpoint errors.
            return {"status": "NEEDS_MANUAL_INTERVENTION", "reason": "execution_outcome_unavailable",
                    "trace": event(state, "request_execution", outcome="reconciliation_required")}
        return {"receipt": receipt.model_dump(mode="json"), "execution_outcome": receipt.model_dump(mode="json"),
                "status": receipt_status(receipt), "reason": None,
                "trace": event(state, "request_execution", outcome=receipt.phase, receipt_id=receipt.receipt_id)}

    def finalize(state):
        require_compatible_state(state)
        updates = {}
        if state.get("readiness") and state["status"] != "PENDING_REVIEW":
            updates["readiness"] = {**state["readiness"], "execution_ready": False}
        if state.get("proposal"):
            runtime.review.publish(Proposal.model_validate(state["proposal"]), report(state, runtime))
            status = {"REJECTED": "REJECTED", "EXECUTION_REQUESTED": "APPROVED", "BLOCKED": "BLOCKED"}.get(state["status"])
            if state.get("preflight"):
                status = "APPROVED"
            if state["status"] == "STALE":
                status = "EXPIRED" if state.get("reason") == "execution_window_expired" else "SUPERSEDED"
            if status:
                projection = runtime.review.project_proposal(state["proposal"]["proposal_id"], status, state.get("reason"))
                updates["proposal"] = {**state["proposal"], "status": projection["status"]}
        result = report({**state, **updates}, runtime)
        runtime.review.publish_report(state["request"]["run_id"], result)
        runtime.review.finalize_run(state["request"]["run_id"], result)
        return {**updates, "trace": event(state, "finalize", status=state["status"])}

    graph = StateGraph(GuardianState)

    def compatible_node(function):
        def checked(state):
            require_compatible_state(state)
            return function(state)
        return checked

    for name, function in [("accept_case", accept_case), ("load_evidence", load_evidence),
                           ("build_facts", facts_node), ("assess_risk", assess_risk),
                           ("prepare_adoption", prepare_adoption),
                           ("restore_analysis", restore_analysis),
                           ("investigate_context", investigate_context), ("fetch_context", fetch_context),
                           ("lookup_exhausted", lookup_exhausted),
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
    graph.add_conditional_edges("assess_risk", after_risk, ["prepare_adoption", "restore_analysis", "investigate_context"])
    graph.add_conditional_edges("restore_analysis", lambda s: "finalize" if s["status"] == "BLOCKED" else
                                "render_and_validate" if s.get("plan") is not None else "investigate_context",
                                ["finalize", "render_and_validate", "investigate_context"])
    graph.add_conditional_edges("prepare_adoption", lambda s: "publish_review" if s["status"] == "PENDING_REVIEW" else "finalize",
                                ["publish_review", "finalize"])
    graph.add_conditional_edges("investigate_context", investigation_route,
                                ["investigate_context", "fetch_context", "lookup_exhausted", "select_strategy", "finalize"])
    graph.add_edge("lookup_exhausted", "finalize")
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
