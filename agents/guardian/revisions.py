"""Review revision coordination through ports; production scheduling is external."""

from .contracts import AnalysisReport, AnalysisRequest, EvidenceBundle, Proposal, RevisionRequest
from .policy import build_facts, canonical_hash, validate_investigation, validate_plan
from .versions import require_compatible_state


def read_evidence(raw):
    return EvidenceBundle.model_validate(raw.model_dump(mode="json") if isinstance(raw, EvidenceBundle) else raw)


def coverage_provenance(series):
    return {(tuple(c.source_ids), tuple(c.audit_policy_refs), c.status, tuple(c.reason_codes), c.known_lost_events)
            for c in series.coverage}


def reuse_supported(previous, current, proposal, report, now):
    """Allow freshness/retained-use refreshes, conservatively reanalyze other edits."""
    if proposal.action != "remediate" or report.investigation is None or report.plan is None:
        return False
    fixed = ("target", "subject", "binding", "baseline_id", "policy", "source_mode", "source_errors")
    if any(getattr(previous, k) != getattr(current, k) for k in fixed):
        return False
    if previous.context is None or current.context is None:
        return False
    if previous.context.model_dump(exclude={"collected_at"}) != current.context.model_dump(exclude={"collected_at"}):
        return False
    old, new = previous.usage, current.usage
    if old is None or new is None or new.query_window.start != old.query_window.start or new.query_window.end < old.query_window.end:
        return False
    old_keys = {s.request_key_id: s.request_key for s in old.series}
    new_keys = {s.request_key_id: s.request_key for s in new.series}
    if old_keys != new_keys or old.collector_version != new.collector_version or old.aggregation_version != new.aggregation_version:
        return False
    facts, gates = build_facts(current, now)
    if any(g.result != "pass" for g in gates):
        return False
    if not set(proposal.removed_permission_ids) <= {f["permission_id"] for f in facts if f["eligible"]}:
        return False
    # Old citations must remain available; do not relabel old model output with
    # new references or silently reinterpret a different collection policy.
    for a, b in zip(sorted(old.series, key=lambda s: s.request_key_id), sorted(new.series, key=lambda s: s.request_key_id)):
        if coverage_provenance(a) != coverage_provenance(b) or a.carried_authorized_requests != b.carried_authorized_requests:
            return False
        old_counts = {k: sum(getattr(bucket.counts, k) for bucket in a.buckets)
                      for k in ("successful_completed", "authorized_error", "authorized_incomplete", "denied", "unknown")}
        new_counts = {k: sum(getattr(bucket.counts, k) for bucket in b.buckets) for k in old_counts}
        if (any(new_counts[k] < value for k, value in old_counts.items())
                or any(new_counts[k] != old_counts[k] for k in ("denied", "unknown"))):
            return False
    try:
        validate_investigation(report.investigation, facts, current)
        validate_plan(report.plan, facts, report.investigation, current)
    except ValueError:
        return False
    return True


def prepare_revision(state, runtime, reason):
    require_compatible_state(state)
    req = AnalysisRequest.model_validate(state["request"])
    p = runtime.review.get_proposal(state["proposal"]["proposal_id"])
    if (p.run_id != req.run_id or p.case_id != req.case_id or p.revision != req.revision
            or p.approval_hash != state["proposal"]["approval_hash"] or state.get("receipt")):
        raise ValueError("revision_source_mismatch_or_action_started")
    existing = runtime.review.get_successor(p.proposal_id)
    if existing is not None:
        if (existing.reason != reason or existing.source_run_id != req.run_id
                or existing.source_approval_hash != p.approval_hash or existing.request.case_id != req.case_id):
            raise ValueError("revision_source_mismatch")
        return existing
    old = read_evidence(state["evidence"])
    if canonical_hash(old.model_dump(mode="json")) != p.evidence_hash:
        raise ValueError("revision_source_evidence_mismatch")
    # Queue the context intent even while the answer/source is unavailable.
    # Its worker loads and binds the actual current snapshot when it starts.
    current = old if reason == "revision_requested" else read_evidence(runtime.evidence.current(req))
    if ((current.target.cluster_id, current.target.namespace, current.target.name, current.target.uid) !=
            (old.target.cluster_id, old.target.namespace, old.target.name, old.target.uid)):
        raise ValueError("revision_target_scope_changed")
    source_report = AnalysisReport.model_validate(runtime.review.get_report(req.run_id))
    if source_report.case_id != req.case_id or source_report.run_id != req.run_id:
        raise ValueError("revision_report_scope_mismatch")
    reuse = reason != "revision_requested" and reuse_supported(old, current, p, source_report, runtime.clock())
    token = canonical_hash([p.proposal_id, reason]).split(":")[1][:24]
    revision_id = f"revision-{token}"
    next_req = AnalysisRequest(case_id=req.case_id, run_id=f"run-{token}", revision=req.revision + 1,
                               trigger=req.trigger, snapshot_id=current.snapshot_id,
                               cluster_id=current.target.cluster_id, target_uid=current.target.uid,
                               baseline_id=current.baseline_id, policy_version=current.policy.policy_version,
                               mode=req.mode, intent=req.intent, revision_request_id=revision_id)
    ticket = RevisionRequest(revision_request_id=revision_id, source_proposal_id=p.proposal_id,
                             source_run_id=req.run_id, source_revision=req.revision, source_approval_hash=p.approval_hash,
                             reason=reason, request=next_req, evidence_hash=canonical_hash(current.model_dump(mode="json")),
                             reuse_analysis=reuse, created_at=runtime.clock())
    return runtime.review.request_revision(ticket)


def renew_review(graph, runtime, run_config):
    """Called by the worker after backend expiry; demo invokes it explicitly."""
    state = graph.get_state(run_config).values
    require_compatible_state(state)
    if state["status"] not in ("PENDING_REVIEW", "STALE") or state.get("receipt"):
        raise ValueError("run_is_not_an_unused_review")
    p = runtime.review.get_proposal(state["proposal"]["proposal_id"])
    d = runtime.review.get_proposal_decision(p.proposal_id)
    if d is None:
        if runtime.clock() < p.review_expires_at:
            raise ValueError("review_has_not_expired")
        reason = "review_window_expired"
    else:
        if d.revoked or d.kind not in ("approve_remediation", "adopt_baseline"):
            raise ValueError("decision_cannot_be_renewed")
        if d.execution_expires_at is None or runtime.clock() < d.execution_expires_at:
            raise ValueError("approval_has_not_expired")
        reason = "execution_window_expired"
    ticket = prepare_revision(state, runtime, reason)
    # A backend scheduler owns expiry/outbox processing. This only closes the
    # worker checkpoint after the durable revision intent has been accepted.
    graph.update_state(run_config, {"status": "STALE", "reason": reason,
                                   "proposal": {**state["proposal"], "status": "EXPIRED"},
                                   "readiness": {**state["readiness"], "execution_ready": False} if state.get("readiness") else None,
                                   "revision_request": ticket.model_dump(mode="json")}, as_node="finalize")
    runtime.review.finalize_run(p.run_id, {**runtime.review.get_report(p.run_id), "status": "STALE", "reason": reason})
    return ticket
