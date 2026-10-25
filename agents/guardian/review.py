"""Deterministic review preparation; no reviewer authentication or cluster writes."""

from datetime import timedelta

from .contracts import Gate, Proposal
from .policy import canonical_hash, global_gates, render


def checked_gates(results, unavailable_reason):
    gates = [Gate.model_validate(g) for g in results]
    if not gates or len({g.gate_id for g in gates}) != len(gates):
        return [Gate(gate_id=unavailable_reason, result="unknown", reasons=[unavailable_reason])]
    return gates


def adoption_gates(evidence, verification, now):
    # Adoption records desired state; it neither removes permissions nor claims
    # that observation has established a least-privilege policy.
    required = {"supported_target", "consumer_inventory", "context_integrity", "source_and_failure_status"}
    gates = [g for g in global_gates(evidence, now) if g.gate_id in required]
    context = evidence.context
    fresh = context is not None and 0 <= (now - context.collected_at).total_seconds() <= evidence.policy.maximum_source_lag_seconds
    gates.append(Gate(gate_id="snapshot_freshness", result="pass" if fresh else "unknown",
                      reasons=[] if fresh else ["stale_source"]))
    gates.extend(checked_gates(verification.check_adoption(evidence), "adoption_preconditions_unavailable"))
    return gates


def adoption_proposal(request, evidence, versions, gates, now):
    simulation = request.mode == "simulation"
    ready = request.mode != "preview" and all(g.result == "pass" for g in gates)
    rendered = render(evidence, set())
    rendered.update(patch=[], diff="")
    evidence_hash = canonical_hash(evidence.model_dump(mode="json"))
    candidate_hash = canonical_hash({"action": "adopt_baseline", "target": evidence.target.model_dump(mode="json")})
    approval_hash = canonical_hash({"candidate": candidate_hash, "evidence": evidence_hash,
                                   "action": "adopt_baseline", "versions": versions,
                                   "policy": evidence.policy.model_dump(), "simulation": simulation})
    return Proposal(proposal_id=f"proposal-{request.run_id}-r{request.revision}",
                    case_id=request.case_id, run_id=request.run_id, revision=request.revision,
                    action="adopt_baseline", simulation=simulation,
                    status="PENDING_APPROVAL" if ready else "BLOCKED", target=evidence.target,
                    unchanged_binding=evidence.binding, evidence_hash=evidence_hash,
                    candidate_hash=candidate_hash, approval_hash=approval_hash,
                    policy_version=evidence.policy.policy_version, removed_permission_ids=[],
                    gates=gates, uncertainty=["Adoption records approved desired state; it does not establish least privilege."],
                    published_at=now, review_expires_at=now + timedelta(seconds=evidence.policy.review_window_seconds),
                    execution_window_seconds=evidence.policy.execution_window_seconds,
                    verification_profile_id=None, **rendered)
