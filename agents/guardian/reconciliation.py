"""One bounded read-only receipt reconciliation per worker delivery."""

from .contracts import Proposal
from .governance import action_key, receipt_status, validate_receipt
from .graph import event, governed_transport, report
from .versions import require_compatible_state


def reconcile_run(graph, runtime, run_config):
    snapshot = graph.get_state(run_config)
    state = snapshot.values
    require_compatible_state(state)
    if (state["request"]["mode"] != "governed" or not governed_transport(runtime)
            or not state.get("decision_id") or not state.get("preflight") or snapshot.next):
        raise ValueError("run_not_ready_for_receipt_reconciliation")
    proposal = Proposal.model_validate(state["proposal"])
    raw = runtime.governance.get_receipt(action_key(proposal, state["decision_id"]))
    if raw is None:
        raise ValueError("receipt_not_available_no_retry_permitted")
    receipt = validate_receipt(raw, proposal, state["decision_id"], runtime.clock(),
                               previous=state.get("execution_outcome"),
                               recovery_authority_id=state.get("recovery_authority_id"))
    payload = receipt.model_dump(mode="json")
    if payload == state.get("execution_outcome"):
        return state
    # The authoritative service records receipt/notification projection before
    # the checkpoint update. Crash replay repeats only that idempotent projection.
    runtime.governance.record_outcome(proposal.run_id, receipt)
    updated = {**state, "execution_outcome": payload, "receipt": payload,
               "status": receipt_status(receipt), "reason": None,
               "trace": event(state, "reconcile_receipt", receipt_id=receipt.receipt_id,
                              sequence=receipt.sequence, outcome=receipt.phase)}
    graph.update_state(run_config, updated, as_node="finalize")
    runtime.review.publish_report(proposal.run_id, report(updated, runtime))
    return graph.get_state(run_config).values
