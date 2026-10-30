from typing import Any, Literal
from pydantic import BaseModel, Field


class ExecutionReceipt(BaseModel):
    status: str = "success"
    applied: list[str] = Field(default_factory=list)
    deleted: list[str] = Field(default_factory=list)
    errors: list[str] = Field(default_factory=list)
    timestamp: str = ""


class RevertResult(BaseModel):
    queue_id: str
    status: str
    receipt: ExecutionReceipt | dict[str, Any]
    message: str


class BaselineEntry(BaseModel):
    baseline_id: str
    service_account: str
    namespace: str
    canonical_hash: str
    status: Literal["ACTIVE", "SUPERSEDED", "BROKEN_ROLLBACK", "PENDING_APPROVAL", "REJECTED"]
    rbac_state: dict[str, Any] | str
    applied_at: str
    approved_by: str | None = ""
    run_id: str | None = ""
    parent_id: str | None = ""
    version_number: str
    sa_key: str | None = None


class QueueEntry(BaseModel):
    id: str
    baseline_id: str
    event_type: Literal["NEW_POLICY", "DRIFT_DETECTED"] = "DRIFT_DETECTED"
    risk_tier: Literal["CRITICAL", "HIGH", "LOW"]
    status: Literal["PENDING", "PROMOTED", "REJECTED", "REVERTED", "DISMISSED"] = "PENDING"
    diff_summary: dict[str, Any] | str
    llm_analysis: str
    sa_key: str
    created_at: str
    resolved_by: str | None = None
    resolved_at: str | None = None
    snapshot_hash: str
    original_state: dict[str, Any] | str | None = None
    latest_state: dict[str, Any] | str | None = None
    net_diff: dict[str, Any] | str | None = None
    version_count: int = 1
    version_chain: list[dict[str, Any]] = Field(default_factory=list)
    revert_receipt: dict[str, Any] | None = None

