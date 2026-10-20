"""Checkpoint payloads contain JSON data only; clients stay in worker runtime."""

from typing import Any, TypedDict

from .lifecycle import RunStatus


class GuardianState(TypedDict, total=False):
    versions: dict[str, str]
    request: dict
    evidence: dict
    facts: list[dict]
    risk: list[dict]
    investigation: dict | None
    plan: dict | None
    proposal: dict | None
    decision_id: str | None
    status: RunStatus
    reason: str | None
    model_calls: int
    lookup_rounds: int
    lookup_calls: int
    investigator_repairs: int
    planner_repairs: int
    model_status: str
    retry_stage: bool
    trace: list[dict[str, Any]]
    receipt: dict | None
    readiness: dict | None
    started_at: str
