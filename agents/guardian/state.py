"""Checkpoint payloads contain JSON data only; clients stay in worker runtime."""

from typing import Any, TypedDict


class GuardianState(TypedDict, total=False):
    request: dict
    evidence: dict
    facts: list[dict]
    risk: list[dict]
    investigation: dict | None
    plan: dict | None
    proposal: dict | None
    decision_id: str | None
    status: str
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
    started_at: str
