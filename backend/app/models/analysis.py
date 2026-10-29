"""Strict analysis intake and fenced worker messages. No execution authority."""
from typing import Annotated, Literal
from pydantic import Field
from contracts.usage_summary_v1 import Contract, ID, Window
from agents.guardian.contracts import AnalysisReport, ContextLookup, Proposal

Idempotency = Annotated[str, Field(min_length=8, max_length=128)]


class AnalysisIntake(Contract):
    cluster_id: ID
    namespace: ID
    role_name: ID
    window: Window
    idempotency_key: Idempotency
    trigger: Literal['initial', 'manual', 'drift', 'periodic'] = 'manual'
    supersedes_run_id: ID | None = None
    context_note: str = Field(default='', max_length=2000)


class JobClaim(Contract):
    cluster_id: ID
    namespace: ID


class JobLease(Contract):
    lease_token: ID


class JobComplete(JobLease):
    report: AnalysisReport
    proposal: Proposal | None = None


class ReportDecision(Contract):
    kind: Literal['acknowledge', 'reject', 'request_context', 'approve_remediation', 'adopt_baseline']
    expected_revision: int = Field(strict=True, ge=1)
    expected_report_hash: ID
    idempotency_key: Idempotency
    note: str = Field(default='', max_length=2000)


class BudgetRequest(JobLease):
    operation: Literal['count', 'repair_count', 'reserve_model', 'reserve_lookup', 'begin_lookup', 'complete_lookup']
    stage: Literal['investigator', 'planner'] | None = None
    repair: bool = Field(default=False, strict=True)
    batch_key: ID | None = None
    requests: list[ContextLookup] = Field(default_factory=list, max_length=2)
    index: int | None = Field(default=None, strict=True, ge=0, le=1)
    result: dict | None = None
