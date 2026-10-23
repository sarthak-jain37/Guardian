"""Worker delivery contracts. Delivery never grants reviewer authority."""

from typing import Literal

from pydantic import Field, model_validator

from contracts.usage_summary_v1 import Contract, ID
from .contracts import AnalysisRequest
from .lifecycle import RunStatus


class WorkItem(Contract):
    schema_version: Literal["guardian.work-item.v1"] = "guardian.work-item.v1"
    work_id: ID
    run_id: ID
    kind: Literal["analyze", "resume", "revision"]
    request: AnalysisRequest | None = None
    decision_id: ID | None = None
    revision_request_id: ID | None = None

    @model_validator(mode="after")
    def payload(self):
        if self.kind == "analyze":
            if self.request is None or self.request.run_id != self.run_id or self.decision_id or self.revision_request_id:
                raise ValueError("analysis delivery requires only a matching request")
        elif self.kind == "resume":
            if not self.decision_id or self.request is not None or self.revision_request_id:
                raise ValueError("resume delivery contains only a decision ID")
        elif not self.revision_request_id or self.request is not None or self.decision_id:
            raise ValueError("revision delivery contains only its stored revision ID")
        return self


class WorkOutcome(Contract):
    schema_version: Literal["guardian.work-outcome.v1"] = "guardian.work-outcome.v1"
    work_id: ID
    run_id: ID
    status: RunStatus
    waiting_for_review: bool = Field(strict=True)
    model_calls: int = Field(strict=True, ge=0, le=6)
    lookup_calls: int = Field(strict=True, ge=0, le=4)
