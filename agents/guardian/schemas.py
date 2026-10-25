"""Export schema definitions without loading models, databases or cluster clients."""

from contracts.usage_summary_v1 import UsageSummary

from .contracts import (AnalysisReport, AnalysisRequest, ApprovalDecision, ChangePlan, ContextLookup,
                        EvidenceBundle, Investigation, Proposal, ReadinessAssessment, RevisionRequest)
from .versions import RunVersions
from .modeling import ModelConfig, ModelResult
from .evidence_tools import ToolResult
from .work import WorkItem, WorkOutcome
from .governance import GovernedDecision, PreflightResult, ExecutionReceipt

SCHEMA_MODELS = {
    "usage": ("guardian.usage-summary.v1", UsageSummary),
    "evidence": ("guardian.evidence.v1", EvidenceBundle),
    "request": ("guardian.analysis-request.v5", AnalysisRequest),
    "report": ("guardian.report.v7", AnalysisReport),
    "readiness": ("guardian.readiness.v1", ReadinessAssessment),
    "proposal": ("guardian.proposal.v2", Proposal),
    "test_decision": ("guardian.test-decision.v2", ApprovalDecision),
    "investigation": ("guardian.investigation.v1", Investigation),
    "plan": ("guardian.change-plan.v1", ChangePlan),
    "run_versions": ("guardian.run-versions.v1", RunVersions),
    "revision_request": ("guardian.revision-request.v1", RevisionRequest),
    "model_config": ("guardian.model-config.v1", ModelConfig),
    "model_result": ("guardian.model-result.v1", ModelResult),
    "evidence_tool_request": ("guardian.evidence-tool-request.v1", ContextLookup),
    "evidence_tool_result": ("guardian.evidence-tool-result.v1", ToolResult),
    "work_item": ("guardian.work-item.v2", WorkItem),
    "work_outcome": ("guardian.work-outcome.v2", WorkOutcome),
    "governed_decision": ("guardian.governed-decision.v1", GovernedDecision),
    "preflight": ("guardian.preflight.v1", PreflightResult),
    "execution_receipt": ("guardian.execution-receipt.v1", ExecutionReceipt),
}


def export_schemas() -> dict:
    return {name: {"$id": f"urn:{schema_id}", **model.model_json_schema()}
            for name, (schema_id, model) in SCHEMA_MODELS.items()}
