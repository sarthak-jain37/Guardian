"""Export schema definitions without loading models, databases or cluster clients."""

from contracts.usage_summary_v1 import UsageSummary

from .contracts import (AnalysisReport, AnalysisRequest, ApprovalDecision, ChangePlan,
                        EvidenceBundle, Investigation, Proposal, ReadinessAssessment)
from .versions import RunVersions

SCHEMA_MODELS = {
    "usage": ("guardian.usage-summary.v1", UsageSummary),
    "evidence": ("guardian.evidence.v1", EvidenceBundle),
    "request": ("guardian.analysis-request.v2", AnalysisRequest),
    "report": ("guardian.report.v2", AnalysisReport),
    "readiness": ("guardian.readiness.v1", ReadinessAssessment),
    "proposal": ("guardian.proposal.v1", Proposal),
    "test_decision": ("guardian.test-decision.v1", ApprovalDecision),
    "investigation": ("guardian.investigation.v1", Investigation),
    "plan": ("guardian.change-plan.v1", ChangePlan),
    "run_versions": ("guardian.run-versions.v1", RunVersions),
}


def export_schemas() -> dict:
    return {name: {"$id": f"urn:{schema_id}", **model.model_json_schema()}
            for name, (schema_id, model) in SCHEMA_MODELS.items()}
