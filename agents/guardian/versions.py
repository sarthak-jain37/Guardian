"""Exact pilot compatibility; incompatible runs require a fresh reviewed revision."""

from typing import Literal

from contracts.usage_summary_v1 import Contract, ID
from .prompts import PROMPT_VERSION, SCHEMA_VERSION

GRAPH_VERSION = "guardian.graph.v5"
STATE_VERSION = "guardian.state.v5"
VALIDATOR_VERSION = "guardian.validator.v1"
CANONICALIZATION_VERSION = "guardian.sorted-json-sha256.v1"


class RunVersions(Contract):
    # Required even when they have only one supported value: a legacy checkpoint
    # must not silently acquire the current versions through model defaults.
    graph_version: Literal["guardian.graph.v5"]
    state_version: Literal["guardian.state.v5"]
    validator_version: Literal["guardian.validator.v1"]
    canonicalization_version: Literal["guardian.sorted-json-sha256.v1"]
    policy_version: ID
    prompt_version: Literal["guardian.bounded-stages.v2"]
    model_output_version: Literal["guardian.model-output.v2"]


def current_versions(policy_version: str) -> RunVersions:
    return RunVersions(graph_version=GRAPH_VERSION, state_version=STATE_VERSION,
                       validator_version=VALIDATOR_VERSION,
                       canonicalization_version=CANONICALIZATION_VERSION,
                       policy_version=policy_version, prompt_version=PROMPT_VERSION,
                       model_output_version=SCHEMA_VERSION)


class IncompatibleRunError(ValueError):
    """Preserve historical state and obtain a new revision; never auto-upgrade it."""


def require_compatible_state(state: dict) -> RunVersions:
    try:
        versions = RunVersions.model_validate(state.get("versions"))
        request_policy = state["request"]["policy_version"]
        # Before a successful load (or after an invalid export), the request and
        # stamp still suffice for compatibility. No evidence means no candidate.
        evidence = state.get("evidence")
        evidence_policy = evidence["policy"]["policy_version"] if evidence is not None else request_policy
        if versions.policy_version != request_policy or request_policy != evidence_policy:
            raise ValueError("policy version changed")
    except (ValueError, KeyError, TypeError) as exc:
        raise IncompatibleRunError(
            "incompatible_saved_run: preserve this run and request a fresh revision; "
            "reconcile any previously requested action through the backend"
        ) from exc
    return versions
