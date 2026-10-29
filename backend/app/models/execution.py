"""Operator-owned action/verification contracts. Models cannot choose these fields."""
from typing import Literal
from pydantic import AwareDatetime, Field, model_validator
from contracts.usage_summary_v1 import Contract, ID, utc


class FunctionalProfile(Contract):
    profile_id: Literal['pod-reader-behavior.v1'] = 'pod-reader-behavior.v1'
    namespace: ID
    role_name: ID
    target_uid: ID
    subject_uid: ID
    workload_uid: ID
    image_digest: ID
    argv: list[str] = Field(min_length=1,max_length=16)
    artifact_hashes: dict[str,str] = Field(min_length=1,max_length=16)
    environment_keys: list[ID] = Field(default_factory=list,max_length=8)
    timeout_seconds: int = Field(default=30,strict=True,ge=1,le=60)
    propagation_attempts: int = Field(default=2,strict=True,ge=2,le=3)
    observation_seconds: int = Field(default=10,strict=True,ge=1,le=60)

    @model_validator(mode='after')
    def files(self):
        from pathlib import Path
        import re
        if not Path(self.argv[0]).is_absolute() or any(len(arg)>2048 for arg in self.argv):
            raise ValueError('profile_requires_fixed_absolute_executable')
        if self.argv[0] not in self.artifact_hashes:raise ValueError('executable_digest_required')
        for arg in self.argv[1:]:
            if Path(arg).is_absolute() and arg not in self.artifact_hashes:
                raise ValueError('absolute_profile_artifact_requires_digest')
        if any(not Path(p).is_absolute() or not re.fullmatch('[0-9a-f]{64}',h) for p,h in self.artifact_hashes.items()):
            raise ValueError('invalid_profile_artifact_hash')
        if any(not re.fullmatch('[A-Z][A-Z0-9_]*',key) for key in self.environment_keys):
            raise ValueError('invalid_profile_environment_key')
        return self


class ExecutionPolicy(Contract):
    schema_version: Literal['guardian.execution-policy.v1'] = 'guardian.execution-policy.v1'
    enabled: bool = Field(default=False,strict=True)
    cluster_id: ID
    namespaces: list[ID] = Field(default_factory=list,max_length=16)
    recovery_mode: Literal['optional_advance_exact','fresh_human_only'] = 'optional_advance_exact'
    recovery_seconds: int = Field(default=600,strict=True,ge=30,le=900)
    profiles: list[FunctionalProfile] = Field(default_factory=list,max_length=16)

    @model_validator(mode='after')
    def scope(self):
        if '*' in self.cluster_id or any('*' in n for n in self.namespaces):raise ValueError('exact_execution_scope_required')
        if len(self.namespaces)!=len(set(self.namespaces)):raise ValueError('duplicate_execution_scope')
        ids=[(p.namespace,p.role_name) for p in self.profiles]
        if len(ids)!=len(set(ids)) or any(p.namespace not in self.namespaces for p in self.profiles):raise ValueError('invalid_profile_scope')
        return self


class FunctionalProof(Contract):
    schema_version: Literal['guardian.functional-proof.v1'] = 'guardian.functional-proof.v1'
    phase: Literal['observe','pre','post','restored']
    workload_uid: ID
    image_digest: ID
    started_at: AwareDatetime
    completed_at: AwareDatetime
    runner_healthy: bool = Field(strict=True)
    dependencies_healthy: bool = Field(strict=True)
    checks: dict[str,Literal['pass','fail','unknown']] = Field(min_length=3,max_length=3)
    evidence_refs: list[ID] = Field(min_length=1,max_length=16)

    @model_validator(mode='after')
    def exact(self):
        if set(self.checks)!={'startup','normal','restart'}:raise ValueError('three_actual_behavior_checks_required')
        if utc(self.completed_at)<utc(self.started_at):raise ValueError('invalid_probe_interval')
        return self


class PrepareReview(Contract):
    source_run_id: ID
    action: Literal['remediate','adopt_baseline'] = 'remediate'
    expected_report_hash: ID
    idempotency_key: str = Field(min_length=8,max_length=128)


class RevokeAuthority(Contract):
    reason: str = Field(min_length=1,max_length=2000)
    kind: Literal['forward','recovery','all'] = 'all'


class FreshRecovery(Contract):
    expected_sequence: int = Field(strict=True,ge=1)
    expected_recovery_hash: ID
    idempotency_key: str = Field(min_length=8,max_length=128)
    note: str = Field(default='',max_length=2000)


class ExecutionRequest(Contract):
    proposal_id: ID
    decision_id: ID
    action_key: ID
    action: Literal['remediate','adopt_baseline']
