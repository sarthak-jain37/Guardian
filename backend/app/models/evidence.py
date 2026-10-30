"""Collector/query boundaries; completeness comes from a configured source."""
from typing import Literal
from pydantic import Field, model_validator
from contracts.usage_summary_v1 import Contract, ID, RequestKey, Subject, Window


class UsageQuery(Contract):
    cluster_id: ID
    namespace: ID
    subject: Subject
    window: Window
    keys: dict[ID, RequestKey] = Field(min_length=1, max_length=128)

    @model_validator(mode="after")
    def scope(self):
        if (self.window.end-self.window.start).total_seconds() > 90*86400:
            raise ValueError("split_queries_into_at_most_90_day_windows")
        for key in self.keys.values():
            if key.scope != "namespaced" or key.namespace != self.namespace:
                raise ValueError("query_requires_exact_authorized_target_namespace")
        return self


class CollectionPolicy(Contract):
    schema_version: Literal["guardian.collection-policy.v1"] = "guardian.collection-policy.v1"
    cluster_id: ID
    source_id: ID
    namespace: ID
    audit_policy_ref: ID
    # Exact groups/resources, e.g. '/pods' and '/secrets'. '*' is not accepted.
    resources: list[ID] = Field(min_length=1, max_length=256)
    resource_scopes: dict[ID, Literal["namespaced", "cluster"]] = Field(max_length=512)
    approved_policy_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    completeness_attested: bool = Field(strict=True)
    maximum_lag_seconds: int = Field(default=60, strict=True, ge=1, le=3600)

    @model_validator(mode="after")
    def exact_resources(self):
        if any("*" in resource for resource in self.resources):
            raise ValueError("declare_explicit_audit_scope")
        return self
