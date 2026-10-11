from datetime import timedelta
from typing import Annotated, Literal
from pydantic import AwareDatetime, BaseModel, ConfigDict, Field, model_validator

ID = Annotated[str, Field(min_length=1, max_length=256)]
Count = Annotated[int, Field(strict=True, ge=0)]

class Contract(BaseModel):
    model_config = ConfigDict(extra='forbid')

class Window(Contract):
    start: AwareDatetime
    end: AwareDatetime

    @model_validator(mode='after')
    def ordered_utc(self):
        if self.start.utcoffset() != timedelta(0) or self.end.utcoffset() != timedelta(0):
            raise ValueError('timestamps must be UTC')
        if self.start >= self.end:
            raise ValueError('expected start < end')
        return self

class Subject(Contract):
    username: ID
    kind: Literal['service_account', 'user', 'unknown']
    namespace: ID | None
    name: ID | None
    uid: ID | None
    uid_status: Literal['verified', 'unknown']
    groups: list[ID] = Field(max_length=128)
    identity_evidence_refs: list[ID] = Field(max_length=32)

class RequestKey(Contract):
    kind: Literal['resource', 'non_resource']
    verb: ID
    api_group: str | None = Field(max_length=256)
    resource: ID | None
    subresource: ID | None
    scope: Literal['namespaced', 'all_namespaces', 'cluster', 'non_resource', 'unknown']
    namespace: ID | None
    resource_name: ID | None
    name_resolution: Literal['explicit', 'any_name', 'collection', 'unknown', 'not_applicable']
    name_field_selector: ID | None
    non_resource_path: str | None = Field(max_length=2048)

class Counts(Contract):
    successful_completed: Count
    authorized_error: Count
    authorized_incomplete: Count
    denied: Count
    unknown: Count

class CoverageSlice(Contract):
    interval: Window
    status: Literal['complete_for_declared_scope', 'partial', 'unavailable']
    reason_codes: list[ID] = Field(max_length=32)
    source_ids: list[ID] = Field(max_length=32)
    audit_policy_refs: list[ID] = Field(max_length=32)
    health_evidence_refs: list[ID] = Field(max_length=32)
    known_lost_events: Count | None

class UsageBucket(Contract):
    bucket_start: AwareDatetime
    interval: Window
    counts: Counts
    first_request_at: AwareDatetime | None
    last_request_at: AwareDatetime | None
    evidence_refs: list[ID] = Field(max_length=32)

class CarriedAuthorization(Contract):
    request_ref: ID
    request_started_at: AwareDatetime
    authorized_at: AwareDatetime
    last_observed_at: AwareDatetime
    completed_at: AwareDatetime | None
    evidence_refs: list[ID] = Field(min_length=1, max_length=32)

class UsageSeries(Contract):
    request_key_id: ID
    request_key: RequestKey
    buckets: list[UsageBucket] = Field(max_length=2200)
    coverage: list[CoverageSlice] = Field(min_length=1, max_length=5000)
    carried_authorized_requests: list[CarriedAuthorization] = Field(max_length=1000)

class UsageSummary(Contract):
    schema_version: Literal['guardian.usage-summary.v1']
    summary_id: ID
    revision: Annotated[int, Field(strict=True, ge=1)]
    cluster_id: ID
    subject: Subject
    query_window: Window
    generated_at: AwareDatetime
    processed_through: AwareDatetime | None
    bucket_resolution: Literal['PT1H']
    boundary_mode: Literal['exact']
    collector_version: ID
    aggregation_version: ID
    source_cursor_refs: list[ID] = Field(max_length=128)
    requested_key_ids: list[ID] = Field(min_length=1, max_length=256)
    series: list[UsageSeries] = Field(min_length=1, max_length=256)
    truncated: bool = Field(strict=True)
    warnings: list[ID] = Field(max_length=128)

    @model_validator(mode='after')
    def requested_keys_match(self):
        returned = [item.request_key_id for item in self.series]
        if len(set(returned)) != len(returned):
            raise ValueError('duplicate series')
        if len(set(self.requested_key_ids)) != len(self.requested_key_ids):
            raise ValueError('duplicate requested key')
        if set(returned) != set(self.requested_key_ids):
            raise ValueError('every requested key needs one explicit series')
        return self
