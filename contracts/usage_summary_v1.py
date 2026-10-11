"""Collector boundary from the v3 plan; this module does not collect audit logs."""

from datetime import datetime, timedelta
from typing import Annotated, Literal

from pydantic import AwareDatetime, BaseModel, ConfigDict, Field, model_validator

ID = Annotated[str, Field(min_length=1, max_length=256)]
Count = Annotated[int, Field(strict=True, ge=0)]


class Contract(BaseModel):
    model_config = ConfigDict(extra="forbid", validate_assignment=True)


def utc(value: datetime) -> datetime:
    if value.utcoffset() != timedelta(0):
        raise ValueError("timestamps must be UTC")
    return value


class Window(Contract):
    start: AwareDatetime
    end: AwareDatetime

    @model_validator(mode="after")
    def ordered(self):
        utc(self.start)
        utc(self.end)
        if self.start >= self.end:
            raise ValueError("expected start < end")
        return self


class Subject(Contract):
    username: ID
    kind: Literal["service_account", "user", "unknown"]
    namespace: ID | None
    name: ID | None
    uid: ID | None
    uid_status: Literal["verified", "unknown"]
    groups: list[ID] = Field(max_length=128)
    identity_evidence_refs: list[ID] = Field(max_length=32)

    @model_validator(mode="after")
    def identity(self):
        if self.kind == "service_account":
            if not self.namespace or not self.name:
                raise ValueError("service account needs namespace/name")
            if self.username != f"system:serviceaccount:{self.namespace}:{self.name}":
                raise ValueError("service account identity disagrees")
        if self.uid_status == "verified" and (not self.uid or not self.identity_evidence_refs):
            raise ValueError("verified UID needs identity evidence")
        if self.uid_status == "unknown" and self.uid is not None:
            raise ValueError("unknown UID must remain null")
        return self


class RequestKey(Contract):
    kind: Literal["resource", "non_resource"]
    verb: ID
    api_group: str | None = Field(max_length=256)
    resource: ID | None
    subresource: ID | None
    scope: Literal["namespaced", "all_namespaces", "cluster", "non_resource", "unknown"]
    namespace: ID | None
    resource_name: ID | None
    name_resolution: Literal["explicit", "any_name", "collection", "unknown", "not_applicable"]
    name_field_selector: ID | None
    non_resource_path: str | None = Field(max_length=2048)

    @model_validator(mode="after")
    def semantics(self):
        if self.kind == "resource":
            if self.api_group is None or not self.resource or self.non_resource_path is not None:
                raise ValueError("resource key needs group/resource and no URL")
            if self.scope == "non_resource":
                raise ValueError("resource scope cannot be non_resource")
        else:
            if not self.non_resource_path or self.scope != "non_resource":
                raise ValueError("non-resource key needs path and scope")
            if any(v is not None for v in [self.api_group, self.resource, self.subresource,
                                          self.namespace, self.resource_name, self.name_field_selector]):
                raise ValueError("non-resource key cannot have resource fields")
            if self.name_resolution != "not_applicable":
                raise ValueError("non-resource name resolution must be not_applicable")
        if self.scope == "namespaced" and not self.namespace:
            raise ValueError("namespaced key needs namespace")
        if self.scope in ("cluster", "all_namespaces") and self.namespace is not None:
            raise ValueError("cluster/all-namespace key cannot have namespace")
        if self.name_resolution == "explicit" and not self.resource_name:
            raise ValueError("explicit key needs name")
        if self.name_resolution in ("any_name", "collection", "not_applicable"):
            if self.resource_name is not None or self.name_field_selector is not None:
                raise ValueError("projection cannot have name/selector")
        return self


class Counts(Contract):
    successful_completed: Count
    authorized_error: Count
    authorized_incomplete: Count
    denied: Count
    unknown: Count

    def authorized(self) -> int:
        return self.successful_completed + self.authorized_error + self.authorized_incomplete

    def total(self) -> int:
        return sum(self.model_dump().values())


class CoverageSlice(Contract):
    interval: Window
    status: Literal["complete_for_declared_scope", "partial", "unavailable"]
    reason_codes: list[ID] = Field(max_length=32)
    source_ids: list[ID] = Field(max_length=32)
    audit_policy_refs: list[ID] = Field(max_length=32)
    health_evidence_refs: list[ID] = Field(max_length=32)
    known_lost_events: Count | None

    @model_validator(mode="after")
    def support(self):
        if self.status == "complete_for_declared_scope":
            if self.known_lost_events != 0 or self.reason_codes:
                raise ValueError("complete coverage cannot have unknown/known loss or gaps")
            if not all([self.source_ids, self.audit_policy_refs, self.health_evidence_refs]):
                raise ValueError("complete coverage needs source, policy and health references")
        elif not self.reason_codes:
            raise ValueError("incomplete coverage needs reasons")
        return self


class UsageBucket(Contract):
    bucket_start: AwareDatetime
    interval: Window
    counts: Counts
    first_request_at: AwareDatetime | None
    last_request_at: AwareDatetime | None
    evidence_refs: list[ID] = Field(max_length=32)

    @model_validator(mode="after")
    def bounds(self):
        utc(self.bucket_start)
        if any([self.bucket_start.minute, self.bucket_start.second, self.bucket_start.microsecond]):
            raise ValueError("bucket_start must be UTC hour boundary")
        if not (self.bucket_start <= self.interval.start < self.interval.end <= self.bucket_start + timedelta(hours=1)):
            raise ValueError("bucket interval outside its hour")
        if self.counts.total() == 0:
            if self.first_request_at is not None or self.last_request_at is not None:
                raise ValueError("zero bucket cannot have request times")
        else:
            if self.first_request_at is None or self.last_request_at is None or not self.evidence_refs:
                raise ValueError("nonzero bucket needs request times and evidence")
            utc(self.first_request_at)
            utc(self.last_request_at)
            if not self.interval.start <= self.first_request_at <= self.last_request_at < self.interval.end:
                raise ValueError("request times outside bucket")
        return self


class CarriedAuthorization(Contract):
    request_ref: ID
    request_started_at: AwareDatetime
    authorized_at: AwareDatetime
    last_observed_at: AwareDatetime
    completed_at: AwareDatetime | None
    evidence_refs: list[ID] = Field(min_length=1, max_length=32)

    @model_validator(mode="after")
    def times(self):
        for value in [self.request_started_at, self.authorized_at, self.last_observed_at, self.completed_at]:
            if value is not None:
                utc(value)
        if not self.request_started_at <= self.authorized_at <= self.last_observed_at:
            raise ValueError("carried authorization times disagree")
        if self.completed_at is not None and self.completed_at < self.authorized_at:
            raise ValueError("completion precedes authorization")
        return self


class UsageSeries(Contract):
    request_key_id: ID
    request_key: RequestKey
    buckets: list[UsageBucket] = Field(max_length=2200)
    coverage: list[CoverageSlice] = Field(min_length=1, max_length=5000)
    carried_authorized_requests: list[CarriedAuthorization] = Field(max_length=1000)


class UsageSummary(Contract):
    schema_version: Literal["guardian.usage-summary.v1"]
    summary_id: ID
    revision: Annotated[int, Field(strict=True, ge=1)]
    cluster_id: ID
    subject: Subject
    query_window: Window
    generated_at: AwareDatetime
    processed_through: AwareDatetime | None
    bucket_resolution: Literal["PT1H"]
    boundary_mode: Literal["exact"]
    collector_version: ID
    aggregation_version: ID
    source_cursor_refs: list[ID] = Field(max_length=128)
    requested_key_ids: list[ID] = Field(min_length=1, max_length=256)
    series: list[UsageSeries] = Field(min_length=1, max_length=256)
    truncated: bool = Field(strict=True)
    warnings: list[ID] = Field(max_length=128)

    @model_validator(mode="after")
    def semantics(self):
        utc(self.generated_at)
        if self.query_window.end > self.generated_at:
            raise ValueError("query ends after generation")
        if self.processed_through is not None:
            utc(self.processed_through)
            if self.processed_through > self.generated_at:
                raise ValueError("progress after generation")
        returned = [s.request_key_id for s in self.series]
        if len(set(returned)) != len(returned) or len(set(self.requested_key_ids)) != len(self.requested_key_ids):
            raise ValueError("duplicate request key")
        if set(returned) != set(self.requested_key_ids):
            raise ValueError("every requested key needs one explicit series")
        q = self.query_window
        for series in self.series:
            cursor = q.start
            for coverage in series.coverage:
                if coverage.interval.start != cursor or coverage.interval.end > q.end:
                    raise ValueError("coverage must partition entire query in order")
                if coverage.status == "complete_for_declared_scope":
                    if self.processed_through is None or coverage.interval.end > self.processed_through:
                        raise ValueError("complete coverage exceeds ingestion progress")
                cursor = coverage.interval.end
            if cursor != q.end:
                raise ValueError("coverage does not reach query end")
            cursor = q.start
            for bucket in series.buckets:
                expected_end = min(bucket.bucket_start + timedelta(hours=1), q.end)
                if bucket.interval.start != cursor or bucket.interval.end != expected_end:
                    raise ValueError("buckets must be exact clipped hourly intervals without gaps")
                cursor = bucket.interval.end
            if series.buckets and cursor != q.end:
                raise ValueError("buckets do not reach query end")
            if not series.buckets and any(c.status == "complete_for_declared_scope" for c in series.coverage):
                raise ValueError("complete coverage needs explicit buckets, including zero")
            for carried in series.carried_authorized_requests:
                if not carried.request_started_at < q.start or not carried.authorized_at < q.end:
                    raise ValueError("carried request does not overlap window")
                if carried.completed_at is not None and carried.completed_at <= q.start:
                    raise ValueError("carried request already completed before window")
                if carried.last_observed_at > self.generated_at or (carried.completed_at and carried.completed_at > self.generated_at):
                    raise ValueError("carried request observed in future")
        return self
