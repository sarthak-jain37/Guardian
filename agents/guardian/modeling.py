"""Strict worker profiles and model results; no provider is initialized here."""

import hashlib
import json
import time
import tomllib
from copy import deepcopy
from pathlib import Path
from typing import Literal
from urllib.parse import urlsplit

from pydantic import Field, JsonValue, model_validator

from contracts.usage_summary_v1 import Contract, ID
from .prompts import PROMPT_VERSION, SCHEMA_VERSION, messages


class ModelConfig(Contract):
    schema_version: Literal["guardian.model-config.v2"] = "guardian.model-config.v2"
    profile: Literal["test", "dev-laptop", "lab"] = "test"
    profile_version: Literal["guardian.model-profile.v1"] = "guardian.model-profile.v1"
    provider: Literal["scripted", "llama-cpp", "vllm", "ollama"] = "scripted"
    model_name: ID = "scripted-test"
    model_revision: ID | None = None
    model_path: str | None = Field(default=None, max_length=4096)
    endpoint: str | None = Field(default=None, max_length=2048)
    api_key_env: ID | None = None
    context_length: int = Field(default=8192, strict=True, ge=2048, le=131072)
    max_output_tokens: int = Field(default=2048, strict=True, ge=64, le=8192)
    max_input_bytes: int = Field(default=131072, strict=True, ge=1024, le=524288)
    max_output_bytes: int = Field(default=65536, strict=True, ge=1024, le=262144)
    request_timeout_seconds: int = Field(default=180, strict=True, ge=1, le=600)
    active_run_timeout_seconds: int = Field(default=600, strict=True, ge=1, le=3600)
    concurrency: int = Field(default=1, strict=True, ge=1, le=1)
    queue_limit: int = Field(default=8, strict=True, ge=1, le=64)
    temperature: float = Field(default=0.0, ge=0, le=2)
    seed: int | None = Field(default=17, strict=True, ge=0)
    threads: int = Field(default=4, strict=True, ge=1, le=64)
    structured_output_mode: Literal["json_schema"] = "json_schema"
    prompt_version: Literal["guardian.bounded-stages.v4"] = PROMPT_VERSION
    output_schema_version: Literal["guardian.model-output.v2"] = SCHEMA_VERSION

    @model_validator(mode="after")
    def provider_scope(self):
        if self.max_output_tokens >= self.context_length:
            raise ValueError("output budget must be smaller than context")
        if self.provider == "scripted" and self.profile != "test":
            raise ValueError("scripted inference requires the test profile")
        if self.provider != "scripted" and self.profile == "test":
            raise ValueError("real inference requires a real-model profile")
        if self.profile == "lab" and not self.model_revision:
            raise ValueError("lab profile requires an explicit requested model revision")
        if self.provider == "llama-cpp" and (not self.model_path or self.endpoint is not None):
            raise ValueError("llama-cpp requires a model path and no endpoint")
        if self.provider in ("vllm", "ollama"):
            parsed = urlsplit(self.endpoint or "")
            if (parsed.scheme not in ("http", "https") or not parsed.hostname or parsed.username or parsed.password
                    or parsed.query or parsed.fragment):
                raise ValueError("remote provider requires an HTTP endpoint without embedded credentials")
            if self.model_path is not None:
                raise ValueError("remote inference cannot use a local model path")
        elif self.endpoint is not None or self.api_key_env is not None:
            raise ValueError("endpoint credentials belong only to the remote provider")
        return self

    def fingerprint(self):
        encoded = json.dumps(self.model_dump(mode="json"), sort_keys=True, separators=(",", ":")).encode()
        return "sha256:" + hashlib.sha256(encoded).hexdigest()


class ModelResult(Contract):
    schema_version: Literal["guardian.model-result.v2"] = "guardian.model-result.v2"
    stage: Literal["investigator", "planner"]
    producer: ID
    config_hash: ID
    requested_model: ID
    requested_revision: ID | None
    resolved_model: ID | None
    resolved_revision: ID | None
    prompt_version: Literal["guardian.bounded-stages.v4"] = PROMPT_VERSION
    output_schema_version: Literal["guardian.model-output.v2"] = SCHEMA_VERSION
    profile_version: Literal["guardian.model-profile.v1"] = "guardian.model-profile.v1"
    duration_seconds: float = Field(ge=0)
    input_tokens: int | None = Field(default=None, strict=True, ge=0)
    output_tokens: int | None = Field(default=None, strict=True, ge=0)
    finish_reason: ID | None = None
    input_hash: ID | None = None
    output_schema_hash: ID | None = None
    response: dict[str, JsonValue] | None
    error: Literal["unavailable", "timeout", "invalid_response", "output_truncated", "input_too_large", "output_too_large"] | None

    @model_validator(mode="after")
    def outcome(self):
        if (self.error is None) != (self.response is not None):
            raise ValueError("result must contain either a response or an explicit error")
        return self


def load_profile(path):
    return ModelConfig.model_validate(tomllib.loads(Path(path).read_text()))


def model_config(client):
    return getattr(client, "config", ModelConfig())


PROMPT_SELECTION_VERSION = "guardian.prompt-selection.v1"


def prompt_facts(facts,snapshot_id):
    """Bound citation menus without changing facts or full-evidence validation."""
    selected=[]
    for fact in facts:
        refs=fact['evidence_ids']
        def priority(ref):
            if ref.startswith(('usage-','request-','inventory:')):return 0
            if ref.startswith('audit:'):return 1
            return 2
        menu=sorted(refs,key=lambda ref:(priority(ref),ref))[:8]
        value={**fact,'evidence_ids':menu}
        if len(menu)<len(refs):value.update(omitted_evidence_id_count=len(refs)-len(menu),
            omitted_detail_ref='snapshot:'+snapshot_id+'/permission:'+fact['permission_id'])
        selected.append(value)
    return selected


def scoped_schema(schema, payload):
    schema = deepcopy(schema)
    menu = payload.get("allowed_lookups")
    if menu and "ContextLookup" in schema.get("$defs", {}):
        schema["$defs"]["ContextLookup"] = {"oneOf": [
            {"type": "object", "properties": {key: {"const": value} for key, value in entry.items()},
             "required": list(entry), "additionalProperties": False} for entry in menu]}
    if payload.get("remaining_lookup_rounds") == 0 and "context_requests" in schema.get("properties", {}):
        schema["properties"]["context_requests"]["maxItems"] = 0
    # Reflect the *existing* domain validator's allowed decisions in decoding.
    # This supplies no expected answer: an eligible permission can still be
    # retained, deferred or investigated. Ineligible removal is never a choice.
    facts = payload.get("facts", [])
    definition = "PermissionAssessment" if "PermissionAssessment" in schema.get("$defs", {}) else "PlanDecision"
    field = "permission_assessments" if definition == "PermissionAssessment" else "decisions"
    if facts and definition in schema.get("$defs", {}):
        suggested = {a["permission_id"] for a in payload.get("investigation", {}).get("permission_assessments", [])
                     if a["recommendation"] == "propose_remove"}
        entries = []
        for fact in facts:
            entry = deepcopy(schema["$defs"][definition])
            properties = entry["properties"]
            properties["permission_id"] = {"type": "string", "const": fact["permission_id"]}
            properties["evidence_ids"]["items"] = {"type": "string", "enum": fact["evidence_ids"]}
            if definition == "PermissionAssessment" and not fact.get("eligible", False):
                properties["recommendation"]["enum"] = ["retain", "request_context", "human_investigation"]
            elif definition == "PlanDecision" and (not fact.get("eligible", False) or fact["permission_id"] not in suggested):
                properties["action"]["enum"] = ["retain"]
            entries.append(entry)
        schema["properties"][field] = {"type": "array", "prefixItems": entries,
                                      "minItems": len(entries), "maxItems": len(entries)}
    if "target_id" in schema.get("properties", {}) and payload.get("target_uid"):
        schema["properties"]["target_id"] = {"type": "string", "const": payload["target_uid"]}
    return schema


def model_input(stage, payload, schema, client):
    value = {"messages": messages(stage, payload), "output_schema": scoped_schema(schema, payload)}
    encoded = json.dumps(value, ensure_ascii=False, sort_keys=True).encode()
    record = {"input_hash": "sha256:" + hashlib.sha256(encoded).hexdigest(), "bytes": len(encoded)}
    if len(encoded) > model_config(client).max_input_bytes:
        return {**record, "omitted_reason": "input_too_large"}
    return {**record, "selection_version": PROMPT_SELECTION_VERSION, **value}


def call_model(client, stage, payload, schema, timeout_seconds):
    """Only the explicitly scripted test boundary accepts legacy raw dictionaries."""
    from .adapters.models import ScriptedModelClient

    config = model_config(client)
    chat = messages(stage, payload)
    schema = scoped_schema(schema, payload)
    started = time.monotonic()
    result = None
    error = None
    audit = model_input(stage, payload, schema, client)
    if audit.get("omitted_reason"):
        error = "input_too_large"
    else:
        try:
            if isinstance(client, ScriptedModelClient):
                raw = client.generate(stage, payload, schema)
                result = ModelResult(stage=stage, producer="scripted-test", config_hash=config.fingerprint(),
                                     requested_model=config.model_name, requested_revision=config.model_revision,
                                     resolved_model="scripted-test", resolved_revision=None,
                                     duration_seconds=time.monotonic() - started, response=raw, error=None)
            else:
                raw = client.generate(stage, chat, schema, config, timeout_seconds=timeout_seconds)
                result = ModelResult.model_validate(raw)
            if (result.stage != stage or result.producer != client.producer
                    or result.config_hash != config.fingerprint()):
                raise ValueError("model_result_scope_mismatch")
            if len(result.model_dump_json().encode()) > config.max_output_bytes:
                result = None
                error = "output_too_large"
        except TimeoutError:
            error = "timeout"
        except Exception:
            # Provider exception strings can contain endpoints/credentials. Keep
            # only stable error codes in checkpoints and reports.
            error = "unavailable"
    if error:
        result = ModelResult(stage=stage, producer=client.producer, config_hash=config.fingerprint(),
                             requested_model=config.model_name, requested_revision=config.model_revision,
                             resolved_model=None, resolved_revision=None, duration_seconds=time.monotonic() - started,
                             response=None, error=error)
    schema_hash = "sha256:" + hashlib.sha256(json.dumps(schema, sort_keys=True).encode()).hexdigest()
    return result.model_copy(update={"input_hash": audit["input_hash"], "output_schema_hash": schema_hash})
