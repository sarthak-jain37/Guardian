"""Lazy model boundaries. CPU tests never import or initialize llama.cpp."""

import json
import multiprocessing
import time
from copy import deepcopy
from pathlib import Path

from ..modeling import ModelConfig, ModelResult


class ScriptedModelClient:
    producer = "scripted-test"

    def __init__(self, responses=None):
        self.responses = list(responses or [])
        self.calls = []

    def generate(self, stage, payload, output_schema):
        self.calls.append(stage)
        if self.responses:
            response = self.responses.pop(0)
            if isinstance(response, Exception):
                raise response
            return response
        facts = payload["facts"]
        if stage == "investigator":
            return {"summary": "Scripted fixture assessment; not actual model reasoning.",
                    "permission_assessments": [
                        {"permission_id": f["permission_id"],
                         "recommendation": "propose_remove" if f["eligible"] else "retain" if f["protected"] else "request_context",
                         "evidence_ids": f["evidence_ids"][:8],
                         "reason": "Covered non-use in exercised disposable scope." if f["eligible"]
                         else ", ".join(f["reason_codes"])} for f in facts],
                    "uncertainty": ["Finite observation cannot establish every future need."],
                    "questions": ["Can the relevant rare workflow be exercised or documented?"]
                    if any("unexercised_relevant_cycle" in f["reason_codes"] for f in facts) else [],
                    "context_requests": []}
        recommended = {a["permission_id"] for a in payload["investigation"]["permission_assessments"]
                       if a["recommendation"] == "propose_remove"}
        return {"strategy_id": "narrow_dedicated_role", "target_id": payload["target_uid"],
                "decisions": [{"permission_id": f["permission_id"],
                               "action": "remove" if f["permission_id"] in recommended and f["eligible"] else "retain",
                               "evidence_ids": f["evidence_ids"][:8],
                               "reason": "Select only eligible recommendations; retain other grants."} for f in facts],
                "rationale": "Scripted supported subset, with residual risk disclosed.",
                "verification_profile_id": "pod-reader-behavior.v1"}


def runtime_schema(schema, payload):
    """Avoid llama.cpp's expanded length grammar; full bounds remain in Pydantic."""
    schema = deepcopy(schema)
    def visit(value):
        if isinstance(value, dict):
            for key in ["maxLength", "minLength", "maxItems"]:
                if key != "maxItems" or value.get(key) != 0:
                    value.pop(key, None)
            for child in value.values():
                visit(child)
        elif isinstance(value, list):
            for child in value:
                visit(child)
    visit(schema)
    for name in ["PermissionAssessment", "PlanDecision"]:
        definition = schema.get("$defs", {}).get(name)
        if definition:
            definition["properties"]["permission_id"]["enum"] = [f["permission_id"] for f in payload["facts"]]
    # Require one entry per supplied ID without constraining its recommendation/action.
    # This is the same inventory requirement independently enforced by the validators.
    definition_name = "PermissionAssessment" if "PermissionAssessment" in schema.get("$defs", {}) else "PlanDecision"
    field = "permission_assessments" if definition_name == "PermissionAssessment" else "decisions"
    if definition_name in schema.get("$defs", {}):
        entries = []
        for fact in payload["facts"]:
            entry = deepcopy(schema["$defs"][definition_name])
            entry["properties"]["permission_id"] = {"type": "string", "const": fact["permission_id"]}
            entry["properties"]["evidence_ids"] = {"type": "array", "minItems": 1, "maxItems": 3,
                                                    "items": {"type": "string", "enum": fact["evidence_ids"]}}
            entries.append(entry)
        schema["properties"][field] = {"type": "array", "prefixItems": entries,
                                       "minItems": len(entries), "maxItems": len(entries)}
    if "ContextLookup" in schema.get("$defs", {}):
        properties = schema["$defs"]["ContextLookup"].get("properties")
        if properties:
            properties["subject_id"]["enum"] = [payload["allowed_lookup"]["subject_id"]]
    if "target_id" in schema.get("properties", {}):
        schema["properties"]["target_id"]["enum"] = [payload["target_uid"]]
    return schema


def remote_completion(config, messages, schema):
    """Bounded configured vLLM transport. Called only in the isolated process."""
    import os
    from urllib.request import HTTPRedirectHandler, Request, build_opener

    class NoRedirect(HTTPRedirectHandler):
        def redirect_request(self, *args, **kwargs):
            raise ValueError("model_endpoint_redirect_rejected")

    body = {"model": config.model_name, "messages": messages, "max_tokens": config.max_output_tokens,
            "temperature": config.temperature,
            "response_format": {"type": "json_schema", "json_schema": {"name": "guardian", "schema": schema}}}
    if config.provider == "ollama":
        body = {"model": config.model_name, "messages": messages, "stream": False,
                "think": False, "format": schema, "keep_alive": "5m",
                "options": {"temperature": config.temperature, "num_ctx": config.context_length,
                            "num_predict": config.max_output_tokens}}
    if config.seed is not None and config.provider == "ollama":
        body["options"]["seed"] = config.seed
    elif config.seed is not None:
        body["seed"] = config.seed
    headers = {"Content-Type": "application/json"}
    if config.api_key_env:
        key = os.environ.get(config.api_key_env)
        if not key:
            raise ValueError("model_credential_unavailable")
        headers["Authorization"] = "Bearer " + key
    route = "/api/chat" if config.provider == "ollama" else "/chat/completions"
    request = Request(config.endpoint.rstrip("/") + route, data=json.dumps(body).encode(), headers=headers)
    with build_opener(NoRedirect()).open(request, timeout=config.request_timeout_seconds) as response:
        data = response.read(config.max_output_bytes + 1)
    if len(data) > config.max_output_bytes:
        return {"error": "output_too_large"}
    value = json.loads(data)
    if config.provider == "ollama":
        if value.get("done") is not True or value.get("done_reason") != "stop":
            return {"error": "output_truncated"}
        # Preserve common parsing, byte limits and error handling for both APIs.
        value = {"choices": [{"finish_reason": "stop", "message": value["message"]}],
                 "model": value.get("model"), "usage": {"prompt_tokens": value.get("prompt_eval_count"),
                 "completion_tokens": value.get("eval_count")}}
    return value


def completion_output(response, limit):
    choice = response["choices"][0]
    if choice.get("finish_reason") != "stop":
        return {"error": "output_truncated"}
    content = choice["message"]["content"]
    if not isinstance(content, str) or len(content.encode()) > limit:
        return {"error": "output_too_large"}
    output = json.loads(content)
    if not isinstance(output, dict):
        return {"error": "invalid_response"}
    return {"output": output, "usage": response.get("usage", {}),
            "resolved_model": response.get("model"), "finish_reason": choice.get("finish_reason")}


def _provider_worker(connection, settings):
    try:
        config = ModelConfig.model_validate(settings)
        model = None
        if config.provider == "llama-cpp":
            from llama_cpp import Llama
            model = Llama(model_path=config.model_path, n_ctx=config.context_length, n_threads=config.threads,
                          n_gpu_layers=0, verbose=False)
        connection.send({"ready": True})
        while True:
            request = connection.recv()
            if request is None:
                break
            chat, schema = request
            if model is not None:
                payload = json.loads(chat[-1]["content"])
                response = model.create_chat_completion(messages=chat,
                    response_format={"type": "json_object", "schema": runtime_schema(schema, payload)},
                    temperature=config.temperature, seed=config.seed, max_tokens=config.max_output_tokens)
                response["model"] = Path(config.model_path).name
            else:
                response = remote_completion(config, chat, schema)
            connection.send(response if "error" in response else completion_output(response, config.max_output_bytes))
    except Exception:
        # Never forward provider exception strings, URLs or credentials.
        connection.send({"error": "unavailable"})
    finally:
        connection.close()


class ProcessModelClient:
    """One lazy process per worker; startup and inference share one deadline."""

    def __init__(self, config):
        self.config = config
        self.process = None
        self.connection = None

    def _receive(self, deadline):
        remaining = max(0, deadline - time.monotonic())
        if not self.connection.poll(remaining):
            self.close()
            raise TimeoutError("model deadline exceeded")
        try:
            return self.connection.recv()
        except EOFError as exc:
            self.close()
            raise RuntimeError("model process exited") from exc

    def generate(self, stage, messages, output_schema, config, *, timeout_seconds=None):
        if config != self.config:
            raise ValueError("model configuration changed")
        started = time.monotonic()
        deadline = started + min(config.request_timeout_seconds, timeout_seconds or config.request_timeout_seconds)
        error = None
        result = {}
        try:
            if self.process is None:
                context = multiprocessing.get_context("spawn")
                self.connection, child = context.Pipe()
                self.process = context.Process(target=_provider_worker, args=(child, config.model_dump(mode="json")), daemon=True)
                self.process.start()
                child.close()
                ready = self._receive(deadline)
                if not ready.get("ready"):
                    raise RuntimeError("model startup unavailable")
            self.connection.send((messages, output_schema))
            result = self._receive(deadline)
            error = result.get("error")
        except TimeoutError:
            error = "timeout"
        except Exception:
            error = "unavailable"
        if error:
            self.close()
        usage = result.get("usage", {})
        return ModelResult(stage=stage, producer=self.producer, config_hash=config.fingerprint(),
                           requested_model=config.model_name, requested_revision=config.model_revision,
                           resolved_model=result.get("resolved_model"), resolved_revision=None,
                           duration_seconds=time.monotonic() - started, input_tokens=usage.get("prompt_tokens"),
                           output_tokens=usage.get("completion_tokens"), finish_reason=result.get("finish_reason"),
                           response=result.get("output") if not error else None, error=error)

    def close(self):
        if self.process is not None:
            if self.process.is_alive():
                self.process.terminate()
            self.process.join(timeout=2)
            if self.process.is_alive():
                self.process.kill()
                self.process.join(timeout=2)
            self.process = None
        if self.connection is not None:
            self.connection.close()
            self.connection = None


class LlamaCppModelClient(ProcessModelClient):
    producer = "llama-cpp"

    def __init__(self, model_path, timeout_seconds=180, context_length=8192, threads=4, config=None):
        config = config or ModelConfig(profile="dev-laptop", provider="llama-cpp", model_name=Path(model_path).name,
                                      model_path=str(Path(model_path).resolve()), request_timeout_seconds=timeout_seconds,
                                      context_length=context_length, threads=threads)
        super().__init__(config)


class VllmModelClient(ProcessModelClient):
    producer = "vllm"


class OllamaModelClient(ProcessModelClient):
    producer = "ollama"
