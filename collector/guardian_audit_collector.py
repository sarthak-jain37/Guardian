#!/usr/bin/env python3
"""
Guardian — Node 1: Audit & Data Collector (single-file version)
================================================================================

Everything from the modular collector/ package, consolidated into one
standalone Python script. No package imports required — just:

    python3 guardian_audit_collector.py --once     # single scan, then exit
    python3 guardian_audit_collector.py              # continuous polling loop

or import it directly:

    import guardian_audit_collector as guardian
    guardian.run_once()

Sections below, in dependency order (each was originally its own module
under collector/ — kept as clearly separated blocks so it's still easy
to navigate):

    1. CONFIG        — environment-variable configuration
    2. MODELS         — PermissionKey / AuditEvent / ScanStats dataclasses
    3. DISCOVER        — audit-log path auto-discovery
    4. STATE             — scanner offset persistence + rotation detection
    5. PARSER              — raw JSON line -> AuditEvent, all filtering
    6. AGGREGATOR             — AuditEvent list -> nested usage dict
    7. OUTPUT                   — atomic JSON read/write, schema conversion
    8. AUDIT_COLLECTOR             — orchestration: run_once() / run_forever()
    9. __main__                       — CLI entrypoint

Guardian architecture boundary: this component is an EVIDENCE COLLECTOR
only. It never decides a permission is excessive, never touches RBAC,
never generates RBAC YAML, and never calls an LLM. It answers exactly
one question: what permissions did each ServiceAccount actually use,
how often, and when was each last observed.
"""
from __future__ import annotations

import json
import logging
import os
import re
import signal
import sys
import time
from dataclasses import asdict, dataclass, field
from datetime import datetime, timedelta, timezone
from enum import Enum, auto
from pathlib import Path
from typing import Iterable
from urllib.parse import parse_qs, urlsplit

# ================================================================================
# 1. CONFIG
# ================================================================================


def _env_int(name: str, default: int) -> int:
    raw = os.environ.get(name)
    if raw is None or raw.strip() == "":
        return default
    try:
        return int(raw)
    except ValueError:
        raise ValueError(f"Environment variable {name}={raw!r} is not a valid integer")


@dataclass(frozen=True)
class Config:
    # Where the raw Kubernetes audit log lives. If unset, discovery
    # attempts auto-discovery (proc/cmdline, static manifest).
    audit_log_path: str | None = field(
        default_factory=lambda: os.environ.get("AUDIT_LOG_PATH") or None
    )

    # Final machine-readable Guardian output AND the persisted aggregate
    # (the output file doubles as the durable aggregate store for this
    # JSON-based PoC).
    output_path: str = field(
        default_factory=lambda: os.environ.get("OUTPUT_PATH", "/data/guardian_audit.json")
    )

    # Scanner offset/state file — NOT the same as the aggregated
    # statistics. Tracks only "how far into the raw log have we read".
    state_path: str = field(
        default_factory=lambda: os.environ.get("STATE_PATH", "/data/.audit_scan_state.json")
    )

    # "*" (default) analyzes every namespace. A concrete namespace value
    # restricts collection to that namespace only.
    target_namespace: str = field(
        default_factory=lambda: os.environ.get("TARGET_NAMESPACE", "*")
    )

    # How often (seconds) the continuous polling loop rescans the log.
    scan_interval_seconds: int = field(
        default_factory=lambda: _env_int("SCAN_INTERVAL_SECONDS", 30)
    )

    # Debug log for malformed/error events.
    error_log_path: str = field(
        default_factory=lambda: os.environ.get(
            "ERROR_LOG_PATH", "/data/guardian_collector_errors.log"
        )
    )

    def matches_namespace(self, namespace: str | None) -> bool:
        """Whether an event's namespace passes the configured filter."""
        if self.target_namespace == "*":
            return True
        return namespace == self.target_namespace

    def ensure_parent_dirs(self) -> None:
        for p in (self.output_path, self.state_path, self.error_log_path):
            Path(p).parent.mkdir(parents=True, exist_ok=True)


def load_config() -> Config:
    return Config()


# ================================================================================
# 2. MODELS
# ================================================================================

# Kubernetes verbs that don't map cleanly onto a single normal RBAC rule
# check. Still recorded (never silently dropped/relabeled), just kept
# in a separate bucket — see `is_special`.
SPECIAL_VERBS = frozenset({"watch", "proxy", "connect"})


@dataclass(frozen=True)
class PermissionKey:
    """Identity of a permission: (apiGroup, resource, verb).

    Never identify a permission by verb alone — "get pods" and
    "get secrets" are different permissions.
    """

    api_group: str  # "" for the core/legacy API group, never omitted/invented
    resource: str
    verb: str

    @property
    def is_special(self) -> bool:
        return self.verb in SPECIAL_VERBS

    def as_tuple(self) -> tuple[str, str, str]:
        return (self.api_group, self.resource, self.verb)


@dataclass
class AuditEvent:
    """A parsed, filtered-down Kubernetes audit event.

    Only ever constructed for events that already passed the
    ResponseComplete + success-status + ServiceAccount-user filters.
    """

    service_account: str
    namespace_identity: str  # namespace the ServiceAccount itself belongs to
    resource_namespace: str | None  # namespace of the object acted upon (None = cluster-scoped)
    api_group: str
    resource: str
    verb: str
    timestamp: str  # ISO-8601 UTC, from requestReceivedTimestamp (falls back to stageTimestamp)
    response_code: int
    field_manager: str | None = None  # from requestURI's ?fieldManager=... query param, when present

    @property
    def permission_key(self) -> PermissionKey:
        return PermissionKey(self.api_group, self.resource, self.verb)


@dataclass
class ScanStats:
    """Per-cycle counters for operational logging."""

    events_scanned: int = 0
    service_account_events: int = 0
    ignored_non_service_account: int = 0
    failed_events_ignored: int = 0
    malformed_events: int = 0
    skipped_incomplete_stage: int = 0
    filtered_by_namespace: int = 0
    new_events_processed: int = 0
    service_accounts_touched: set = field(default_factory=set)


# ================================================================================
# 3. DISCOVER — audit-log path auto-discovery
# ================================================================================
#
# Never invents a path such as /var/log/audit.log. Discovery order:
#   1. AUDIT_LOG_PATH env var (explicit config always wins — Config)
#   2. Running kube-apiserver process: /proc/<pid>/cmdline
#   3. Static kube-apiserver manifest: /etc/kubernetes/manifests/kube-apiserver.yaml
#   4. Give up and report clearly, with a kubectl hint the operator can
#      run themselves (we do not shell out to kubectl automatically).

discover_logger = logging.getLogger("guardian.collector.discover")

_ARG_RE = re.compile(r"--audit-log-path=([^\s\x00]+)")


class AuditLogNotFoundError(RuntimeError):
    """Raised when no audit log path could be discovered or configured."""


def _scan_proc_for_apiserver() -> str | None:
    proc = Path("/proc")
    if not proc.is_dir():
        return None
    for entry in proc.iterdir():
        if not entry.name.isdigit():
            continue
        cmdline_path = entry / "cmdline"
        try:
            raw = cmdline_path.read_bytes()
        except (OSError, PermissionError):
            continue
        cmdline = raw.replace(b"\x00", b" ").decode("utf-8", errors="ignore")
        if "kube-apiserver" not in cmdline:
            continue
        match = _ARG_RE.search(cmdline)
        if match:
            discover_logger.info("Discovered audit-log-path via /proc/%s/cmdline", entry.name)
            return match.group(1)
    return None


def _scan_static_manifest(
    manifest_path: str = "/etc/kubernetes/manifests/kube-apiserver.yaml",
) -> str | None:
    p = Path(manifest_path)
    if not p.exists():
        return None
    try:
        text = p.read_text()
    except OSError:
        return None

    try:
        import yaml  # optional; only used if present

        doc = yaml.safe_load(text)
        containers = (doc or {}).get("spec", {}).get("containers", [])
        for c in containers:
            for arg in c.get("command", []) + c.get("args", []):
                m = _ARG_RE.search(arg)
                if m:
                    discover_logger.info("Discovered audit-log-path via static manifest (YAML parse)")
                    return m.group(1)
    except Exception:  # pragma: no cover - PyYAML absent or unexpected shape
        pass

    # Dependency-free fallback: scan raw text for the flag.
    m = _ARG_RE.search(text)
    if m:
        discover_logger.info("Discovered audit-log-path via static manifest (raw scan)")
        return m.group(1)
    return None


def discover_audit_log_path(configured_path: str | None) -> str:
    """Resolve the audit log path or raise AuditLogNotFoundError."""
    if configured_path:
        discover_logger.info("Using configured AUDIT_LOG_PATH=%s", configured_path)
        return configured_path

    found = _scan_proc_for_apiserver()
    if found:
        return found

    found = _scan_static_manifest()
    if found:
        return found

    raise AuditLogNotFoundError(
        "Could not discover the Kubernetes audit log path. Checked: "
        "(1) AUDIT_LOG_PATH env var, (2) /proc/<pid>/cmdline for a running "
        "kube-apiserver, (3) /etc/kubernetes/manifests/kube-apiserver.yaml. "
        "This usually means the collector cannot see the control-plane "
        "process/filesystem from its current container. Run on the "
        "control-plane node, mount the audit-log directory into the "
        "Guardian container, or inspect the apiserver Pod yourself with "
        "`kubectl -n kube-system get pod -l component=kube-apiserver -o "
        "yaml | grep audit-log-path` and set AUDIT_LOG_PATH explicitly. "
        "Refusing to guess a default path."
    )


# ================================================================================
# 4. STATE — incremental-read scanner state
# ================================================================================
#
# Tracks ONLY "how far into the raw audit log have we read" — distinct
# from the aggregated ServiceAccount statistics (see OUTPUT below).

state_logger = logging.getLogger("guardian.collector.state")


@dataclass
class ScannerState:
    offset: int = 0
    # inode is used as a secondary rotation signal alongside size shrink,
    # since some rotation strategies replace the file (new inode) without
    # necessarily shrinking it below the old offset.
    inode: int | None = None

    @classmethod
    def load(cls, path: str) -> "ScannerState":
        p = Path(path)
        if not p.exists():
            state_logger.info("No existing scanner state at %s — starting from offset 0", path)
            return cls()
        try:
            data = json.loads(p.read_text())
            return cls(offset=int(data.get("offset", 0)), inode=data.get("inode"))
        except (json.JSONDecodeError, ValueError, OSError) as exc:
            state_logger.error(
                "Scanner state at %s was unreadable (%s) — resetting to offset 0", path, exc
            )
            return cls()

    def save(self, path: str) -> None:
        p = Path(path)
        p.parent.mkdir(parents=True, exist_ok=True)
        tmp_path = p.with_suffix(p.suffix + f".tmp.{os.getpid()}")
        tmp_path.write_text(json.dumps(asdict(self)))
        with open(tmp_path, "r+b") as f:
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp_path, p)  # atomic on POSIX

    def reconcile_with_file(self, file_size: int, file_inode: int) -> bool:
        """Detect rotation/truncation and reset offset to 0 if needed.

        Returns True if a reset happened (useful for logging).
        """
        if self.offset > file_size:
            state_logger.warning(
                "Stored offset (%d) exceeds current file size (%d) — log was "
                "rotated/truncated; resetting offset to 0",
                self.offset,
                file_size,
            )
            self.offset = 0
            self.inode = file_inode
            return True
        if self.inode is not None and self.inode != file_inode:
            state_logger.warning(
                "Audit log inode changed (%s -> %s) — log was rotated; resetting offset to 0",
                self.inode,
                file_inode,
            )
            self.offset = 0
            self.inode = file_inode
            return True
        if self.inode is None:
            self.inode = file_inode
        return False


# ================================================================================
# 5. PARSER — raw JSON line -> AuditEvent, all filtering
# ================================================================================

parser_logger = logging.getLogger("guardian.collector.parser")

_SA_USERNAME_RE = re.compile(r"^system:serviceaccount:(?P<namespace>[^:]+):(?P<name>[^:]+)$")


class SkipReason(Enum):
    MALFORMED_JSON = auto()
    INCOMPLETE_STAGE = auto()
    FAILED_REQUEST = auto()
    NOT_SERVICE_ACCOUNT = auto()
    NAMESPACE_FILTERED = auto()


class ParseResult:
    """Either a usable AuditEvent, or a reason it was skipped."""

    __slots__ = ("event", "skip_reason", "raw_error")

    def __init__(
        self,
        event: AuditEvent | None = None,
        skip_reason: SkipReason | None = None,
        raw_error: str | None = None,
    ) -> None:
        self.event = event
        self.skip_reason = skip_reason
        self.raw_error = raw_error

    @property
    def ok(self) -> bool:
        return self.event is not None


def _is_success(response_status: dict | None) -> tuple[bool, int | None]:
    """200 <= code < 300. Never a bare == 200 check."""
    if not response_status:
        return False, None
    code = response_status.get("code")
    if not isinstance(code, int):
        return False, None
    return 200 <= code < 300, code


def _extract_service_account(username: str | None) -> tuple[str, str] | None:
    """Returns (namespace, sa_name) or None if not a ServiceAccount identity.

    Excludes system:apiserver, system:node:*, human/admin users, etc.
    """
    if not username:
        return None
    m = _SA_USERNAME_RE.match(username)
    if not m:
        return None
    return m.group("namespace"), m.group("name")


def _extract_field_manager(request_uri: str | None) -> str | None:
    """Pull ?fieldManager=... off requestURI, when present.

    Kubernetes tags every write (patch/apply/update/create) with a
    "field manager" identifying which client/tool made the change —
    e.g. "kubectl-client-side-apply", "kubectl-server-side-apply",
    "kubectl-edit", "kubectl-patch", or a controller's own name. Plain
    reads (get/list/watch) typically don't carry one, so this is
    commonly None — that's expected, not an error.
    """
    if not request_uri:
        return None
    try:
        query = urlsplit(request_uri).query
    except ValueError:
        return None
    if not query:
        return None
    params = parse_qs(query)
    values = params.get("fieldManager")
    if not values:
        return None
    return values[0] or None


def parse_line(raw_line: str, *, namespace_filter) -> ParseResult:
    """Parse+filter a single raw audit-log line.

    `namespace_filter` is a callable `(namespace: str | None) -> bool`
    (typically `Config.matches_namespace`) applied to the ServiceAccount's
    OWN namespace (from its username), not the object's namespace — a
    ServiceAccount always belongs to exactly one namespace, whereas the
    object it acted on may be cluster-scoped.
    """
    line = raw_line.strip()
    if not line:
        return ParseResult(skip_reason=SkipReason.MALFORMED_JSON, raw_error="empty line")

    try:
        event = json.loads(line)
    except json.JSONDecodeError as exc:
        return ParseResult(
            skip_reason=SkipReason.MALFORMED_JSON,
            raw_error=f"{exc} | line_prefix={line[:120]!r}",
        )

    if not isinstance(event, dict):
        return ParseResult(
            skip_reason=SkipReason.MALFORMED_JSON,
            raw_error=f"top-level JSON was not an object: {type(event).__name__}",
        )

    # Only fully completed requests count as evidence of actual usage.
    if event.get("stage") != "ResponseComplete":
        return ParseResult(skip_reason=SkipReason.INCOMPLETE_STAGE)

    success, code = _is_success(event.get("responseStatus"))
    if not success:
        return ParseResult(skip_reason=SkipReason.FAILED_REQUEST)

    user = event.get("user") or {}
    sa = _extract_service_account(user.get("username"))
    if sa is None:
        return ParseResult(skip_reason=SkipReason.NOT_SERVICE_ACCOUNT)
    sa_namespace, sa_name = sa

    if not namespace_filter(sa_namespace):
        return ParseResult(skip_reason=SkipReason.NAMESPACE_FILTERED)

    object_ref = event.get("objectRef") or {}
    resource = object_ref.get("resource")
    if not resource:
        # Without a resource we cannot form a meaningful PermissionKey.
        return ParseResult(
            skip_reason=SkipReason.MALFORMED_JSON,
            raw_error="missing objectRef.resource on an otherwise valid event",
        )

    api_group = object_ref.get("apiGroup") or ""  # "" = core group; never invented
    resource_namespace = object_ref.get("namespace")  # None => cluster-scoped, never "default"
    verb = event.get("verb") or "unknown"
    timestamp = event.get("requestReceivedTimestamp") or event.get("stageTimestamp")
    if not timestamp:
        return ParseResult(
            skip_reason=SkipReason.MALFORMED_JSON,
            raw_error="missing both requestReceivedTimestamp and stageTimestamp",
        )
    field_manager = _extract_field_manager(event.get("requestURI"))

    parsed = AuditEvent(
        service_account=sa_name,
        namespace_identity=sa_namespace,
        resource_namespace=resource_namespace,
        api_group=api_group,
        resource=resource,
        verb=verb,
        timestamp=timestamp,
        response_code=code if code is not None else 0,
        field_manager=field_manager,
    )
    return ParseResult(event=parsed)


# ================================================================================
# 6. AGGREGATOR — AuditEvent list -> nested usage dict
# ================================================================================
#
# Schema shape (per ServiceAccount):
#
#     service_account -> actions (verb) -> count, last_seen
#                                        -> resources (what it acted on) -> count, last_seen
#                                                                        -> field_managers (which tool) -> count, last_seen
#
# i.e. for each ServiceAccount, group by the FUNCTION/VERB performed
# first ("get", "list", "create", ...), then break each verb down by
# which resources it was used against, and each resource down further
# by which tool/fieldManager made the change.

aggregator_logger = logging.getLogger("guardian.collector.aggregator")


def _parse_ts(ts: str) -> datetime:
    # Kubernetes timestamps are RFC3339 with a trailing "Z".
    return datetime.fromisoformat(ts.replace("Z", "+00:00"))


def _quarter_label(dt: datetime) -> str:
    q = (dt.month - 1) // 3 + 1
    return f"{dt.year}-Q{q}"


def _quarter_bounds(label: str) -> tuple[str, str]:
    year_str, q_str = label.split("-Q")
    year = int(year_str)
    q = int(q_str)
    start_month = (q - 1) * 3 + 1
    start = datetime(year, start_month, 1, tzinfo=timezone.utc)
    if start_month + 3 > 12:
        next_q_start = datetime(year + 1, 1, 1, tzinfo=timezone.utc)
    else:
        next_q_start = datetime(year, start_month + 3, 1, tzinfo=timezone.utc)
    end = next_q_start - timedelta(days=1)  # last calendar day of the quarter
    return start.date().isoformat(), end.date().isoformat()


def _resource_key(api_group: str, resource: str) -> str:
    return f"{api_group}|{resource}"


def _blank_sa_record(namespace: str, service_account: str) -> dict:
    return {
        "service_account": service_account,
        "namespace": namespace,
        # keyed internally by verb -> {count, last_seen, resources: {api_group|resource -> {...}}}
        "actions": {},
        # same shape as "actions" but for watch/proxy/connect, kept
        # separate since they don't map onto a normal RBAC verb check
        "special_actions": {},
        "quarterly_usage": {},  # keyed by "YYYY-Qn"
    }


def _record_into(bucket: dict, perm_key: PermissionKey, timestamp: str, field_manager: str | None) -> None:
    action = bucket.setdefault(
        perm_key.verb,
        {"verb": perm_key.verb, "count": 0, "last_seen": timestamp, "resources": {}},
    )
    action["count"] += 1
    if timestamp > action["last_seen"]:
        action["last_seen"] = timestamp

    res_key = _resource_key(perm_key.api_group, perm_key.resource)
    res_entry = action["resources"].setdefault(
        res_key,
        {
            "api_group": perm_key.api_group,
            "resource": perm_key.resource,
            "count": 0,
            "first_seen": timestamp,
            "last_seen": timestamp,
            "field_managers": {},  # keyed by field manager name, e.g. "kubectl-edit"
        },
    )
    res_entry["count"] += 1
    if timestamp > res_entry["last_seen"]:
        res_entry["last_seen"] = timestamp
    if timestamp < res_entry["first_seen"]:
        res_entry["first_seen"] = timestamp

    if field_manager:
        fm_entry = res_entry["field_managers"].setdefault(
            field_manager, {"field_manager": field_manager, "count": 0, "last_seen": timestamp}
        )
        fm_entry["count"] += 1
        if timestamp > fm_entry["last_seen"]:
            fm_entry["last_seen"] = timestamp


def apply_events(aggregate: dict, events: Iterable[AuditEvent], stats: ScanStats | None = None) -> dict:
    """Merge `events` into `aggregate` (mutated in place, and returned).

    `aggregate` uses the internal (dict-keyed) representation produced by
    `_blank_sa_record` / `load_aggregate` — call `to_serializable` before
    writing JSON.
    """
    for event in events:
        sa_key = (event.namespace_identity, event.service_account)
        record = aggregate.setdefault(
            sa_key, _blank_sa_record(event.namespace_identity, event.service_account)
        )

        try:
            dt = _parse_ts(event.timestamp)
        except ValueError:
            aggregator_logger.error(
                "Unparseable timestamp %r for %s — skipping event", event.timestamp, sa_key
            )
            continue

        perm_key = event.permission_key
        target_bucket = record["special_actions"] if perm_key.is_special else record["actions"]
        _record_into(target_bucket, perm_key, event.timestamp, event.field_manager)

        # --- quarterly_usage ---
        q_label = _quarter_label(dt)
        q_start, q_end = _quarter_bounds(q_label)
        q_record = record["quarterly_usage"].setdefault(
            q_label,
            {"start_date": q_start, "end_date": q_end, "verb_counts": {}, "resources_touched": {}},
        )
        q_record["verb_counts"][perm_key.verb] = q_record["verb_counts"].get(perm_key.verb, 0) + 1
        q_record["resources_touched"][perm_key.resource] = (
            q_record["resources_touched"].get(perm_key.resource, 0) + 1
        )

        if stats is not None:
            stats.new_events_processed += 1
            stats.service_accounts_touched.add(f"{event.namespace_identity}/{event.service_account}")

    return aggregate


# ================================================================================
# 7. OUTPUT — atomic JSON read/write, schema conversion
# ================================================================================
#
# Output schema per ServiceAccount (verb-first, then resource, then
# field-manager breakdown):
#
#     {
#       "service_account": "backup-sa",
#       "namespace": "prod",
#       "actions": [
#         {
#           "verb": "get",
#           "count": 45231,
#           "last_seen": "...",
#           "resources": [
#             {"api_group": "", "resource": "secrets", "count": 2710,
#              "first_seen": "...", "last_seen": "...", "field_managers": []},
#             {"api_group": "", "resource": "pods", "count": 1765,
#              "first_seen": "...", "last_seen": "...", "field_managers": [
#                  {"field_manager": "kubectl-edit", "count": 40, "last_seen": "..."}
#              ]}
#           ]
#         }
#       ],
#       "special_actions": [ ... same shape ... watch/proxy/connect ... ],
#       "quarterly_usage": { "2026-Q3": {...} }
#     }
#
# Writes are atomic (temp file + fsync + os.replace) so the downstream
# consumer never observes a partially written file.


def _serialize_action_bucket(bucket: dict) -> list[dict]:
    actions = []
    for verb, action in sorted(bucket.items()):
        resources = []
        for res in sorted(action["resources"].values(), key=lambda r: (r["api_group"], r["resource"])):
            res_out = {
                "api_group": res["api_group"],
                "resource": res["resource"],
                "count": res["count"],
                "first_seen": res["first_seen"],
                "last_seen": res["last_seen"],
                "field_managers": sorted(
                    res.get("field_managers", {}).values(), key=lambda fm: fm["field_manager"]
                ),
            }
            resources.append(res_out)
        actions.append(
            {
                "verb": action["verb"],
                "count": action["count"],
                "last_seen": action["last_seen"],
                "resources": resources,
            }
        )
    return actions


def _deserialize_action_list(action_list: list[dict]) -> dict:
    bucket = {}
    for action in action_list:
        verb = action["verb"]
        resources = {}
        for r in action.get("resources", []):
            res_key = f"{r['api_group']}|{r['resource']}"
            resources[res_key] = {
                "api_group": r["api_group"],
                "resource": r["resource"],
                "count": r["count"],
                "first_seen": r["first_seen"],
                "last_seen": r["last_seen"],
                "field_managers": {fm["field_manager"]: dict(fm) for fm in r.get("field_managers", [])},
            }
        bucket[verb] = {
            "verb": verb,
            "count": action["count"],
            "last_seen": action["last_seen"],
            "resources": resources,
        }
    return bucket


def load_aggregate(output_path: str) -> dict:
    """Load a previously written guardian_audit.json back into the
    internal (namespace, sa) -> record dict shape used by the aggregator.

    Returns an empty dict if no output exists yet (first run).
    """
    p = Path(output_path)
    if not p.exists():
        return {}
    try:
        data = json.loads(p.read_text())
    except (json.JSONDecodeError, OSError):
        # Corrupt output must never crash the collector or cause data
        # loss silently — but we also must not fabricate history. Start
        # fresh and let the operator investigate via the error log.
        return {}

    aggregate: dict = {}
    for sa_entry in data.get("service_accounts", []):
        namespace = sa_entry.get("namespace")
        sa_name = sa_entry.get("service_account")
        if not sa_name:
            continue
        key = (namespace, sa_name)
        aggregate[key] = {
            "service_account": sa_name,
            "namespace": namespace,
            "actions": _deserialize_action_list(sa_entry.get("actions", [])),
            "special_actions": _deserialize_action_list(sa_entry.get("special_actions", [])),
            "quarterly_usage": dict(sa_entry.get("quarterly_usage", {})),
        }
    return aggregate


def to_serializable(aggregate: dict, *, window_start: str | None = None) -> dict:
    now = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
    service_accounts = []
    for (_namespace, _sa_name), record in sorted(aggregate.items(), key=lambda kv: kv[0]):
        service_accounts.append(
            {
                "service_account": record["service_account"],
                "namespace": record["namespace"],
                "actions": _serialize_action_bucket(record["actions"]),
                "special_actions": _serialize_action_bucket(record["special_actions"]),
                "quarterly_usage": record["quarterly_usage"],
            }
        )
    return {
        "generated_at": now,
        "time_window": {"start": window_start, "end": now},
        "service_accounts": service_accounts,
    }


def write_atomic(output_path: str, payload: dict) -> None:
    p = Path(output_path)
    p.parent.mkdir(parents=True, exist_ok=True)
    tmp_path = p.with_suffix(p.suffix + f".tmp.{os.getpid()}")
    tmp_path.write_text(json.dumps(payload, indent=2, sort_keys=False))
    with open(tmp_path, "r+b") as f:
        f.flush()
        os.fsync(f.fileno())
    os.replace(tmp_path, p)  # atomic on POSIX


# ================================================================================
# 8. AUDIT_COLLECTOR — orchestration: run_once() / run_forever()
# ================================================================================

logger = logging.getLogger("guardian.collector")


def _configure_logging(config: Config) -> logging.Logger:
    if not logger.handlers:
        handler = logging.StreamHandler()
        handler.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(name)s: %(message)s"))
        logger.addHandler(handler)
        logger.setLevel(logging.INFO)

    err_logger = logging.getLogger("guardian.collector.errors")
    if not err_logger.handlers:
        os.makedirs(os.path.dirname(config.error_log_path) or ".", exist_ok=True)
        file_handler = logging.FileHandler(config.error_log_path)
        file_handler.setFormatter(logging.Formatter("%(asctime)s %(message)s"))
        err_logger.addHandler(file_handler)
        err_logger.setLevel(logging.INFO)
        err_logger.propagate = False
    return err_logger


def run_once(config: Config | None = None) -> ScanStats:
    """Execute a single scan cycle. Returns the cycle's ScanStats.

    Safe to call repeatedly/idempotently: state and aggregate are both
    loaded from disk at the start and persisted atomically at the end,
    so a restart mid-cycle cannot double-count or corrupt output.
    """
    config = config or load_config()
    config.ensure_parent_dirs()
    err_logger = _configure_logging(config)

    try:
        audit_log_path = discover_audit_log_path(config.audit_log_path)
    except AuditLogNotFoundError as exc:
        logger.error(str(exc))
        raise

    logger.info("Audit log discovered: %s", audit_log_path)
    logger.info("Starting collector scan (target_namespace=%s)...", config.target_namespace)

    stats = ScanStats()
    scanner_state = ScannerState.load(config.state_path)

    try:
        file_size = os.path.getsize(audit_log_path)
        file_inode = os.stat(audit_log_path).st_ino
    except OSError as exc:
        logger.error("Could not stat audit log at %s: %s", audit_log_path, exc)
        raise

    reset = scanner_state.reconcile_with_file(file_size, file_inode)
    if reset:
        logger.warning("Scanner offset was reset due to rotation/truncation")

    aggregate = load_aggregate(config.output_path)
    events_to_apply = []

    with open(audit_log_path, "r", encoding="utf-8", errors="replace") as f:
        f.seek(scanner_state.offset)
        for raw_line in f:
            stats.events_scanned += 1
            result = parse_line(raw_line, namespace_filter=config.matches_namespace)

            if result.ok:
                stats.service_account_events += 1
                events_to_apply.append(result.event)
                continue

            reason = result.skip_reason
            if reason is SkipReason.MALFORMED_JSON:
                stats.malformed_events += 1
                err_logger.info("MALFORMED_EVENT: %s", result.raw_error)
            elif reason is SkipReason.INCOMPLETE_STAGE:
                stats.skipped_incomplete_stage += 1
            elif reason is SkipReason.FAILED_REQUEST:
                stats.failed_events_ignored += 1
            elif reason is SkipReason.NOT_SERVICE_ACCOUNT:
                stats.ignored_non_service_account += 1
            elif reason is SkipReason.NAMESPACE_FILTERED:
                stats.filtered_by_namespace += 1

        scanner_state.offset = f.tell()

    apply_events(aggregate, events_to_apply, stats=stats)

    window_start = None
    if aggregate:
        # Earliest first_seen across all recorded resource usage, if we
        # want a real window start; kept simple/best-effort for the PoC.
        try:
            window_start = min(
                res["first_seen"]
                for record in aggregate.values()
                for bucket in (record["actions"], record["special_actions"])
                for action in bucket.values()
                for res in action["resources"].values()
            )
        except ValueError:
            window_start = None

    payload = to_serializable(aggregate, window_start=window_start)
    write_atomic(config.output_path, payload)
    scanner_state.save(config.state_path)

    logger.info("Events scanned: %d", stats.events_scanned)
    logger.info("ServiceAccount events: %d", stats.service_account_events)
    logger.info("Ignored non-ServiceAccount events: %d", stats.ignored_non_service_account)
    logger.info("Failed events ignored: %d", stats.failed_events_ignored)
    logger.info("Skipped (incomplete stage) events: %d", stats.skipped_incomplete_stage)
    logger.info("Filtered by namespace: %d", stats.filtered_by_namespace)
    logger.info("Malformed events: %d", stats.malformed_events)
    logger.info("New events processed: %d", stats.new_events_processed)
    logger.info("ServiceAccounts touched this cycle: %d", len(stats.service_accounts_touched))
    logger.info("Output updated: %s", config.output_path)

    return stats


def run_forever(config: Config | None = None) -> None:
    """Continuous polling loop, per SCAN_INTERVAL_SECONDS."""
    config = config or load_config()
    _configure_logging(config)

    stop = {"flag": False}

    def _handle_signal(signum, _frame):
        logger.info("Received signal %s — shutting down after current cycle", signum)
        stop["flag"] = True

    signal.signal(signal.SIGTERM, _handle_signal)
    signal.signal(signal.SIGINT, _handle_signal)

    logger.info("Starting continuous collector loop (interval=%ds)", config.scan_interval_seconds)
    while not stop["flag"]:
        try:
            run_once(config)
        except AuditLogNotFoundError:
            logger.error(
                "Audit log unavailable this cycle — will retry in %ds", config.scan_interval_seconds
            )
        except Exception:  # noqa: BLE001 - a single bad cycle must not kill the loop
            logger.exception("Unexpected error during scan cycle — will retry next interval")
        for _ in range(config.scan_interval_seconds):
            if stop["flag"]:
                break
            time.sleep(1)


# ================================================================================
# 9. __main__ — CLI entrypoint
# ================================================================================
#
# Usage:
#     python3 guardian_audit_collector.py           # continuous polling loop
#     python3 guardian_audit_collector.py --once     # single scan, then exit

if __name__ == "__main__":
    if "--once" in sys.argv:
        run_once()
    else:
        run_forever()
