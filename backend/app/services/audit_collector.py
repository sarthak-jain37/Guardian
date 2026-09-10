import json
import logging
import os
from typing import Any
from urllib.parse import parse_qs, urlparse

logger = logging.getLogger(__name__)


APPLY_EVENT_TYPES = {
    "kubectl-client-side-apply",
    "kubectl-server-side-apply",
}

MODIFY_EVENT_TYPES = {
    "kubectl-edit",
    "kubectl-create",
    "kubectl-patch",
}


RBAC_RESOURCES = {
    "roles",
    "clusterroles",
    "rolebindings",
    "clusterrolebindings",
    "serviceaccounts",
}


class AuditLogSource:
    """
    Reads Kubernetes API-server audit events from a JSON-lines
    audit log.
    """

    def __init__(self, path: str):
        self.path = path
        self._offset = 0

    def read_events(self) -> list[dict[str, Any]]:
        """
        Read newly appended audit events from the audit log.
        """

        if not os.path.exists(self.path):
            logger.warning(
                "Kubernetes audit log does not exist: %s",
                self.path,
            )
            return []

        events = []

        try:
            with open(self.path, "r", encoding="utf-8") as file:

                file.seek(0, os.SEEK_END)
                file_size = file.tell()

                if file_size < self._offset:
                    logger.info(
                        "Audit log was rotated or truncated. "
                        "Resetting read position."
                    )
                    self._offset = 0

                file.seek(self._offset)

                for line in file:
                    line = line.strip()

                    if not line:
                        continue

                    try:
                        event = json.loads(line)

                    except json.JSONDecodeError:
                        logger.warning(
                            "Skipping malformed audit log entry."
                        )
                        continue

                    if isinstance(event, dict):
                        events.append(event)

                self._offset = file.tell()

        except OSError:
            logger.exception(
                "Failed to read Kubernetes audit log."
            )
            return []

        return events


from backend.app.core.config import KUBERNETES_AUDIT_LOG_PATH

audit_source = AuditLogSource(KUBERNETES_AUDIT_LOG_PATH)


def _is_response_complete(event: dict[str, Any]) -> bool:
    """
    Only process completed API requests.
    """

    stage = event.get("stage")

    if stage is None:
        return True

    return stage == "ResponseComplete"


def _is_successful_request(event: dict[str, Any]) -> bool:
    """
    Check whether the Kubernetes API request completed successfully.
    """

    response_status = event.get("responseStatus") or {}
    status_code = response_status.get("code")

    if status_code is None:
        return True

    return 200 <= status_code < 300


def _is_rbac_event(event: dict[str, Any]) -> bool:
    object_ref = event.get("objectRef") or {}

    api_group = object_ref.get("apiGroup")
    resource = object_ref.get("resource")

    if api_group == "rbac.authorization.k8s.io":
        return resource in {
            "roles",
            "clusterroles",
            "rolebindings",
            "clusterrolebindings",
        }

    if api_group == "" and resource == "serviceaccounts":
        return True

    return False


def _get_field_manager(event: dict[str, Any]) -> str | None:
    """
    Extract the fieldManager value from the audit request URI.
    """

    request_uri = event.get("requestURI")

    if not request_uri:
        return None

    try:
        query = parse_qs(
            urlparse(request_uri).query
        )

        field_managers = query.get("fieldManager")

        if field_managers:
            return field_managers[0]

    except (ValueError, TypeError):
        logger.warning(
            "Could not parse request URI: %s",
            request_uri,
        )

    return None


def _classify_event(event: dict[str, Any]) -> str | None:
    """
    Classify a Kubernetes audit event into one of Guardian's
    supported event categories.
    """

    verb = event.get("verb", "").lower()
    user_agent = event.get("userAgent", "").lower()

    field_manager = _get_field_manager(event)
    
    if field_manager == "kubectl-client-side-apply" or field_manager == "kubectl-server-side-apply":
        return field_manager


    if (
        verb in {"patch", "update"}
        and "kubectl-edit" in user_agent
    ):
        return "kubectl-edit"

    if (
        verb == "create"
        and "kubectl" in user_agent
    ):
        return "kubectl-create"

    if (
        verb == "patch"
        and "kubectl" in user_agent
    ):
        return "kubectl-patch"

    return None


def _normalize_event(
    event: dict[str, Any],
    event_type: str,
) -> dict[str, Any]:
    """
    Extract the audit information Guardian needs.
    """

    object_ref = event.get("objectRef") or {}
    user = event.get("user") or {}
    response_status = event.get("responseStatus") or {}

    return {
        "audit_id": event.get("auditID"),

        "timestamp": event.get(
            "requestReceivedTimestamp"
        ),

        "user": user.get(
            "username"
        ),

        "groups": user.get(
            "groups",
            [],
        ),

        "event_type": event_type,

        "verb": event.get(
            "verb"
        ),

        "api_group": object_ref.get(
            "apiGroup"
        ),

        "resource": object_ref.get(
            "resource"
        ),

        "namespace": object_ref.get(
            "namespace"
        ),

        "name": object_ref.get(
            "name"
        ),

        "user_agent": event.get(
            "userAgent"
        ),

        "status": response_status.get(
            "code"
        ),
    }


def process_audit_events(
    raw_events: list[dict[str, Any]],
) -> dict[str, dict[str, Any]]:
    """
    Convert raw Kubernetes audit events into the structure
    expected by event_processor.py.
    """

    data: dict[str, dict[str, Any]] = {}

    for event in raw_events:

        if not isinstance(event, dict):
            continue

        if not _is_response_complete(event):
            continue

        if not _is_successful_request(event):
            continue

        if not _is_rbac_event(event):
            continue

        event_type = _classify_event(event)

        if event_type is None:
            continue

        timestamp = event.get(
            "requestReceivedTimestamp"
        )

        if not timestamp:
            logger.warning(
                "Ignoring audit event without timestamp."
            )
            continue

        normalized_event = _normalize_event(
            event,
            event_type,
        )

        if event_type not in data:
            data[event_type] = {
                "timestamps": [],
                "events": [],
            }

        data[event_type]["timestamps"].append(
            timestamp
        )

        data[event_type]["events"].append(
            normalized_event
        )

    return data


def collect_audit_logs() -> dict[str, dict[str, Any]]:
    """
    Collect new Kubernetes API-server audit events,
    process them, and return Guardian-compatible data.
    """

    raw_events = audit_source.read_events()

    if not raw_events:
        return {}

    return process_audit_events(raw_events)