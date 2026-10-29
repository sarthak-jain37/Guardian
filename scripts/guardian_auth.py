"""Issue/revoke scoped operator-managed credentials. Tokens print once on issue.

Run with `python -m scripts.guardian_auth`. Keep the registry outside the source
checkout and deliver each token privately to its owner. No credential is seeded.
"""
import argparse
import fcntl
import hashlib
import json
import os
import secrets
import tempfile
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
from pathlib import Path

from backend.app.core.auth import Credential, Grant, Principal, Registry, MAX_REGISTRY_BYTES


@contextmanager
def registry_update(path):
    path = Path(path).resolve()
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    descriptor = os.open(str(path) + ".lock", os.O_CREAT | os.O_RDWR, 0o600)
    with os.fdopen(descriptor, "w") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        registry = Registry.model_validate_json(path.read_bytes()) if path.exists() else Registry(
            schema_version="guardian.auth.v1", credentials=[])
        yield registry
        serialized = registry.model_dump_json(indent=2) + "\n"
        if len(serialized.encode()) > MAX_REGISTRY_BYTES:
            raise ValueError("credential_registry_too_large")
        # Atomic replacement prevents readers from seeing a half-written registry.
        descriptor, temporary = tempfile.mkstemp(dir=path.parent, prefix=".guardian-auth-")
        try:
            with os.fdopen(descriptor, "w") as output:
                output.write(serialized)
                output.flush()
                os.fsync(output.fileno())
            os.replace(temporary, path)
            directory = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
            try:
                os.fsync(directory)
            finally:
                os.close(directory)
        finally:
            if os.path.exists(temporary):
                os.unlink(temporary)


def issue(path, principal, hours=8):
    if type(hours) is not int or not 1 <= hours <= 720:
        raise ValueError("credential_hours_must_be_1_to_720")
    principal = Principal.model_validate(principal)
    token = secrets.token_urlsafe(32)
    credential = Credential(token_sha256=hashlib.sha256(token.encode()).hexdigest(), principal=principal,
                            expires_at=datetime.now(timezone.utc) + timedelta(hours=hours))
    with registry_update(path) as registry:
        if len(registry.credentials) >= 128:
            raise ValueError("credential_registry_full")
        registry.credentials.append(credential)
    return token


def revoke(path, token_sha256):
    with registry_update(path) as registry:
        previous = len(registry.credentials)
        registry.credentials = [c for c in registry.credentials if c.token_sha256 != token_sha256]
        return previous != len(registry.credentials)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--registry", required=True, type=Path)
    commands = parser.add_subparsers(dest="command", required=True)
    create = commands.add_parser("issue")
    create.add_argument("--actor", required=True)
    create.add_argument("--kind", required=True, choices=("human", "service"))
    create.add_argument("--cluster", required=True)
    create.add_argument("--namespace", required=True)
    create.add_argument("--permission", action="append", required=True, choices=("read", "publish", "review", "deliver", "operate", "execute"))
    create.add_argument("--hours", type=int, default=8)
    remove = commands.add_parser("revoke")
    remove.add_argument("--token-sha256", required=True)
    args = parser.parse_args()
    if args.command == "issue":
        principal = Principal(actor=args.actor, kind=args.kind, grants=[Grant(
            cluster_id=args.cluster, namespace=args.namespace, permissions=args.permission)])
        print(issue(args.registry, principal, args.hours))
    else:
        print(json.dumps({"revoked": revoke(args.registry, args.token_sha256)}))


if __name__ == "__main__":
    main()
