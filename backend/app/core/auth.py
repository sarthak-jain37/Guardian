"""Scoped opaque bearer credentials, issued by an operator, never by a model.

Only token digests live in the registry. File registries reload on every request
so removing a credential or changing its scope takes effect without a restart.
Deploy behind TLS or on loopback; this is not an identity-provider login flow.
"""
import hashlib
import hmac
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Annotated, Literal

from fastapi import Depends, HTTPException, Request
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from pydantic import AwareDatetime, Field, model_validator

from contracts.usage_summary_v1 import Contract, ID, utc

Permission = Literal["read", "publish", "review", "deliver", "operate", "execute"]
MAX_REGISTRY_BYTES = 65536


class Grant(Contract):
    cluster_id: ID
    namespace: ID
    permissions: list[Permission] = Field(min_length=1, max_length=6)

    @model_validator(mode="after")
    def exact_scope(self):
        if "*" in self.cluster_id or "*" in self.namespace:
            raise ValueError("wildcard_scope_is_unsupported")
        if len(self.permissions) != len(set(self.permissions)):
            raise ValueError("duplicate_permission")
        return self


class Principal(Contract):
    actor: ID
    kind: Literal["human", "service"]
    grants: list[Grant] = Field(min_length=1, max_length=64)
    credential_id: str | None = Field(default=None,exclude=True)

    @model_validator(mode="after")
    def separation(self):
        allowed = {"read", "review", "operate"} if self.kind == "human" else {"read", "publish", "deliver", "execute"}
        if any(not set(grant.permissions) <= allowed for grant in self.grants):
            raise ValueError("human_and_service_authority_must_be_separate")
        return self

    def require(self, permission, cluster_id, namespace):
        if not any(g.cluster_id == cluster_id and g.namespace == namespace and permission in g.permissions
                   for g in self.grants):
            raise HTTPException(403, "scope_not_authorized")


class Credential(Contract):
    token_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    principal: Principal
    expires_at: AwareDatetime

    @model_validator(mode="after")
    def timestamp(self):
        utc(self.expires_at)
        return self


class Registry(Contract):
    schema_version: Literal["guardian.auth.v1"]
    credentials: list[Credential] = Field(max_length=128)

    @model_validator(mode="after")
    def unique_tokens(self):
        digests = [c.token_sha256 for c in self.credentials]
        if len(digests) != len(set(digests)):
            raise ValueError("duplicate_credential")
        return self


class Authenticator:
    def __init__(self, path):
        self.path = Path(path)

    def registry(self):
        try:
            with self.path.open("rb") as source:
                raw = source.read(MAX_REGISTRY_BYTES + 1)
            if len(raw) > MAX_REGISTRY_BYTES:
                raise ValueError("registry_too_large")
            return Registry.model_validate(json.loads(raw))
        except (OSError, ValueError):
            raise HTTPException(503, "authentication_registry_unavailable") from None
    def authenticate(self, token):
        if not 32 <= len(token) <= 512 or not token.isascii():
            raise HTTPException(401, "invalid_credential", headers={"WWW-Authenticate": "Bearer"})
        registry=self.registry()
        digest = hashlib.sha256(token.encode("ascii")).hexdigest()
        now = datetime.now(timezone.utc)
        for credential in registry.credentials:
            if hmac.compare_digest(credential.token_sha256, digest) and now < credential.expires_at:
                return credential.principal.model_copy(update={'credential_id':digest})
        raise HTTPException(401, "invalid_credential", headers={"WWW-Authenticate": "Bearer"})

    def current_authority(self,actor,credential_id,cluster_id,namespace,permission='review'):
        """Revalidate the exact credential that approved, never just an actor name."""
        if not credential_id:return False
        now=datetime.now(timezone.utc)
        for credential in self.registry().credentials:
            if (hmac.compare_digest(credential.token_sha256,credential_id) and now<credential.expires_at
                    and credential.principal.actor==actor and credential.principal.kind=='human'):
                try:credential.principal.require(permission,cluster_id,namespace)
                except HTTPException:return False
                return True
        return False


bearer = HTTPBearer(auto_error=False)


def authenticated(request: Request, credential: Annotated[HTTPAuthorizationCredentials | None, Depends(bearer)]):
    if credential is None or credential.scheme.lower() != "bearer":
        raise HTTPException(401, "authentication_required", headers={"WWW-Authenticate": "Bearer"})
    authenticator = getattr(request.app.state, "authenticator", None)
    if authenticator is None:
        raise HTTPException(503, "authentication_not_configured")
    return authenticator.authenticate(credential.credentials)


Authenticated = Annotated[Principal, Depends(authenticated)]
