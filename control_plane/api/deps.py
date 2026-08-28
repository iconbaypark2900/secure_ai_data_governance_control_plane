"""FastAPI dependencies: sessions, authentication, and scope checks."""

from __future__ import annotations

from collections.abc import AsyncIterator, Awaitable, Callable
from typing import Annotated

from fastapi import Depends, Header, HTTPException, Request, status
from sqlalchemy.ext.asyncio import AsyncSession

from control_plane.audit.service import AuditService
from control_plane.auth.keys import Scope, scope_satisfies
from control_plane.auth.service import ApiKeyService, AuthenticatedKey
from control_plane.catalog.service import CatalogService
from control_plane.config import Settings, get_settings
from control_plane.db import get_sessionmaker
from control_plane.pdp import PolicyDecisionPoint
from control_plane.policy.store import PolicyStore

__all__ = [
    "Caller",
    "CallerDep",
    "SessionDep",
    "SettingsDep",
    "get_audit",
    "get_catalog",
    "get_pdp",
    "get_policy_store",
    "require_scope",
]


async def get_db() -> AsyncIterator[AsyncSession]:
    """One session per request, committed if the handler returns cleanly."""
    factory = get_sessionmaker()
    async with factory() as session:
        try:
            yield session
            await session.commit()
        except Exception:
            await session.rollback()
            raise


SessionDep = Annotated[AsyncSession, Depends(get_db)]


def settings_dep() -> Settings:
    return get_settings()


SettingsDep = Annotated[Settings, Depends(settings_dep)]


class Caller:
    """Who is making this request."""

    __slots__ = ("anonymous", "identity", "key", "scopes")

    def __init__(
        self,
        *,
        identity: str,
        scopes: frozenset[str],
        key: AuthenticatedKey | None = None,
        anonymous: bool = False,
    ) -> None:
        self.identity = identity
        self.scopes = scopes
        self.key = key
        self.anonymous = anonymous

    def has(self, scope: str) -> bool:
        return scope_satisfies(self.scopes, scope)

    def may_act_for(self, principal_id: str) -> bool:
        return self.key.may_act_for(principal_id) if self.key else True


async def get_caller(
    request: Request,
    session: SessionDep,
    settings: SettingsDep,
    authorization: Annotated[str | None, Header()] = None,
    x_api_key: Annotated[str | None, Header()] = None,
) -> Caller:
    """Authenticate the request.

    Accepts either ``Authorization: Bearer <key>`` or ``X-API-Key: <key>``. The
    bearer form is what most HTTP clients reach for; the header form is what
    proxies and sidecars find easier to inject.
    """
    if settings.auth_disabled:
        # Guarded in Settings: this combination cannot occur in production.
        return Caller(identity="anonymous", scopes=frozenset(Scope.ALL), anonymous=True)

    presented = x_api_key
    if not presented and authorization:
        scheme, _, token = authorization.partition(" ")
        if scheme.lower() == "bearer" and token:
            presented = token.strip()

    if not presented:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="an API key is required",
            headers={"WWW-Authenticate": "Bearer"},
        )

    authenticated = await ApiKeyService(session).authenticate(presented)
    if authenticated is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="the presented API key is not valid",
            headers={"WWW-Authenticate": "Bearer"},
        )

    request.state.api_key_prefix = authenticated.record.prefix
    return Caller(
        identity=authenticated.name or authenticated.record.prefix,
        scopes=authenticated.scopes,
        key=authenticated,
    )


CallerDep = Annotated[Caller, Depends(get_caller)]


def require_scope(scope: str) -> Callable[[Caller], Awaitable[Caller]]:
    """A dependency asserting the caller holds ``scope``."""

    async def dependency(caller: CallerDep) -> Caller:
        if not caller.has(scope):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"this endpoint requires the {scope!r} scope",
            )
        return caller

    return dependency


# --- service factories ------------------------------------------------------ #


def get_catalog(session: SessionDep) -> CatalogService:
    return CatalogService(session)


def get_policy_store(session: SessionDep) -> PolicyStore:
    return PolicyStore(session)


def get_audit(session: SessionDep) -> AuditService:
    return AuditService(session)


def get_pdp(session: SessionDep, settings: SettingsDep) -> PolicyDecisionPoint:
    return PolicyDecisionPoint(session, settings=settings)


CatalogDep = Annotated[CatalogService, Depends(get_catalog)]
PolicyStoreDep = Annotated[PolicyStore, Depends(get_policy_store)]
AuditDep = Annotated[AuditService, Depends(get_audit)]
PDPDep = Annotated[PolicyDecisionPoint, Depends(get_pdp)]
