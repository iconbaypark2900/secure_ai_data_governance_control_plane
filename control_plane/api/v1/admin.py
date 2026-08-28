"""Credential management and service metadata."""

from __future__ import annotations

from datetime import datetime
from typing import Annotated, Any

from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy import text

from control_plane.api.deps import AuditDep, CallerDep, SessionDep, SettingsDep, require_scope
from control_plane.audit.chain import AuditEvent
from control_plane.auth.keys import Scope, normalise_scopes
from control_plane.auth.service import ApiKeyService
from control_plane.classification import taxonomy
from control_plane.classification.detectors import DETECTORS

router = APIRouter(tags=["admin"])


class ApiKeyIn(BaseModel):
    model_config = ConfigDict(extra="forbid")

    name: str = Field(min_length=1, max_length=255)
    scopes: list[str] = Field(
        description="Any of: decide, catalog:read, catalog:write, policy:read, "
        "policy:write, audit:read, approvals, admin."
    )
    description: str = ""
    allowed_principals: list[str] = Field(
        default_factory=list,
        description="Principal ids this key may submit decisions for. Supports a "
        "trailing '*'. Empty means any principal -- suitable for a shared "
        "gateway, not for a key handed to a single agent.",
    )
    expires_at: datetime | None = None
    attributes: dict[str, Any] = Field(default_factory=dict)


@router.post(
    "/keys",
    status_code=status.HTTP_201_CREATED,
    summary="Issue an API key",
    dependencies=[Depends(require_scope(Scope.ADMIN))],
)
async def issue_key(
    body: ApiKeyIn, session: SessionDep, audit: AuditDep, caller: CallerDep
) -> dict[str, Any]:
    """Mint a key.

    The plaintext appears in this response and is never recoverable afterwards --
    only its Argon2id hash is stored.
    """
    try:
        scopes = normalise_scopes(body.scopes)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc

    record, issued = await ApiKeyService(session).issue(
        name=body.name,
        scopes=scopes,
        description=body.description,
        allowed_principals=body.allowed_principals,
        attributes=body.attributes,
        created_by=caller.identity,
        expires_at=body.expires_at,
    )
    await audit.append(
        AuditEvent.KEY_ISSUED,
        actor=caller.identity,
        subject=record.prefix,
        payload={
            "name": record.name,
            "scopes": scopes,
            "allowed_principals": body.allowed_principals,
        },
    )
    return {
        "key": issued.plaintext,
        "prefix": record.prefix,
        "name": record.name,
        "scopes": scopes,
        "warning": "Store this key now. It cannot be retrieved again.",
    }


@router.get(
    "/keys",
    summary="List issued keys (never their secrets)",
    dependencies=[Depends(require_scope(Scope.ADMIN))],
)
async def list_keys(
    session: SessionDep,
    include_revoked: Annotated[bool, Query()] = False,
) -> list[dict[str, Any]]:
    records = await ApiKeyService(session).list_keys(include_revoked=include_revoked)
    return [
        {
            "prefix": record.prefix,
            "name": record.name,
            "description": record.description,
            "scopes": list(record.scopes or []),
            "allowed_principals": list(record.allowed_principals or []),
            "created_by": record.created_by,
            "created_at": record.created_at.isoformat() if record.created_at else None,
            "last_used_at": record.last_used_at.isoformat() if record.last_used_at else None,
            "expires_at": record.expires_at.isoformat() if record.expires_at else None,
            "revoked_at": record.revoked_at.isoformat() if record.revoked_at else None,
        }
        for record in records
    ]


@router.delete(
    "/keys/{prefix}",
    summary="Revoke a key",
    dependencies=[Depends(require_scope(Scope.ADMIN))],
)
async def revoke_key(
    prefix: str, session: SessionDep, audit: AuditDep, caller: CallerDep
) -> dict[str, Any]:
    record = await ApiKeyService(session).revoke(prefix)
    if record is None or record.revoked_at is None:
        raise HTTPException(status_code=404, detail=f"no active key with prefix {prefix!r}")
    await audit.append(
        AuditEvent.KEY_REVOKED,
        actor=caller.identity,
        subject=prefix,
        payload={"name": record.name},
    )
    return {"prefix": prefix, "revoked_at": record.revoked_at.isoformat()}


@router.get("/meta/taxonomy", summary="The sensitivity-label taxonomy")
async def get_taxonomy() -> dict[str, Any]:
    """The full label vocabulary and which detector, if any, produces each.

    A label with no detector can still be applied by hand -- ``pii.name`` needs a
    model, and claiming otherwise with a regex would be worse than admitting it.
    """
    detector_labels: dict[str, list[str]] = {}
    for detector in DETECTORS:
        detector_labels.setdefault(detector.label, []).append(detector.name)
    return {
        "categories": [str(category) for category in taxonomy.Category],
        "severities": [str(severity) for severity in taxonomy.Severity],
        "labels": [
            {
                "key": label.key,
                "name": label.name,
                "category": str(label.category),
                "severity": str(label.severity),
                "description": label.description,
                "regulations": list(label.regulations),
                "detectors": sorted(detector_labels.get(label.key, [])),
                "automatically_detected": label.key in detector_labels,
            }
            for label in taxonomy.LABELS
        ],
    }


@router.get("/health", summary="Liveness probe", include_in_schema=False)
async def health(settings: SettingsDep) -> dict[str, Any]:
    return {
        "status": "ok",
        "service": settings.app_name,
        "environment": str(settings.environment),
    }


@router.get("/ready", summary="Readiness probe", include_in_schema=False)
async def ready(session: SessionDep, settings: SettingsDep) -> dict[str, Any]:
    """Ready means the database answers. Without it there is no policy set, and
    with no policy set every decision would be a default deny."""
    try:
        await session.execute(text("SELECT 1"))
    except Exception as exc:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail=f"database is unavailable: {exc}",
        ) from exc
    return {
        "status": "ready",
        "database": "ok",
        "default_effect": settings.default_effect,
        "fail_closed": settings.fail_closed,
    }
