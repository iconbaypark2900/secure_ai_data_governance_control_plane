"""Policy administration.

Every mutation writes an audit record before returning. A policy change is a
change to the security posture of the system, and the record of it belongs in
the same tamper-evident log as the decisions it goes on to shape.
"""

from __future__ import annotations

from typing import Annotated, Any

from fastapi import APIRouter, Depends, HTTPException, Query, status

from control_plane.api.deps import AuditDep, CallerDep, PolicyStoreDep, require_scope
from control_plane.audit.chain import AuditEvent
from control_plane.auth.keys import Scope
from control_plane.classification import taxonomy
from control_plane.models.policy import PolicyRecord, PolicyVersion
from control_plane.policy.model import KNOWN_OBLIGATIONS, ROOT_SELECTORS, Effect, Policy
from control_plane.policy.operators import known_operators
from control_plane.policy.store import PolicyConflict, PolicyNotFound
from control_plane.schemas.policy import (
    PolicyIn,
    PolicyOut,
    PolicySyncRequest,
    PolicySyncResult,
    PolicyVersionOut,
)

router = APIRouter(prefix="/policies", tags=["policies"])


def _parse(document: dict[str, Any]) -> Policy:
    try:
        return Policy.model_validate(document)
    except Exception as exc:
        raise HTTPException(
            status_code=422,
            detail=f"invalid policy: {exc}",
        ) from exc


def _out(record: PolicyRecord) -> PolicyOut:
    return PolicyOut(
        key=record.key,
        name=record.name,
        description=record.description,
        effect=record.effect,
        priority=record.priority,
        enabled=record.enabled,
        version=record.version,
        tags=list(record.tags or []),
        document=dict(record.document or {}),
        created_by=record.created_by,
        updated_by=record.updated_by,
        created_at=record.created_at.isoformat() if record.created_at else None,
        updated_at=record.updated_at.isoformat() if record.updated_at else None,
    )


def _version_out(record: PolicyVersion) -> PolicyVersionOut:
    return PolicyVersionOut(
        policy_key=record.policy_key,
        version=record.version,
        document=dict(record.document or {}),
        change_note=record.change_note,
        changed_by=record.changed_by,
        created_at=record.created_at.isoformat() if record.created_at else None,
    )


@router.get(
    "",
    response_model=list[PolicyOut],
    summary="List policies",
    dependencies=[Depends(require_scope(Scope.POLICY_READ))],
)
async def list_policies(
    store: PolicyStoreDep,
    enabled: Annotated[bool | None, Query()] = None,
    effect: Annotated[str | None, Query()] = None,
    tag: Annotated[str | None, Query()] = None,
    limit: Annotated[int, Query(ge=1, le=1000)] = 200,
    offset: Annotated[int, Query(ge=0)] = 0,
) -> list[PolicyOut]:
    records = await store.list_records(
        enabled=enabled, effect=effect, tag=tag, limit=limit, offset=offset
    )
    return [_out(record) for record in records]


@router.get(
    "/schema",
    summary="The policy language: selectors, operators, effects, and labels",
    dependencies=[Depends(require_scope(Scope.POLICY_READ))],
)
async def policy_schema() -> dict[str, Any]:
    """Everything a policy author -- or the policy editor UI -- needs to know.

    Served from the running code rather than a document, so it cannot drift away
    from what the engine actually accepts.
    """
    return {
        "selectors": sorted(ROOT_SELECTORS),
        "operators": list(known_operators()),
        "effects": [str(effect) for effect in Effect],
        "combinators": ["all", "any", "not"],
        "obligation_types": sorted(KNOWN_OBLIGATIONS),
        "redaction_strategies": ["mask", "partial", "hash", "tokenize", "synthetic", "drop"],
        "labels": [
            {
                "key": label.key,
                "name": label.name,
                "category": str(label.category),
                "severity": str(label.severity),
                "description": label.description,
                "regulations": list(label.regulations),
            }
            for label in taxonomy.LABELS
        ],
    }


@router.post(
    "/sync",
    response_model=PolicySyncResult,
    summary="Reconcile the stored policy set with a declared set",
    dependencies=[Depends(require_scope(Scope.POLICY_WRITE))],
)
async def sync_policies(
    body: PolicySyncRequest,
    store: PolicyStoreDep,
    audit: AuditDep,
    caller: CallerDep,
) -> PolicySyncResult:
    """Apply a whole policy set at once, the way a deployment would."""
    policies = [_parse(document) for document in body.policies]
    result = await store.sync(policies, actor=caller.identity, prune=body.prune)
    await audit.append(
        AuditEvent.CONFIG_CHANGED,
        actor=caller.identity,
        subject="policy-set",
        payload={"operation": "sync", **result, "note": body.change_note},
    )
    return PolicySyncResult(**result)


@router.post(
    "",
    response_model=PolicyOut,
    status_code=status.HTTP_201_CREATED,
    summary="Create a policy",
    dependencies=[Depends(require_scope(Scope.POLICY_WRITE))],
)
async def create_policy(
    body: PolicyIn, store: PolicyStoreDep, audit: AuditDep, caller: CallerDep
) -> PolicyOut:
    policy = _parse(body.policy)
    try:
        record = await store.create(policy, actor=caller.identity, note=body.change_note)
    except PolicyConflict as exc:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=str(exc)) from exc
    await audit.append(
        AuditEvent.POLICY_CREATED,
        actor=caller.identity,
        subject=record.key,
        payload={
            "version": record.version,
            "effect": record.effect,
            "priority": record.priority,
            "note": body.change_note,
        },
    )
    return _out(record)


@router.get(
    "/{key}",
    response_model=PolicyOut,
    summary="Retrieve a policy",
    dependencies=[Depends(require_scope(Scope.POLICY_READ))],
)
async def get_policy(key: str, store: PolicyStoreDep) -> PolicyOut:
    record = await store.get_record(key)
    if record is None:
        raise HTTPException(status_code=404, detail=f"no policy {key!r}")
    return _out(record)


@router.put(
    "/{key}",
    response_model=PolicyOut,
    summary="Replace a policy, creating a new version",
    dependencies=[Depends(require_scope(Scope.POLICY_WRITE))],
)
async def update_policy(
    key: str, body: PolicyIn, store: PolicyStoreDep, audit: AuditDep, caller: CallerDep
) -> PolicyOut:
    policy = _parse(body.policy)
    try:
        record = await store.update(key, policy, actor=caller.identity, note=body.change_note)
    except PolicyNotFound as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except PolicyConflict as exc:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=str(exc)) from exc
    await audit.append(
        AuditEvent.POLICY_UPDATED,
        actor=caller.identity,
        subject=record.key,
        payload={
            "version": record.version,
            "effect": record.effect,
            "priority": record.priority,
            "note": body.change_note,
        },
    )
    return _out(record)


@router.post(
    "/{key}/enabled",
    response_model=PolicyOut,
    summary="Enable or disable a policy",
    dependencies=[Depends(require_scope(Scope.POLICY_WRITE))],
)
async def set_enabled(
    key: str,
    enabled: Annotated[bool, Query(description="True to enable, false to disable.")],
    store: PolicyStoreDep,
    audit: AuditDep,
    caller: CallerDep,
    note: Annotated[str, Query(max_length=1000)] = "",
) -> PolicyOut:
    try:
        record = await store.set_enabled(key, enabled, actor=caller.identity, note=note)
    except PolicyNotFound as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    await audit.append(
        AuditEvent.POLICY_ENABLED if enabled else AuditEvent.POLICY_DISABLED,
        actor=caller.identity,
        subject=record.key,
        payload={"version": record.version, "note": note},
    )
    return _out(record)


@router.delete(
    "/{key}",
    status_code=status.HTTP_204_NO_CONTENT,
    summary="Delete a policy",
    dependencies=[Depends(require_scope(Scope.POLICY_WRITE))],
)
async def delete_policy(
    key: str, store: PolicyStoreDep, audit: AuditDep, caller: CallerDep
) -> None:
    if not await store.delete(key):
        raise HTTPException(status_code=404, detail=f"no policy {key!r}")
    await audit.append(AuditEvent.POLICY_DELETED, actor=caller.identity, subject=key, payload={})


@router.get(
    "/{key}/versions",
    response_model=list[PolicyVersionOut],
    summary="A policy's version history",
    dependencies=[Depends(require_scope(Scope.POLICY_READ))],
)
async def list_versions(
    key: str, store: PolicyStoreDep, limit: Annotated[int, Query(ge=1, le=200)] = 50
) -> list[PolicyVersionOut]:
    return [_version_out(record) for record in await store.list_versions(key, limit=limit)]


@router.get(
    "/{key}/versions/{version}",
    response_model=PolicyVersionOut,
    summary="One historical policy version",
    dependencies=[Depends(require_scope(Scope.POLICY_READ))],
)
async def get_version(key: str, version: int, store: PolicyStoreDep) -> PolicyVersionOut:
    record = await store.get_version(key, version)
    if record is None:
        raise HTTPException(status_code=404, detail=f"no version {version} of policy {key!r}")
    return _version_out(record)
