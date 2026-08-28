"""The approval queue for decisions a policy parked for a human."""

from __future__ import annotations

import uuid
from datetime import UTC, datetime
from typing import Annotated, Any

from fastapi import APIRouter, Body, Depends, HTTPException, Query
from sqlalchemy import select

from control_plane.api.deps import AuditDep, CallerDep, SessionDep, require_scope
from control_plane.audit.chain import AuditEvent, as_utc
from control_plane.auth.keys import Scope
from control_plane.models.decision import ApprovalRequest, DecisionRecord

router = APIRouter(prefix="/approvals", tags=["approvals"])


def _out(approval: ApprovalRequest, decision: DecisionRecord | None = None) -> dict[str, Any]:
    payload: dict[str, Any] = {
        "id": str(approval.id),
        "decision_id": str(approval.decision_id),
        "status": approval.status,
        "requested_by": approval.requested_by,
        "justification": approval.justification,
        "decided_by": approval.decided_by,
        "decision_note": approval.decision_note,
        "created_at": approval.created_at.isoformat() if approval.created_at else None,
        "resolved_at": approval.resolved_at.isoformat() if approval.resolved_at else None,
        "expires_at": approval.expires_at.isoformat() if approval.expires_at else None,
    }
    if decision is not None:
        payload["decision"] = {
            "action": decision.action,
            "resource_urn": decision.resource_urn,
            "principal_id": decision.principal_id,
            "classifications": decision.classifications,
            "reason": decision.reason,
            "determining_policy": decision.determining_policy,
        }
    return payload


@router.get(
    "",
    summary="List approval requests",
    dependencies=[Depends(require_scope(Scope.APPROVALS))],
)
async def list_approvals(
    session: SessionDep,
    status_filter: Annotated[str | None, Query(alias="status")] = "pending",
    limit: Annotated[int, Query(ge=1, le=200)] = 50,
) -> list[dict[str, Any]]:
    statement = (
        select(ApprovalRequest, DecisionRecord)
        .join(DecisionRecord, DecisionRecord.id == ApprovalRequest.decision_id)
        .order_by(ApprovalRequest.created_at.desc())
        .limit(limit)
    )
    if status_filter:
        statement = statement.where(ApprovalRequest.status == status_filter)
    rows = (await session.execute(statement)).all()
    return [_out(approval, decision) for approval, decision in rows]


@router.post(
    "/{approval_id}/decide",
    summary="Grant or deny a parked decision",
    dependencies=[Depends(require_scope(Scope.APPROVALS))],
)
async def resolve_approval(
    approval_id: uuid.UUID,
    session: SessionDep,
    audit: AuditDep,
    caller: CallerDep,
    grant: Annotated[bool, Query(description="True to grant, false to deny.")],
    note: Annotated[str, Body(embed=True)] = "",
) -> dict[str, Any]:
    """Resolve one request.

    An expired request cannot be granted. The window exists so that a decision
    approved on stale context cannot be redeemed indefinitely afterwards.
    """
    approval = (
        await session.execute(select(ApprovalRequest).where(ApprovalRequest.id == approval_id))
    ).scalar_one_or_none()
    if approval is None:
        raise HTTPException(status_code=404, detail=f"no approval request {approval_id}")
    if approval.status != "pending":
        raise HTTPException(
            status_code=409,
            detail=f"approval request is already {approval.status}",
        )

    now = datetime.now(UTC)
    if approval.expires_at is not None and as_utc(approval.expires_at) <= now:
        approval.status = "expired"
        await session.flush()
        raise HTTPException(status_code=409, detail="approval request has expired")

    approval.status = "granted" if grant else "denied"
    approval.decided_by = caller.identity
    approval.decision_note = note
    approval.resolved_at = now
    await session.flush()

    await audit.append(
        AuditEvent.APPROVAL_GRANTED if grant else AuditEvent.APPROVAL_DENIED,
        actor=caller.identity,
        subject=str(approval.decision_id),
        payload={"approval_id": str(approval.id), "note": note},
    )
    return _out(approval)
