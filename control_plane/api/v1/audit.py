"""Reading and verifying the audit trail."""

from __future__ import annotations

from typing import Annotated, Any

from fastapi import APIRouter, Depends, Query

from control_plane.api.deps import AuditDep, require_scope
from control_plane.auth.keys import Scope

router = APIRouter(prefix="/audit", tags=["audit"])


@router.get(
    "",
    summary="List audit records, newest first",
    dependencies=[Depends(require_scope(Scope.AUDIT_READ))],
)
async def list_audit(
    audit: AuditDep,
    event: Annotated[str | None, Query()] = None,
    actor: Annotated[str | None, Query()] = None,
    subject: Annotated[str | None, Query()] = None,
    limit: Annotated[int, Query(ge=1, le=1000)] = 100,
    offset: Annotated[int, Query(ge=0)] = 0,
) -> dict[str, Any]:
    rows = await audit.list_records(
        limit=limit, offset=offset, event=event, actor=actor, subject=subject
    )
    return {
        "total": await audit.count(),
        "limit": limit,
        "offset": offset,
        "items": [row.to_record().to_dict() for row in rows],
    }


@router.get(
    "/verify",
    summary="Recompute the hash chain and report any tampering",
    dependencies=[Depends(require_scope(Scope.AUDIT_READ))],
)
async def verify_audit(
    audit: AuditDep,
    start_seq: Annotated[int, Query(ge=1)] = 1,
    end_seq: Annotated[int | None, Query(ge=1)] = None,
) -> dict[str, Any]:
    """Verify a range of the chain.

    Each record's digest covers its own content and its predecessor's digest, so
    any edit, deletion, or reordering shows up here as a specific sequence
    number rather than a vague failure.
    """
    result = await audit.verify(start_seq=start_seq, end_seq=end_seq)
    return {**result.to_dict(), "start_seq": start_seq, "end_seq": end_seq}
