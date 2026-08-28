"""Reading and verifying the audit trail."""

from __future__ import annotations

from typing import Annotated, Any

from fastapi import APIRouter, Depends, Query

from control_plane.api.deps import AuditDep, CallerDep, require_scope
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
    stream: Annotated[str | None, Query()] = None,
    limit: Annotated[int, Query(ge=1, le=1000)] = 100,
    offset: Annotated[int, Query(ge=0)] = 0,
) -> dict[str, Any]:
    rows = await audit.list_records(
        limit=limit, offset=offset, event=event, actor=actor, subject=subject, stream=stream
    )
    return {
        "total": await audit.count(),
        "limit": limit,
        "offset": offset,
        "items": [row.to_record().to_dict() for row in rows],
    }


@router.get(
    "/streams",
    summary="The independent chains the log is split across",
    dependencies=[Depends(require_scope(Scope.AUDIT_READ))],
)
async def list_streams(audit: AuditDep) -> dict[str, Any]:
    """Where each chain has reached.

    The log is one chain per stream so appends do not all serialise behind one
    lock. Each is verifiable on its own; the checkpoint is what covers the set.
    """
    heads = await audit.stream_heads()
    return {
        "streams": [head.to_dict() for head in heads],
        "count": len(heads),
        "total_records": sum(head.seq for head in heads),
    }


@router.post(
    "/checkpoint",
    summary="Seal a record of where every stream has reached",
    dependencies=[Depends(require_scope(Scope.AUDIT_READ))],
)
async def take_checkpoint(audit: AuditDep, caller: CallerDep) -> dict[str, Any]:
    """Record every stream's head, in a chain of its own.

    What sharding gives up: per-stream verification proves each chain is
    internally consistent and says nothing about how many chains there should
    be, so a stream that vanishes entirely leaves everything remaining verifying
    perfectly. A checkpoint makes that disappearance contradict something already
    written. Take them on a schedule.
    """
    record = await audit.checkpoint(actor=caller.identity)
    return record.to_dict()


@router.get(
    "/verify",
    summary="Recompute the chains and report any tampering",
    dependencies=[Depends(require_scope(Scope.AUDIT_READ))],
)
async def verify_audit(
    audit: AuditDep,
    stream: Annotated[str | None, Query(description="Verify one stream only.")] = None,
    start_seq: Annotated[int, Query(ge=1)] = 1,
    end_seq: Annotated[int | None, Query(ge=1)] = None,
) -> dict[str, Any]:
    """Verify the log.

    Each record's digest covers its own content and its predecessor's, so an
    edit, deletion, or reordering shows up as a specific sequence number rather
    than a vague failure. Without ``stream``, every chain is checked and the
    result is held against the most recent checkpoint -- which is the only thing
    that can notice a whole chain being gone.
    """
    if stream is not None:
        result = await audit.verify(stream=stream, start_seq=start_seq, end_seq=end_seq)
        return {
            "valid": result.valid,
            "streams": {stream: result.to_dict()},
            "checkpoint": {"checked": 0, "message": "not evaluated for a single stream"},
            "message": result.message,
        }
    return await audit.verify_all()
