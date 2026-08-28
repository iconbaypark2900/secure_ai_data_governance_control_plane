"""The decision endpoints: the hot path, plus the tools for understanding it."""

from __future__ import annotations

import uuid
from typing import Annotated, Any

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy import func, select

from control_plane.api.deps import CallerDep, PDPDep, PolicyStoreDep, SessionDep, require_scope
from control_plane.auth.keys import Scope
from control_plane.classification.scanner import Scanner
from control_plane.models.decision import DecisionRecord
from control_plane.policy.engine import PolicyEngine
from control_plane.policy.model import CombiningAlgorithm, Policy
from control_plane.schemas.decision import (
    ClassifyRequest,
    ClassifyResponse,
    DecideRequest,
    DecideResponse,
    FindingOut,
    SimulateRequest,
    SimulateResponse,
)

router = APIRouter(tags=["decisions"])


@router.post(
    "/decide",
    response_model=DecideResponse,
    summary="Decide whether an action on data is permitted",
    dependencies=[Depends(require_scope(Scope.DECIDE))],
)
async def decide(request: DecideRequest, pdp: PDPDep, caller: CallerDep) -> DecideResponse:
    """Evaluate one access request.

    This is the only endpoint an enforcement point needs. It resolves the
    resource's labels, classifies any payload in flight, evaluates the policy
    set, applies redaction obligations, and records the result.
    """
    if not caller.may_act_for(request.principal.id):
        # A key scoped to one agent must not be usable to speak for another.
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=(
                f"this API key may not submit decisions for principal {request.principal.id!r}"
            ),
        )
    return await pdp.decide(request, actor=caller.identity)


@router.post(
    "/simulate",
    response_model=SimulateResponse,
    summary="Evaluate a request against candidate policies without enforcing",
    dependencies=[Depends(require_scope(Scope.POLICY_READ))],
)
async def simulate(body: SimulateRequest, pdp: PDPDep, store: PolicyStoreDep) -> SimulateResponse:
    """Answer "what would this policy change do?" before it is deployed.

    Runs the request twice -- once against the candidate set and once against
    what is stored -- and reports whether the outcome differs. Nothing is
    persisted by either run.
    """
    try:
        if body.policies is not None:
            candidates = [Policy.model_validate(document) for document in body.policies]
        else:
            candidates = await store.load_policies(enabled_only=not body.include_disabled)
            if body.additional_policies:
                candidates += [
                    Policy.model_validate(document) for document in body.additional_policies
                ]
    except Exception as exc:
        raise HTTPException(
            status_code=422,
            detail=f"candidate policy set is invalid: {exc}",
        ) from exc

    simulated_request = body.request.model_copy(deep=True)
    simulated_request.options.persist = False
    simulated_request.options.explain = True

    engine = PolicyEngine(candidates, algorithm=CombiningAlgorithm.DENY_OVERRIDES)
    decision = await pdp.decide(simulated_request, engine=engine)

    baseline = None
    changed = False
    if body.policies is not None or body.additional_policies:
        baseline = await pdp.decide(simulated_request, engine=await store.build_engine())
        changed = (baseline.effect, sorted(baseline.matched_policies)) != (
            decision.effect,
            sorted(decision.matched_policies),
        )

    return SimulateResponse(
        decision=decision,
        baseline=baseline,
        changed=changed,
        policies_evaluated=len(engine),
    )


@router.post(
    "/classify",
    response_model=ClassifyResponse,
    summary="Classify content without making an authorisation decision",
    dependencies=[Depends(require_scope(Scope.DECIDE))],
)
async def classify(body: ClassifyRequest) -> ClassifyResponse:
    """Run the detectors over a payload and report what is in it.

    Useful for cataloguing a sample, for tuning detectors, and for showing a
    user why their document was treated the way it was.
    """
    scanner = (
        Scanner.for_labels(body.labels, min_confidence=body.min_confidence)
        if body.labels
        else Scanner(min_confidence=body.min_confidence)
    )
    result = (
        scanner.scan_text(body.payload)
        if isinstance(body.payload, str)
        else scanner.scan_structured(body.payload)
    )
    summary = result.summary()
    return ClassifyResponse(
        findings=[FindingOut(**f.redacted_dict()) for f in result.findings],
        labels=summary["labels"],
        label_counts=summary["label_counts"],
        max_severity=summary["max_severity"],
        regulations=summary["regulations"],
        scanned_chars=summary["scanned_chars"],
        truncated=summary["truncated"],
    )


@router.get(
    "/decisions",
    summary="List recorded decisions",
    dependencies=[Depends(require_scope(Scope.AUDIT_READ))],
)
async def list_decisions(
    session: SessionDep,
    effect: Annotated[str | None, Query()] = None,
    principal_id: Annotated[str | None, Query()] = None,
    resource_urn: Annotated[str | None, Query()] = None,
    policy: Annotated[str | None, Query(description="Filter by determining policy")] = None,
    limit: Annotated[int, Query(ge=1, le=500)] = 50,
    offset: Annotated[int, Query(ge=0)] = 0,
) -> dict[str, Any]:
    statement = select(DecisionRecord).order_by(DecisionRecord.created_at.desc())
    if effect:
        statement = statement.where(DecisionRecord.effect == effect)
    if principal_id:
        statement = statement.where(DecisionRecord.principal_id == principal_id)
    if resource_urn:
        statement = statement.where(DecisionRecord.resource_urn == resource_urn)
    if policy:
        statement = statement.where(DecisionRecord.determining_policy == policy)

    total = (
        await session.execute(select(func.count()).select_from(statement.subquery()))
    ).scalar_one()
    rows = (await session.execute(statement.limit(limit).offset(offset))).scalars().all()
    return {
        "total": int(total),
        "limit": limit,
        "offset": offset,
        "items": [_decision_summary(row) for row in rows],
    }


@router.get(
    "/decisions/stats",
    summary="Aggregate decision counts",
    dependencies=[Depends(require_scope(Scope.AUDIT_READ))],
)
async def decision_stats(session: SessionDep) -> dict[str, Any]:
    """Counts by effect and by determining policy, for the dashboard."""
    by_effect = (
        await session.execute(
            select(DecisionRecord.effect, func.count()).group_by(DecisionRecord.effect)
        )
    ).all()
    by_policy = (
        await session.execute(
            select(DecisionRecord.determining_policy, func.count())
            .where(DecisionRecord.determining_policy.is_not(None))
            .group_by(DecisionRecord.determining_policy)
            .order_by(func.count().desc())
            .limit(20)
        )
    ).all()
    totals = (
        await session.execute(
            select(
                func.count(DecisionRecord.id),
                func.coalesce(func.avg(DecisionRecord.latency_ms), 0.0),
                func.coalesce(func.sum(DecisionRecord.redaction_count), 0),
            )
        )
    ).one()
    return {
        "total": int(totals[0]),
        "avg_latency_ms": round(float(totals[1]), 3),
        "total_redactions": int(totals[2]),
        "by_effect": {effect: int(count) for effect, count in by_effect},
        "by_policy": [{"policy": key, "count": int(count)} for key, count in by_policy],
    }


@router.get(
    "/decisions/{decision_id}",
    summary="Retrieve one decision, including its evaluation trace",
    dependencies=[Depends(require_scope(Scope.AUDIT_READ))],
)
async def get_decision(decision_id: uuid.UUID, session: SessionDep) -> dict[str, Any]:
    record = (
        await session.execute(select(DecisionRecord).where(DecisionRecord.id == decision_id))
    ).scalar_one_or_none()
    if record is None:
        raise HTTPException(status_code=404, detail=f"no decision {decision_id}")
    return {**_decision_summary(record), "trace": record.trace, "context": record.context}


def _decision_summary(record: DecisionRecord) -> dict[str, Any]:
    return {
        "id": str(record.id),
        "created_at": record.created_at.isoformat() if record.created_at else None,
        "principal_id": record.principal_id,
        "principal_type": record.principal_type,
        "action": record.action,
        "resource_urn": record.resource_urn,
        "effect": record.effect,
        "reason": record.reason,
        "determining_policy": record.determining_policy,
        "matched_policies": record.matched_policies,
        "obligations": record.obligations,
        "classifications": record.classifications,
        "finding_count": record.finding_count,
        "redaction_count": record.redaction_count,
        "latency_ms": record.latency_ms,
        "correlation_id": record.correlation_id,
    }
