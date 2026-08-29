"""The decision endpoints: the hot path, plus the tools for understanding it."""

from __future__ import annotations

import uuid
from datetime import UTC, datetime
from typing import Annotated, Any

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy import func, select

from control_plane.api.deps import (
    AuditDep,
    CallerDep,
    PDPDep,
    PolicyStoreDep,
    SessionDep,
    require_scope,
)
from control_plane.audit.chain import AuditEvent
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
    OutcomeOut,
    OutcomeReport,
    SimulateRequest,
    SimulateResponse,
)

#: The only effect that leaves an action for someone to account for. A deny
#: permitted nothing; a require_approval has not happened yet, and redeeming the
#: approval produces a fresh decision which is the one that gets reported.
ACTIONABLE_EFFECT = "allow"

router = APIRouter(tags=["decisions"])


@router.post(
    "/decide",
    response_model=DecideResponse,
    summary="Decide whether an action on data is permitted",
    dependencies=[Depends(require_scope(Scope.DECIDE))],
)
async def decide(
    request: DecideRequest, pdp: PDPDep, session: SessionDep, caller: CallerDep
) -> DecideResponse:
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
    response = await pdp.decide(request, actor=caller.identity)

    # Commit before answering. The session dependency also commits, but its
    # teardown can run *after* the response has gone out -- so a caller that
    # takes the decision_id and immediately reports an outcome, redeems an
    # approval, or fetches the decision can arrive before the row exists. That
    # race was real and intermittent, around one attempt in eight. An identifier
    # handed to a caller has to refer to something that exists.
    if response.decision_id is not None:
        await session.commit()
    return response


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
    outcome: Annotated[
        str | None,
        Query(
            description="enforced, refused, partial, or 'unreported' for permitted "
            "actions no enforcement point has accounted for. Denials are never "
            "'unreported': nothing was permitted, so there is nothing to report."
        ),
    ] = None,
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
    if outcome == "unreported":
        # The most interesting filter: a point that quietly stops reporting is a
        # point that quietly stopped being observed.
        #
        # Restricted to decisions that permitted something, which is not a
        # detail. A deny has no action for anyone to account for, so it can
        # never be reported and would sit here permanently -- and denials are
        # common, so the one filter meant to surface a silent enforcement point
        # would be mostly noise that never resolves. A parked decision is the
        # same: nothing has happened yet, and redeeming the approval produces a
        # new decision that is the one to account for.
        statement = statement.where(
            DecisionRecord.effect == ACTIONABLE_EFFECT,
            DecisionRecord.outcome.is_(None),
        )
    elif outcome:
        statement = statement.where(DecisionRecord.outcome == outcome)

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
    # Scoped to permitted actions, like the listing filter and for the same
    # reason: a deny has nothing to account for, so counting it as "unreported"
    # describes the taxonomy rather than the fleet. Scoped this way the buckets
    # sum to the allow count, which is a number an operator can check.
    by_outcome = (
        await session.execute(
            select(DecisionRecord.outcome, func.count())
            .where(DecisionRecord.effect == ACTIONABLE_EFFECT)
            .group_by(DecisionRecord.outcome)
        )
    ).all()
    # "Permitted, then refused downstream" -- the reconciliation that was not
    # answerable before enforcement points reported back.
    permitted_not_enforced = (
        await session.execute(
            select(func.count(DecisionRecord.id)).where(
                DecisionRecord.effect == "allow",
                DecisionRecord.outcome.in_(("refused", "partial")),
            )
        )
    ).scalar_one()

    return {
        "total": int(totals[0]),
        "avg_latency_ms": round(float(totals[1]), 3),
        "total_redactions": int(totals[2]),
        "by_effect": {effect: int(count) for effect, count in by_effect},
        "by_outcome": {(o or "unreported"): int(c) for o, c in by_outcome},
        "permitted_but_not_enforced": int(permitted_not_enforced),
        "by_policy": [{"policy": key, "count": int(count)} for key, count in by_policy],
    }


@router.post(
    "/decisions/{decision_id}/outcome",
    response_model=OutcomeOut,
    summary="Report what the enforcement point actually did",
    dependencies=[Depends(require_scope(Scope.DECIDE))],
)
async def report_outcome(
    decision_id: uuid.UUID,
    body: OutcomeReport,
    session: SessionDep,
    audit: AuditDep,
    caller: CallerDep,
) -> OutcomeOut:
    """Close the loop between what was permitted and what happened.

    Everything else in this API records a *decision*. Without this, an
    enforcement point that could not discharge an obligation -- or refused for
    its own reasons -- leaves a record reading "allow" behind an action that
    never took place, and an auditor reconciling the two has one side of the
    ledger.

    An outcome is written once. A repeat of the same report is idempotent, so a
    retrying caller is not punished for it. A *different* one is refused and
    sealed into the audit chain as a conflict: an attempt to restate what
    already happened is precisely the thing a tamper-evident log exists to
    surface.
    """
    record = (
        await session.execute(select(DecisionRecord).where(DecisionRecord.id == decision_id))
    ).scalar_one_or_none()
    if record is None:
        raise HTTPException(status_code=404, detail=f"no decision {decision_id}")

    if record.outcome is not None:
        if record.outcome == str(body.outcome):
            return _outcome_out(record)
        await audit.append(
            AuditEvent.DECISION_OUTCOME_CONFLICT,
            actor=caller.identity,
            subject=str(decision_id),
            payload={
                "recorded": record.outcome,
                "submitted": str(body.outcome),
                "recorded_by": record.outcome_reported_by,
                "reason": body.reason,
            },
        )
        # Commit before refusing. The request handler raises from here, and the
        # session dependency rolls back on an exception -- which would discard
        # the very record this branch exists to write. Nothing else is pending:
        # the decision row was only read, so this commits the audit entry alone.
        await session.commit()
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=(
                f"this decision was already reported as {record.outcome!r} by "
                f"{record.outcome_reported_by or 'an unrecorded caller'}; a "
                f"conflicting report has been recorded in the audit chain"
            ),
        )

    record.outcome = str(body.outcome)
    record.outcome_reason = body.reason
    record.outcome_reported_at = datetime.now(UTC)
    record.outcome_reported_by = caller.identity
    record.discharged = sorted(set(body.discharged))
    record.undischarged = sorted(set(body.undischarged))
    await session.flush()

    await audit.append(
        AuditEvent.DECISION_OUTCOME,
        actor=caller.identity,
        subject=str(decision_id),
        payload={
            "outcome": record.outcome,
            "effect": record.effect,
            "reason": body.reason,
            "discharged": record.discharged,
            "undischarged": record.undischarged,
            # Both halves in one record, so the reconciliation an auditor wants
            # does not require joining two tables to notice a contradiction.
            "permitted": record.effect == "allow",
        },
    )
    return _outcome_out(record)


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


def _outcome_out(record: DecisionRecord) -> OutcomeOut:
    return OutcomeOut(
        decision_id=record.id,
        outcome=record.outcome,
        reason=record.outcome_reason,
        discharged=list(record.discharged or []),
        undischarged=list(record.undischarged or []),
        reported_at=(
            record.outcome_reported_at.isoformat() if record.outcome_reported_at else None
        ),
        reported_by=record.outcome_reported_by,
    )


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
        "outcome": record.outcome,
        "outcome_reason": record.outcome_reason,
        "discharged": list(record.discharged or []),
        "undischarged": list(record.undischarged or []),
        "outcome_reported_at": (
            record.outcome_reported_at.isoformat() if record.outcome_reported_at else None
        ),
    }
