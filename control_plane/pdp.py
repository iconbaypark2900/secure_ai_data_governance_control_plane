"""The policy decision point.

Everything else in this package is a component; this is the thing that answers
the question. One call to :meth:`PolicyDecisionPoint.decide` runs the whole
pipeline:

1. Enrich the principal from the catalog, so a caller cannot assert its own
   trust tier.
2. Resolve the resource's labels, including any inherited from pattern
   registrations.
3. Scan the payload in flight and merge what it finds into those labels, so a
   prompt carrying an SSN is governed as PHI-adjacent data whatever the resource
   was registered as.
4. Evaluate the policy set.
5. Execute redaction obligations, if asked to.
6. Record the decision and seal an audit entry.

The pipeline fails closed. An error anywhere between steps 1 and 4 produces a
deny with the failure recorded, never an allow-by-accident.
"""

from __future__ import annotations

import asyncio
import time
import uuid
from collections.abc import Mapping, Sequence
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from functools import partial
from typing import Any

import structlog
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from control_plane.audit.chain import AuditEvent, as_utc, content_digest
from control_plane.audit.service import AuditService
from control_plane.catalog.service import CatalogService
from control_plane.classification.scanner import Finding, Scanner, ScanResult
from control_plane.config import Settings, get_settings
from control_plane.metrics import get_metrics
from control_plane.models.decision import ApprovalRequest, DecisionRecord
from control_plane.policy.engine import Decision, PolicyEngine
from control_plane.policy.model import (
    CONTROL_PLANE_OBLIGATIONS,
    AccessRequest,
    Effect,
    Obligation,
    Principal,
    Resource,
)
from control_plane.policy.store import PolicyStore
from control_plane.redaction.tokenization import DeterministicTokenizer
from control_plane.redaction.transforms import RedactionResult, Redactor
from control_plane.schemas.decision import (
    ApprovalOut,
    DecideRequest,
    DecideResponse,
    FindingOut,
    RedactionOut,
)

__all__ = ["APPROVAL_TTL", "PolicyDecisionPoint"]

log = structlog.get_logger(__name__)

#: How long a parked decision stays actionable before it must be re-requested.
APPROVAL_TTL = timedelta(hours=24)

#: Obligation types the control plane carries out itself. Anything else is handed
#: to the enforcement point, which must satisfy it or deny. Imported rather than
#: restated: two copies of this set would eventually disagree, and the direction
#: they would disagree in is a duty silently going unenforced.
SELF_EXECUTABLE = CONTROL_PLANE_OBLIGATIONS


class PolicyDecisionPoint:
    """Orchestrates one decision end to end."""

    def __init__(
        self,
        session: AsyncSession,
        *,
        settings: Settings | None = None,
        scanner: Scanner | None = None,
    ) -> None:
        self._session = session
        self._settings = settings or get_settings()
        # Built from settings rather than the module default, so CP_MAX_SCAN_CHARS
        # is a setting that does something.
        self._scanner = scanner or Scanner(max_chars=self._settings.max_scan_chars)
        self._tokenizer = DeterministicTokenizer.from_settings(self._settings)
        self._catalog = CatalogService(session)
        self._policies = PolicyStore(session)
        self._audit = AuditService(session)

    # --- the entry point ---------------------------------------------------- #

    async def decide(
        self,
        request: DecideRequest,
        *,
        engine: PolicyEngine | None = None,
        actor: str = "",
    ) -> DecideResponse:
        """Evaluate ``request`` and return the answer."""
        started = time.perf_counter()

        try:
            enriched_principal = await self._enrich_principal(request.principal)
            resolved = await self._catalog.resolve(request.resource.urn)
            scan = await self._scan(request)
            findings = self._filter_findings(scan, request.options.min_confidence)

            catalog_labels = set(resolved.label_keys)
            declared_labels = set(request.resource.classifications)
            payload_labels = {f.label for f in findings}
            all_labels = sorted(catalog_labels | declared_labels | payload_labels)

            access = AccessRequest(
                env={"payload_truncated": scan.truncated, "payload_scanned": scan.scanned_chars},
                principal=enriched_principal,
                action=request.action,
                resource=Resource(
                    urn=request.resource.urn,
                    kind=request.resource.kind or resolved.kind or None,
                    classifications=sorted(catalog_labels | declared_labels),
                    attributes={
                        **resolved.attributes,
                        **request.resource.attributes,
                        "registered": resolved.registered,
                        "matched_patterns": resolved.matched_patterns,
                    },
                ),
                context=dict(request.context),
                findings=sorted(payload_labels),
            )

            active_engine = engine or await self._policies.build_engine()
            decision = active_engine.evaluate(access, explain=request.options.explain)

            payload_digest = (
                content_digest(request.payload, self._settings.audit_key_bytes())
                if request.payload is not None
                else None
            )
            fingerprint = self._fingerprint(access, payload_digest)

            # A human approval, if one is being presented and actually applies.
            approval: ApprovalRequest | None = None
            approval_error: str | None = None
            if decision.effect is Effect.REQUIRE_APPROVAL and request.approval_id is not None:
                approval, approval_error = await self._validate_approval(
                    request.approval_id, fingerprint
                )
                if approval is not None:
                    decision = self._redeemed_decision(decision, approval, active_engine)

        except Exception as exc:
            # Fail closed. An exception here means the control plane could not
            # establish that the request is safe, which is not the same as it
            # being safe.
            log.error("decision_pipeline_failed", error=str(exc), action=request.action)
            if not self._settings.fail_closed:
                raise
            return DecideResponse(
                effect="deny",
                reason=f"decision pipeline failed and the control plane fails closed: {exc}",
                latency_ms=round((time.perf_counter() - started) * 1000, 3),
                policy_errors=[str(exc)],
            )

        decision = self._guard_tokenization(decision)

        response = self._build_response(request, decision, findings, all_labels)
        response.payload_truncated = scan.truncated
        response.approval_error = approval_error
        response.approval_redeemed = approval is not None
        if approval is not None:
            response.approval = _approval_out(approval)

        if request.options.persist:
            record = await self._persist(
                request,
                decision,
                response,
                findings,
                started,
                actor=actor,
                payload_digest=payload_digest,
            )
            response.decision_id = record.id

            if approval is not None:
                # Spend it. Single use: "approve this one export" must not
                # become "approve every export until the window closes".
                await self._mark_redeemed(approval, record.id, actor=actor)
                response.approval = _approval_out(approval)
            elif decision.effect is Effect.REQUIRE_APPROVAL:
                parked = await self._park_for_approval(record, request, fingerprint)
                response.approval = _approval_out(parked)

        elapsed = time.perf_counter() - started
        response.latency_ms = round(elapsed * 1000, 3)
        get_metrics().observe_decision(
            effect=response.effect,
            duration_seconds=elapsed,
            finding_labels=(f.label for f in findings),
            redactions=(r.model_dump() for r in response.redactions),
        )
        return response

    # --- pipeline stages ----------------------------------------------------- #

    async def _enrich_principal(self, principal: Principal) -> Principal:
        """Overlay catalog attributes on the caller's assertion.

        The catalog's values win on conflict. A request that says "my trust tier
        is high" must not be able to make itself true.
        """
        attributes = await self._catalog.enrich_principal(principal.id, principal.attributes)
        return Principal(id=principal.id, type=principal.type, attributes=attributes)

    async def _scan(self, request: DecideRequest) -> ScanResult:
        """Classify the payload, off the event loop unless told otherwise.

        Regex matching is CPU-bound. Run inline it holds the loop for the whole
        scan, which stalls every other request's database round trip too -- so a
        single large payload degrades latency for everything sharing the worker,
        not just for itself.
        """
        if request.payload is None or not request.options.scan_payload:
            return ScanResult()

        payload = request.payload
        work = (
            partial(self._scanner.scan_text, payload)
            if isinstance(payload, str)
            else partial(self._scanner.scan_structured, payload)
        )
        if not self._settings.scan_in_thread:
            return work()
        return await asyncio.to_thread(work)

    @staticmethod
    def _filter_findings(scan: ScanResult, min_confidence: float) -> tuple[Finding, ...]:
        return tuple(f for f in scan.findings if f.confidence >= min_confidence)

    def _build_response(
        self,
        request: DecideRequest,
        decision: Decision,
        findings: Sequence[Finding],
        labels: Sequence[str],
    ) -> DecideResponse:
        from control_plane.classification import taxonomy

        unsupported = sorted(
            {o.type for o in decision.obligations if o.type not in SELF_EXECUTABLE}
        )

        response = DecideResponse(
            effect=str(decision.effect),  # type: ignore[arg-type]
            reason=decision.reason,
            determining_policy=decision.determining_policy,
            matched_policies=list(decision.matched_policies),
            obligations=[o.to_dict() for o in decision.obligations],
            classifications=list(labels),
            findings=[FindingOut(**f.redacted_dict()) for f in findings],
            regulations=list(taxonomy.regulations_for(labels)),
            unsupported_obligations=unsupported if request.options.apply_obligations else [],
            policy_errors=list(decision.errors),
        )

        if request.options.explain:
            response.explain = decision.to_dict(include_trace=True)

        # Only an allow returns content, and only when asked to apply obligations.
        if decision.effect is Effect.ALLOW and request.options.apply_obligations:
            redacted = self._apply_obligations(request.payload, decision.obligations, findings)
            if redacted is not None:
                response.payload = redacted.payload
                response.redactions = [RedactionOut(**item.to_dict()) for item in redacted.applied]
            elif request.payload is not None:
                response.payload = request.payload

        return response

    def _apply_obligations(
        self,
        payload: Any,
        obligations: Sequence[Obligation],
        findings: Sequence[Finding],
    ) -> RedactionResult | None:
        """Execute redaction obligations against the payload."""
        if payload is None:
            return None
        redact_obligations = [o.to_dict() for o in obligations if o.type == "redact"]
        if not redact_obligations or not findings:
            return None

        redactor = Redactor.from_obligations(
            redact_obligations,
            key=self._settings.redaction_key_bytes(),
            vault=self._tokenizer,
        )
        if isinstance(payload, str):
            return redactor.apply_to_text(payload, findings)
        return redactor.apply_to_structured(payload, findings)

    # --- persistence --------------------------------------------------------- #

    async def _persist(
        self,
        request: DecideRequest,
        decision: Decision,
        response: DecideResponse,
        findings: Sequence[Finding],
        started: float,
        *,
        actor: str,
        payload_digest: str | None = None,
    ) -> DecisionRecord:
        latency_ms = round((time.perf_counter() - started) * 1000, 3)
        digest = payload_digest

        record = DecisionRecord(
            id=uuid.uuid4(),
            principal_id=request.principal.id,
            principal_type=str(request.principal.type),
            action=request.action,
            resource_urn=request.resource.urn or "",
            resource_kind=request.resource.kind or "",
            effect=str(decision.effect),
            reason=decision.reason,
            determining_policy=decision.determining_policy,
            matched_policies=list(decision.matched_policies),
            obligations=[o.to_dict() for o in decision.obligations],
            classifications=list(response.classifications),
            finding_count=len(findings),
            redaction_count=len(response.redactions),
            payload_digest=digest,
            context=_safe_context(request.context),
            # The trace is stored only when explicitly requested: it is the
            # largest part of a decision and the least often read.
            trace=decision.to_dict(include_trace=request.options.explain),
            latency_ms=latency_ms,
            correlation_id=request.correlation_id,
        )
        self._session.add(record)
        await self._session.flush()

        await self._audit.append(
            AuditEvent.DECISION,
            actor=actor or request.principal.id,
            subject=request.resource.urn or request.action,
            payload={
                "decision_id": str(record.id),
                "effect": str(decision.effect),
                "action": request.action,
                "principal_type": str(request.principal.type),
                "determining_policy": decision.determining_policy,
                "matched_policies": list(decision.matched_policies),
                "classifications": list(response.classifications),
                "finding_count": len(findings),
                "redaction_count": len(response.redactions),
                "payload_digest": digest,
                "correlation_id": request.correlation_id,
                "latency_ms": latency_ms,
            },
        )
        return record

    def _guard_tokenization(self, decision: Decision) -> Decision:
        """Deny when a decision requires tokenisation that cannot be performed.

        An obligation is a duty, not advice. If a policy permits an action only
        on condition that certain values are replaced with reversible tokens,
        and no tokenisation key is configured, then the condition cannot be met
        and the permission does not apply. Emitting a hash instead would satisfy
        the shape of the obligation and not its meaning.

        This is a configuration error surfacing as a denial, which is the right
        direction: the alternative is data leaving under a control everyone
        believes is in place.
        """
        if self._tokenizer is not None or decision.effect is Effect.DENY:
            return decision
        requires = sorted(
            {
                str(obligation.get("labels") or obligation.get("classifications") or "*")
                for obligation in (o.to_dict() for o in decision.obligations)
                if obligation.get("type") == "redact"
                and str(obligation.get("strategy", "")).lower() == "tokenize"
            }
        )
        if not requires:
            return decision

        log.error(
            "tokenization_unavailable",
            determining_policy=decision.determining_policy,
            labels=requires,
            hint="set CP_TOKENIZATION_KEY, or change the policy's redaction strategy",
        )
        return replace(
            decision,
            effect=Effect.DENY,
            obligations=(),
            reason=(
                f"{decision.reason}; denied because the decision requires the "
                f"'tokenize' strategy for {', '.join(requires)} and no tokenisation "
                f"key is configured, so the obligation cannot be satisfied"
            ),
            errors=(
                *decision.errors,
                "tokenization is required by policy but CP_TOKENIZATION_KEY is not set",
            ),
        )

    # --- approvals ----------------------------------------------------------- #

    def _fingerprint(self, access: AccessRequest, payload_digest: str | None) -> str:
        """A keyed digest of everything a reviewer was implicitly agreeing to.

        This is what scopes an approval to one request. Without it, an approval
        id is a bearer capability for *any* request that happens to need one:
        get an innocuous export approved, then present the same id for an
        exfiltration. Every policy-relevant input goes in, so if any of them
        changed -- the resource was reclassified, the destination flipped to
        external, the payload is different -- the binding no longer matches and
        the approval will not redeem.
        """
        return content_digest(
            {
                "principal_id": access.principal.id,
                "principal_type": str(access.principal.type),
                "action": access.action,
                "resource_urn": access.resource.urn,
                "classifications": sorted(access.resource.classifications),
                "findings": sorted(access.findings),
                "context": _safe_context(access.context),
                "payload": payload_digest,
            },
            self._settings.audit_key_bytes(),
        )

    async def _validate_approval(
        self, approval_id: uuid.UUID, fingerprint: str
    ) -> tuple[ApprovalRequest | None, str | None]:
        """Look up a presented approval and decide whether it applies here."""
        approval = (
            await self._session.execute(
                select(ApprovalRequest).where(ApprovalRequest.id == approval_id)
            )
        ).scalar_one_or_none()
        if approval is None:
            return None, f"no approval request {approval_id}"
        error = approval.redemption_error(fingerprint, datetime.now(UTC))
        if error is not None:
            return None, error
        return approval, None

    def _redeemed_decision(
        self, decision: Decision, approval: ApprovalRequest, engine: PolicyEngine
    ) -> Decision:
        """Turn a parked decision into an allow, carrying every duty with it.

        Obligations are re-collected across both ``allow`` and
        ``require_approval`` policies. An ``allow`` policy that matched but lost
        to the parking rule still said "if you permit this, redact the PII", and
        redeeming an approval must not become a way to shed that.
        """
        obligations = engine.obligations_for(
            decision.matched_policies, {Effect.ALLOW, Effect.REQUIRE_APPROVAL}
        )
        granted_by = approval.decided_by or "an unrecorded approver"
        return replace(
            decision,
            effect=Effect.ALLOW,
            obligations=obligations,
            reason=(
                f"{decision.reason}; redeemed approval {approval.id} granted by "
                f"{granted_by} at {_iso(approval.resolved_at)}"
            ),
        )

    async def _mark_redeemed(
        self, approval: ApprovalRequest, decision_id: uuid.UUID, *, actor: str
    ) -> None:
        approval.redeemed_at = datetime.now(UTC)
        approval.redeemed_by = actor or approval.requested_by
        approval.redeemed_decision_id = decision_id
        await self._session.flush()
        await self._audit.append(
            AuditEvent.APPROVAL_REDEEMED,
            actor=actor or approval.requested_by,
            subject=str(decision_id),
            payload={
                "approval_id": str(approval.id),
                "decision_id": str(decision_id),
                "granted_by": approval.decided_by,
                "originally_parked_as": str(approval.decision_id),
            },
        )

    async def _park_for_approval(
        self, record: DecisionRecord, request: DecideRequest, fingerprint: str
    ) -> ApprovalRequest:
        """Queue this request for a human, or hand back the ticket it already has.

        A caller that re-sends a parked request -- a retry, an impatient poll, a
        second worker picking up the same job -- must not create a second
        approval each time. An identical request that is already awaiting a
        decision gets the existing ticket back, so the queue stays a list of
        distinct things to review rather than a log of attempts.
        """
        now = datetime.now(UTC)
        existing = (
            await self._session.execute(
                select(ApprovalRequest)
                .where(
                    ApprovalRequest.request_fingerprint == fingerprint,
                    ApprovalRequest.status == "pending",
                )
                .order_by(ApprovalRequest.created_at.desc())
                .limit(1)
            )
        ).scalar_one_or_none()
        if existing is not None and (
            existing.expires_at is None or _as_utc(existing.expires_at) > now
        ):
            return existing

        approval = ApprovalRequest(
            decision_id=record.id,
            status="pending",
            requested_by=request.principal.id,
            justification=str(request.context.get("justification", "")),
            request_fingerprint=fingerprint,
            expires_at=now + APPROVAL_TTL,
        )
        self._session.add(approval)
        await self._session.flush()
        await self._audit.append(
            AuditEvent.APPROVAL_REQUESTED,
            actor=request.principal.id,
            subject=request.resource.urn or request.action,
            payload={
                "approval_id": str(approval.id),
                "decision_id": str(record.id),
                "action": request.action,
            },
        )
        return approval


def _approval_out(approval: ApprovalRequest) -> ApprovalOut:
    """The caller-facing view of an approval, at any point in its lifecycle."""
    return ApprovalOut(
        id=approval.id,
        status=approval.status,
        requested_by=approval.requested_by,
        created_at=_iso(approval.created_at) or "",
        expires_at=_iso(approval.expires_at),
        decided_by=approval.decided_by,
        decision_note=approval.decision_note,
        resolved_at=_iso(approval.resolved_at),
        redeemed_at=_iso(approval.redeemed_at),
        redeemed_by=approval.redeemed_by,
    )


#: Context keys that must never be copied into a stored decision record.
_SENSITIVE_CONTEXT_KEYS = frozenset(
    {"authorization", "token", "api_key", "apikey", "password", "secret", "cookie"}
)


def _safe_context(context: Mapping[str, Any]) -> dict[str, Any]:
    """Drop credential-shaped context before it reaches durable storage.

    Callers put useful things in ``context``. Occasionally they put a bearer
    token there too, and the decision table is not the place for it to come to
    rest.
    """
    cleaned: dict[str, Any] = {}
    for key, value in context.items():
        if str(key).lower() in _SENSITIVE_CONTEXT_KEYS:
            cleaned[str(key)] = "[dropped]"
        elif isinstance(value, str) and len(value) > 512:
            cleaned[str(key)] = value[:512] + "..."
        else:
            cleaned[str(key)] = value
    return cleaned


def _as_utc(value: datetime) -> datetime:
    return as_utc(value)


def _iso(value: datetime | None) -> str | None:
    return as_utc(value).isoformat() if value else None
