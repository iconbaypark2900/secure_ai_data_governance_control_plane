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

import time
import uuid
from collections.abc import Mapping, Sequence
from datetime import UTC, datetime, timedelta
from typing import Any

import structlog
from sqlalchemy.ext.asyncio import AsyncSession

from control_plane.audit.chain import AuditEvent, as_utc, content_digest
from control_plane.audit.service import AuditService
from control_plane.catalog.service import CatalogService
from control_plane.classification.scanner import DEFAULT_SCANNER, Finding, Scanner, ScanResult
from control_plane.config import Settings, get_settings
from control_plane.models.decision import ApprovalRequest, DecisionRecord
from control_plane.policy.engine import Decision, PolicyEngine
from control_plane.policy.model import AccessRequest, Effect, Obligation, Principal, Resource
from control_plane.policy.store import PolicyStore
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

#: Obligation types the control plane can carry out itself. Anything else is
#: handed to the enforcement point, which must satisfy it or deny.
SELF_EXECUTABLE = frozenset({"redact", "annotate", "log", "ttl"})


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
        self._scanner = scanner or DEFAULT_SCANNER
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
            scan = self._scan(request)
            findings = self._filter_findings(scan, request.options.min_confidence)

            catalog_labels = set(resolved.label_keys)
            declared_labels = set(request.resource.classifications)
            payload_labels = {f.label for f in findings}
            all_labels = sorted(catalog_labels | declared_labels | payload_labels)

            access = AccessRequest(
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

        response = self._build_response(request, decision, findings, all_labels)

        if request.options.persist:
            record = await self._persist(
                request, decision, response, findings, started, actor=actor
            )
            response.decision_id = record.id
            if decision.effect is Effect.REQUIRE_APPROVAL:
                approval = await self._park_for_approval(record, request)
                response.approval = ApprovalOut(
                    id=approval.id,
                    status=approval.status,
                    requested_by=approval.requested_by,
                    created_at=_iso(approval.created_at),
                    expires_at=_iso(approval.expires_at),
                )

        response.latency_ms = round((time.perf_counter() - started) * 1000, 3)
        return response

    # --- pipeline stages ----------------------------------------------------- #

    async def _enrich_principal(self, principal: Principal) -> Principal:
        """Overlay catalog attributes on the caller's assertion.

        The catalog's values win on conflict. A request that says "my trust tier
        is high" must not be able to make itself true.
        """
        attributes = await self._catalog.enrich_principal(principal.id, principal.attributes)
        return Principal(id=principal.id, type=principal.type, attributes=attributes)

    def _scan(self, request: DecideRequest) -> ScanResult:
        if request.payload is None or not request.options.scan_payload:
            return ScanResult()
        if isinstance(request.payload, str):
            return self._scanner.scan_text(request.payload)
        return self._scanner.scan_structured(request.payload)

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
            redact_obligations, key=self._settings.redaction_key_bytes()
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
    ) -> DecisionRecord:
        latency_ms = round((time.perf_counter() - started) * 1000, 3)
        digest = (
            content_digest(request.payload, self._settings.audit_key_bytes())
            if request.payload is not None
            else None
        )

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

    async def _park_for_approval(
        self, record: DecisionRecord, request: DecideRequest
    ) -> ApprovalRequest:
        approval = ApprovalRequest(
            decision_id=record.id,
            status="pending",
            requested_by=request.principal.id,
            justification=str(request.context.get("justification", "")),
            expires_at=datetime.now(UTC) + APPROVAL_TTL,
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


def _iso(value: datetime | None) -> str | None:
    return as_utc(value).isoformat() if value else None
