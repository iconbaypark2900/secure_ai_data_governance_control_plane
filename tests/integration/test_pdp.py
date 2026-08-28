"""The decision pipeline end to end, against a real database."""

from __future__ import annotations

import pytest
from sqlalchemy import select

from control_plane.audit.service import AuditService
from control_plane.catalog.service import CatalogService
from control_plane.classification.scanner import scan_text
from control_plane.models.decision import ApprovalRequest, DecisionRecord
from control_plane.pdp import PolicyDecisionPoint
from control_plane.policy.model import Policy
from control_plane.policy.store import PolicyStore
from control_plane.schemas.decision import DecideOptions, DecideRequest


async def seed(session) -> None:
    """A small but realistic policy set and catalog."""
    catalog = CatalogService(session)

    kb, _ = await catalog.upsert_asset(
        "qdrant://kb_docs", name="Support knowledge base", kind="vector_collection"
    )
    await catalog.set_classification(kb, "pii.email", source="manual")

    customers, _ = await catalog.upsert_asset("pg://public.customers", name="Customers")
    await catalog.set_classification(customers, "pii.ssn", source="manual")
    await catalog.set_classification(customers, "pci.card_number", source="manual")

    # A pattern asset: everything under the clinical schema is PHI, whether or
    # not the individual table was ever registered.
    clinical, _ = await catalog.upsert_asset("pg://clinical.*", name="Clinical schema")
    await catalog.set_classification(clinical, "phi.mrn", source="manual")

    await catalog.upsert_principal(
        "agent:support_bot", type_="agent", attributes={"trust_tier": "low", "team": "support"}
    )
    await catalog.upsert_principal(
        "user:analyst", type_="user", attributes={"trust_tier": "high", "team": "data"}
    )

    store = PolicyStore(session)
    for policy in [
        Policy(
            key="deny-phi-to-external-models",
            name="PHI must not reach an external model",
            effect="deny",
            priority=900,
            match={
                "all": [
                    {"resource.classifications": {"any_of": ["phi"]}},
                    {"context.destination": "external"},
                ]
            },
        ),
        Policy(
            key="deny-secrets-everywhere",
            name="Credentials never leave the control plane",
            effect="deny",
            priority=950,
            match={"findings": {"any_of": ["secret"]}},
        ),
        Policy(
            key="approve-bulk-customer-export",
            name="Bulk customer export needs a human",
            effect="require_approval",
            priority=500,
            match={
                "all": [
                    {"action": "export"},
                    {"resource.urn": {"glob": "pg://public.*"}},
                ]
            },
        ),
        Policy(
            key="allow-agent-read-with-redaction",
            name="Agents may read, with PII masked",
            effect="allow",
            priority=100,
            match={"all": [{"principal.type": "agent"}, {"action": ["read", "embed"]}]},
            obligations=[{"type": "redact", "labels": ["pii", "pci"], "strategy": "mask"}],
        ),
        Policy(
            key="allow-analysts-read",
            name="High-trust analysts read unredacted",
            effect="allow",
            priority=200,
            match={
                "all": [
                    {"principal.type": "user"},
                    {"principal.trust_tier": "high"},
                    {"action": ["read", "query"]},
                ]
            },
        ),
    ]:
        await store.create(policy, actor="seed")
    await session.flush()


@pytest.fixture
async def pdp(session):
    await seed(session)
    return PolicyDecisionPoint(session)


def request_for(**overrides) -> DecideRequest:
    base = {
        "principal": {"id": "agent:support_bot", "type": "agent"},
        "action": "read",
        "resource": {"urn": "qdrant://kb_docs"},
    }
    base.update(overrides)
    return DecideRequest.model_validate(base)


class TestDecisions:
    async def test_allow_with_redaction(self, pdp) -> None:
        response = await pdp.decide(
            request_for(payload="Contact jane.doe@acme.com about invoice 4111 1111 1111 1111")
        )
        assert response.effect == "allow"
        assert response.determining_policy == "allow-agent-read-with-redaction"
        assert "jane.doe@acme.com" not in response.payload
        assert "4111 1111 1111 1111" not in response.payload
        assert {r.label for r in response.redactions} == {"pii.email", "pci.card_number"}

    async def test_deny_never_returns_the_payload(self, pdp) -> None:
        """The central invariant: a deny must not echo what it denied."""
        response = await pdp.decide(request_for(payload="token ghp_" + "a" * 36, action="read"))
        assert response.effect == "deny"
        assert response.payload is None
        assert response.determining_policy == "deny-secrets-everywhere"

    async def test_payload_classification_drives_the_decision(self, pdp) -> None:
        """The resource is clean; the content in flight is not."""
        clean = await pdp.decide(request_for(payload="nothing sensitive here"))
        assert clean.effect == "allow"

        dirty = await pdp.decide(request_for(payload="aws key AKIAIOSFODNN7EXAMPLE"))
        assert dirty.effect == "deny"

    async def test_pattern_assets_classify_unregistered_tables(self, pdp) -> None:
        """pg://clinical.encounters was never registered, but is still PHI."""
        response = await pdp.decide(
            request_for(
                resource={"urn": "pg://clinical.encounters"},
                context={"destination": "external"},
            )
        )
        assert response.effect == "deny"
        assert response.determining_policy == "deny-phi-to-external-models"
        assert "phi.mrn" in response.classifications

    async def test_require_approval_parks_the_decision(self, pdp, session) -> None:
        response = await pdp.decide(
            request_for(
                principal={"id": "user:analyst", "type": "user"},
                action="export",
                resource={"urn": "pg://public.customers"},
            )
        )
        assert response.effect == "require_approval"
        assert response.approval is not None
        assert response.approval.status == "pending"
        assert response.payload is None

        parked = (await session.execute(select(ApprovalRequest))).scalars().all()
        assert len(parked) == 1

    async def test_catalog_attributes_override_caller_claims(self, pdp) -> None:
        """An agent cannot promote itself into the analyst policy."""
        response = await pdp.decide(
            request_for(
                principal={
                    "id": "agent:support_bot",
                    "type": "agent",
                    "attributes": {"trust_tier": "high"},
                }
            )
        )
        assert response.determining_policy == "allow-agent-read-with-redaction"

    async def test_high_trust_user_reads_unredacted(self, pdp) -> None:
        response = await pdp.decide(
            request_for(
                principal={"id": "user:analyst", "type": "user"},
                payload="Contact jane.doe@acme.com",
            )
        )
        assert response.effect == "allow"
        assert response.redactions == []
        assert "jane.doe@acme.com" in response.payload

    async def test_unmatched_request_is_denied_by_default(self, pdp) -> None:
        response = await pdp.decide(
            request_for(principal={"id": "unknown:thing", "type": "service"}, action="drop")
        )
        assert response.effect == "deny"
        assert "no policy matched" in response.reason

    async def test_regulations_are_reported(self, pdp) -> None:
        response = await pdp.decide(request_for(resource={"urn": "pg://public.customers"}))
        assert "PCI-DSS" in response.regulations


class TestPersistence:
    async def test_decision_is_recorded(self, pdp, session) -> None:
        response = await pdp.decide(request_for(payload="jane.doe@acme.com"))
        record = (
            await session.execute(
                select(DecisionRecord).where(DecisionRecord.id == response.decision_id)
            )
        ).scalar_one()
        assert record.effect == "allow"
        assert record.redaction_count == 1
        assert record.payload_digest is not None

    async def test_payload_content_is_never_stored(self, pdp, session) -> None:
        secret = "Contact jane.doe@acme.com"
        await pdp.decide(request_for(payload=secret))
        record = (await session.execute(select(DecisionRecord))).scalars().first()
        assert "jane.doe@acme.com" not in str(record.as_dict())

    async def test_credential_shaped_context_is_dropped(self, pdp, session) -> None:
        await pdp.decide(request_for(context={"authorization": "Bearer sk-live-abc123"}))
        record = (await session.execute(select(DecisionRecord))).scalars().first()
        assert record.context["authorization"] == "[dropped]"

    async def test_every_decision_seals_an_audit_record(self, pdp, session, audit_key) -> None:
        await pdp.decide(request_for())
        await pdp.decide(request_for(action="export", resource={"urn": "pg://public.customers"}))
        audit = AuditService(session, key=audit_key)
        assert await audit.count() >= 2
        assert (await audit.verify()).valid is True

    async def test_persist_false_writes_nothing(self, pdp, session) -> None:
        response = await pdp.decide(request_for(options=DecideOptions(persist=False).model_dump()))
        assert response.decision_id is None
        assert (await session.execute(select(DecisionRecord))).scalars().all() == []


class TestExplainability:
    async def test_explain_returns_the_full_trace(self, pdp) -> None:
        response = await pdp.decide(request_for(options=DecideOptions(explain=True).model_dump()))
        assert response.explain is not None
        keys = {entry["key"] for entry in response.explain["trace"]}
        assert "deny-phi-to-external-models" in keys

    async def test_trace_is_omitted_by_default(self, pdp) -> None:
        assert (await pdp.decide(request_for())).explain is None


class TestFailureModes:
    async def test_pipeline_failure_denies(self, pdp, monkeypatch) -> None:
        """Fail closed: an internal error must not become an allow."""

        def explode(*args, **kwargs):
            raise RuntimeError("catalog unavailable")

        monkeypatch.setattr(CatalogService, "resolve", explode)
        response = await pdp.decide(request_for())
        assert response.effect == "deny"
        assert "fails closed" in response.reason

    async def test_obligations_the_plane_cannot_execute_are_flagged(self, session) -> None:
        await seed(session)
        store = PolicyStore(session)
        await store.create(
            Policy(
                key="watermark-everything",
                name="Watermark agent output",
                effect="allow",
                priority=101,
                match={"principal.type": "agent"},
                obligations=[{"type": "watermark", "text": "internal use only"}],
            ),
            actor="test",
        )
        response = await PolicyDecisionPoint(session).decide(request_for())
        assert "watermark" in response.unsupported_obligations


class TestScannerIntegration:
    async def test_min_confidence_is_honoured(self, pdp) -> None:
        text = "server at 203.0.113.9"
        assert "pii.ip_address" in scan_text(text).labels
        response = await pdp.decide(
            request_for(payload=text, options=DecideOptions(min_confidence=0.9).model_dump())
        )
        assert "pii.ip_address" not in response.classifications

    async def test_scanning_can_be_disabled(self, pdp) -> None:
        response = await pdp.decide(
            request_for(
                payload="token ghp_" + "a" * 36,
                options=DecideOptions(scan_payload=False).model_dump(),
            )
        )
        assert response.effect == "allow"
