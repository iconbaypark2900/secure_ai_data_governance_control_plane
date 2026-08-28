"""The approval loop, end to end.

An approval is a capability. Most of what follows tests that it is a *scoped*
one: bound to the request a human actually reviewed, spendable once, expiring,
and incapable of overriding a deny. Those four properties are the difference
between "a person approved this export" and "anyone holding this id can do
anything that needs approval".
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest
from sqlalchemy import select

from control_plane.audit.service import AuditService
from control_plane.catalog.service import CatalogService
from control_plane.models.decision import ApprovalRequest, DecisionRecord
from control_plane.pdp import PolicyDecisionPoint
from control_plane.policy.model import Policy
from control_plane.policy.store import PolicyStore
from control_plane.schemas.decision import DecideOptions, DecideRequest


async def seed(session) -> None:
    catalog = CatalogService(session)
    customers, _ = await catalog.upsert_asset("pg://public.customers", name="Customers")
    await catalog.set_classification(customers, "pii.email", source="manual")
    await catalog.set_classification(customers, "pii.ssn", source="manual")

    payments, _ = await catalog.upsert_asset("pg://public.payments", name="Payments")
    await catalog.set_classification(payments, "pci.card_number", source="manual")

    await catalog.upsert_principal("user:analyst", type_="user", attributes={"trust_tier": "high"})

    store = PolicyStore(session)
    for policy in [
        Policy(
            key="deny-credentials",
            name="Credentials never move",
            effect="deny",
            priority=1000,
            match={"findings": {"any_of": ["secret"]}},
        ),
        Policy(
            key="approve-export",
            name="Export needs a named approver",
            effect="require_approval",
            priority=600,
            match={"action": "export"},
        ),
        # Matches the same requests and loses to the parking rule. Its
        # obligation must survive redemption.
        Policy(
            key="allow-analyst-with-redaction",
            name="Analysts read with SSNs masked",
            effect="allow",
            priority=200,
            match={"principal.type": "user"},
            obligations=[{"type": "redact", "labels": ["pii.ssn"], "strategy": "mask"}],
        ),
    ]:
        await store.create(policy, actor="seed")
    await session.flush()


@pytest.fixture
async def pdp(session):
    await seed(session)
    return PolicyDecisionPoint(session)


def export_request(**overrides) -> DecideRequest:
    body = {
        "principal": {"id": "user:analyst", "type": "user"},
        "action": "export",
        "resource": {"urn": "pg://public.customers"},
        "context": {"destination": "internal"},
    }
    body.update(overrides)
    return DecideRequest.model_validate(body)


async def grant(session, approval_id, *, by: str = "user:manager") -> ApprovalRequest:
    """Approve, the way the console does."""
    approval = (
        await session.execute(select(ApprovalRequest).where(ApprovalRequest.id == approval_id))
    ).scalar_one()
    approval.status = "granted"
    approval.decided_by = by
    approval.decision_note = "ticket DATA-1183"
    approval.resolved_at = datetime.now(UTC)
    await session.flush()
    return approval


class TestTheHappyPath:
    async def test_park_grant_redeem(self, pdp, session) -> None:
        parked = await pdp.decide(export_request())
        assert parked.effect == "require_approval"
        assert parked.approval is not None
        assert parked.approval.status == "pending"

        await grant(session, parked.approval.id)

        redeemed = await pdp.decide(export_request(approval_id=str(parked.approval.id)))
        assert redeemed.effect == "allow"
        assert redeemed.approval_redeemed is True
        assert redeemed.approval_error is None
        assert "redeemed approval" in redeemed.reason
        assert "user:manager" in redeemed.reason

    async def test_redemption_carries_the_allow_policy_obligations(self, pdp, session) -> None:
        """Redeeming must not be a way to shed redaction a policy required."""
        parked = await pdp.decide(
            export_request(payload="contact jane.doe@acme.com, SSN 536-90-4432")
        )
        await grant(session, parked.approval.id)

        redeemed = await pdp.decide(
            export_request(
                payload="contact jane.doe@acme.com, SSN 536-90-4432",
                approval_id=str(parked.approval.id),
            )
        )
        assert redeemed.effect == "allow"
        assert "536-90-4432" not in redeemed.payload
        assert {r.label for r in redeemed.redactions} == {"pii.ssn"}

    async def test_the_approval_reports_who_granted_it(self, pdp, session) -> None:
        parked = await pdp.decide(export_request())
        await grant(session, parked.approval.id, by="user:ciso")
        redeemed = await pdp.decide(export_request(approval_id=str(parked.approval.id)))
        assert redeemed.approval.decided_by == "user:ciso"
        assert redeemed.approval.redeemed_at is not None


class TestBinding:
    """An approval authorises one request, not a class of them."""

    @pytest.fixture
    async def granted(self, pdp, session):
        parked = await pdp.decide(export_request())
        await grant(session, parked.approval.id)
        return str(parked.approval.id)

    async def test_a_different_resource_is_refused(self, pdp, granted) -> None:
        response = await pdp.decide(
            export_request(resource={"urn": "pg://public.payments"}, approval_id=granted)
        )
        assert response.effect == "require_approval"
        assert "granted for a different request" in response.approval_error

    async def test_a_different_action_is_refused(self, pdp, granted, session) -> None:
        await PolicyStore(session).create(
            Policy(
                key="approve-dump",
                name="Dump needs approval",
                effect="require_approval",
                priority=600,
                match={"action": "dump"},
            ),
            actor="test",
        )
        response = await pdp.decide(export_request(action="dump", approval_id=granted))
        assert response.effect == "require_approval"
        assert "granted for a different request" in response.approval_error

    async def test_a_different_principal_is_refused(self, pdp, granted) -> None:
        response = await pdp.decide(
            export_request(
                principal={"id": "user:someone_else", "type": "user"}, approval_id=granted
            )
        )
        assert response.effect == "require_approval"
        assert "granted for a different request" in response.approval_error

    async def test_a_changed_destination_is_refused(self, pdp, granted) -> None:
        """Approved for an internal export; not therefore approved to send it out."""
        response = await pdp.decide(
            export_request(context={"destination": "external"}, approval_id=granted)
        )
        assert response.effect == "require_approval"
        assert "granted for a different request" in response.approval_error

    async def test_a_different_payload_is_refused(self, pdp, session) -> None:
        parked = await pdp.decide(export_request(payload="the rows we agreed on"))
        await grant(session, parked.approval.id)
        response = await pdp.decide(
            export_request(payload="quite different rows", approval_id=str(parked.approval.id))
        )
        assert response.effect == "require_approval"
        assert "granted for a different request" in response.approval_error

    async def test_the_identical_request_is_accepted(self, pdp, granted) -> None:
        assert (await pdp.decide(export_request(approval_id=granted))).effect == "allow"


class TestApprovalCannotOverrideDeny:
    """The invariant that matters most.

    Policy can tighten between the grant and the redemption, and when it does
    the approval must lose. These tests hold the request *identical* across
    park and redeem, so the fingerprint still matches and the only thing that
    can refuse the redemption is the deny itself -- otherwise they would pass
    for the wrong reason.
    """

    async def test_a_deny_added_after_the_grant_still_denies(self, pdp, session) -> None:
        parked = await pdp.decide(export_request())
        await grant(session, parked.approval.id)

        await PolicyStore(session).create(
            Policy(
                key="deny-all-exports",
                name="Exports suspended",
                effect="deny",
                priority=1000,
                match={"action": "export"},
            ),
            actor="incident-response",
        )

        response = await pdp.decide(export_request(approval_id=str(parked.approval.id)))
        assert response.effect == "deny"
        assert response.determining_policy == "deny-all-exports"
        assert response.payload is None
        assert response.approval_redeemed is False

    async def test_a_deny_does_not_consume_the_approval(self, pdp, session) -> None:
        """The grant survives the suspension, so it still works once lifted."""
        parked = await pdp.decide(export_request())
        approval_id = parked.approval.id
        await grant(session, approval_id)

        await PolicyStore(session).create(
            Policy(
                key="deny-all-exports",
                name="Exports suspended",
                effect="deny",
                priority=1000,
                match={"action": "export"},
            ),
            actor="incident-response",
        )
        await pdp.decide(export_request(approval_id=str(approval_id)))

        approval = (
            await session.execute(select(ApprovalRequest).where(ApprovalRequest.id == approval_id))
        ).scalar_one()
        assert approval.redeemed_at is None

        await PolicyStore(session).set_enabled("deny-all-exports", False, actor="test")
        assert (await pdp.decide(export_request(approval_id=str(approval_id)))).effect == "allow"

    async def test_content_that_denies_is_refused_despite_an_approval(self, pdp, session) -> None:
        """A human approving an export has not approved transmitting a credential."""
        payload = "the rows, plus AKIAIOSFODNN7EXAMPLE"
        parked = await pdp.decide(export_request(payload=payload))
        # Parking happens because deny-credentials does not match the empty
        # payload at grant time; here it does, so the request denies outright.
        assert parked.effect == "deny"
        assert parked.approval is None

    async def test_an_approval_is_not_needed_once_policy_allows(self, pdp, session) -> None:
        """If the parking rule is withdrawn, the request simply proceeds."""
        parked = await pdp.decide(export_request())
        await grant(session, parked.approval.id)
        await PolicyStore(session).set_enabled("approve-export", False, actor="test")

        response = await pdp.decide(export_request(approval_id=str(parked.approval.id)))
        assert response.effect == "allow"
        assert response.approval_redeemed is False


class TestSingleUse:
    async def test_a_second_redemption_is_refused(self, pdp, session) -> None:
        parked = await pdp.decide(export_request())
        await grant(session, parked.approval.id)

        first = await pdp.decide(export_request(approval_id=str(parked.approval.id)))
        assert first.effect == "allow"

        second = await pdp.decide(export_request(approval_id=str(parked.approval.id)))
        assert second.effect == "require_approval"
        assert "already redeemed" in second.approval_error

    async def test_redemption_records_what_it_was_spent_on(self, pdp, session) -> None:
        parked = await pdp.decide(export_request())
        await grant(session, parked.approval.id)
        redeemed = await pdp.decide(export_request(approval_id=str(parked.approval.id)))

        approval = (
            await session.execute(
                select(ApprovalRequest).where(ApprovalRequest.id == parked.approval.id)
            )
        ).scalar_one()
        assert approval.redeemed_decision_id == redeemed.decision_id
        assert approval.redeemed_at is not None

    async def test_a_simulation_does_not_spend_it(self, pdp, session) -> None:
        """Exploring what an approval would do must not consume it."""
        parked = await pdp.decide(export_request())
        await grant(session, parked.approval.id)

        simulated = await pdp.decide(
            export_request(
                approval_id=str(parked.approval.id),
                options=DecideOptions(persist=False).model_dump(),
            )
        )
        assert simulated.effect == "allow"

        approval = (
            await session.execute(
                select(ApprovalRequest).where(ApprovalRequest.id == parked.approval.id)
            )
        ).scalar_one()
        assert approval.redeemed_at is None


class TestLifecycleRefusals:
    async def test_a_pending_approval_cannot_be_redeemed(self, pdp) -> None:
        parked = await pdp.decide(export_request())
        response = await pdp.decide(export_request(approval_id=str(parked.approval.id)))
        assert response.effect == "require_approval"
        assert "awaiting a decision" in response.approval_error

    async def test_a_denied_approval_cannot_be_redeemed(self, pdp, session) -> None:
        parked = await pdp.decide(export_request())
        approval = (
            await session.execute(
                select(ApprovalRequest).where(ApprovalRequest.id == parked.approval.id)
            )
        ).scalar_one()
        approval.status = "denied"
        await session.flush()

        response = await pdp.decide(export_request(approval_id=str(parked.approval.id)))
        assert "was denied" in response.approval_error

    async def test_an_expired_approval_cannot_be_redeemed(self, pdp, session) -> None:
        parked = await pdp.decide(export_request())
        approval = await grant(session, parked.approval.id)
        approval.expires_at = datetime.now(UTC) - timedelta(minutes=1)
        await session.flush()

        response = await pdp.decide(export_request(approval_id=str(parked.approval.id)))
        assert "expired at" in response.approval_error

    async def test_an_unknown_approval_id_is_reported(self, pdp) -> None:
        import uuid

        response = await pdp.decide(export_request(approval_id=str(uuid.uuid4())))
        assert "no approval request" in response.approval_error

    async def test_an_unbound_approval_cannot_be_redeemed(self, pdp, session) -> None:
        """Rows granted before fingerprinting existed have no scope to check."""
        parked = await pdp.decide(export_request())
        approval = await grant(session, parked.approval.id)
        approval.request_fingerprint = ""
        await session.flush()

        response = await pdp.decide(export_request(approval_id=str(parked.approval.id)))
        assert "no request binding" in response.approval_error


class TestQueueHygiene:
    async def test_re_sending_a_parked_request_reuses_its_ticket(self, pdp, session) -> None:
        """A retrying caller must not flood the reviewer's queue."""
        first = await pdp.decide(export_request())
        second = await pdp.decide(export_request())
        third = await pdp.decide(export_request())

        assert first.approval.id == second.approval.id == third.approval.id
        parked = (await session.execute(select(ApprovalRequest))).scalars().all()
        assert len(parked) == 1

    async def test_a_genuinely_different_request_gets_its_own_ticket(self, pdp, session) -> None:
        await pdp.decide(export_request())
        await pdp.decide(export_request(resource={"urn": "pg://public.payments"}))
        parked = (await session.execute(select(ApprovalRequest))).scalars().all()
        assert len(parked) == 2

    async def test_each_attempt_is_still_its_own_decision_record(self, pdp, session) -> None:
        """Reusing the ticket must not lose the record of who asked, and when."""
        await pdp.decide(export_request())
        await pdp.decide(export_request())
        decisions = (await session.execute(select(DecisionRecord))).scalars().all()
        assert len(decisions) == 2


class TestAuditTrail:
    async def test_the_whole_loop_is_sealed(self, pdp, session, audit_key) -> None:
        parked = await pdp.decide(export_request())
        await grant(session, parked.approval.id)
        await pdp.decide(export_request(approval_id=str(parked.approval.id)))

        audit = AuditService(session, key=audit_key)
        events = [row.event for row in await audit.list_records(limit=50)]
        assert "approval.requested" in events
        assert "approval.redeemed" in events
        assert (await audit.verify()).valid is True

    async def test_the_redemption_record_names_the_approver(self, pdp, session, audit_key) -> None:
        parked = await pdp.decide(export_request())
        await grant(session, parked.approval.id, by="user:ciso")
        await pdp.decide(export_request(approval_id=str(parked.approval.id)))

        audit = AuditService(session, key=audit_key)
        redemption = next(
            row for row in await audit.list_records(limit=50) if row.event == "approval.redeemed"
        )
        assert redemption.payload["granted_by"] == "user:ciso"
        assert redemption.payload["approval_id"] == str(parked.approval.id)
