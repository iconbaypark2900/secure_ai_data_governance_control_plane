"""What the enforcement point actually did.

Every other record in this system says what was *decided*. These cover the other
half: an enforcement point that could not discharge an obligation left a row
reading "allow" behind an action that never took place, and reconciling the two
is the reason for keeping the log at all.
"""

from __future__ import annotations

import pytest

ALLOW = {
    "policy": {
        "key": "allow-with-a-duty",
        "name": "Allowed, subject to a watermark",
        "effect": "allow",
        "priority": 100,
        "match": {"action": "read"},
        "obligations": [{"type": "watermark", "text": "internal use only"}],
    }
}


def decide_body(**overrides) -> dict:
    body = {
        "principal": {"id": "agent:bot", "type": "agent"},
        "action": "read",
        "resource": {"urn": "qdrant://kb"},
    }
    body.update(overrides)
    return body


@pytest.fixture
async def decided(client):
    await client.post("/v1/policies", json=ALLOW)
    response = await client.post("/v1/decide", json=decide_body())
    return client, response.json()["decision_id"]


class TestReporting:
    async def test_an_enforcement_point_can_say_it_enforced(self, decided) -> None:
        client, decision_id = decided
        response = await client.post(
            f"/v1/decisions/{decision_id}/outcome",
            json={"outcome": "enforced", "discharged": ["watermark"]},
        )
        assert response.status_code == 200
        assert response.json()["outcome"] == "enforced"

    async def test_a_refusal_must_explain_itself(self, decided) -> None:
        """An unexplained refusal is a gap in the record, not an entry in it."""
        client, decision_id = decided
        response = await client.post(
            f"/v1/decisions/{decision_id}/outcome", json={"outcome": "refused"}
        )
        assert response.status_code == 422

    async def test_a_refusal_with_a_reason_is_accepted(self, decided) -> None:
        client, decision_id = decided
        response = await client.post(
            f"/v1/decisions/{decision_id}/outcome",
            json={
                "outcome": "refused",
                "reason": "no watermark renderer configured",
                "undischarged": ["watermark"],
            },
        )
        assert response.json()["undischarged"] == ["watermark"]

    async def test_partial_must_name_what_it_skipped(self, decided) -> None:
        """Otherwise it says nothing a refusal would not."""
        client, decision_id = decided
        response = await client.post(
            f"/v1/decisions/{decision_id}/outcome",
            json={"outcome": "partial", "reason": "renderer down"},
        )
        assert response.status_code == 422

    async def test_an_unknown_decision_is_a_404(self, client) -> None:
        import uuid

        response = await client.post(
            f"/v1/decisions/{uuid.uuid4()}/outcome", json={"outcome": "enforced"}
        )
        assert response.status_code == 404


class TestWriteOnce:
    async def test_the_same_report_twice_is_idempotent(self, decided) -> None:
        """A retrying caller should not be punished for retrying."""
        client, decision_id = decided
        body = {"outcome": "enforced", "discharged": ["watermark"]}
        first = await client.post(f"/v1/decisions/{decision_id}/outcome", json=body)
        second = await client.post(f"/v1/decisions/{decision_id}/outcome", json=body)
        assert first.status_code == second.status_code == 200

    async def test_a_conflicting_report_is_refused(self, decided) -> None:
        client, decision_id = decided
        await client.post(f"/v1/decisions/{decision_id}/outcome", json={"outcome": "enforced"})
        response = await client.post(
            f"/v1/decisions/{decision_id}/outcome",
            json={"outcome": "refused", "reason": "actually it did not happen"},
        )
        assert response.status_code == 409
        assert "already reported" in response.json()["detail"]

    async def test_the_attempt_to_restate_it_is_sealed(self, decided) -> None:
        """Trying to change what already happened is exactly what the log is for."""
        client, decision_id = decided
        await client.post(f"/v1/decisions/{decision_id}/outcome", json={"outcome": "enforced"})
        await client.post(
            f"/v1/decisions/{decision_id}/outcome",
            json={"outcome": "refused", "reason": "second thoughts"},
        )
        events = (await client.get("/v1/audit")).json()
        conflict = next(i for i in events["items"] if i["event"] == "decision.outcome_conflict")
        assert conflict["payload"]["recorded"] == "enforced"
        assert conflict["payload"]["submitted"] == "refused"


class TestReconciliation:
    async def test_permitted_but_not_enforced_is_a_query(self, decided) -> None:
        """The thing that was not answerable before."""
        client, decision_id = decided
        await client.post(
            f"/v1/decisions/{decision_id}/outcome",
            json={
                "outcome": "refused",
                "reason": "no renderer",
                "undischarged": ["watermark"],
            },
        )
        stats = (await client.get("/v1/decisions/stats")).json()
        assert stats["by_effect"]["allow"] == 1
        assert stats["by_outcome"]["refused"] == 1
        assert stats["permitted_but_not_enforced"] == 1

    async def test_unreported_decisions_can_be_listed(self, decided) -> None:
        """A point that quietly stops reporting is one that stopped being observed."""
        client, _ = decided
        await client.post("/v1/decide", json=decide_body())

        unreported = (await client.get("/v1/decisions?outcome=unreported")).json()
        assert unreported["total"] == 2
        assert all(item["outcome"] is None for item in unreported["items"])

    async def test_filtering_by_a_reported_outcome(self, decided) -> None:
        client, decision_id = decided
        await client.post(f"/v1/decisions/{decision_id}/outcome", json={"outcome": "enforced"})
        listing = (await client.get("/v1/decisions?outcome=enforced")).json()
        assert listing["total"] == 1
        assert (await client.get("/v1/decisions?outcome=unreported")).json()["total"] == 0

    async def test_silence_is_not_read_as_success(self, decided) -> None:
        client, decision_id = decided
        detail = (await client.get(f"/v1/decisions/{decision_id}")).json()
        assert detail["outcome"] is None
        stats = (await client.get("/v1/decisions/stats")).json()
        assert stats["by_outcome"]["unreported"] == 1


class TestAuditTrail:
    async def test_the_outcome_is_sealed(self, decided) -> None:
        client, decision_id = decided
        await client.post(
            f"/v1/decisions/{decision_id}/outcome",
            json={
                "outcome": "partial",
                "reason": "renderer unavailable",
                "discharged": ["redact"],
                "undischarged": ["watermark"],
            },
        )
        events = (await client.get("/v1/audit")).json()
        outcome = next(i for i in events["items"] if i["event"] == "decision.outcome")
        assert outcome["payload"]["outcome"] == "partial"
        assert outcome["payload"]["permitted"] is True
        assert outcome["payload"]["undischarged"] == ["watermark"]
        assert (await client.get("/v1/audit/verify")).json()["valid"] is True

    async def test_both_halves_are_in_one_record(self, decided) -> None:
        """So noticing a contradiction does not require joining two tables."""
        client, decision_id = decided
        await client.post(
            f"/v1/decisions/{decision_id}/outcome",
            json={"outcome": "refused", "reason": "no renderer"},
        )
        events = (await client.get("/v1/audit")).json()
        outcome = next(i for i in events["items"] if i["event"] == "decision.outcome")
        assert outcome["payload"]["permitted"] is True
        assert outcome["payload"]["outcome"] == "refused"


class TestTheIdentifierIsUsableImmediately:
    """A decision id handed to a caller has to refer to something that exists.

    The session dependency commits in its teardown, which can run *after* the
    response has gone out -- so an enforcement point that decided and then
    immediately reported hit a 404 about one attempt in eight. The decide
    endpoint now commits before answering.

    The in-process harness commits inside the request, so it cannot reproduce
    the timing; what these hold is the contract that was violated.
    """

    async def test_a_decision_can_be_reported_the_instant_it_is_made(self, client) -> None:
        await client.post("/v1/policies", json=ALLOW)
        decided = await client.post("/v1/decide", json=decide_body())
        decision_id = decided.json()["decision_id"]

        reported = await client.post(
            f"/v1/decisions/{decision_id}/outcome",
            json={"outcome": "enforced", "discharged": ["watermark"]},
        )
        assert reported.status_code == 200

    async def test_and_fetched(self, client) -> None:
        await client.post("/v1/policies", json=ALLOW)
        decided = await client.post("/v1/decide", json=decide_body())
        fetched = await client.get(f"/v1/decisions/{decided.json()['decision_id']}")
        assert fetched.status_code == 200

    async def test_a_parked_approval_can_be_resolved_at_once(self, client) -> None:
        """Same contract, the other identifier the decide response hands back."""
        await client.post(
            "/v1/policies",
            json={
                "policy": {
                    "key": "approve-exports",
                    "name": "Exports need a human",
                    "effect": "require_approval",
                    "priority": 500,
                    "match": {"action": "export"},
                }
            },
        )
        decided = await client.post("/v1/decide", json=decide_body(action="export"))
        approval_id = decided.json()["approval"]["id"]
        resolved = await client.post(
            f"/v1/approvals/{approval_id}/decide?grant=true", json={"note": "ok"}
        )
        assert resolved.status_code == 200
