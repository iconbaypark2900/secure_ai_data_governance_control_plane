"""Routing through the decision pipeline.

The gap this closes: the engine could decide "this must not go to a US model"
and had nowhere to put "send it to the EU model instead".
"""

from __future__ import annotations

from sqlalchemy import select

from control_plane.catalog.service import CatalogService
from control_plane.models.decision import DecisionRecord
from control_plane.pdp import PolicyDecisionPoint
from control_plane.policy.model import Policy
from control_plane.policy.store import PolicyStore
from control_plane.schemas.decision import DecideRequest

MODELS = [
    ("model://openai/gpt-4o", {"region": "us", "hosting": "saas", "routing_priority": 5}),
    (
        "model://internal/llama-3-70b",
        {
            "region": "eu",
            "hosting": "on_prem",
            "aliases": ["eu-only-llm"],
            "routing_priority": 10,
        },
    ),
]


async def seed(session, *, models=MODELS, policies=()) -> None:
    catalog = CatalogService(session)
    for urn, attributes in models:
        await catalog.upsert_asset(urn, kind="model", attributes=attributes)

    clinical, _ = await catalog.upsert_asset("pg://clinical.notes")
    await catalog.set_classification(clinical, "phi.mrn", source="manual")

    store = PolicyStore(session)
    for policy in policies:
        await store.create(policy, actor="seed")
    await session.flush()


ROUTE_EU = Policy(
    key="phi-stays-in-the-eu",
    name="PHI is inferred on EU-resident models",
    effect="allow",
    priority=300,
    match={"resource.classifications": {"any_of": ["phi"]}},
    obligations=[{"type": "route", "require": {"region": "eu"}}],
)


def request_for(**overrides) -> DecideRequest:
    body = {
        "principal": {"id": "agent:copilot", "type": "agent"},
        "action": "infer",
        "resource": {"urn": "pg://clinical.notes", "kind": "table"},
        "context": {"destination": "external"},
    }
    body.update(overrides)
    return DecideRequest.model_validate(body)


class TestRedirect:
    async def test_a_policy_redirects_rather_than_refusing(self, session) -> None:
        await seed(session, policies=[ROUTE_EU])
        response = await PolicyDecisionPoint(session).decide(request_for())

        assert response.effect == "allow"
        assert response.route is not None
        assert response.route["target"] == "model://internal/llama-3-70b"
        assert response.route["redirected"] is True

    async def test_the_resolved_target_reaches_the_obligation(self, session) -> None:
        """The enforcement point should not have to re-derive the answer."""
        await seed(session, policies=[ROUTE_EU])
        response = await PolicyDecisionPoint(session).decide(request_for())
        route = next(o for o in response.obligations if o["type"] == "route")
        assert route["resolved"] == "model://internal/llama-3-70b"

    async def test_no_route_obligation_means_no_routing(self, session) -> None:
        await seed(
            session,
            policies=[
                Policy(
                    key="plain-allow",
                    name="Plain",
                    effect="allow",
                    priority=300,
                    match={"action": "infer"},
                )
            ],
        )
        assert (await PolicyDecisionPoint(session).decide(request_for())).route is None


class TestUnsatisfiable:
    async def test_it_denies_rather_than_falling_back(self, session) -> None:
        """Sending it to the requested model would invert the policy exactly."""
        await seed(
            session,
            models=[("model://openai/gpt-4o", {"region": "us", "hosting": "saas"})],
            policies=[ROUTE_EU],
        )
        response = await PolicyDecisionPoint(session).decide(request_for())

        assert response.effect == "deny"
        assert "no registered model satisfies" in response.reason
        assert response.route["target"] is None
        assert response.route["rejected"]["model://openai/gpt-4o"].startswith("region is")

    async def test_an_empty_model_registry_denies(self, session) -> None:
        await seed(session, models=[], policies=[ROUTE_EU])
        response = await PolicyDecisionPoint(session).decide(request_for())
        assert response.effect == "deny"

    async def test_a_denied_decision_carries_no_payload(self, session) -> None:
        await seed(
            session,
            models=[("model://openai/gpt-4o", {"region": "us"})],
            policies=[ROUTE_EU],
        )
        response = await PolicyDecisionPoint(session).decide(request_for(payload="patient notes"))
        assert response.effect == "deny"
        assert response.payload is None


class TestForensics:
    async def test_the_chosen_model_is_recorded(self, session) -> None:
        """'Which model saw this data' is the first question after an incident."""
        await seed(session, policies=[ROUTE_EU])
        await PolicyDecisionPoint(session).decide(request_for())

        record = (await session.execute(select(DecisionRecord))).scalars().one()
        route = next(o for o in record.obligations if o["type"] == "route")
        assert route["resolved"] == "model://internal/llama-3-70b"

    async def test_the_audit_record_names_the_target(self, session, audit_key) -> None:
        from control_plane.audit.service import AuditService

        await seed(session, policies=[ROUTE_EU])
        await PolicyDecisionPoint(session).decide(request_for())

        audit = AuditService(session, key=audit_key)
        decision = next(r for r in await audit.list_records(limit=20) if r.event == "decision")
        assert decision.payload["route_target"] == "model://internal/llama-3-70b"
        assert (await audit.verify()).valid is True

    async def test_it_explains_which_candidates_lost_and_why(self, session) -> None:
        await seed(session, policies=[ROUTE_EU])
        response = await PolicyDecisionPoint(session).decide(request_for())
        assert "region is 'us'" in response.route["rejected"]["model://openai/gpt-4o"]


class TestModelsAreOrdinaryAssets:
    async def test_a_model_is_registered_like_any_other_asset(self, session) -> None:
        await seed(session, policies=[ROUTE_EU])
        candidates = await CatalogService(session).model_candidates()
        assert {c.urn for c in candidates} == {u for u, _ in MODELS}

    async def test_non_model_assets_are_not_routing_candidates(self, session) -> None:
        await seed(session, policies=[ROUTE_EU])
        candidates = await CatalogService(session).model_candidates()
        assert "pg://clinical.notes" not in {c.urn for c in candidates}
