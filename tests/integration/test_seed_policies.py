"""The shipped policy set must actually behave as its descriptions claim.

A reference policy set that reads well and denies the wrong things is worse than
none, because people copy it. These tests are the check on that.
"""

from __future__ import annotations

from pathlib import Path

import pytest
import yaml

from control_plane.catalog.service import CatalogService
from control_plane.pdp import PolicyDecisionPoint
from control_plane.policy.model import PolicySet
from control_plane.policy.store import PolicyStore
from control_plane.schemas.decision import DecideRequest

ROOT = Path(__file__).resolve().parents[2]
POLICIES = ROOT / "seed" / "policies.yaml"
CATALOG = ROOT / "seed" / "catalog.yaml"


@pytest.fixture
async def reference(session):
    """The shipped policy set and catalog, loaded exactly as `cpctl seed` does."""
    policy_set = PolicySet.model_validate(yaml.safe_load(POLICIES.read_text()))
    await PolicyStore(session).sync(policy_set.policies, actor="test")

    catalog = yaml.safe_load(CATALOG.read_text())
    service = CatalogService(session)
    for entry in catalog["assets"]:
        asset, _ = await service.upsert_asset(
            entry["urn"], name=entry.get("name"), kind=entry.get("kind")
        )
        for label in entry.get("classifications", []):
            await service.set_classification(
                asset,
                label["label"],
                source=label.get("source", "manual"),
                confidence=float(label.get("confidence", 1.0)),
            )
    for entry in catalog["principals"]:
        await service.upsert_principal(
            entry["external_id"], type_=entry["type"], attributes=entry.get("attributes")
        )
    await session.flush()
    return PolicyDecisionPoint(session)


async def ask(pdp, **kwargs):
    body = {
        "principal": {"id": kwargs.pop("principal"), "type": kwargs.pop("type", "agent")},
        "action": kwargs.pop("action"),
        "resource": {"urn": kwargs.pop("resource", None)},
        "context": kwargs.pop("context", {}),
        "payload": kwargs.pop("payload", None),
    }
    return await pdp.decide(DecideRequest.model_validate(body))


class TestProhibitions:
    async def test_credentials_are_refused_from_any_principal(self, reference) -> None:
        for principal, kind in (
            ("user:analyst", "user"),
            ("agent:support_bot", "agent"),
            ("service:llm_gateway", "service"),
        ):
            response = await ask(
                reference,
                principal=principal,
                type=kind,
                action="read",
                resource="qdrant://kb_docs",
                payload="export AWS_KEY=AKIAIOSFODNN7EXAMPLE",
            )
            assert response.effect == "deny", principal
            assert response.determining_policy == "deny-credentials-anywhere"

    async def test_phi_is_refused_to_external_models(self, reference) -> None:
        response = await ask(
            reference,
            principal="agent:analytics_copilot",
            action="infer",
            resource="pg://clinical.encounters",
            context={"destination": "external"},
        )
        assert response.effect == "deny"
        assert response.determining_policy == "deny-phi-to-external-models"

    async def test_an_unregistered_clinical_table_is_still_phi(self, reference) -> None:
        """The pattern registration is what makes forgetting to register safe."""
        response = await ask(
            reference,
            principal="agent:analytics_copilot",
            action="infer",
            resource="pg://clinical.a_table_nobody_registered",
            context={"destination": "external"},
        )
        assert response.effect == "deny"
        assert "phi.mrn" in response.classifications

    async def test_card_numbers_never_reach_a_model(self, reference) -> None:
        response = await ask(
            reference,
            principal="user:analyst",
            type="user",
            action="infer",
            resource="qdrant://kb_docs",
            payload="charge 4111 1111 1111 1111 please",
        )
        assert response.effect == "deny"
        assert response.determining_policy == "deny-card-numbers-to-models"

    async def test_unreviewed_agents_cannot_reach_sensitive_stores(self, reference) -> None:
        response = await ask(
            reference,
            principal="agent:unreviewed_scraper",
            action="read",
            resource="pg://public.customers",
        )
        assert response.effect == "deny"
        assert response.determining_policy == "deny-unreviewed-agents-on-sensitive-stores"


class TestOrdinaryWork:
    async def test_a_reviewed_agent_still_gets_its_everyday_grant(self, reference) -> None:
        """The prohibition on unreviewed agents must not swallow the normal path."""
        response = await ask(
            reference,
            principal="agent:support_bot",
            action="read",
            resource="qdrant://kb_docs",
            payload="Customer jane.doe@acme.com, SSN 536-90-4432, asks about refunds.",
        )
        assert response.effect == "allow"
        assert response.determining_policy == "allow-agents-read-redacted"
        assert "536-90-4432" not in response.payload
        assert "jane.doe@acme.com" not in response.payload

    async def test_contact_details_are_pseudonymised_not_destroyed(self, reference) -> None:
        """Hashing keeps one customer distinguishable from another across a thread."""
        first = await ask(
            reference,
            principal="agent:support_bot",
            action="read",
            resource="qdrant://kb_docs",
            payload="from jane.doe@acme.com",
        )
        second = await ask(
            reference,
            principal="agent:support_bot",
            action="read",
            resource="qdrant://kb_docs",
            payload="from jane.doe@acme.com again",
        )
        third = await ask(
            reference,
            principal="agent:support_bot",
            action="read",
            resource="qdrant://kb_docs",
            payload="from other.person@acme.com",
        )
        token = first.payload.split()[-1]
        assert token in second.payload
        assert token not in third.payload

    async def test_a_cleared_analyst_reads_through(self, reference) -> None:
        response = await ask(
            reference,
            principal="user:analyst",
            type="user",
            action="read",
            resource="pg://public.customers",
            payload="jane.doe@acme.com",
        )
        assert response.effect == "allow"
        assert response.payload == "jane.doe@acme.com"

    async def test_public_data_is_ungoverned(self, reference) -> None:
        response = await ask(
            reference,
            principal="service:llm_gateway",
            type="service",
            action="read",
            resource="s3://public-datasets/census",
        )
        assert response.effect == "allow"
        assert response.determining_policy == "allow-public-data-freely"

    async def test_public_classification_does_not_excuse_sensitive_content(self, reference) -> None:
        """A store labelled public that turns out to contain a key is not public."""
        response = await ask(
            reference,
            principal="service:llm_gateway",
            type="service",
            action="read",
            resource="s3://public-datasets/census",
            payload="oops ghp_" + "a" * 36,
        )
        assert response.effect == "deny"


class TestHumanInTheLoop:
    async def test_bulk_export_is_parked(self, reference) -> None:
        response = await ask(
            reference,
            principal="user:analyst",
            type="user",
            action="export",
            resource="pg://public.customers",
        )
        assert response.effect == "require_approval"
        assert response.approval is not None

    async def test_training_on_personal_data_is_parked(self, reference) -> None:
        response = await ask(
            reference,
            principal="agent:analytics_copilot",
            action="read",
            resource="pg://public.customers",
            context={"purpose": "fine_tuning"},
        )
        assert response.effect == "require_approval"
        assert response.determining_policy == "approve-training-on-personal-data"


class TestPostureAsAWhole:
    async def test_an_unrecognised_request_is_denied(self, reference) -> None:
        response = await ask(
            reference, principal="agent:nobody", action="drop_table", resource="pg://anything"
        )
        assert response.effect == "deny"
        assert "no policy matched" in response.reason

    async def test_every_shipped_policy_parses(self) -> None:
        policy_set = PolicySet.model_validate(yaml.safe_load(POLICIES.read_text()))
        assert len(policy_set.policies) >= 10

    async def test_every_shipped_policy_is_reachable(self, reference, session) -> None:
        """A policy nothing can ever match is dead weight and misleading."""
        store = PolicyStore(session)
        stored = {record.key for record in await store.list_records(limit=100)}
        catalog_keys = {p["key"] for p in yaml.safe_load(POLICIES.read_text())["policies"]}
        assert stored == catalog_keys
