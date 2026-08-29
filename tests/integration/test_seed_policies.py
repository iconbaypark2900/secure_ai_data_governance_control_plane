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
            entry["urn"],
            name=entry.get("name"),
            kind=entry.get("kind"),
            attributes=entry.get("attributes"),
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
        "resource": {
            "urn": kwargs.pop("resource", None),
            "kind": kwargs.pop("resource_kind", None),
        },
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


class TestResidencyRouting:
    """The redirect, not the refusal.

    The shipped set could previously only say no to regulated data meeting the
    wrong model. It now says where to send it instead.
    """

    async def test_regulated_data_is_routed_to_an_eu_model(self, reference) -> None:
        response = await ask(
            reference,
            principal="agent:analytics_copilot",
            action="infer",
            resource="pg://public.payments",
            context={"destination": "external"},
        )
        assert response.effect == "allow"
        assert response.route is not None
        assert response.route["target"] == "model://internal/llama-3-70b"

    async def test_an_ordinary_read_of_the_same_data_is_not_routed(self, reference) -> None:
        """Routing a database read to a model is meaningless.

        A routing rule that forgets to scope itself quietly intercepts every
        ordinary read of the data it names -- which is exactly what the first
        draft of this policy did.
        """
        response = await ask(
            reference,
            principal="user:analyst",
            type="user",
            action="read",
            resource="pg://public.customers",
            payload="jane.doe@acme.com",
        )
        assert response.route is None
        assert response.payload == "jane.doe@acme.com"

    async def test_the_models_are_registered_as_catalog_assets(self, reference, session) -> None:
        from control_plane.catalog.service import CatalogService

        candidates = await CatalogService(session).model_candidates()
        assert {c.urn for c in candidates} == {
            "model://internal/llama-3-70b",
            "model://azure/gpt-4o-eu",
            "model://openai/gpt-4o",
        }

    async def test_losing_every_eu_model_denies_rather_than_falling_back(
        self, reference, session
    ) -> None:
        """The property that makes constraint-based routing safe."""
        from control_plane.catalog.service import CatalogService

        catalog = CatalogService(session)
        for urn in ("model://internal/llama-3-70b", "model://azure/gpt-4o-eu"):
            await catalog.delete_asset(urn)

        response = await ask(
            reference,
            principal="agent:analytics_copilot",
            action="infer",
            resource="pg://public.payments",
            context={"destination": "external"},
        )
        assert response.effect == "deny"
        assert "no registered model satisfies" in response.reason


class TestTheReturnLeg:
    """Both directions have to work, or the proxy in front of them does not.

    Found by putting the reference proxy in front of a local ollama and sending
    it a real prompt. The prompt was permitted and the answer was denied.
    """

    async def test_a_model_answer_reaches_an_agent_on_an_internal_model(self, reference) -> None:
        """The gap: the only allow for a model 'return' required destination=external.

        A model running on your own hardware is the ordinary self-hosted case,
        and there every answer came back "no policy matched; applied the default
        effect 'deny'". The reference proxy defaults PEP_DESTINATION to
        external, which is what kept it hidden.
        """
        response = await ask(
            reference,
            principal="agent:support_bot",
            action="return",
            resource="model://internal/llama-3-70b",
            resource_kind="model",
            payload="Sure -- their address is 44 Rue de Rivoli.",
            context={"destination": "internal"},
        )
        assert response.effect == "allow"

    async def test_identifiers_in_the_answer_are_still_redacted(self, reference) -> None:
        """A model given clean input can still emit something that was not."""
        response = await ask(
            reference,
            principal="agent:support_bot",
            action="return",
            resource="model://internal/llama-3-70b",
            resource_kind="model",
            payload="Contact them on jane.doe@acme.com or 415-555-0142.",
            context={"destination": "internal"},
        )
        assert response.effect == "allow"
        assert "jane.doe@acme.com" not in str(response.payload)
        assert "415-555-0142" not in str(response.payload)

    async def test_a_credential_in_the_answer_is_still_refused(self, reference) -> None:
        """Deny overrides. Permitting the return leg must not weaken that."""
        response = await ask(
            reference,
            principal="agent:support_bot",
            action="return",
            resource="model://internal/llama-3-70b",
            resource_kind="model",
            payload="the key is sk-ant-api03-AbCdEfGhIjKlMnOpQrStUvWxYz0123456789",
            context={"destination": "internal"},
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
