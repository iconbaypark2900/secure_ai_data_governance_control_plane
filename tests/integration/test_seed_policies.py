"""The shipped policy set must actually behave as its descriptions claim.

A reference policy set that reads well and denies the wrong things is worse than
none, because people copy it. These tests are the check on that.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest
import yaml

from control_plane.catalog.service import CatalogService
from control_plane.pdp import PolicyDecisionPoint
from control_plane.policy.model import (
    CONTROL_PLANE_OBLIGATIONS,
    KNOWN_OBLIGATIONS,
    PolicySet,
)
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

    async def test_every_shipped_obligation_is_one_something_carries_out(self) -> None:
        """The reference set is the thing people copy, so it must not overclaim.

        Free, and it would have caught this: the shipped set attached `log` to
        three grants and `annotate` to a fourth, and nothing anywhere executed
        either. Cheaper than the schema check alone, because a type can be
        removed from OBLIGATION_SPECS while the YAML that used it stays behind
        and is only noticed when someone runs the seed.
        """
        import sys

        sys.path.insert(0, str(ROOT))
        from pep.reverse_proxy.obligations import SATISFIABLE

        policy_set = PolicySet.model_validate(yaml.safe_load(POLICIES.read_text()))
        attached = {o.type for policy in policy_set.policies for o in policy.obligations}
        assert attached <= KNOWN_OBLIGATIONS
        # Someone has to carry each one: this plane, or the reference proxy.
        # Anything else is a shipped policy that denies its own traffic.
        assert attached <= CONTROL_PLANE_OBLIGATIONS | SATISFIABLE

    async def test_every_shipped_policy_is_reachable(self, reference, session) -> None:
        """A policy nothing can ever match is dead weight and misleading."""
        store = PolicyStore(session)
        stored = {record.key for record in await store.list_records(limit=100)}
        catalog_keys = {p["key"] for p in yaml.safe_load(POLICIES.read_text())["policies"]}
        assert stored == catalog_keys


#: Every shipped policy whose description makes a claim about identifiers, with
#: the request that exercises the claim and the strings that must not survive it.
#:
#: This is the table the file's own opening sentence promised and did not have.
#: The 23 tests above it assert set membership over obligation *types* -- that a
#: `redact` is attached, that no unimplemented type is -- and `grep -n
#: description` over them returns one hit, the module docstring. A type being
#: attached says nothing about what it reaches: the external-inference grant
#: carried `redact` over `[pii, pci]` while its description asserted that what
#: leaves the boundary is de-identified, and an MRN, an NPI and an ICD-10 code
#: went to the third-party model in the clear. Every one of those 23 passed.
#:
#: A row is added here whenever a description says an identifier class does not
#: leave. If the sentence is not worth checking, it is not worth writing: the
#: alternative -- and the mistake ADR 0017's fix made -- is to delete an inert
#: obligation and assert its content as prose, which moves the claim from a
#: place something can check to a place nothing can.
DE_IDENTIFICATION_CLAIMS: list[dict[str, Any]] = [
    {
        "policy": "allow-agents-external-inference-scrubbed",
        "claim": "every value labelled pii.*, pci.* or phi.* is hashed before it leaves",
        "request": {
            "principal": "agent:support_bot",
            "action": "infer",
            "context": {"destination": "external"},
        },
        "payload": (
            "Patient chart: MRN 4827193, provider NPI 1245319599, diagnosis E11.9, "
            "contact jane.doe@acme.com on 415-555-0142, SSN 536-90-4432."
        ),
        "must_not_survive": [
            "4827193",
            "1245319599",
            "E11.9",
            "jane.doe@acme.com",
            "415-555-0142",
            "536-90-4432",
        ],
    },
    {
        "policy": "allow-agents-external-inference-scrubbed",
        "claim": "the same, on the return leg -- a model's answer crosses the same boundary",
        "request": {
            "principal": "agent:support_bot",
            "action": "return",
            "context": {"destination": "external"},
        },
        "payload": ("Their MRN is 4827193, diagnosis E11.9; reach them at jane.doe@acme.com."),
        "must_not_survive": ["4827193", "E11.9", "jane.doe@acme.com"],
    },
    {
        "policy": "allow-agents-read-redacted",
        "claim": (
            "social security, passport, driving licence and national ID numbers are "
            "masked; email addresses and phone numbers are hashed"
        ),
        "request": {
            "principal": "agent:support_bot",
            "action": "read",
            "resource": "qdrant://kb_docs",
        },
        "payload": (
            "Customer jane.doe@acme.com, phone 415-555-0142, SSN 536-90-4432, passport 990000000."
        ),
        "must_not_survive": ["jane.doe@acme.com", "415-555-0142", "536-90-4432"],
    },
]


class TestTheDescriptionsAreChecked:
    """The guard whose absence let a false claim ship.

    Descriptions are not documentation here; they are the reason people copy
    this set, and a sentence in one is what a reader will believe over the
    obligation three lines below it. So each row of the table above drives the
    real policy set with a payload carrying the identifier class its
    description names, and looks at what came back.

    Where the two disagree, the rule is: widen the obligation where data crosses
    the trust boundary, correct the description where it does not. Never widen a
    deny -- that is the move that breaks live callers, and it is what redirected
    the previous attempt.
    """

    @pytest.mark.parametrize(
        "case", DE_IDENTIFICATION_CLAIMS, ids=lambda c: f"{c['policy']}:{c['request']['action']}"
    )
    async def test_the_identifiers_a_description_names_do_not_come_back(
        self, reference, case
    ) -> None:
        response = await ask(reference, payload=case["payload"], **case["request"])
        assert response.effect == "allow", case["claim"]
        assert case["policy"] in response.matched_policies, (
            f"{case['policy']} did not even apply to the request written to "
            f"exercise it, so this row is checking nothing. Matched: "
            f"{response.matched_policies}"
        )
        returned = str(response.payload)
        survived = [value for value in case["must_not_survive"] if value in returned]
        assert not survived, (
            f"{case['policy']} says: {case['claim']}. It returned {survived} "
            f"verbatim. Either the obligation has to reach them or the sentence "
            f"has to stop saying it does."
        )

    async def test_what_the_obligations_missed_is_reported_rather_than_argued(
        self, reference
    ) -> None:
        """The general half, which no wording can settle.

        A description can only be true about the labels the scanner has a
        detector for. What it cannot promise is that nothing else got through --
        so the response says, per decision, which findings the redaction rules
        did not cover. That number is what makes the next version of this
        argument a measurement instead of a reading.
        """
        covered = await ask(
            reference,
            principal="agent:support_bot",
            action="infer",
            context={"destination": "external"},
            payload="MRN 4827193 and jane.doe@acme.com",
        )
        assert covered.residual_labels == []

        # The everyday internal grant redacts contact and strong-ID labels only,
        # exactly as its description now says -- so an MRN in the payload is
        # left in place, and reported.
        uncovered = await ask(
            reference,
            principal="agent:support_bot",
            action="read",
            resource="qdrant://kb_docs",
            payload="MRN 4827193 and jane.doe@acme.com",
        )
        assert uncovered.effect == "allow"
        assert "phi.mrn" in uncovered.residual_labels
        assert "pii.email" not in uncovered.residual_labels

    async def test_the_claim_is_bounded_by_what_the_scanner_can_find(self, reference) -> None:
        """Why the description says "every value the scanner labels" and not "every value".

        Found by writing the row above. `phi.icd10` only fires near a context
        word -- "diagnosis", "dx", "coded as" -- so a bare E11.9 in a model's
        answer is never detected, and a redaction obligation cannot hash what
        was never found. No wording of the policy fixes that and no obligation
        reaches it; it is a detector limit, and the sentence is written to be
        true in its presence rather than to paper over it.

        Pinned so that the day the detector improves, this test fails and the
        description can be widened on evidence.
        """
        bare = await ask(
            reference,
            principal="agent:support_bot",
            action="return",
            context={"destination": "external"},
            payload="Their code is E11.9.",
        )
        assert bare.effect == "allow"
        assert "E11.9" in str(bare.payload)
        assert bare.residual_labels == []

    async def test_a_pipeline_failure_is_recorded_like_the_description_says(
        self, reference, session, monkeypatch, audit_key
    ) -> None:
        """`allow-analysts-read-unredacted` claims a record and an audit event
        on every decision unless persist is false. It was untrue in one place:
        the fail-closed path returned before the persist block, so a decision
        the pipeline could not complete wrote neither half. Made true rather
        than made weaker -- that decision is the one most worth a row.
        """
        from sqlalchemy import select

        from control_plane.audit.service import AuditService
        from control_plane.models.decision import DecisionRecord

        def explode(*args, **kwargs):
            raise RuntimeError("catalog unavailable")

        monkeypatch.setattr(CatalogService, "resolve", explode)
        response = await ask(
            reference,
            principal="user:analyst",
            type="user",
            action="read",
            resource="pg://public.customers",
        )
        assert response.effect == "deny"
        assert response.decision_id is not None

        record = (
            await session.execute(
                select(DecisionRecord).where(DecisionRecord.id == response.decision_id)
            )
        ).scalar_one()
        assert record.effect == "deny"
        assert (await AuditService(session, key=audit_key).verify()).valid is True
