"""The decision pipeline end to end, against a real database."""

from __future__ import annotations

from typing import Any

import pytest
from pydantic import ValidationError
from sqlalchemy import select

from control_plane.audit.service import AuditService
from control_plane.catalog.service import CatalogService
from control_plane.classification.scanner import scan_text
from control_plane.models.decision import ApprovalRequest, DecisionRecord
from control_plane.pdp import PolicyDecisionPoint
from control_plane.policy.model import CONTROL_PLANE_OBLIGATIONS, Policy
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

    async def test_a_fail_closed_deny_is_recorded_like_any_other(
        self, pdp, session, monkeypatch, audit_key
    ) -> None:
        """The `except` path returned before the persist block, writing neither half.

        ``test_every_decision_seals_an_audit_record`` makes the claim in its
        name and never exercised this branch; the shipped policy set makes it in
        prose -- "every decision unless the caller sets options.persist false".
        A decision the pipeline could not complete is the one most worth having
        a row for: it is a deny nobody asked for, and without this it is
        invisible to every query an operator runs afterwards.
        """

        def explode(*args, **kwargs):
            raise RuntimeError("catalog unavailable")

        monkeypatch.setattr(CatalogService, "resolve", explode)
        response = await pdp.decide(request_for(payload="jane.doe@acme.com"))
        assert response.effect == "deny"
        assert response.decision_id is not None

        record = (
            await session.execute(
                select(DecisionRecord).where(DecisionRecord.id == response.decision_id)
            )
        ).scalar_one()
        assert record.effect == "deny"
        assert record.determining_policy is None
        assert "catalog unavailable" in record.reason
        # ADR 0006: the digest is computed inside the failed try, so there is
        # none to store. A row saying nothing about the payload beats no row.
        assert record.payload_digest is None

        audit = AuditService(session, key=audit_key)
        assert await audit.count() >= 1
        assert (await audit.verify()).valid is True

    async def test_a_fail_closed_deny_at_persist_false_still_writes_nothing(
        self, pdp, session, monkeypatch
    ) -> None:
        def explode(*args, **kwargs):
            raise RuntimeError("catalog unavailable")

        monkeypatch.setattr(CatalogService, "resolve", explode)
        response = await pdp.decide(request_for(options=DecideOptions(persist=False).model_dump()))
        assert response.effect == "deny"
        assert response.decision_id is None
        assert (await session.execute(select(DecisionRecord))).scalars().all() == []

    async def test_a_failure_to_record_a_failure_is_still_a_deny(
        self, pdp, session, monkeypatch
    ) -> None:
        """Persistence must never be able to convert the deny into a raise.

        The whole value of failing closed is that the caller gets an answer it
        can act on. A second exception on the way to writing the row about the
        first one would take that away.
        """

        def explode(*args, **kwargs):
            raise RuntimeError("catalog unavailable")

        async def also_explode(*args, **kwargs):
            raise RuntimeError("the database is gone too")

        monkeypatch.setattr(CatalogService, "resolve", explode)
        monkeypatch.setattr(PolicyDecisionPoint, "_persist_failure", also_explode)
        response = await pdp.decide(request_for())
        assert response.effect == "deny"
        assert response.decision_id is None

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


#: One well-formed obligation of each type the control plane claims to execute,
#: paired with a payload that gives it something to do. A type may not be added
#: to CONTROL_PLANE_OBLIGATIONS without an entry here, and an entry cannot be
#: written until an executor exists for the test below to observe. That is the
#: friction this table is for.
CONTROL_PLANE_FIXTURES: dict[str, tuple[dict[str, Any], Any]] = {
    "redact": (
        {"type": "redact", "labels": ["pii.email"], "strategy": "mask"},
        "reach jane.doe@acme.com about the refund",
    ),
}


class TestTheControlPlaneExecutesWhatItClaims:
    """The twin of the enforcement-point check in tests/unit/test_obligations.py.

    That one holds the ENFORCEMENT_POINT half of ADR 0010's rule against the
    reference proxy's SATISFIABLE, and has held since 0010 was written. The
    CONTROL_PLANE half was left to prose, and drifted: `annotate`, `log` and
    `ttl` sat in the published set for three releases with nothing anywhere
    executing them. Nobody noticed, because a control-plane obligation is
    excluded from `unsupported_obligations` and so arrives at an enforcement
    point already reported as discharged -- the one class of unkept duty that
    makes no noise at all. See ADR 0017.

    Behavioural on purpose. Reading pdp.py for a dispatch table would pass the
    first time the dispatch is refactored into something else, and would have
    passed happily throughout the period this exists to have caught. The only
    evidence that counts is a response that came back different.
    """

    @staticmethod
    def _observable(response: Any) -> tuple[Any, tuple[str, ...]]:
        """All an enforcement point can see of what the control plane did."""
        return response.payload, tuple(sorted(r.label for r in response.redactions))

    def test_every_claimed_type_has_something_to_exercise_it(self) -> None:
        unexercised = CONTROL_PLANE_OBLIGATIONS - set(CONTROL_PLANE_FIXTURES)
        assert not unexercised, (
            f"{sorted(unexercised)} is declared CONTROL_PLANE with no fixture "
            "showing the plane doing anything. Write one, or the type belongs "
            "with the enforcement point -- or nowhere."
        )

    async def test_every_control_plane_obligation_visibly_executes(self, session) -> None:
        await seed(session)
        store = PolicyStore(session)
        base = {
            "principal": {"id": "user:analyst", "type": "user"},
            "action": "read",
            "resource": {"urn": "pg://public.customers"},
        }

        for name in sorted(CONTROL_PLANE_OBLIGATIONS):
            assert name in CONTROL_PLANE_FIXTURES, name
            document, payload = CONTROL_PLANE_FIXTURES[name]
            request = DecideRequest.model_validate({**base, "payload": payload})

            # The same request under an allow that carries no duties at all.
            untouched = await PolicyDecisionPoint(session).decide(request)
            assert untouched.effect == "allow", name
            assert not untouched.obligations, name

            key = f"carry-{name}"
            await store.create(
                Policy(
                    key=key,
                    name=f"An allow carrying a {name} obligation",
                    effect="allow",
                    priority=300,
                    match={"all": [{"principal.type": "user"}, {"action": "read"}]},
                    obligations=[document],
                ),
                actor="test",
            )
            carried = await PolicyDecisionPoint(session).decide(request)
            await store.delete(key)

            assert carried.effect == "allow", name
            assert name in {o["type"] for o in carried.obligations}, name
            # The claim being tested: nobody downstream is told to do this.
            assert name not in carried.unsupported_obligations, name
            assert self._observable(carried) != self._observable(untouched), (
                f"a {name!r} obligation reached an allow and the response came "
                f"back identical to one carrying no obligation at all. The "
                f"control plane says it discharges {name!r}; no enforcement "
                f"point will be told to, so if nothing here does it, nothing does."
            )


class TestTheResponseSaysWhatThisDecisionDid:
    """The request-shape axis, which ADR 0017's fix left uncovered.

    ``TestTheControlPlaneExecutesWhatItClaims`` above holds the *type* axis: a
    type may not claim CONTROL_PLANE status without a fixture showing the plane
    doing something. It exercises exactly one request shape -- payload present,
    scanning on, obligations applied -- and every type passes there.

    A control-plane obligation is discharged per *decision*, not per type. The
    plane's redaction pass runs only on the conjunction below; outside it the
    duty is real, undischarged, and the enforcement point is the only party
    left who can carry it out. Before this class, four ordinary request shapes
    came back ``obligations=[redact], unsupported_obligations=[]`` with nothing
    redacted -- and ``grep -rn apply_obligations tests/`` returned one line,
    asserting a default. The false branch had never been executed by a test.
    See ADR 0018.
    """

    @staticmethod
    async def _carrying(session, name: str) -> Any:
        """A PDP whose policy set carries one obligation of ``name``."""
        document, _ = CONTROL_PLANE_FIXTURES[name]
        await PolicyStore(session).create(
            Policy(
                key=f"carry-{name}",
                name=f"An allow carrying a {name} obligation",
                effect="allow",
                priority=300,
                match={"all": [{"principal.type": "agent"}, {"action": "read"}]},
                obligations=[document],
            ),
            actor="test",
        )
        return PolicyDecisionPoint(session)

    @pytest.mark.parametrize("name", sorted(CONTROL_PLANE_OBLIGATIONS))
    async def test_a_shape_the_plane_cannot_execute_in_reports_the_duty(
        self, session, name
    ) -> None:
        """No payload and apply_obligations=False both leave the duty undone."""
        await seed(session)
        pdp = await self._carrying(session, name)
        _, payload = CONTROL_PLANE_FIXTURES[name]

        no_payload = await pdp.decide(request_for())
        assert no_payload.effect == "allow", name
        assert name in {o["type"] for o in no_payload.obligations}, name
        assert name in no_payload.unsupported_obligations, (
            f"{name!r} was reported discharged on a request carrying no payload. "
            f"The plane's pass had nothing to run on, so nobody did it."
        )

        withheld = await pdp.decide(
            request_for(
                payload=payload,
                options=DecideOptions(apply_obligations=False).model_dump(),
            )
        )
        assert withheld.effect == "allow", name
        assert name in withheld.unsupported_obligations, (
            f"{name!r} was reported discharged on a request that explicitly "
            f"asked the plane not to execute obligations."
        )

    @pytest.mark.parametrize("name", sorted(CONTROL_PLANE_OBLIGATIONS))
    def test_a_shape_that_suppresses_the_evidence_is_refused(self, name) -> None:
        """The other two shapes never reach a decision at all.

        ``scan_payload=False`` and a raised ``min_confidence`` do not merely
        stop the obligation running; they stop the *scan*, so a deny that keys
        on findings never fires either. There is no obligation to report and no
        response to correct -- the only place to catch it is the boundary.
        """
        _, payload = CONTROL_PLANE_FIXTURES[name]
        with pytest.raises(ValidationError):
            request_for(payload=payload, options=DecideOptions(scan_payload=False).model_dump())
        with pytest.raises(ValidationError):
            request_for(payload=payload, options=DecideOptions(min_confidence=0.95).model_dump())

    async def test_a_clean_payload_still_counts_as_executed(self, session) -> None:
        """The predicate is 'the pass ran', never 'something was redacted'.

        This is the outage guard, and it is the F-01 trap in new clothing. Every
        clean prompt through the reverse proxy and every clean MCP tool call
        arrives here: payload present, nothing sensitive in it, zero redactions.
        Keying on ``redactions`` being non-empty would report ``redact``
        outstanding on all of them, and both SDKs would refuse the call.
        """
        await seed(session)
        pdp = await self._carrying(session, "redact")
        response = await pdp.decide(request_for(payload="the refund was processed on Tuesday"))
        assert response.effect == "allow"
        assert "redact" in {o["type"] for o in response.obligations}
        assert response.redactions == []
        assert response.unsupported_obligations == []

    @pytest.mark.parametrize("name", sorted(CONTROL_PLANE_OBLIGATIONS))
    async def test_a_pass_over_only_a_prefix_is_not_a_discharge(
        self, session, name, monkeypatch
    ) -> None:
        """Truncation: the pass ran, and it did not cover the payload.

        The three conjuncts guarding the discharge are all facts about what the
        caller *asked for* -- obligations applied, scanning on, effect allow --
        and none is a fact about what the scanner reached. Past
        ``CP_MAX_SCAN_CHARS`` only the head is classified, so only the head is
        rewritten and the tail is returned verbatim, while every conjunct still
        holds. Reporting the duty discharged there is the same sentence as F-01,
        one axis over.

        ``payload_truncated`` carries the fact and is not enough on its own:
        nothing outside ``ui/`` reads it, and ``residual_labels`` is derived
        from findings the tail never produced, so it comes back empty.
        """
        await seed(session)
        pdp = await self._carrying(session, name)
        _, payload = CONTROL_PLANE_FIXTURES[name]
        monkeypatch.setattr(pdp._scanner, "max_chars", 8)

        response = await pdp.decide(request_for(payload="x" * 64 + " " + payload))

        assert response.effect == "allow", name
        assert response.payload_truncated is True, name
        assert name in {o["type"] for o in response.obligations}, name
        assert name in response.unsupported_obligations, (
            f"{name!r} was reported discharged on a payload the scanner only "
            f"read the head of. The tail was never classified, so nothing in it "
            f"was rewritten, and it was returned verbatim."
        )

    async def test_a_subtree_too_deep_to_scan_is_not_a_discharge(
        self, session, monkeypatch
    ) -> None:
        """The depth axis, and the reason this class needed a structured payload.

        ``CONTROL_PLANE_FIXTURES`` carries one fixture and it is a *string*, so
        every guard above -- the execution check, the whole request-shape matrix,
        the prefix test -- reaches ``scan_text`` and none of them reaches
        ``scan_structured``. The depth ceiling had therefore never been executed
        by a discharge test.

        It abandoned a subtree past ``max_depth`` and recorded nothing, so a
        nested payload came back with no findings, ``payload_truncated`` false,
        ``residual_labels`` empty -- it derives from findings the subtree never
        produced -- and ``redact`` reported discharged, with the identifiers
        returned verbatim and the audit entry sealing the claim.
        """
        await seed(session)
        pdp = await self._carrying(session, "redact")
        ceiling = 3
        monkeypatch.setattr(pdp._scanner, "max_depth", ceiling)

        leaf = {"ssn": "536-90-4432"}
        buried: Any = leaf
        for _ in range(ceiling + 4):
            buried = {"wrapper": buried}

        response = await pdp.decide(request_for(payload=buried))

        assert response.effect == "allow"
        assert response.payload_truncated is True
        assert "redact" in {o["type"] for o in response.obligations}
        assert "redact" in response.unsupported_obligations, (
            "redact was reported discharged over a payload whose subtree the "
            "scanner abandoned. Nothing in it was read, so nothing in it was "
            "rewritten, and it was returned verbatim."
        )

        shallow = await pdp.decide(request_for(payload=leaf))
        assert shallow.payload_truncated is False
        assert shallow.unsupported_obligations == []
        assert {r.label for r in shallow.redactions} == {"pii.ssn"}

    async def test_a_finding_no_rule_covers_is_named_rather_than_hidden(self, session) -> None:
        """Residual coverage is a number on the response, not an argument in prose.

        The pass ran, so ``redact`` is discharged and the enforcement point is
        told nothing -- correctly: no policy assigned it a duty here, and
        handing it one would refuse every ordinary call. What it is owed is the
        fact that the obligation's labels did not reach everything the scanner
        found.
        """
        await seed(session)
        await PolicyStore(session).create(
            Policy(
                key="redact-email-only",
                name="Redact contact details and nothing else",
                effect="allow",
                priority=300,
                match={"all": [{"principal.type": "agent"}, {"action": "read"}]},
                obligations=[{"type": "redact", "labels": ["pii.email"], "strategy": "mask"}],
            ),
            actor="test",
        )
        response = await PolicyDecisionPoint(session).decide(
            request_for(payload="patient MRN 4827193, contact jane.doe@acme.com")
        )
        assert response.effect == "allow"
        assert response.unsupported_obligations == []
        assert "phi.mrn" in response.residual_labels
        assert "pii.email" not in response.residual_labels

    async def test_an_enforcement_point_duty_survives_apply_obligations_false(
        self, session
    ) -> None:
        """S1: the correction channel is not a function of who applies redaction.

        ``apply_obligations`` says whether the *plane* executes its own
        obligations. Blanking the whole list on the strength of it told a
        non-SDK enforcement point that its watermark duty was clear. Both
        shipped SDKs are insulated only because they ignore the field, which is
        why nothing in the suite could notice.
        """
        await seed(session)
        await PolicyStore(session).create(
            Policy(
                key="watermark-and-purpose",
                name="Duties only the enforcement point can carry out",
                effect="allow",
                priority=300,
                match={"all": [{"principal.type": "agent"}, {"action": "read"}]},
                obligations=[
                    {"type": "watermark", "text": "internal only"},
                    {"type": "require_purpose", "purposes": ["support"]},
                ],
            ),
            actor="test",
        )
        pdp = PolicyDecisionPoint(session)
        payload = "reach jane.doe@acme.com about the refund"
        applied = await pdp.decide(request_for(payload=payload))
        withheld = await pdp.decide(
            request_for(
                payload=payload,
                options=DecideOptions(apply_obligations=False).model_dump(),
            )
        )
        # The seed set's redact obligation applies to both requests. The plane
        # executed it on the first and not on the second, and only the second
        # difference is legitimate: the two enforcement-point duties are
        # identical in both, because who applies redaction has no bearing on
        # them.
        assert applied.unsupported_obligations == ["require_purpose", "watermark"]
        assert withheld.unsupported_obligations == ["redact", "require_purpose", "watermark"]


class TestTheShapesTheEnforcementPointsActuallySend:
    """Every in-repo call site, replicated, asserting it still works.

    F-01's first attempt was redirected by a measurement of exactly this kind:
    reclassifying `log` would have denied every governed tool call, because
    ``pep/mcp_proxy`` calls ``enforcing()`` with no ``can_satisfy``. These are
    the shapes that measurement was made of. They are here so the next change
    to the predicate is made against them rather than around them.
    """

    async def test_the_mcp_listing_shape_still_allows(self, session) -> None:
        """``_governed_listing``: apply_obligations=False, no payload, persist=False.

        It reads ``decision.allowed`` and nothing else, so reporting ``redact``
        unsupported here is truthful and inert. One line from breaking, though:
        if it ever calls ``enforcing()``, every tool disappears from every
        agent's list. This test is what that change has to walk past.
        """
        await seed(session)
        response = await PolicyDecisionPoint(session).decide(
            request_for(
                resource={"urn": "mcp://files/read_file", "kind": "tool"},
                options=DecideOptions(apply_obligations=False, persist=False).model_dump(),
            )
        )
        assert response.effect == "allow"

    async def test_the_mcp_invocation_shape_reports_nothing_outstanding(self, session) -> None:
        """``_governed_call`` inbound: structured payload, defaults, no can_satisfy.

        ``{}`` is not ``None``, so an argument-free tool call is scanned like
        any other and the pass runs. This is the site the predicate is shaped
        around.
        """
        await seed(session)
        pdp = PolicyDecisionPoint(session)
        for arguments in ({}, {"path": "/etc/hosts", "note": "reach jane.doe@acme.com"}):
            response = await pdp.decide(
                request_for(
                    resource={"urn": "mcp://files/read_file", "kind": "tool"},
                    payload=arguments,
                )
            )
            assert response.effect == "allow", arguments
            assert response.unsupported_obligations == [], arguments

    async def test_the_reverse_proxy_shape_reports_nothing_outstanding(self, session) -> None:
        """A prompt through ``pep/reverse_proxy``: text payload, defaults.

        It calls ``enforce(can_satisfy=SATISFIABLE)``, and SATISFIABLE does not
        contain ``redact`` -- correctly, the proxy has no redactor. So anything
        that puts ``redact`` outstanding here refuses every governed prompt.
        """
        await seed(session)
        await PolicyStore(session).create(
            Policy(
                key="allow-inference-redacted",
                name="Agents infer with identifiers masked",
                effect="allow",
                priority=100,
                match={"all": [{"principal.type": "agent"}, {"action": "infer"}]},
                obligations=[{"type": "redact", "labels": ["pii"], "strategy": "mask"}],
            ),
            actor="test",
        )
        response = await PolicyDecisionPoint(session).decide(
            request_for(
                action="infer",
                resource={"urn": "model://gpt-4o", "kind": "model"},
                payload="summarise the ticket for jane.doe@acme.com",
            )
        )
        assert response.effect == "allow"
        assert response.unsupported_obligations == []


class TestScannerIntegration:
    """What a caller may and may not do to the evidence its own request is judged on.

    Both tests here used to specify the defect. ``test_scanning_can_be_disabled``
    sent a live GitHub token with ``scan_payload=False`` against a set containing
    ``deny-secrets-everywhere`` at priority 950 and asserted ``allow`` -- a
    written specification of the credential bypass, passing for as long as it
    existed. ``test_min_confidence_is_honoured`` did the same in the softer
    direction. See ADR 0018.
    """

    async def test_min_confidence_may_be_lowered_but_not_raised(self, pdp) -> None:
        """A caller may make the plane more sensitive, never less.

        The ceiling is the schema default, so no request that worked before this
        change stops working: it forbids only the half of the range that weakens
        the scan the decision is made from.
        """
        text = "server at 203.0.113.9"
        assert "pii.ip_address" in scan_text(text).labels

        sensitive = await pdp.decide(
            request_for(payload=text, options=DecideOptions(min_confidence=0.1).model_dump())
        )
        assert "pii.ip_address" in sensitive.classifications

        at_the_ceiling = await pdp.decide(
            request_for(payload=text, options=DecideOptions(min_confidence=0.5).model_dump())
        )
        assert "pii.ip_address" not in at_the_ceiling.classifications

        with pytest.raises(ValidationError, match="min_confidence"):
            request_for(payload=text, options=DecideOptions(min_confidence=0.9).model_dump())

    async def test_scanning_cannot_be_disabled_on_a_request_carrying_a_payload(self, pdp) -> None:
        """ "Here is the data, do not look at it, tell me whether it is safe."

        A contradiction that needs no knowledge of the policy set to refuse.
        Before it was refused, it was the exception path to the one rule whose
        own description says it has none: the same token below is denied at
        defaults by ``deny-secrets-everywhere`` and allowed with this flag set.
        """
        token = "token ghp_" + "a" * 36
        with pytest.raises(ValidationError, match="scan_payload"):
            request_for(payload=token, options=DecideOptions(scan_payload=False).model_dump())

        denied = await pdp.decide(request_for(payload=token))
        assert denied.effect == "deny"
        assert denied.determining_policy == "deny-secrets-everywhere"

    async def test_scanning_may_still_be_disabled_when_there_is_no_payload(self, pdp) -> None:
        """The flag is not banned, only the contradiction is.

        A caller that classified elsewhere declares ``resource.classifications``
        and sends no payload. Nothing is being suppressed, so nothing is refused.
        """
        response = await pdp.decide(
            request_for(options=DecideOptions(scan_payload=False).model_dump())
        )
        assert response.effect == "allow"
