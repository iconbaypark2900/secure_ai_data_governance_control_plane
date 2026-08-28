"""Tokenisation end to end: policy, decision, and reversal.

The gap this closes: a policy could ask for the `tokenize` strategy and silently
receive an irreversible hash. Nobody found out until somebody needed to reverse
one, which is the worst possible moment.
"""

from __future__ import annotations

import pytest

from control_plane.audit.service import AuditService
from control_plane.config import Settings
from control_plane.pdp import PolicyDecisionPoint
from control_plane.policy.model import Policy
from control_plane.policy.store import PolicyStore
from control_plane.redaction.tokenization import DeterministicTokenizer
from control_plane.schemas.decision import DecideRequest

TOKENIZE_POLICY = Policy(
    key="allow-support-tokenised",
    name="Support reads with contact details tokenised",
    effect="allow",
    priority=200,
    match={"principal.type": "agent"},
    obligations=[{"type": "redact", "labels": ["pii.email", "pii.phone"], "strategy": "tokenize"}],
)


def settings_with(**overrides) -> Settings:
    base = {
        "environment": "test",
        "audit_hmac_key": "test-audit-key",
        "redaction_hmac_key": "test-redaction-key",
        "database_url": "sqlite+aiosqlite:///:memory:",
    }
    base.update(overrides)
    return Settings(**base)


def request_for(payload: str) -> DecideRequest:
    return DecideRequest.model_validate(
        {
            "principal": {"id": "agent:support_bot", "type": "agent"},
            "action": "read",
            "resource": {"urn": "qdrant://kb"},
            "payload": payload,
        }
    )


@pytest.fixture
async def store(session):
    await PolicyStore(session).create(TOKENIZE_POLICY, actor="seed")
    await session.flush()
    return session


class TestWithoutAKey:
    async def test_the_decision_is_denied_rather_than_downgraded(self, store) -> None:
        """The whole point. A hash would satisfy the shape and not the meaning."""
        pdp = PolicyDecisionPoint(store, settings=settings_with())
        response = await pdp.decide(request_for("mail jane.doe@acme.com"))

        assert response.effect == "deny"
        assert "tokenize" in response.reason
        assert "CP_TOKENIZATION_KEY" in str(response.policy_errors)

    async def test_no_payload_comes_back(self, store) -> None:
        pdp = PolicyDecisionPoint(store, settings=settings_with())
        response = await pdp.decide(request_for("mail jane.doe@acme.com"))
        assert response.payload is None

    async def test_other_strategies_are_unaffected(self, session) -> None:
        """Only tokenisation is blocked; masking still works without a key."""
        await PolicyStore(session).create(
            Policy(
                key="allow-masked",
                name="Masked",
                effect="allow",
                priority=300,
                match={"principal.type": "agent"},
                obligations=[{"type": "redact", "labels": ["pii"], "strategy": "mask"}],
            ),
            actor="seed",
        )
        pdp = PolicyDecisionPoint(session, settings=settings_with())
        response = await pdp.decide(request_for("mail jane.doe@acme.com"))
        assert response.effect == "allow"
        assert "[REDACTED:pii.email]" in response.payload


class TestWithAKey:
    @pytest.fixture
    def pdp(self, store):
        return PolicyDecisionPoint(store, settings=settings_with(tokenization_key="k" * 32))

    async def test_the_payload_carries_a_reversible_token(self, pdp) -> None:
        response = await pdp.decide(request_for("mail jane.doe@acme.com"))

        assert response.effect == "allow"
        assert "jane.doe@acme.com" not in response.payload
        token = response.redactions[0].replacement
        assert token.startswith("tok_")

        tokenizer = DeterministicTokenizer(key=b"k" * 32)
        assert tokenizer.detokenize(token) == "jane.doe@acme.com"

    async def test_the_same_customer_gets_the_same_token(self, pdp) -> None:
        """Joinability is the reason to tokenise rather than mask."""
        first = await pdp.decide(request_for("from jane.doe@acme.com"))
        second = await pdp.decide(request_for("also from jane.doe@acme.com, urgent"))
        third = await pdp.decide(request_for("from someone.else@acme.com"))

        token_of = lambda r: r.redactions[0].replacement  # noqa: E731
        assert token_of(first) == token_of(second)
        assert token_of(first) != token_of(third)

    async def test_the_decision_record_holds_no_value(self, pdp, session) -> None:
        from sqlalchemy import select

        from control_plane.models.decision import DecisionRecord

        await pdp.decide(request_for("mail jane.doe@acme.com"))
        record = (await session.execute(select(DecisionRecord))).scalars().first()
        assert "jane.doe@acme.com" not in str(record.as_dict())


class TestReversalOverHttp:
    @pytest.fixture
    async def wired(self, authed_client, monkeypatch):
        from control_plane.config import reset_settings_cache

        client, admin, issue = authed_client
        monkeypatch.setenv("CP_TOKENIZATION_KEY", "k" * 32)
        reset_settings_cache()
        tokenizer = DeterministicTokenizer(key=("k" * 32).encode())
        return client, admin, issue, tokenizer

    async def test_a_token_reverses(self, wired) -> None:
        client, admin, _, tokenizer = wired
        token = tokenizer.tokenize("pii.email", "jane.doe@acme.com")

        response = await client.post(
            "/v1/detokenize",
            headers={"X-API-Key": admin},
            json={"tokens": [token], "justification": "incident INC-4821"},
        )
        body = response.json()
        assert body["recovered"] == 1
        assert body["results"][0]["value"] == "jane.doe@acme.com"

    async def test_an_unreadable_token_says_nothing_about_why(self, wired) -> None:
        client, admin, _, _ = wired
        response = await client.post(
            "/v1/detokenize",
            headers={"X-API-Key": admin},
            json={"tokens": ["tok_notarealtoken", "garbage"], "justification": "checking"},
        )
        body = response.json()
        assert body["recovered"] == 0
        assert all(r["value"] is None for r in body["results"])

    async def test_it_needs_its_own_scope(self, wired) -> None:
        """An audit reader should not be able to re-identify."""
        client, _, issue, tokenizer = wired
        reader = await issue(["audit:read", "catalog:read"])
        response = await client.post(
            "/v1/detokenize",
            headers={"X-API-Key": reader},
            json={"tokens": [tokenizer.tokenize("pii.email", "a@b.com")], "justification": "x"},
        )
        assert response.status_code == 403
        assert "detokenize" in response.json()["detail"]

    async def test_a_scoped_key_works(self, wired) -> None:
        client, _, issue, tokenizer = wired
        investigator = await issue(["detokenize"])
        response = await client.post(
            "/v1/detokenize",
            headers={"X-API-Key": investigator},
            json={
                "tokens": [tokenizer.tokenize("pii.email", "a@b.com")],
                "justification": "INC-1",
            },
        )
        assert response.json()["results"][0]["value"] == "a@b.com"

    async def test_a_justification_is_required(self, wired) -> None:
        client, admin, _, tokenizer = wired
        response = await client.post(
            "/v1/detokenize",
            headers={"X-API-Key": admin},
            json={"tokens": [tokenizer.tokenize("pii.email", "a@b.com")]},
        )
        assert response.status_code == 422

    async def test_bulk_reversal_is_capped(self, wired) -> None:
        """A row of tokens is an investigation; a table of them is something else."""
        client, admin, _, tokenizer = wired
        response = await client.post(
            "/v1/detokenize",
            headers={"X-API-Key": admin},
            json={
                "tokens": [tokenizer.tokenize("pii.email", f"a{i}@b.com") for i in range(60)],
                "justification": "bulk",
            },
        )
        assert response.status_code == 422

    async def test_every_reversal_is_audited_without_the_value(self, wired) -> None:
        client, admin, _, tokenizer = wired
        await client.post(
            "/v1/detokenize",
            headers={"X-API-Key": admin},
            json={
                "tokens": [tokenizer.tokenize("pii.email", "jane.doe@acme.com")],
                "justification": "incident INC-4821",
            },
        )
        events = (await client.get("/v1/audit", headers={"X-API-Key": admin})).json()
        reversal = next(i for i in events["items"] if i["event"] == "tokens.reversed")
        assert reversal["payload"]["justification"] == "incident INC-4821"
        assert reversal["payload"]["recovered"] == 1
        assert "jane.doe@acme.com" not in str(reversal)
        assert "tok_" not in str(reversal["payload"]["token_digests"])

    async def test_a_failed_reversal_is_audited_too(self, wired) -> None:
        """An attempt that recovers nothing is still an attempt worth seeing."""
        client, admin, _, _ = wired
        await client.post(
            "/v1/detokenize",
            headers={"X-API-Key": admin},
            json={"tokens": ["tok_nope"], "justification": "probing"},
        )
        events = (await client.get("/v1/audit", headers={"X-API-Key": admin})).json()
        reversal = next(i for i in events["items"] if i["event"] == "tokens.reversed")
        assert reversal["payload"]["recovered"] == 0


class TestVerifyWithoutDisclosing:
    @pytest.fixture
    async def wired(self, authed_client, monkeypatch):
        from control_plane.config import reset_settings_cache

        client, admin, _issue = authed_client
        monkeypatch.setenv("CP_TOKENIZATION_KEY", "k" * 32)
        reset_settings_cache()
        return client, admin, DeterministicTokenizer(key=("k" * 32).encode())

    async def test_a_correct_guess_is_confirmed(self, wired) -> None:
        client, admin, tokenizer = wired
        response = await client.post(
            "/v1/detokenize/verify",
            headers={"X-API-Key": admin},
            json={
                "token": tokenizer.tokenize("pii.email", "jane.doe@acme.com"),
                "label": "pii.email",
                "value": "jane.doe@acme.com",
                "justification": "confirming a match for INC-4821",
            },
        )
        assert response.json() == {"matches": True}

    async def test_a_wrong_guess_is_refuted(self, wired) -> None:
        client, admin, tokenizer = wired
        response = await client.post(
            "/v1/detokenize/verify",
            headers={"X-API-Key": admin},
            json={
                "token": tokenizer.tokenize("pii.email", "jane.doe@acme.com"),
                "label": "pii.email",
                "value": "someone@else.com",
                "justification": "checking",
            },
        )
        assert response.json() == {"matches": False}

    async def test_neither_side_reaches_the_audit_log(self, wired) -> None:
        client, admin, tokenizer = wired
        await client.post(
            "/v1/detokenize/verify",
            headers={"X-API-Key": admin},
            json={
                "token": tokenizer.tokenize("pii.email", "jane.doe@acme.com"),
                "label": "pii.email",
                "value": "jane.doe@acme.com",
                "justification": "checking",
            },
        )
        events = (await client.get("/v1/audit", headers={"X-API-Key": admin})).json()
        record = next(i for i in events["items"] if i["event"] == "tokens.verified")
        assert "jane.doe@acme.com" not in str(record)
        assert record["payload"]["matched"] is True


class TestUnconfiguredDeployment:
    async def test_reversal_says_tokenisation_is_not_configured(
        self, authed_client, monkeypatch
    ) -> None:
        from control_plane.config import reset_settings_cache

        client, admin, _ = authed_client
        monkeypatch.delenv("CP_TOKENIZATION_KEY", raising=False)
        reset_settings_cache()
        response = await client.post(
            "/v1/detokenize",
            headers={"X-API-Key": admin},
            json={"tokens": ["tok_x"], "justification": "why not"},
        )
        assert response.status_code == 409
        assert "not configured" in response.json()["detail"]


class TestAuditIntegrity:
    async def test_the_chain_survives_all_of_it(self, session, audit_key) -> None:
        settings = settings_with(tokenization_key="k" * 32)
        await PolicyStore(session).create(TOKENIZE_POLICY, actor="seed")
        pdp = PolicyDecisionPoint(session, settings=settings)
        await pdp.decide(request_for("mail jane.doe@acme.com"))
        assert (await AuditService(session, key=audit_key).verify()).valid is True
