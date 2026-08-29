"""The enforcement-point client's own guarantees."""

from __future__ import annotations

import sys
from pathlib import Path

import httpx
import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "sdk" / "python"))

from control_plane_sdk import (
    ApprovalTimeout,
    AsyncControlPlaneClient,
    ControlPlaneError,
    ControlPlaneUnavailable,
    Decision,
    DecisionDenied,
    ObligationUnsatisfied,
)

ALLOW_BODY = {
    "effect": "allow",
    "reason": "policy 'allow-agents' matched",
    "decision_id": "11111111-1111-1111-1111-111111111111",
    "payload": "safe content",
    "obligations": [{"type": "redact", "labels": ["pii"]}],
    "redactions": [{"label": "pii.email", "strategy": "mask", "start": 0, "end": 5}],
    "classifications": ["pii.email"],
}


def client_with(handler, **kwargs) -> AsyncControlPlaneClient:
    transport = httpx.MockTransport(handler)
    http = httpx.AsyncClient(transport=transport, base_url="http://cp.test")
    return AsyncControlPlaneClient("http://cp.test", "cpk_x_y", client=http, **kwargs)


class TestDecisionSemantics:
    def test_enforce_returns_the_payload_on_allow(self) -> None:
        assert Decision.from_response(ALLOW_BODY).enforce() == "safe content"

    def test_enforce_raises_on_deny(self) -> None:
        decision = Decision.from_response({"effect": "deny", "reason": "PHI to external"})
        with pytest.raises(DecisionDenied, match="PHI to external"):
            decision.enforce()

    def test_an_unsatisfiable_obligation_blocks_the_action(self) -> None:
        """'allow, but watermark' must not degrade into a plain allow."""
        decision = Decision.from_response(
            {"effect": "allow", "payload": "x", "obligations": [{"type": "watermark"}]}
        )
        with pytest.raises(ObligationUnsatisfied, match="watermark"):
            decision.enforce()

    def test_a_declared_capability_unblocks_it(self) -> None:
        decision = Decision.from_response(
            {"effect": "allow", "payload": "x", "obligations": [{"type": "watermark"}]}
        )
        assert decision.enforce(can_satisfy=["watermark"]) == "x"

    def test_redaction_obligations_need_no_declaration(self) -> None:
        """The control plane already applied them to the returned payload."""
        assert Decision.from_response(ALLOW_BODY).enforce() == "safe content"

    def test_require_approval_is_not_an_allow(self) -> None:
        decision = Decision.from_response({"effect": "require_approval", "reason": "queued"})
        assert decision.allowed is False
        assert decision.needs_approval is True
        with pytest.raises(DecisionDenied):
            decision.enforce()


class TestFailureBehaviour:
    async def test_an_unreachable_control_plane_denies(self) -> None:
        def unreachable(_request: httpx.Request) -> httpx.Response:
            raise httpx.ConnectError("connection refused")

        client = client_with(unreachable, retries=0)
        decision = await client.decide(principal_id="a", action="read")
        assert decision.allowed is False
        assert "fails closed" in decision.reason

    async def test_fail_open_raises_instead_of_denying(self) -> None:
        """Opt-in only, and it raises rather than silently allowing."""

        def unreachable(_request: httpx.Request) -> httpx.Response:
            raise httpx.ConnectError("connection refused")

        client = client_with(unreachable, retries=0, fail_closed=False)
        with pytest.raises(ControlPlaneUnavailable):
            await client.decide(principal_id="a", action="read")

    async def test_transient_errors_are_retried(self) -> None:
        attempts = {"count": 0}

        def flaky(request: httpx.Request) -> httpx.Response:
            attempts["count"] += 1
            if attempts["count"] < 3:
                raise httpx.ConnectError("connection reset")
            return httpx.Response(200, json=ALLOW_BODY)

        client = client_with(flaky, retries=2)
        decision = await client.decide(principal_id="a", action="read")
        assert decision.allowed is True
        assert attempts["count"] == 3

    async def test_rejected_credentials_deny_rather_than_pass_through(self) -> None:
        client = client_with(
            lambda _r: httpx.Response(401, json={"detail": "invalid key"}), retries=0
        )
        decision = await client.decide(principal_id="a", action="read")
        assert decision.allowed is False
        assert "rejected this enforcement point" in decision.reason

    async def test_a_server_error_surfaces_rather_than_being_hidden(self) -> None:
        client = client_with(lambda _r: httpx.Response(500, text="boom"), retries=0)
        with pytest.raises(ControlPlaneError, match="500"):
            await client.decide(principal_id="a", action="read")


class TestCaching:
    async def test_payload_free_decisions_are_cached(self) -> None:
        calls = {"count": 0}

        def counting(_request: httpx.Request) -> httpx.Response:
            calls["count"] += 1
            return httpx.Response(200, json=ALLOW_BODY)

        client = client_with(counting, cache_ttl=60)
        for _ in range(3):
            await client.decide(principal_id="a", action="read", resource_urn="pg://t")
        assert calls["count"] == 1

    async def test_decisions_about_content_are_never_cached(self) -> None:
        """The payload is part of what was decided, so it cannot be reused."""
        calls = {"count": 0}

        def counting(_request: httpx.Request) -> httpx.Response:
            calls["count"] += 1
            return httpx.Response(200, json=ALLOW_BODY)

        client = client_with(counting, cache_ttl=60)
        for text in ("harmless", "ssn 536-90-4432", "harmless"):
            await client.decide(principal_id="a", action="read", payload=text)
        assert calls["count"] == 3

    async def test_a_different_principal_is_a_different_cache_entry(self) -> None:
        calls = {"count": 0}

        def counting(_request: httpx.Request) -> httpx.Response:
            calls["count"] += 1
            return httpx.Response(200, json=ALLOW_BODY)

        client = client_with(counting, cache_ttl=60)
        await client.decide(principal_id="a", action="read")
        await client.decide(principal_id="b", action="read")
        assert calls["count"] == 2

    async def test_context_participates_in_the_cache_key(self) -> None:
        calls = {"count": 0}

        def counting(_request: httpx.Request) -> httpx.Response:
            calls["count"] += 1
            return httpx.Response(200, json=ALLOW_BODY)

        client = client_with(counting, cache_ttl=60)
        await client.decide(principal_id="a", action="read", context={"destination": "internal"})
        await client.decide(principal_id="a", action="read", context={"destination": "external"})
        assert calls["count"] == 2

    @pytest.mark.parametrize(
        ("first", "second"),
        [
            ({"external": True}, {"external": "True"}),
            ({"external": True}, {"external": "true"}),
            ({"limit": 1}, {"limit": "1"}),
            ({"tier": 0}, {"tier": False}),
            ({"region": None}, {"region": "None"}),
        ],
    )
    async def test_values_of_different_types_are_different_questions(
        self, first: dict, second: dict
    ) -> None:
        """A cache that answers a different question is a correctness bug.

        The key was built by string-formatting each value, which conflated
        things the policy engine does not: a rule matching ``context.external``
        against the boolean true does not match the string "True". The second
        caller then received the first one's decision, and on this pairing that
        can be an allow standing in for a deny.

        Found while porting the client to TypeScript -- writing the same
        function twice and asking what the two would disagree about.
        """
        calls = {"count": 0}

        def counting(_request: httpx.Request) -> httpx.Response:
            calls["count"] += 1
            return httpx.Response(200, json=ALLOW_BODY)

        client = client_with(counting, cache_ttl=60)
        await client.decide(principal_id="a", action="read", context=first)
        await client.decide(principal_id="a", action="read", context=second)
        assert calls["count"] == 2

    async def test_the_same_context_still_hits_whatever_the_key_order(self) -> None:
        """Fixing the collision must not stop the cache caching."""
        calls = {"count": 0}

        def counting(_request: httpx.Request) -> httpx.Response:
            calls["count"] += 1
            return httpx.Response(200, json=ALLOW_BODY)

        client = client_with(counting, cache_ttl=60)
        await client.decide(principal_id="a", action="read", context={"a": 1, "b": True})
        await client.decide(principal_id="a", action="read", context={"b": True, "a": 1})
        assert calls["count"] == 1

    def test_a_value_that_is_not_json_serialisable_does_not_raise(self) -> None:
        """The key builder must not become a second failure mode.

        Such a context never reaches the wire -- the request body cannot encode
        it either -- so this is asserted against the key builder directly rather
        than through decide(), which would fail for an unrelated reason and pass
        this test for the wrong one.
        """
        from control_plane_sdk.client import _cache_key

        body = {
            "principal": {"id": "a", "type": "service"},
            "action": "read",
            "resource": {"urn": None, "classifications": []},
            "context": {"when": object()},
        }
        assert isinstance(_cache_key(body), str)

    async def test_a_classification_containing_the_separator_is_not_confused(self) -> None:
        calls = {"count": 0}

        def counting(_request: httpx.Request) -> httpx.Response:
            calls["count"] += 1
            return httpx.Response(200, json=ALLOW_BODY)

        client = client_with(counting, cache_ttl=60)
        await client.decide(principal_id="a", action="read", classifications=["a,b"])
        await client.decide(principal_id="a", action="read", classifications=["a", "b"])
        assert calls["count"] == 2


class TestRequestShape:
    async def test_the_key_is_sent_and_the_body_is_well_formed(self) -> None:
        captured: dict = {}

        def capture(request: httpx.Request) -> httpx.Response:
            import json

            captured["headers"] = dict(request.headers)
            captured["body"] = json.loads(request.content)
            return httpx.Response(200, json=ALLOW_BODY)

        client = client_with(capture)
        await client.decide(
            principal_id="agent:bot",
            principal_type="agent",
            action="embed",
            resource_urn="qdrant://kb",
            classifications=["pii.email"],
            context={"destination": "internal"},
            correlation_id="trace-9",
        )
        assert captured["headers"]["x-api-key"] == "cpk_x_y"
        body = captured["body"]
        assert body["principal"] == {"id": "agent:bot", "type": "agent", "attributes": {}}
        assert body["resource"]["classifications"] == ["pii.email"]
        assert body["correlation_id"] == "trace-9"
        assert body["options"]["apply_obligations"] is True


PARKED_BODY = {
    "effect": "require_approval",
    "reason": "'Export needs a named approver' produced 'require_approval'",
    "decision_id": "22222222-2222-2222-2222-222222222222",
    "approval": {
        "id": "33333333-3333-3333-3333-333333333333",
        "status": "pending",
        "requested_by": "user:analyst",
        "created_at": "2026-08-28T12:00:00+00:00",
    },
}


class TestApprovalFlow:
    def test_a_parked_decision_exposes_the_handle_to_wait_on(self) -> None:
        decision = Decision.from_response(PARKED_BODY)
        assert decision.needs_approval is True
        assert decision.allowed is False
        assert decision.approval_id == "33333333-3333-3333-3333-333333333333"

    def test_a_decision_with_no_approval_has_no_handle(self) -> None:
        assert Decision.from_response(ALLOW_BODY).approval_id is None

    def test_redemption_is_reported(self) -> None:
        decision = Decision.from_response({**ALLOW_BODY, "approval_redeemed": True})
        assert decision.approval_redeemed is True
        assert decision.approval_error is None

    def test_a_failed_redemption_says_why(self) -> None:
        decision = Decision.from_response(
            {**PARKED_BODY, "approval_error": "the approval expired at 2026-08-27T12:00:00+00:00"}
        )
        assert "expired" in decision.approval_error

    async def test_the_approval_id_is_sent(self) -> None:
        captured: dict = {}

        def capture(request: httpx.Request) -> httpx.Response:
            import json

            captured["body"] = json.loads(request.content)
            return httpx.Response(200, json=ALLOW_BODY)

        client = client_with(capture)
        await client.decide(principal_id="user:analyst", action="export", approval_id="abc-123")
        assert captured["body"]["approval_id"] == "abc-123"

    async def test_a_redemption_is_never_served_from_cache(self) -> None:
        """Redeeming spends the approval; a cached reply would skip or replay it."""
        calls = {"count": 0}

        def counting(_request: httpx.Request) -> httpx.Response:
            calls["count"] += 1
            return httpx.Response(200, json=ALLOW_BODY)

        client = client_with(counting, cache_ttl=60)
        for _ in range(3):
            await client.decide(principal_id="user:analyst", action="export", approval_id="abc-123")
        assert calls["count"] == 3

    async def test_a_redemption_does_not_poison_the_cache(self) -> None:
        """The allow it produced must not be replayed for the plain question."""
        seen: list[dict] = []

        def recording(request: httpx.Request) -> httpx.Response:
            import json

            body = json.loads(request.content)
            seen.append(body)
            return httpx.Response(200, json=ALLOW_BODY if body.get("approval_id") else PARKED_BODY)

        client = client_with(recording, cache_ttl=60)
        await client.decide(principal_id="user:analyst", action="export", approval_id="abc")
        plain = await client.decide(principal_id="user:analyst", action="export")
        assert plain.needs_approval is True
        assert len(seen) == 2

    async def test_await_approval_returns_once_resolved(self) -> None:
        states = iter(["pending", "pending", "granted"])

        def polling(_request: httpx.Request) -> httpx.Response:
            return httpx.Response(200, json={"id": "abc", "status": next(states)})

        client = client_with(polling)
        result = await client.await_approval("abc", timeout=5, poll_interval=0.001)
        assert result["status"] == "granted"

    async def test_await_approval_returns_a_refusal_rather_than_raising(self) -> None:
        """A denial is an answer. The caller decides what to do about it."""
        client = client_with(lambda _r: httpx.Response(200, json={"id": "abc", "status": "denied"}))
        assert (await client.await_approval("abc"))["status"] == "denied"

    async def test_await_approval_gives_up(self) -> None:
        client = client_with(
            lambda _r: httpx.Response(200, json={"id": "abc", "status": "pending"})
        )
        with pytest.raises(ApprovalTimeout, match="still unresolved"):
            await client.await_approval("abc", timeout=0.01, poll_interval=0.001)


class TestOutcomeReporting:
    """Closing the loop between what was permitted and what happened."""

    @staticmethod
    def _recording():
        seen: list[dict] = []

        def handler(request: httpx.Request) -> httpx.Response:
            import json

            if request.url.path.endswith("/outcome"):
                seen.append({"path": request.url.path, **json.loads(request.content)})
                return httpx.Response(200, json={"decision_id": "x", "outcome": "recorded"})
            return httpx.Response(200, json=ALLOW_BODY)

        return seen, handler

    async def test_enforcing_reports_that_it_was_enforced(self) -> None:
        seen, handler = self._recording()
        client = client_with(handler)
        decision = await client.decide(principal_id="a", action="read")

        assert await client.enforce(decision) == "safe content"
        assert seen[0]["outcome"] == "enforced"
        assert seen[0]["discharged"] == ["redact"]

    async def test_an_undischargeable_duty_reports_a_refusal(self) -> None:
        """The case the whole feature exists for: permitted, and did not happen."""
        seen, handler = self._recording()
        client = client_with(handler)
        decision = Decision.from_response(
            {
                **ALLOW_BODY,
                "obligations": [{"type": "watermark", "text": "x"}],
                "decision_id": "11111111-1111-1111-1111-111111111111",
            }
        )

        with pytest.raises(ObligationUnsatisfied):
            await client.enforce(decision)

        assert seen[0]["outcome"] == "refused"
        assert seen[0]["undischarged"] == ["watermark"]
        assert "watermark" in seen[0]["reason"]

    async def test_a_denial_is_not_reported(self) -> None:
        """The record already says it was refused, and nothing was ever attempted."""
        seen, handler = self._recording()
        client = client_with(handler)
        decision = Decision.from_response({"effect": "deny", "reason": "no", "decision_id": "d"})

        with pytest.raises(DecisionDenied):
            await client.enforce(decision)
        assert seen == []

    async def test_partial_names_what_went_undischarged(self) -> None:
        seen, handler = self._recording()
        client = client_with(handler)
        decision = Decision.from_response(
            {
                **ALLOW_BODY,
                "obligations": [{"type": "redact"}, {"type": "watermark"}],
                "decision_id": "22222222-2222-2222-2222-222222222222",
            }
        )

        await client.report_partial(
            decision, undischarged=["watermark"], reason="the renderer was unavailable"
        )
        assert seen[0]["outcome"] == "partial"
        assert seen[0]["discharged"] == ["redact"]
        assert seen[0]["undischarged"] == ["watermark"]

    async def test_reporting_never_fails_the_caller(self) -> None:
        """The action has already happened; a bookkeeping round trip must not
        turn a reporting problem into an outage."""

        def unreachable(request: httpx.Request) -> httpx.Response:
            if request.url.path.endswith("/outcome"):
                raise httpx.ConnectError("connection refused")
            return httpx.Response(200, json=ALLOW_BODY)

        client = client_with(unreachable, retries=0)
        decision = await client.decide(principal_id="a", action="read")
        assert await client.enforce(decision) == "safe content"

    async def test_an_unpersisted_decision_has_nothing_to_report(self) -> None:
        client = client_with(lambda _r: httpx.Response(200, json=ALLOW_BODY))
        decision = Decision.from_response({**ALLOW_BODY, "decision_id": None})
        assert await client.report_outcome(decision, "enforced") is False

    async def test_outstanding_is_what_nobody_will_carry_out(self) -> None:
        decision = Decision.from_response(
            {**ALLOW_BODY, "obligations": [{"type": "redact"}, {"type": "route"}]}
        )
        assert decision.outstanding() == ["route"]
        assert decision.outstanding(["route"]) == []

    async def test_enforcing_reports_an_obligation_it_cannot_discharge(self) -> None:
        """The same refusal, arriving before the work rather than during it.

        enforce() reported this and enforcing() did not, so a duty nobody could
        carry out left the decision unreported -- the state that list exists to
        surface, missing the case most worth surfacing.
        """
        posts: list[tuple[str, dict]] = []

        def handler(request: httpx.Request) -> httpx.Response:
            import json as _json

            if request.url.path.endswith("/outcome"):
                posts.append((request.url.path, _json.loads(request.content)))
                return httpx.Response(204)
            return httpx.Response(
                200,
                json={
                    **ALLOW_BODY,
                    "decision_id": "d_1",
                    "obligations": [{"type": "watermark"}, {"type": "log"}],
                },
            )

        client = client_with(handler)
        decision = await client.decide(principal_id="a", action="read")
        with pytest.raises(ObligationUnsatisfied):
            async with client.enforcing(decision):
                pytest.fail("the block must not run")

        assert len(posts) == 1
        _, body = posts[0]
        assert body["outcome"] == "refused"
        assert body["discharged"] == ["log"]
        assert body["undischarged"] == ["watermark"]

    async def test_enforcing_reports_nothing_for_a_denial(self) -> None:
        """It permitted nothing; the record already says it was refused."""
        posts: list[dict] = []

        def handler(request: httpx.Request) -> httpx.Response:
            import json as _json

            if request.url.path.endswith("/outcome"):
                posts.append(_json.loads(request.content))
                return httpx.Response(204)
            return httpx.Response(
                200, json={"effect": "deny", "reason": "no", "decision_id": "d_2"}
            )

        client = client_with(handler)
        decision = await client.decide(principal_id="a", action="read")
        with pytest.raises(DecisionDenied):
            async with client.enforcing(decision):
                pytest.fail("the block must not run")
        assert posts == []
