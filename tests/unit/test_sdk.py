"""The enforcement-point client's own guarantees."""

from __future__ import annotations

import sys
from pathlib import Path

import httpx
import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "sdk" / "python"))

from control_plane_sdk import (
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
