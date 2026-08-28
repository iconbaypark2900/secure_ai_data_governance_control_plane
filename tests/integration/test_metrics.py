"""Prometheus metrics.

``prometheus-client`` was a declared dependency with no uses and no endpoint.
These tests hold the other half in place -- and, more importantly, hold the line
on what must *not* appear in a scrape.
"""

from __future__ import annotations

import pytest

from control_plane.metrics import reset_metrics


@pytest.fixture(autouse=True)
def _fresh_registry():
    """Counters are process-global; a test asserting a count needs its own."""
    reset_metrics()
    yield
    reset_metrics()


ALLOW_POLICY = {
    "policy": {
        "key": "allow-all-reads",
        "name": "Allow reads",
        "effect": "allow",
        "priority": 100,
        "match": {"action": "read"},
        "obligations": [{"type": "redact", "labels": ["pii"], "strategy": "mask"}],
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


class TestEndpoint:
    async def test_it_serves_prometheus_text(self, client) -> None:
        response = await client.get("/metrics")
        assert response.status_code == 200
        assert "text/plain" in response.headers["content-type"]
        assert "control_plane_decisions_total" in response.text

    async def test_it_needs_no_credential(self, authed_client) -> None:
        """Scrapers do not carry API keys; restrict the port instead."""
        http, _, _ = authed_client
        assert (await http.get("/metrics")).status_code == 200

    async def test_it_can_be_turned_off(self, client, monkeypatch) -> None:
        from control_plane.api.deps import get_db
        from control_plane.config import reset_settings_cache
        from control_plane.main import create_app

        monkeypatch.setenv("CP_METRICS_ENABLED", "false")
        reset_settings_cache()
        app = create_app()
        app.dependency_overrides[get_db] = client._transport.app.dependency_overrides[get_db]

        from httpx import ASGITransport, AsyncClient

        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as http:
            assert (await http.get("/metrics")).status_code == 404


class TestWhatIsCounted:
    async def test_decisions_are_counted_by_effect(self, client) -> None:
        await client.post("/v1/policies", json=ALLOW_POLICY)
        await client.post("/v1/decide", json=decide_body())
        await client.post("/v1/decide", json=decide_body(action="delete"))

        body = (await client.get("/metrics")).text
        assert 'control_plane_decisions_total{effect="allow"} 1.0' in body
        assert 'control_plane_decisions_total{effect="deny"} 1.0' in body

    async def test_findings_are_counted_by_label(self, client) -> None:
        await client.post("/v1/policies", json=ALLOW_POLICY)
        await client.post("/v1/decide", json=decide_body(payload="mail jane.doe@acme.com"))
        body = (await client.get("/metrics")).text
        assert 'control_plane_findings_total{label="pii.email"} 1.0' in body

    async def test_redactions_are_counted_by_strategy(self, client) -> None:
        await client.post("/v1/policies", json=ALLOW_POLICY)
        await client.post("/v1/decide", json=decide_body(payload="mail a.b@c.com"))
        body = (await client.get("/metrics")).text
        assert 'control_plane_redactions_total{strategy="mask"} 1.0' in body

    async def test_latency_is_observed(self, client) -> None:
        await client.post("/v1/policies", json=ALLOW_POLICY)
        await client.post("/v1/decide", json=decide_body())
        body = (await client.get("/metrics")).text
        assert "control_plane_decision_duration_seconds_count 1.0" in body

    async def test_policy_load_health_is_exposed(self, client) -> None:
        """A non-zero error count means a control is silently absent."""
        await client.post("/v1/policies", json=ALLOW_POLICY)
        await client.post("/v1/decide", json=decide_body())
        body = (await client.get("/metrics")).text
        assert "control_plane_policies_loaded 1.0" in body
        assert "control_plane_policy_load_errors 0.0" in body


class TestWhatIsNotCounted:
    async def test_a_scrape_carries_no_decision_detail(self, client) -> None:
        """Counts and latencies, not decisions.

        Nothing operator-defined may become a metric label: a policy key or a
        resource URN is unbounded cardinality controlled by whoever writes
        policies, which is a way to run a monitoring system out of memory -- and
        a principal or a payload has no business being there at all.
        """
        await client.post("/v1/policies", json=ALLOW_POLICY)
        await client.post(
            "/v1/decide",
            json=decide_body(payload="jane.doe@acme.com at qdrant://kb"),
        )
        body = (await client.get("/metrics")).text

        assert "jane.doe@acme.com" not in body
        assert "agent:bot" not in body
        assert "qdrant://kb" not in body
        assert "allow-all-reads" not in body
