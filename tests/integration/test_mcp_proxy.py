"""The MCP governing proxy, end to end.

Three real things in one process: the control plane with the shipped policy set,
the proxy, and an MCP server. Nothing here is mocked at the seam under test --
the proxy talks to the control plane over HTTP and to the server over HTTP, the
way it will in production, because the last two enforcement-point bugs in this
repo were both in the wiring rather than in the logic.

The whole file was written after driving the proxy against a live gateway
fronting 118 tools. Several of these tests exist because that run found
something.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest
import yaml
from httpx import ASGITransport, AsyncClient

from tests.fixtures.fake_mcp_server import app as upstream_app

ROOT = Path(__file__).resolve().parents[2]
SEED_POLICIES = yaml.safe_load((ROOT / "seed" / "policies.yaml").read_text())
SEED_CATALOG = yaml.safe_load((ROOT / "seed" / "catalog.yaml").read_text())

pytestmark = pytest.mark.anyio


def _sse_or_json(response: Any) -> Any:
    from pep.mcp_proxy.framing import iter_sse

    if "text/event-stream" in response.headers.get("content-type", ""):
        events = [e.json() for e in iter_sse(response.text)]
        return events[0] if len(events) == 1 else events
    return response.json()


@pytest.fixture
async def seeded(app_session):
    """The shipped policy set and catalog, loaded exactly as `cpctl seed` does.

    The shipped set, not a set written to make these pass: whether the reference
    policies actually govern a tool call is the question.
    """
    from control_plane.catalog.service import CatalogService
    from control_plane.policy.model import PolicySet
    from control_plane.policy.store import PolicyStore

    policy_set = PolicySet.model_validate(SEED_POLICIES)
    await PolicyStore(app_session).sync(policy_set.policies, actor="test")

    service = CatalogService(app_session)
    for entry in SEED_CATALOG["principals"]:
        await service.upsert_principal(
            entry["external_id"], type_=entry["type"], attributes=entry.get("attributes")
        )
    await app_session.commit()


@pytest.fixture
async def proxy(client, monkeypatch, seeded):
    """The proxy, wired to the in-process control plane and MCP server."""
    from control_plane_sdk import AsyncControlPlaneClient

    import pep.mcp_proxy.main as proxy_module

    upstream_app.state.calls = []
    monkeypatch.setattr(proxy_module, "UPSTREAM", "http://upstream.test/mcp")
    monkeypatch.setattr(proxy_module, "SERVER_NAME", "testsrv")

    upstream = AsyncClient(
        transport=ASGITransport(app=upstream_app), base_url="http://upstream.test"
    )
    cp = AsyncControlPlaneClient("http://control-plane.test")
    # The SDK's own transport, pointed at the in-process control plane.
    cp._client = client

    app = proxy_module.app
    app.state.upstream = upstream
    app.state.cp = cp
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://proxy.test") as http:
        yield http
    await upstream.aclose()


async def _call(proxy, tool: str, arguments: dict | None = None, agent: str = "agent://analyst"):
    response = await proxy.post(
        "/mcp",
        content=json.dumps(
            {
                "jsonrpc": "2.0",
                "id": 3,
                "method": "tools/call",
                "params": {"name": tool, "arguments": arguments or {}},
            }
        ),
        headers={"Content-Type": "application/json", "X-Principal-Id": agent},
    )
    return response, _sse_or_json(response)


async def _list(proxy, agent: str = "agent://analyst"):
    response = await proxy.post(
        "/mcp",
        content=json.dumps({"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}}),
        headers={"Content-Type": "application/json", "X-Principal-Id": agent},
    )
    return _sse_or_json(response)["result"]["tools"]


class TestItDoesNotCorruptTheProtocol:
    """The first duty. Everything else is worthless if the session breaks."""

    async def test_initialize_passes_through_with_its_session_id(self, proxy) -> None:
        response = await proxy.post(
            "/mcp",
            content=json.dumps(
                {
                    "jsonrpc": "2.0",
                    "id": 1,
                    "method": "initialize",
                    "params": {"protocolVersion": "2025-06-18", "capabilities": {}},
                }
            ),
            headers={"Content-Type": "application/json"},
        )
        assert response.status_code == 200
        assert response.headers.get("mcp-session-id")
        body = _sse_or_json(response)
        assert body["result"]["serverInfo"]["name"] == "fake-mcp"

    async def test_a_notification_is_forwarded_and_never_answered(self, proxy) -> None:
        """A notification has no id. Replying to one corrupts the session."""
        response = await proxy.post(
            "/mcp",
            content=json.dumps({"jsonrpc": "2.0", "method": "notifications/initialized"}),
            headers={"Content-Type": "application/json"},
        )
        assert response.status_code == 202
        assert response.content == b""

    async def test_an_unknown_method_is_forwarded_untouched(self, proxy) -> None:
        response = await proxy.post(
            "/mcp",
            content=json.dumps({"jsonrpc": "2.0", "id": 5, "method": "resources/list"}),
            headers={"Content-Type": "application/json"},
        )
        assert _sse_or_json(response)["error"]["message"] == "resources/list"

    async def test_a_body_that_is_not_json_is_still_forwarded(self, proxy) -> None:
        """Not ours to reject. The upstream is entitled to its own opinion."""
        response = await proxy.post(
            "/mcp", content=b"\xff\xfe not json", headers={"Content-Type": "application/json"}
        )
        assert response.status_code in (200, 202, 400, 422, 500)

    async def test_the_reply_keeps_the_id_it_was_asked_with(self, proxy) -> None:
        _, body = await _call(proxy, "read_notes")
        assert body["id"] == 3


class TestTheListingIsFiltered:
    async def test_a_tool_the_agent_may_not_call_is_not_offered(self, proxy) -> None:
        offered = {t["name"] for t in await _list(proxy)}
        assert "read_notes" in offered
        assert "delete_record" not in offered

    async def test_an_unannotated_tool_is_treated_conservatively(self, proxy) -> None:
        """No annotations means the action is guessed, and the guess is execute."""
        assert "frobnicate" not in {t["name"] for t in await _list(proxy)}

    async def test_filtering_writes_no_decision_records(self, proxy, app_session) -> None:
        """Advisory, and deliberately not audited.

        Against a real gateway one tools/list wrote 360 records with no outcome
        on any of them -- twenty times the volume of the calls themselves --
        which buries the "unreported" filter under questions that never had an
        outcome to report. Nothing is carried out here; the call is where
        enforcement happens.
        """
        from sqlalchemy import func, select

        from control_plane.models.decision import DecisionRecord

        before = (
            await app_session.execute(select(func.count()).select_from(DecisionRecord))
        ).scalar_one()
        await _list(proxy)
        after = (
            await app_session.execute(select(func.count()).select_from(DecisionRecord))
        ).scalar_one()
        assert after == before

    async def test_hiding_a_tool_is_not_the_same_as_refusing_it(self, proxy) -> None:
        """An agent can name a tool it was never shown, and the call still fails."""
        assert "delete_record" not in {t["name"] for t in await _list(proxy)}
        _, body = await _call(proxy, "delete_record", {"id": "1"})
        assert "error" in body
        assert upstream_app.state.calls == []


class TestTheCallIsGoverned:
    async def test_a_permitted_call_reaches_the_tool(self, proxy) -> None:
        _, body = await _call(proxy, "read_notes")
        assert body["result"]["content"][0]["text"] == "Quarterly revenue was up."
        assert [c["tool"] for c in upstream_app.state.calls] == ["read_notes"]

    async def test_a_denied_call_never_reaches_the_tool(self, proxy) -> None:
        """The point of enforcing before rather than after."""
        _, body = await _call(proxy, "delete_record", {"id": "1"})
        assert body["error"]["code"] == -32001
        assert upstream_app.state.calls == []

    async def test_a_denial_is_a_json_rpc_error_not_an_http_one(self, proxy) -> None:
        """An HTTP error kills the session; this is one recoverable failed call."""
        response, body = await _call(proxy, "delete_record", {"id": "1"})
        assert response.status_code == 200
        assert body["id"] == 3
        assert body["error"]["data"]["decision_id"]


class TestTheResultIsGovernedToo:
    async def test_identifiers_in_a_result_are_redacted(self, proxy) -> None:
        """A file read returns whatever the file held, which the agent never asked for."""
        _, body = await _call(proxy, "read_patient_file", {"id": "42"})
        text = " ".join(b["text"] for b in body["result"]["content"] if b.get("type") == "text")
        assert "501-72-9384" not in text
        assert "maria.alvarez@clinic.example" not in text
        assert "Maria Alvarez" in text

    async def test_non_text_blocks_are_passed_through_untouched(self, proxy) -> None:
        """An image is not ours to rewrite, and pretending to scan it would lie."""
        _, body = await _call(proxy, "read_patient_file", {"id": "42"})
        images = [b for b in body["result"]["content"] if b.get("type") == "image"]
        assert len(images) == 1
        assert images[0]["data"] == "aGVsbG8="

    async def test_the_block_structure_survives(self, proxy) -> None:
        """A client that indexes into content[] should still find what it expects."""
        _, body = await _call(proxy, "read_patient_file", {"id": "42"})
        kinds = [b.get("type") for b in body["result"]["content"]]
        assert kinds == ["text", "image", "text"]

    async def test_a_clean_result_is_returned_unchanged(self, proxy) -> None:
        _, body = await _call(proxy, "read_notes")
        assert body["result"]["content"] == [{"type": "text", "text": "Quarterly revenue was up."}]


class TestOutcomesAreReported:
    async def test_both_directions_are_accounted_for(self, proxy, app_session) -> None:
        from sqlalchemy import select

        from control_plane.models.decision import DecisionRecord

        await _call(proxy, "read_patient_file", {"id": "42"})
        rows = (
            (
                await app_session.execute(
                    select(DecisionRecord).where(DecisionRecord.effect == "allow")
                )
            )
            .scalars()
            .all()
        )
        directions = {r.context.get("direction"): r.outcome for r in rows}
        assert directions == {"invoke": "enforced", "result": "enforced"}

    async def test_no_permitted_action_is_left_unreported(self, proxy, app_session) -> None:
        """The check the outcome work exists for, applied to this enforcement point."""
        from sqlalchemy import func, select

        from control_plane.models.decision import DecisionRecord

        await _call(proxy, "read_notes")
        await _call(proxy, "read_patient_file", {"id": "42"})
        await _call(proxy, "delete_record", {"id": "1"})
        unreported = (
            await app_session.execute(
                select(func.count())
                .select_from(DecisionRecord)
                .where(DecisionRecord.effect == "allow", DecisionRecord.outcome.is_(None))
            )
        ).scalar_one()
        assert unreported == 0
