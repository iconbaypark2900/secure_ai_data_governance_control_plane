"""Qdrant adapter behaviour.

Every response body below was recorded from a live qdrant 1.19.0, not invented.
That distinction is the point of this file: the adapter previously had no tests
at all, and the assumptions it encoded about someone else's API had never met
that API. Two of them were wrong, and both are pinned here.
"""

from __future__ import annotations

import json

import httpx
import pytest

from control_plane.adapters.base import AdapterError, AdapterUnavailable
from control_plane.adapters.qdrant import QdrantAdapter

#: Recorded from GET /collections.
COLLECTIONS = {
    "result": {"collections": [{"name": "default"}, {"name": "probe_t1"}]},
    "status": "ok",
    "time": 1.312e-05,
}
#: Recorded from GET /collections/default -- a named-vector collection, which is
#: what anything built by a RAG pipeline actually looks like.
NAMED = {
    "result": {
        "status": "green",
        "points_count": 88,
        "config": {
            "params": {
                "vectors": {"fast-all-minilm-l6-v2": {"size": 384, "distance": "Cosine"}},
                "shard_number": 1,
            }
        },
    }
}
#: Recorded from GET /collections/probe_t1 -- the unnamed single-vector shape.
UNNAMED = {
    "result": {
        "status": "green",
        "points_count": 0,
        "config": {"params": {"vectors": {"size": 4, "distance": "Cosine"}, "shard_number": 1}},
    }
}
SCROLL = {
    "result": {
        "points": [
            {"id": "0195e0b1-2f3a-7c11-9d44-6a1f0c2b8e55", "payload": {"document": "hello"}},
            {"id": "0195e0b1-2f3a-7c11-9d44-6a1f0c2b8e56", "payload": {"document": "world"}},
        ],
        "next_page_offset": "0195e0b1-2f3a-7c11-9d44-6a1f0c2b8e57",
    },
    "status": "ok",
    "time": 0.0004,
}


def _adapter(handler: object, *, api_key: str | None = None) -> QdrantAdapter:
    client = httpx.AsyncClient(
        base_url="http://qdrant.test",
        transport=httpx.MockTransport(handler),  # type: ignore[arg-type]
        headers={"api-key": api_key} if api_key else {},
    )
    return QdrantAdapter("http://qdrant.test", api_key, client=client)


def _ok(request: httpx.Request) -> httpx.Response:
    path = request.url.path
    if path == "/collections":
        return httpx.Response(200, json=COLLECTIONS)
    if path == "/collections/default":
        return httpx.Response(200, json=NAMED)
    if path == "/collections/probe_t1":
        return httpx.Response(200, json=UNNAMED)
    if path in ("/collections/default/points/scroll", "/collections/probe_t1/points/scroll"):
        return httpx.Response(200, json=SCROLL)
    return httpx.Response(404, json={"status": {"error": "Not found"}})


class TestDiscovery:
    @pytest.mark.anyio
    async def test_reads_the_real_collections_shape(self) -> None:
        assets = await _adapter(_ok).discover()
        assert [a.urn for a in assets] == ["qdrant://default", "qdrant://probe_t1"]
        assert all(a.kind == "vector_collection" for a in assets)

    @pytest.mark.anyio
    async def test_handles_both_vector_config_shapes(self) -> None:
        """Qdrant reports vectors two different ways and both occur in practice."""
        by_urn = {a.urn: a.attributes for a in await _adapter(_ok).discover()}
        assert by_urn["qdrant://default"]["vector_size"] == 384
        assert by_urn["qdrant://probe_t1"]["vector_size"] == 4

    @pytest.mark.anyio
    async def test_records_the_embedding_model_behind_a_named_vector(self) -> None:
        """Which model read the data is a governance fact, not a detail.

        A named vector is named after the embedding model that produced it. If
        that model is hosted outside the boundary, the collection is a record of
        an egress, and the catalog should be able to say so.
        """
        by_urn = {a.urn: a.attributes for a in await _adapter(_ok).discover()}
        assert by_urn["qdrant://default"]["vector_names"] == ["fast-all-minilm-l6-v2"]
        assert "vector_names" not in by_urn["qdrant://probe_t1"]

    @pytest.mark.anyio
    async def test_a_collection_survives_a_failed_detail_lookup(self) -> None:
        """Naming it is what makes it governable; detail is a nicety."""

        def flaky(request: httpx.Request) -> httpx.Response:
            if request.url.path == "/collections":
                return httpx.Response(200, json=COLLECTIONS)
            return httpx.Response(500, json={"status": {"error": "boom"}})

        assets = await _adapter(flaky).discover()
        assert [a.urn for a in assets] == ["qdrant://default", "qdrant://probe_t1"]
        assert "points_count" not in assets[0].attributes


class TestSampling:
    @pytest.mark.anyio
    async def test_yields_payloads_and_admits_the_sample_was_partial(self) -> None:
        samples = [s async for s in _adapter(_ok).sample("qdrant://default", limit=2)]
        assert len(samples) == 1
        assert samples[0].content == [{"document": "hello"}, {"document": "world"}]
        assert samples[0].record_count == 2
        # next_page_offset was set, so a clean scan is not proof the asset is clean.
        assert samples[0].partial is True

    @pytest.mark.anyio
    async def test_a_complete_page_is_not_partial(self) -> None:
        def complete(request: httpx.Request) -> httpx.Response:
            body = json.loads(json.dumps(SCROLL))
            body["result"]["next_page_offset"] = None
            return httpx.Response(200, json=body)

        samples = [s async for s in _adapter(complete).sample("qdrant://default")]
        assert samples[0].partial is False


class TestFailuresStayInsideTheContract:
    """Callers catch AdapterError. Anything else takes the whole run down.

    Every case here escaped as a raw httpx.HTTPStatusError before, and every one
    of them was reproduced against a live server rather than imagined.
    """

    @pytest.mark.anyio
    @pytest.mark.parametrize("status", [401, 403])
    async def test_rejected_credentials_are_reported_as_unavailable(self, status: int) -> None:
        adapter = _adapter(
            lambda r: httpx.Response(status, json={"status": {"error": "Unauthorized"}})
        )
        with pytest.raises(AdapterUnavailable, match="api_key"):
            await adapter.discover()

    @pytest.mark.anyio
    async def test_a_collection_that_vanished_mid_run_is_an_adapter_error(self) -> None:
        """Enumerate, then sample: a collection can be deleted in between."""
        adapter = _adapter(_ok)
        with pytest.raises(AdapterError):
            [s async for s in adapter.sample("qdrant://gone")]

    @pytest.mark.anyio
    async def test_a_server_error_is_unavailable(self) -> None:
        adapter = _adapter(lambda r: httpx.Response(503, text="upstream down"))
        with pytest.raises(AdapterUnavailable):
            await adapter.discover()

    @pytest.mark.anyio
    async def test_pointing_at_something_that_is_not_qdrant_says_so(self) -> None:
        """The commonest configuration error is a URL aimed at the wrong service."""
        adapter = _adapter(lambda r: httpx.Response(200, html="<html>hello</html>"))
        with pytest.raises(AdapterError, match="not JSON"):
            await adapter.discover()

    @pytest.mark.anyio
    async def test_json_from_the_wrong_service_is_not_read_as_an_empty_instance(self) -> None:
        """Otherwise a misdirected adapter reports 'discovered nothing' as success."""
        adapter = _adapter(lambda r: httpx.Response(200, json={"cluster_name": "opensearch"}))
        with pytest.raises(AdapterError, match="result"):
            await adapter.discover()

    @pytest.mark.anyio
    async def test_an_unreachable_instance_is_unavailable(self) -> None:
        def refuse(request: httpx.Request) -> httpx.Response:
            raise httpx.ConnectError("connection refused", request=request)

        with pytest.raises(AdapterUnavailable, match="unreachable"):
            await _adapter(refuse).discover()


class TestHealth:
    @pytest.mark.anyio
    async def test_health_means_authorised_enumeration(self) -> None:
        assert await _adapter(_ok).health() is True

    @pytest.mark.anyio
    async def test_health_is_false_when_credentials_are_rejected(self) -> None:
        """The finding that motivated the change.

        Qdrant answers /healthz with 200 even on an instance that requires an
        API key -- verified against 1.19.0 -- so a liveness probe reports green
        on the one misconfiguration most likely to be present, and discovery
        then fails on the very next call. Health has to mean "can enumerate".
        """
        adapter = _adapter(
            lambda r: httpx.Response(401, json={"status": {"error": "Unauthorized"}})
        )
        assert await adapter.health() is False

    @pytest.mark.anyio
    async def test_health_is_false_when_nothing_is_listening(self) -> None:
        def refuse(request: httpx.Request) -> httpx.Response:
            raise httpx.ConnectError("connection refused", request=request)

        assert await _adapter(refuse).health() is False
