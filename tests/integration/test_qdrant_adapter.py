"""The Qdrant adapter against a real Qdrant.

These exist because the adapter shipped with no tests whatsoever, and the first
real call revealed two defects a fake could not have caught: ``/healthz``
answers 200 without an API key on an instance that requires one, so health
reported green on a misconfiguration; and every HTTP error status escaped as a
raw httpx exception, taking the whole discovery run down instead of arriving as
the AdapterError the caller catches.

Skipped unless CP_TEST_QDRANT_URL points at an instance this suite may write to.
Set CP_TEST_QDRANT_API_KEY when that instance requires one.
"""

from __future__ import annotations

import os
import uuid

import httpx
import pytest

from control_plane.adapters.base import AdapterError, AdapterUnavailable
from control_plane.adapters.qdrant import QdrantAdapter

pytestmark = pytest.mark.integration

QDRANT_URL = os.environ.get("CP_TEST_QDRANT_URL", "")
QDRANT_KEY = os.environ.get("CP_TEST_QDRANT_API_KEY") or None

requires_qdrant = pytest.mark.skipif(not QDRANT_URL, reason="CP_TEST_QDRANT_URL is not set")


@pytest.fixture
async def collection():
    """A throwaway collection with payloads worth classifying."""
    name = f"cp_test_{uuid.uuid4().hex[:10]}"
    headers = {"api-key": QDRANT_KEY} if QDRANT_KEY else {}
    async with httpx.AsyncClient(base_url=QDRANT_URL, headers=headers, timeout=20.0) as http:
        await http.put(
            f"/collections/{name}",
            json={"vectors": {"probe-embed-v1": {"size": 4, "distance": "Cosine"}}},
        )
        await http.put(
            f"/collections/{name}/points?wait=true",
            json={
                "points": [
                    {
                        "id": 1,
                        "vector": {"probe-embed-v1": [0.1, 0.2, 0.3, 0.4]},
                        "payload": {
                            "document": "Contact Jane Doe at jane.doe@acme.com.",
                            "metadata": {"ssn": "536-90-4432", "tags": ["intake"]},
                        },
                    },
                    {
                        "id": 2,
                        "vector": {"probe-embed-v1": [0.4, 0.3, 0.2, 0.1]},
                        "payload": {"document": "Quarterly revenue was up."},
                    },
                ]
            },
        )
        try:
            yield name
        finally:
            await http.delete(f"/collections/{name}")


@pytest.fixture
async def adapter():
    a = QdrantAdapter(QDRANT_URL, QDRANT_KEY)
    try:
        yield a
    finally:
        await a.aclose()


@requires_qdrant
class TestAgainstALiveInstance:
    @pytest.mark.anyio
    async def test_discovers_the_collection(self, adapter, collection) -> None:
        urns = {a.urn for a in await adapter.discover()}
        assert f"qdrant://{collection}" in urns

    @pytest.mark.anyio
    async def test_reports_vector_configuration(self, adapter, collection) -> None:
        found = next(a for a in await adapter.discover() if a.name == collection)
        assert found.attributes["points_count"] == 2
        assert found.attributes["vector_size"] == 4
        assert found.attributes["vector_names"] == ["probe-embed-v1"]

    @pytest.mark.anyio
    async def test_samples_payloads_without_vectors(self, adapter, collection) -> None:
        samples = [s async for s in adapter.sample(f"qdrant://{collection}", limit=10)]
        assert samples[0].record_count == 2
        assert all("vector" not in p for p in samples[0].content)
        assert any("jane.doe@acme.com" in str(p) for p in samples[0].content)

    @pytest.mark.anyio
    async def test_a_partial_page_says_so(self, adapter, collection) -> None:
        samples = [s async for s in adapter.sample(f"qdrant://{collection}", limit=1)]
        assert samples[0].record_count == 1
        assert samples[0].partial is True

    @pytest.mark.anyio
    async def test_health_passes_when_we_can_enumerate(self, adapter) -> None:
        assert await adapter.health() is True

    @pytest.mark.anyio
    async def test_sampling_a_collection_that_is_gone_stays_in_the_contract(self, adapter) -> None:
        with pytest.raises(AdapterError):
            [s async for s in adapter.sample("qdrant://cp_test_definitely_absent")]

    @pytest.mark.anyio
    async def test_nothing_listening_is_unavailable(self) -> None:
        a = QdrantAdapter("http://127.0.0.1:1")
        assert await a.health() is False
        with pytest.raises(AdapterUnavailable):
            await a.discover()
        await a.aclose()


@requires_qdrant
@pytest.mark.skipif(not QDRANT_KEY, reason="CP_TEST_QDRANT_API_KEY is not set")
class TestAgainstAnAuthenticatedInstance:
    """The case that produced the health-check finding."""

    @pytest.mark.anyio
    async def test_a_wrong_key_fails_health_even_though_healthz_is_200(self) -> None:
        async with httpx.AsyncClient(base_url=QDRANT_URL, timeout=20.0) as http:
            liveness = await http.get("/healthz")
        assert liveness.status_code == 200, "premise: /healthz needs no credentials"

        a = QdrantAdapter(QDRANT_URL, "definitely-not-the-key")
        assert await a.health() is False
        with pytest.raises(AdapterUnavailable, match="api_key"):
            await a.discover()
        await a.aclose()
