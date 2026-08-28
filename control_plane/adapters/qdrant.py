"""Qdrant adapter.

Vector collections are the awkward case for data governance. The source records
were governed; the embeddings and the payloads copied alongside them usually
were not, and a collection built from a customer table inherits its sensitivity
without inheriting its controls.

This adapter enumerates collections and samples their payloads so the classifier
can see what actually ended up in them.
"""

from __future__ import annotations

from collections.abc import AsyncIterator, Sequence
from typing import Any

import httpx

from control_plane.adapters.base import (
    AdapterUnavailable,
    DiscoveredAsset,
    Sample,
)

__all__ = ["QdrantAdapter"]


class QdrantAdapter:
    """Reads collection metadata and payload samples from a Qdrant instance."""

    name = "qdrant"

    def __init__(
        self,
        base_url: str = "http://localhost:6333",
        api_key: str | None = None,
        *,
        timeout: float = 10.0,
        client: httpx.AsyncClient | None = None,
    ) -> None:
        self.base_url = base_url.rstrip("/")
        self.api_key = api_key
        self.timeout = timeout
        self._client = client
        self._owns_client = client is None

    def _http(self) -> httpx.AsyncClient:
        if self._client is None:
            headers = {"api-key": self.api_key} if self.api_key else {}
            self._client = httpx.AsyncClient(
                base_url=self.base_url, timeout=self.timeout, headers=headers
            )
        return self._client

    async def aclose(self) -> None:
        if self._client is not None and self._owns_client:
            await self._client.aclose()
            self._client = None

    def urn_for(self, collection: str) -> str:
        return f"qdrant://{collection}"

    async def health(self) -> bool:
        try:
            response = await self._http().get("/healthz")
            return response.status_code == 200
        except (httpx.TimeoutException, httpx.TransportError):
            return False

    async def discover(self) -> Sequence[DiscoveredAsset]:
        """List collections, with their vector configuration as attributes."""
        try:
            response = await self._http().get("/collections")
            response.raise_for_status()
        except (httpx.TimeoutException, httpx.TransportError) as exc:
            raise AdapterUnavailable(f"qdrant at {self.base_url} is unreachable: {exc}") from exc

        collections = response.json().get("result", {}).get("collections", [])
        discovered: list[DiscoveredAsset] = []
        for entry in collections:
            name = entry.get("name")
            if not name:
                continue
            attributes: dict[str, Any] = {"source": "qdrant"}
            try:
                detail = await self._http().get(f"/collections/{name}")
                if detail.status_code == 200:
                    result = detail.json().get("result", {})
                    attributes["points_count"] = result.get("points_count")
                    attributes["vector_size"] = _vector_size(result)
            except (httpx.TimeoutException, httpx.TransportError):
                # Detail is a nicety; a collection we can name is still worth
                # registering, and registering it is what makes it governable.
                pass
            discovered.append(
                DiscoveredAsset(
                    urn=self.urn_for(name),
                    name=name,
                    kind="vector_collection",
                    description="Qdrant collection.",
                    attributes=attributes,
                )
            )
        return discovered

    async def sample(self, urn: str, *, limit: int = 100) -> AsyncIterator[Sample]:
        """Scroll a page of points and yield their payloads.

        Vectors are excluded: they are not human-readable and the classifier
        cannot learn anything from them. The payload is where the copied
        personal data lives.
        """
        collection = urn.removeprefix("qdrant://")
        try:
            response = await self._http().post(
                f"/collections/{collection}/points/scroll",
                json={"limit": limit, "with_payload": True, "with_vector": False},
            )
            response.raise_for_status()
        except (httpx.TimeoutException, httpx.TransportError) as exc:
            raise AdapterUnavailable(f"qdrant at {self.base_url} is unreachable: {exc}") from exc

        result = response.json().get("result", {})
        points = result.get("points", [])
        payloads = [point.get("payload") for point in points if point.get("payload")]
        yield Sample(
            urn=urn,
            content=payloads,
            record_count=len(payloads),
            partial=result.get("next_page_offset") is not None,
        )


def _vector_size(result: dict[str, Any]) -> Any:
    """Extract the vector dimension from either config shape Qdrant returns."""
    vectors = (
        result.get("config", {}).get("params", {}).get("vectors")
        if isinstance(result.get("config"), dict)
        else None
    )
    if isinstance(vectors, dict):
        if "size" in vectors:
            return vectors["size"]
        # Named-vector collections: report the first configured vector's size.
        for value in vectors.values():
            if isinstance(value, dict) and "size" in value:
                return value["size"]
    return None
