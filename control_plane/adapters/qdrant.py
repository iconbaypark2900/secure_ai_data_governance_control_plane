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
    AdapterError,
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

    async def _get(self, path: str) -> Any:
        """GET and decode, translating every failure into the adapter contract.

        Callers up the stack catch ``AdapterError``; anything else escapes as a
        traceback and takes the whole discovery run with it. Qdrant answers with
        status codes far more often than it refuses a connection -- a stale API
        key, a URL pointing at a different service, a collection deleted between
        enumeration and sampling -- so those have to arrive as adapter errors.
        """
        try:
            response = await self._http().get(path)
        except (httpx.TimeoutException, httpx.TransportError) as exc:
            raise AdapterUnavailable(f"qdrant at {self.base_url} is unreachable: {exc}") from exc
        return self._decode(response, path)

    def _decode(self, response: httpx.Response, path: str) -> Any:
        if response.status_code in (401, 403):
            raise AdapterUnavailable(
                f"qdrant at {self.base_url} rejected our credentials for {path} "
                f"({response.status_code}): check the configured api_key."
            )
        if response.status_code >= 500:
            raise AdapterUnavailable(
                f"qdrant at {self.base_url} failed on {path}: {response.status_code}."
            )
        if response.status_code >= 400:
            raise AdapterError(f"qdrant refused {path}: {response.status_code}.")
        try:
            body = response.json()
        except ValueError as exc:
            raise AdapterError(
                f"{self.base_url} answered {path} with something that is not JSON; "
                f"is this really a qdrant instance?"
            ) from exc
        if not isinstance(body, dict) or "result" not in body:
            raise AdapterError(
                f"{self.base_url} answered {path} without a 'result' key; "
                f"is this really a qdrant instance?"
            )
        return body["result"]

    async def health(self) -> bool:
        """Whether this adapter can actually do its job against the instance.

        Deliberately not ``/healthz``. That endpoint answers 200 without an API
        key even on an instance that requires one -- verified against qdrant
        1.19 -- so a liveness probe reports green on the single most common
        misconfiguration, and discovery then fails on the next call. Health here
        means authorised enumeration, because that is what discovery needs.
        """
        try:
            await self._get("/collections")
        except AdapterError:
            return False
        return True

    async def discover(self) -> Sequence[DiscoveredAsset]:
        """List collections, with their vector configuration as attributes."""
        result = await self._get("/collections")
        collections = result.get("collections", []) if isinstance(result, dict) else []
        discovered: list[DiscoveredAsset] = []
        for entry in collections:
            name = entry.get("name")
            if not name:
                continue
            attributes: dict[str, Any] = {"source": "qdrant"}
            try:
                detail = await self._get(f"/collections/{name}")
            except AdapterError:
                # Detail is a nicety; a collection we can name is still worth
                # registering, and registering it is what makes it governable.
                detail = None
            if isinstance(detail, dict):
                attributes["points_count"] = detail.get("points_count")
                attributes["vector_size"] = _vector_size(detail)
                names = _vector_names(detail)
                if names:
                    # Named vectors carry the embedding model. Which model read
                    # the data is a governance fact: an externally hosted one
                    # means the collection is a record of an egress.
                    attributes["vector_names"] = names
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
        path = f"/collections/{collection}/points/scroll"
        try:
            response = await self._http().post(
                path,
                json={"limit": limit, "with_payload": True, "with_vector": False},
            )
        except (httpx.TimeoutException, httpx.TransportError) as exc:
            raise AdapterUnavailable(f"qdrant at {self.base_url} is unreachable: {exc}") from exc

        result = self._decode(response, path)
        points = result.get("points", []) if isinstance(result, dict) else []
        payloads = [point.get("payload") for point in points if point.get("payload")]
        yield Sample(
            urn=urn,
            content=payloads,
            record_count=len(payloads),
            partial=isinstance(result, dict) and result.get("next_page_offset") is not None,
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


def _vector_names(result: dict[str, Any]) -> list[str]:
    """The configured vector names, which in practice name the embedding model."""
    config = result.get("config")
    vectors = config.get("params", {}).get("vectors") if isinstance(config, dict) else None
    if not isinstance(vectors, dict) or "size" in vectors:
        return []
    return sorted(k for k, v in vectors.items() if isinstance(v, dict))
