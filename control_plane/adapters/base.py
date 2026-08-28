"""The contract an adapter implements.

An adapter connects the control plane to a system that actually holds data. It
does two jobs and no more:

*Discovery* -- enumerate what exists, so the catalog is not maintained by hand.
The asset nobody remembered to register is the one that leaks, so the catalog
has to be able to populate itself.

*Sampling* -- fetch representative content so the classifier can infer what an
asset holds. Samples are read into memory, scanned, and dropped; only masked
previews and counts are ever stored.

Adapters do not enforce. Enforcement happens at the enforcement point, on the
data path. An adapter that could also block would be a second, weaker policy
engine, and two policy engines disagree eventually.
"""

from __future__ import annotations

from collections.abc import AsyncIterator, Sequence
from dataclasses import dataclass, field
from typing import Any, Protocol, runtime_checkable

__all__ = ["Adapter", "AdapterError", "AdapterUnavailable", "DiscoveredAsset", "Sample"]


class AdapterError(RuntimeError):
    """An adapter could not complete an operation."""


class AdapterUnavailable(AdapterError):
    """The backing system could not be reached.

    Distinct from other failures because it is usually a configuration problem
    rather than a defect, and the operator wants to be told which.
    """


@dataclass(frozen=True, slots=True)
class DiscoveredAsset:
    """Something an adapter found."""

    urn: str
    name: str
    kind: str
    owner: str = ""
    description: str = ""
    attributes: dict[str, Any] = field(default_factory=dict)
    #: Labels the source system itself asserts -- a column comment, a tag, a
    #: bucket policy. Recorded with source "imported" so provenance survives.
    suggested_labels: tuple[str, ...] = ()

    def to_dict(self) -> dict[str, Any]:
        return {
            "urn": self.urn,
            "name": self.name,
            "kind": self.kind,
            "owner": self.owner,
            "description": self.description,
            "attributes": self.attributes,
            "suggested_labels": list(self.suggested_labels),
        }


@dataclass(frozen=True, slots=True)
class Sample:
    """Representative content drawn from one asset."""

    urn: str
    content: Any
    #: How many records the sample covers, for reporting coverage honestly.
    record_count: int = 0
    #: Set when the asset was larger than the sample, so a clean scan is not
    #: mistaken for proof that the asset is clean.
    partial: bool = True


@runtime_checkable
class Adapter(Protocol):
    """What every adapter provides."""

    name: str

    async def health(self) -> bool:
        """Whether the backing system is reachable."""

    async def discover(self) -> Sequence[DiscoveredAsset]:
        """Enumerate the assets this adapter can see."""

    def sample(self, urn: str, *, limit: int = 100) -> AsyncIterator[Sample]:
        """Yield representative content from one asset."""
