"""The data-asset and principal catalog.

The catalog is what lets a policy say "PHI" instead of naming a table. An
enforcement point sends a URN; the catalog answers with the labels that URN
carries, and the policy engine reasons about those.

Two design choices carry weight here:

*Pattern assets.* A URN registered as ``pg://public.*`` classifies every table
beneath it. Without this, governing a database would mean registering every
table before it could be protected -- and the table nobody remembered to
register is exactly the one that leaks.

*Label provenance survives merging.* A scanner's inference and a steward's
assertion are stored as separate rows and reconciled on read, so re-running a
scan can never silently erase a human decision.
"""

from __future__ import annotations

import fnmatch
import uuid
from collections.abc import Iterable, Mapping, Sequence
from datetime import UTC, datetime
from typing import Any, cast

from sqlalchemy import CursorResult, Select, delete, or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from control_plane.classification import taxonomy
from control_plane.classification.scanner import ScanResult
from control_plane.models.catalog import AssetClassification, DataAsset, Principal

__all__ = ["SOURCE_PRECEDENCE", "CatalogService", "ResolvedAsset"]

#: Higher wins when two sources disagree about the same label.
SOURCE_PRECEDENCE: dict[str, int] = {
    "manual": 40,
    "imported": 30,
    "scan": 20,
    "inherited": 10,
}


class ResolvedAsset:
    """What the catalog knows about one URN, including inherited labels."""

    __slots__ = ("asset", "attributes", "kind", "labels", "matched_patterns", "urn")

    def __init__(
        self,
        urn: str,
        asset: DataAsset | None,
        labels: dict[str, float],
        matched_patterns: list[str],
        attributes: dict[str, Any],
        kind: str,
    ) -> None:
        self.urn = urn
        self.asset = asset
        self.labels = labels
        self.matched_patterns = matched_patterns
        self.attributes = attributes
        self.kind = kind

    @property
    def registered(self) -> bool:
        """False when the URN matched nothing at all in the catalog.

        Worth surfacing: an unregistered asset is not a safe asset, it is an
        unknown one, and a policy can be written to treat it accordingly.
        """
        return self.asset is not None or bool(self.matched_patterns)

    @property
    def label_keys(self) -> list[str]:
        return sorted(self.labels)

    def to_dict(self) -> dict[str, Any]:
        return {
            "urn": self.urn,
            "registered": self.registered,
            "kind": self.kind,
            "classifications": self.label_keys,
            "confidence": {k: round(v, 4) for k, v in sorted(self.labels.items())},
            "matched_patterns": self.matched_patterns,
            "attributes": self.attributes,
            "regulations": list(taxonomy.regulations_for(self.label_keys)),
        }


class CatalogService:
    """Catalog reads and writes for one session."""

    def __init__(self, session: AsyncSession) -> None:
        self._session = session

    # --- assets ------------------------------------------------------------ #

    async def get_asset(self, urn: str) -> DataAsset | None:
        return (
            await self._session.execute(select(DataAsset).where(DataAsset.urn == urn))
        ).scalar_one_or_none()

    async def list_assets(
        self,
        *,
        kind: str | None = None,
        owner: str | None = None,
        label: str | None = None,
        search: str | None = None,
        limit: int = 100,
        offset: int = 0,
    ) -> Sequence[DataAsset]:
        statement: Select[tuple[DataAsset]] = select(DataAsset).order_by(DataAsset.urn)
        if kind:
            statement = statement.where(DataAsset.kind == kind)
        if owner:
            statement = statement.where(DataAsset.owner == owner)
        if search:
            pattern = f"%{search}%"
            statement = statement.where(
                or_(
                    DataAsset.urn.ilike(pattern),
                    DataAsset.name.ilike(pattern),
                    DataAsset.description.ilike(pattern),
                )
            )
        if label:
            covered = taxonomy.expand(label) or {label}
            statement = statement.where(
                DataAsset.id.in_(
                    select(AssetClassification.asset_id).where(
                        AssetClassification.label.in_(sorted(covered))
                    )
                )
            )
        statement = statement.limit(min(limit, 500)).offset(max(0, offset))
        return (await self._session.execute(statement)).scalars().unique().all()

    async def upsert_asset(
        self,
        urn: str,
        *,
        name: str | None = None,
        kind: str | None = None,
        owner: str | None = None,
        description: str | None = None,
        attributes: Mapping[str, Any] | None = None,
    ) -> tuple[DataAsset, bool]:
        """Create or update an asset. Returns ``(asset, created)``."""
        asset = await self.get_asset(urn)
        created = asset is None
        if asset is None:
            asset = DataAsset(urn=urn, name=name or urn, kind=kind or _infer_kind(urn))
            self._session.add(asset)
        if name is not None:
            asset.name = name
        if kind is not None:
            asset.kind = kind
        if owner is not None:
            asset.owner = owner
        if description is not None:
            asset.description = description
        if attributes is not None:
            asset.attributes = dict(attributes)
        await self._session.flush()
        return asset, created

    async def delete_asset(self, urn: str) -> bool:
        asset = await self.get_asset(urn)
        if asset is None:
            return False
        await self._session.delete(asset)
        await self._session.flush()
        return True

    # --- classification ---------------------------------------------------- #

    async def classifications_for(self, asset_id: uuid.UUID) -> Sequence[AssetClassification]:
        """Every label row on one asset.

        Queried explicitly rather than through the relationship. A relationship
        access on a freshly flushed object triggers a lazy load, and a lazy load
        inside async code is an error rather than a slow path -- so the service
        never relies on one.
        """
        return (
            (
                await self._session.execute(
                    select(AssetClassification)
                    .where(AssetClassification.asset_id == asset_id)
                    .order_by(AssetClassification.label, AssetClassification.source)
                )
            )
            .scalars()
            .all()
        )

    async def set_classification(
        self,
        asset: DataAsset,
        label: str,
        *,
        source: str = "manual",
        confidence: float = 1.0,
        evidence: Mapping[str, Any] | None = None,
        asserted_by: str = "",
    ) -> AssetClassification:
        """Attach or refresh one label from one source."""
        if not taxonomy.is_known(label):
            raise ValueError(f"unknown classification label {label!r}")
        existing = (
            await self._session.execute(
                select(AssetClassification).where(
                    AssetClassification.asset_id == asset.id,
                    AssetClassification.label == label,
                    AssetClassification.source == source,
                )
            )
        ).scalar_one_or_none()
        if existing is not None:
            existing.confidence = confidence
            existing.evidence = dict(evidence or {})
            existing.asserted_by = asserted_by or existing.asserted_by
            await self._session.flush()
            return existing
        record = AssetClassification(
            asset_id=asset.id,
            label=label,
            source=source,
            confidence=confidence,
            evidence=dict(evidence or {}),
            asserted_by=asserted_by,
        )
        self._session.add(record)
        await self._session.flush()
        return record

    async def remove_classification(
        self, asset: DataAsset, label: str, *, source: str | None = None
    ) -> int:
        """Detach a label. Without ``source``, removes every source's assertion."""
        statement = delete(AssetClassification).where(
            AssetClassification.asset_id == asset.id, AssetClassification.label == label
        )
        if source is not None:
            statement = statement.where(AssetClassification.source == source)
        result = cast("CursorResult[Any]", await self._session.execute(statement))
        await self._session.flush()
        return int(result.rowcount or 0)

    async def apply_scan(
        self,
        asset: DataAsset,
        result: ScanResult,
        *,
        asserted_by: str = "scanner",
        min_confidence: float = 0.5,
    ) -> list[AssetClassification]:
        """Record what a scan found, keeping only masked evidence.

        Scan-sourced rows are replaced wholesale so that labels which no longer
        appear in the data stop being asserted, while ``manual`` rows are left
        untouched.
        """
        await self._session.execute(
            delete(AssetClassification).where(
                AssetClassification.asset_id == asset.id,
                AssetClassification.source == "scan",
            )
        )
        await self._session.flush()

        applied: list[AssetClassification] = []
        grouped: dict[str, list[Any]] = {}
        for finding in result.findings:
            if finding.confidence >= min_confidence:
                grouped.setdefault(finding.label, []).append(finding)

        for label, findings in grouped.items():
            best = max(f.confidence for f in findings)
            evidence = {
                "occurrences": len(findings),
                # Previews only. The catalog must never become a copy of the data.
                "samples": [f.preview for f in findings[:3]],
                "detectors": sorted({f.detector for f in findings}),
                "paths": sorted({f.path for f in findings if f.path})[:5],
            }
            applied.append(
                await self.set_classification(
                    asset,
                    label,
                    source="scan",
                    confidence=best,
                    evidence=evidence,
                    asserted_by=asserted_by,
                )
            )
        asset.last_scanned_at = datetime.now(UTC)
        await self._session.flush()
        return applied

    # --- resolution -------------------------------------------------------- #

    async def resolve(self, urn: str | None) -> ResolvedAsset:
        """Everything the catalog knows about ``urn``, including pattern matches."""
        if not urn:
            return ResolvedAsset("", None, {}, [], {}, "")

        exact = await self.get_asset(urn)
        labels: dict[str, float] = {}
        attributes: dict[str, Any] = {}
        matched_patterns: list[str] = []
        kind = exact.kind if exact else _infer_kind(urn)

        patterns = await self._matching_patterns(urn)
        # Least specific first, so an exact registration overwrites an inherited
        # label rather than the other way round.
        for pattern_asset in patterns:
            matched_patterns.append(pattern_asset.urn)
            attributes.update(pattern_asset.attributes or {})
            _merge_labels(labels, await self.classifications_for(pattern_asset.id))

        if exact is not None:
            attributes.update(exact.attributes or {})
            _merge_labels(labels, await self.classifications_for(exact.id))

        return ResolvedAsset(urn, exact, labels, matched_patterns, attributes, kind)

    async def _matching_patterns(self, urn: str) -> list[DataAsset]:
        """Registered wildcard assets whose pattern covers ``urn``.

        Glob matching happens in Python rather than SQL: the candidate set is the
        assets whose URN contains a wildcard, which is small, and doing it here
        keeps the semantics identical on Postgres and SQLite.
        """
        candidates = (
            (
                await self._session.execute(
                    select(DataAsset).where(
                        or_(DataAsset.urn.contains("*"), DataAsset.urn.contains("?"))
                    )
                )
            )
            .scalars()
            .unique()
            .all()
        )
        matched = [a for a in candidates if a.urn != urn and fnmatch.fnmatchcase(urn, a.urn)]
        # Shorter patterns are broader; apply them first.
        matched.sort(key=lambda a: (len(a.urn), a.urn))
        return matched

    # --- principals -------------------------------------------------------- #

    async def get_principal(self, external_id: str) -> Principal | None:
        return (
            await self._session.execute(
                select(Principal).where(Principal.external_id == external_id)
            )
        ).scalar_one_or_none()

    async def list_principals(
        self, *, type_: str | None = None, limit: int = 100, offset: int = 0
    ) -> Sequence[Principal]:
        statement = select(Principal).order_by(Principal.external_id)
        if type_:
            statement = statement.where(Principal.type == type_)
        statement = statement.limit(min(limit, 500)).offset(max(0, offset))
        return (await self._session.execute(statement)).scalars().all()

    async def upsert_principal(
        self,
        external_id: str,
        *,
        type_: str | None = None,
        display_name: str | None = None,
        description: str | None = None,
        attributes: Mapping[str, Any] | None = None,
    ) -> tuple[Principal, bool]:
        principal = await self.get_principal(external_id)
        created = principal is None
        if principal is None:
            principal = Principal(external_id=external_id, type=type_ or "unknown")
            self._session.add(principal)
        if type_ is not None:
            principal.type = type_
        if display_name is not None:
            principal.display_name = display_name
        if description is not None:
            principal.description = description
        if attributes is not None:
            principal.attributes = dict(attributes)
        await self._session.flush()
        return principal, created

    async def enrich_principal(
        self, external_id: str, supplied: Mapping[str, Any] | None = None
    ) -> dict[str, Any]:
        """Merge caller-supplied attributes with the catalog's own.

        Catalog attributes win. An enforcement point may add context the control
        plane does not have, but it must not be able to promote its own trust
        tier by asserting one in the request.
        """
        merged: dict[str, Any] = dict(supplied or {})
        principal = await self.get_principal(external_id)
        if principal is not None:
            merged.update(principal.attributes or {})
            merged.setdefault("display_name", principal.display_name)
            merged["registered"] = True
            merged["enabled"] = principal.enabled
        else:
            merged["registered"] = False
        return merged


def _merge_labels(labels: dict[str, float], records: Iterable[AssetClassification]) -> None:
    """Fold one asset's label rows in, keeping the highest-precedence assertion.

    A steward's manual assertion outranks a scanner's inference at the same
    label, so re-running a scan cannot quietly downgrade a human decision.
    """
    ranked: dict[str, tuple[int, float]] = {}
    for record in records:
        rank = SOURCE_PRECEDENCE.get(record.source, 0)
        current = ranked.get(record.label)
        if current is None or (rank, record.confidence) > current:
            ranked[record.label] = (rank, record.confidence)
    for label, (_, confidence) in ranked.items():
        labels[label] = max(labels.get(label, 0.0), confidence)


def _infer_kind(urn: str) -> str:
    """A best-effort asset kind from the URN scheme."""
    scheme = urn.split("://", 1)[0].lower() if "://" in urn else ""
    return {
        "pg": "table",
        "postgres": "table",
        "postgresql": "table",
        "mysql": "table",
        "qdrant": "vector_collection",
        "pgvector": "vector_collection",
        "chroma": "vector_collection",
        "weaviate": "vector_collection",
        "s3": "object_store",
        "gs": "object_store",
        "file": "file",
        "mongodb": "collection",
        "kafka": "stream",
        "model": "model",
        "mcp": "tool",
        "http": "api",
        "https": "api",
    }.get(scheme, "unknown")
