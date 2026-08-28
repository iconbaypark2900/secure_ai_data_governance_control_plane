"""Populating the catalog from a system that actually holds data.

Adapters could always enumerate and sample; nothing ever called them, so the
catalog could only be filled in by hand. This is the path between the two.

A discovery run does up to three things per asset:

1. **Register** it, so the URN resolves to something rather than to "unknown".
2. **Import** whatever the source system already asserts -- a column comment
   saying ``ssn``, a tag, a bucket policy. Recorded with source ``imported``,
   which outranks a scanner's guess and is outranked by a steward's assertion.
3. **Sample and classify** it, if asked. This is where an unregistered vector
   collection turns out to be full of customer emails.

Three properties are load-bearing:

*One asset's failure is not the run's failure.* A table the credentials cannot
read must not stop the other four hundred from being catalogued. Errors are
collected and reported, never raised.

*Nothing a human asserted is overwritten.* Label provenance already ranks
``manual`` above ``imported`` above ``scan``, so re-running discovery cannot
quietly undo a steward's decision.

*Dry run means dry.* Previewing a run against an unfamiliar database is the
normal first step, and it must not write anything at all.
"""

from __future__ import annotations

import fnmatch
import time
from collections.abc import Sequence
from dataclasses import dataclass, field
from typing import Any

import structlog
from sqlalchemy.ext.asyncio import AsyncSession

from control_plane.adapters.base import Adapter, AdapterError, DiscoveredAsset
from control_plane.audit.chain import AuditEvent
from control_plane.audit.service import AuditService
from control_plane.catalog.service import CatalogService
from control_plane.classification import taxonomy
from control_plane.classification.scanner import Scanner

__all__ = ["DEFAULT_MAX_ASSETS", "AssetOutcome", "DiscoveryReport", "DiscoveryService"]

log = structlog.get_logger(__name__)

#: A discovery run against an unfamiliar warehouse should stop somewhere rather
#: than register fifty thousand tables nobody asked about.
DEFAULT_MAX_ASSETS = 500

#: Sampling reads real data into memory. Keep the window small by default.
DEFAULT_SAMPLE_LIMIT = 100

#: Below this, a scan finding is noise rather than a classification.
DEFAULT_MIN_CONFIDENCE = 0.6

#: How many newly-classified URNs to name in the audit record before summarising.
AUDIT_URN_SAMPLE = 25


@dataclass(frozen=True, slots=True)
class AssetOutcome:
    """What happened to one asset."""

    urn: str
    name: str = ""
    kind: str = ""
    created: bool = False
    #: Labels the source system itself asserted.
    labels_imported: tuple[str, ...] = ()
    #: Labels inferred by scanning a sample.
    labels_scanned: tuple[str, ...] = ()
    sampled: bool = False
    records_sampled: int = 0
    #: Set when the sample did not cover the whole asset, so a clean scan is not
    #: mistaken for proof that the asset is clean.
    partial_sample: bool = False
    error: str | None = None

    @property
    def ok(self) -> bool:
        return self.error is None

    @property
    def labels(self) -> tuple[str, ...]:
        return tuple(sorted({*self.labels_imported, *self.labels_scanned}))

    def to_dict(self) -> dict[str, Any]:
        return {
            "urn": self.urn,
            "name": self.name,
            "kind": self.kind,
            "created": self.created,
            "labels_imported": list(self.labels_imported),
            "labels_scanned": list(self.labels_scanned),
            "sampled": self.sampled,
            "records_sampled": self.records_sampled,
            "partial_sample": self.partial_sample,
            "error": self.error,
        }


@dataclass(frozen=True, slots=True)
class DiscoveryReport:
    """The outcome of one run."""

    source: str
    adapter: str
    dry_run: bool = False
    scanned: bool = False
    outcomes: tuple[AssetOutcome, ...] = ()
    #: Failures that stopped the run rather than one asset.
    errors: tuple[str, ...] = ()
    #: Set when the adapter offered more assets than max_assets allowed.
    truncated: bool = False
    duration_ms: float = 0.0

    @property
    def discovered(self) -> int:
        return len(self.outcomes)

    @property
    def created(self) -> tuple[str, ...]:
        return tuple(o.urn for o in self.outcomes if o.created and o.ok)

    @property
    def updated(self) -> tuple[str, ...]:
        return tuple(o.urn for o in self.outcomes if not o.created and o.ok)

    @property
    def failed(self) -> tuple[AssetOutcome, ...]:
        return tuple(o for o in self.outcomes if not o.ok)

    @property
    def classified(self) -> tuple[AssetOutcome, ...]:
        """Assets that came out of this run carrying at least one label."""
        return tuple(o for o in self.outcomes if o.labels)

    @property
    def label_counts(self) -> dict[str, int]:
        counts: dict[str, int] = {}
        for outcome in self.outcomes:
            for label in outcome.labels:
                counts[label] = counts.get(label, 0) + 1
        return dict(sorted(counts.items()))

    @property
    def regulations(self) -> tuple[str, ...]:
        return taxonomy.regulations_for(
            {label for outcome in self.outcomes for label in outcome.labels}
        )

    def summary(self) -> dict[str, Any]:
        return {
            "source": self.source,
            "adapter": self.adapter,
            "dry_run": self.dry_run,
            "scanned": self.scanned,
            "discovered": self.discovered,
            "created": len(self.created),
            "updated": len(self.updated),
            "failed": len(self.failed),
            "classified": len(self.classified),
            "label_counts": self.label_counts,
            "regulations": list(self.regulations),
            "truncated": self.truncated,
            "errors": list(self.errors),
            "duration_ms": self.duration_ms,
        }

    def to_dict(self) -> dict[str, Any]:
        return {**self.summary(), "assets": [o.to_dict() for o in self.outcomes]}


@dataclass
class DiscoveryService:
    """Runs an adapter and folds what it finds into the catalog."""

    session: AsyncSession
    scanner: Scanner = field(default_factory=Scanner)
    _catalog: CatalogService = field(init=False, repr=False)
    _audit: AuditService = field(init=False, repr=False)

    def __post_init__(self) -> None:
        self._catalog = CatalogService(self.session)
        self._audit = AuditService(self.session)

    async def run(
        self,
        adapter: Adapter,
        *,
        source: str = "",
        scan: bool = False,
        dry_run: bool = False,
        max_assets: int = DEFAULT_MAX_ASSETS,
        sample_limit: int = DEFAULT_SAMPLE_LIMIT,
        min_confidence: float = DEFAULT_MIN_CONFIDENCE,
        include: Sequence[str] = (),
        exclude: Sequence[str] = (),
        owner: str = "",
        actor: str = "discovery",
    ) -> DiscoveryReport:
        """Enumerate, register, and optionally classify.

        ``include`` and ``exclude`` are URN globs. Exclusion wins, and it matters
        more than it looks: sampling reads real rows, and there are tables --
        the audit log, a secrets table, anything under legal hold -- that should
        be catalogued without ever being read.
        """
        started = time.perf_counter()
        source_name = source or getattr(adapter, "name", "unknown")
        adapter_name = getattr(adapter, "name", "unknown")

        try:
            found = list(await adapter.discover())
        except AdapterError as exc:
            # Reaching the source at all is the run failing, not one asset.
            log.error("discovery_failed", source=source_name, error=str(exc))
            return DiscoveryReport(
                source=source_name,
                adapter=adapter_name,
                dry_run=dry_run,
                scanned=scan,
                errors=(str(exc),),
                duration_ms=round((time.perf_counter() - started) * 1000, 3),
            )

        selected = [a for a in found if _wanted(a.urn, include, exclude)]
        truncated = len(selected) > max_assets
        if truncated:
            log.warning(
                "discovery_truncated",
                source=source_name,
                found=len(selected),
                max_assets=max_assets,
            )
            selected = selected[:max_assets]

        outcomes = [
            await self._absorb(
                adapter,
                asset,
                scan=scan,
                dry_run=dry_run,
                sample_limit=sample_limit,
                min_confidence=min_confidence,
                owner=owner,
                actor=actor,
            )
            for asset in selected
        ]

        report = DiscoveryReport(
            source=source_name,
            adapter=adapter_name,
            dry_run=dry_run,
            scanned=scan,
            outcomes=tuple(outcomes),
            truncated=truncated,
            duration_ms=round((time.perf_counter() - started) * 1000, 3),
        )

        if not dry_run:
            await self._record(report, actor=actor)
        return report

    async def _absorb(
        self,
        adapter: Adapter,
        asset: DiscoveredAsset,
        *,
        scan: bool,
        dry_run: bool,
        sample_limit: int,
        min_confidence: float,
        owner: str,
        actor: str,
    ) -> AssetOutcome:
        """Register one asset, import its labels, and optionally classify it."""
        imported = tuple(label for label in asset.suggested_labels if taxonomy.is_known(label))
        unknown = [label for label in asset.suggested_labels if not taxonomy.is_known(label)]
        if unknown:
            # A source system's vocabulary is not ours. Say so rather than
            # silently dropping the hint or inventing a label for it.
            log.info(
                "discovery_unknown_labels",
                urn=asset.urn,
                labels=unknown,
                hint="add them to the taxonomy or map them in the adapter",
            )

        if dry_run:
            existing = await self._catalog.get_asset(asset.urn)
            scanned: tuple[str, ...] = ()
            return AssetOutcome(
                urn=asset.urn,
                name=asset.name,
                kind=asset.kind,
                created=existing is None,
                labels_imported=imported,
                labels_scanned=scanned,
                sampled=False,
            )

        try:
            record, created = await self._catalog.upsert_asset(
                asset.urn,
                name=asset.name or asset.urn,
                kind=asset.kind,
                owner=owner or asset.owner or None,
                description=asset.description or None,
                attributes={**asset.attributes, "discovered_by": adapter.name},
            )
            for label in imported:
                await self._catalog.set_classification(
                    record,
                    label,
                    source="imported",
                    confidence=1.0,
                    evidence={"asserted_by_source": adapter.name},
                    asserted_by=actor,
                )
        except Exception as exc:
            return AssetOutcome(urn=asset.urn, name=asset.name, kind=asset.kind, error=str(exc))

        if not scan:
            return AssetOutcome(
                urn=asset.urn,
                name=asset.name,
                kind=asset.kind,
                created=created,
                labels_imported=imported,
            )

        try:
            sampled_labels, count, partial = await self._sample_and_classify(
                adapter,
                record,
                sample_limit=sample_limit,
                min_confidence=min_confidence,
                actor=actor,
            )
        except Exception as exc:
            return AssetOutcome(
                urn=asset.urn,
                name=asset.name,
                kind=asset.kind,
                created=created,
                labels_imported=imported,
                error=f"registered, but sampling failed: {exc}",
            )

        return AssetOutcome(
            urn=asset.urn,
            name=asset.name,
            kind=asset.kind,
            created=created,
            labels_imported=imported,
            labels_scanned=sampled_labels,
            sampled=True,
            records_sampled=count,
            partial_sample=partial,
        )

    async def _sample_and_classify(
        self,
        adapter: Adapter,
        record: Any,
        *,
        sample_limit: int,
        min_confidence: float,
        actor: str,
    ) -> tuple[tuple[str, ...], int, bool]:
        """Read a sample, scan it, and record what it implies.

        The sample is scanned and dropped. Only masked previews and counts reach
        the catalog, so profiling an asset does not make the catalog a copy of it.
        """
        labels: set[str] = set()
        records = 0
        partial = False

        async for sample in adapter.sample(record.urn, limit=sample_limit):
            result = self.scanner.scan_structured(sample.content)
            applied = await self._catalog.apply_scan(
                record, result, asserted_by=actor, min_confidence=min_confidence
            )
            labels.update(row.label for row in applied)
            records += sample.record_count
            partial = partial or sample.partial

        return tuple(sorted(labels)), records, partial

    async def _record(self, report: DiscoveryReport, *, actor: str) -> None:
        """Seal one audit entry for the run.

        One record, not one per asset. Registering four hundred tables is a
        single operator action, and a chain that turns it into four hundred
        entries buries the changes a reader is actually looking for. The
        newly-classified URNs are named -- capped -- because *those* are the
        posture change worth reading.
        """
        classified = [o.urn for o in report.classified]
        await self._audit.append(
            AuditEvent.CATALOG_DISCOVERED,
            actor=actor,
            subject=report.source,
            payload={
                **report.summary(),
                "classified_urns": classified[:AUDIT_URN_SAMPLE],
                "classified_urns_omitted": max(0, len(classified) - AUDIT_URN_SAMPLE),
            },
        )


def _wanted(urn: str, include: Sequence[str], exclude: Sequence[str]) -> bool:
    """Whether a URN survives the include/exclude globs. Exclusion wins."""
    if any(fnmatch.fnmatchcase(urn, pattern) for pattern in exclude):
        return False
    if not include:
        return True
    return any(fnmatch.fnmatchcase(urn, pattern) for pattern in include)
