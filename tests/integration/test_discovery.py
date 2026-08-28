"""Discovery: the path from an adapter to a populated catalog.

Driven by fake adapters, so the suite needs no live Postgres or Qdrant. The
adapters' own query construction is covered by their unit tests; what is under
test here is what the service does with what they return.
"""

from __future__ import annotations

from collections.abc import AsyncIterator, Sequence

import pytest
from sqlalchemy import select

from control_plane.adapters.base import AdapterUnavailable, DiscoveredAsset, Sample
from control_plane.audit.service import AuditService
from control_plane.catalog.discovery import DiscoveryService
from control_plane.catalog.service import CatalogService
from control_plane.models.catalog import AssetClassification, DataAsset


class FakeAdapter:
    """An adapter with a scripted answer, and optional failures."""

    name = "fake"

    def __init__(
        self,
        assets: Sequence[DiscoveredAsset] = (),
        samples: dict[str, object] | None = None,
        *,
        discover_error: str | None = None,
        sample_errors: Sequence[str] = (),
        partial: bool = False,
    ) -> None:
        self._assets = list(assets)
        self._samples = samples or {}
        self._discover_error = discover_error
        self._sample_errors = set(sample_errors)
        self._partial = partial
        self.sampled: list[str] = []

    async def health(self) -> bool:
        return self._discover_error is None

    async def discover(self) -> Sequence[DiscoveredAsset]:
        if self._discover_error:
            raise AdapterUnavailable(self._discover_error)
        return list(self._assets)

    async def sample(self, urn: str, *, limit: int = 100) -> AsyncIterator[Sample]:
        self.sampled.append(urn)
        if urn in self._sample_errors:
            raise AdapterUnavailable(f"cannot read {urn}")
        content = self._samples.get(urn)
        if content is None:
            return
        yield Sample(urn=urn, content=content, record_count=1, partial=self._partial)


def asset(urn: str, **kwargs) -> DiscoveredAsset:
    return DiscoveredAsset(
        urn=urn,
        name=kwargs.pop("name", urn.rsplit(".", 1)[-1]),
        kind=kwargs.pop("kind", "table"),
        **kwargs,
    )


CUSTOMERS = asset("pg://public.customers", suggested_labels=("pii.email", "pii.ssn"))
ORDERS = asset("pg://public.orders")
AUDIT = asset("pg://audit.events")


@pytest.fixture
def service(session):
    return DiscoveryService(session=session)


class TestRegistration:
    async def test_discovered_assets_land_in_the_catalog(self, service, session) -> None:
        report = await service.run(FakeAdapter([CUSTOMERS, ORDERS]), source="warehouse")

        assert report.discovered == 2
        assert set(report.created) == {"pg://public.customers", "pg://public.orders"}
        stored = (await session.execute(select(DataAsset))).scalars().all()
        assert {a.urn for a in stored} == set(report.created)

    async def test_the_adapter_is_recorded_on_each_asset(self, service, session) -> None:
        await service.run(FakeAdapter([ORDERS]), source="warehouse")
        stored = (await session.execute(select(DataAsset))).scalars().one()
        assert stored.attributes["discovered_by"] == "fake"

    async def test_ownership_can_be_set_at_discovery(self, service, session) -> None:
        await service.run(FakeAdapter([ORDERS]), source="w", owner="data-platform")
        stored = (await session.execute(select(DataAsset))).scalars().one()
        assert stored.owner == "data-platform"

    async def test_re_running_updates_rather_than_duplicates(self, service, session) -> None:
        await service.run(FakeAdapter([CUSTOMERS]), source="w")
        second = await service.run(FakeAdapter([CUSTOMERS]), source="w")

        assert second.created == ()
        assert second.updated == ("pg://public.customers",)
        assert len((await session.execute(select(DataAsset))).scalars().all()) == 1


class TestImportedLabels:
    async def test_source_assertions_become_imported_labels(self, service, session) -> None:
        await service.run(FakeAdapter([CUSTOMERS]), source="w")

        rows = (await session.execute(select(AssetClassification))).scalars().all()
        assert {r.label for r in rows} == {"pii.email", "pii.ssn"}
        assert {r.source for r in rows} == {"imported"}

    async def test_an_imported_label_does_not_outrank_a_steward(self, service, session) -> None:
        """A column comment is evidence. It is not a data steward."""
        catalog = CatalogService(session)
        existing, _ = await catalog.upsert_asset("pg://public.customers")
        await catalog.set_classification(
            existing, "confidential.legal", source="manual", asserted_by="user:counsel"
        )

        await service.run(FakeAdapter([CUSTOMERS]), source="w")

        rows = await catalog.classifications_for(existing.id)
        by_source = {r.source for r in rows}
        assert "manual" in by_source and "imported" in by_source
        assert "confidential.legal" in {r.label for r in rows}

    async def test_labels_outside_the_taxonomy_are_skipped(self, service, session) -> None:
        """A source system's vocabulary is not ours; inventing a label is worse."""
        await service.run(
            FakeAdapter([asset("pg://x.y", suggested_labels=("pii.email", "vendor.mystery"))]),
            source="w",
        )
        rows = (await session.execute(select(AssetClassification))).scalars().all()
        assert {r.label for r in rows} == {"pii.email"}

    async def test_the_report_names_what_was_imported(self, service) -> None:
        report = await service.run(FakeAdapter([CUSTOMERS]), source="w")
        assert report.outcomes[0].labels_imported == ("pii.email", "pii.ssn")


class TestSampling:
    SAMPLES = {
        "pg://public.customers": [{"email": "jane.doe@acme.com", "ssn": "536-90-4432"}],
        "pg://public.orders": [{"total": 42, "sku": "ABC-1"}],
    }

    async def test_scanning_is_off_unless_asked(self, service) -> None:
        adapter = FakeAdapter([CUSTOMERS], self.SAMPLES)
        await service.run(adapter, source="w")
        assert adapter.sampled == []

    async def test_a_sample_produces_scan_labels(self, service, session) -> None:
        report = await service.run(
            FakeAdapter([ORDERS, CUSTOMERS], self.SAMPLES), source="w", scan=True
        )
        customers = next(o for o in report.outcomes if o.urn == "pg://public.customers")
        assert set(customers.labels_scanned) == {"pii.email", "pii.ssn"}

        rows = (await session.execute(select(AssetClassification))).scalars().all()
        assert "scan" in {r.source for r in rows}

    async def test_an_asset_with_nothing_in_it_gets_no_labels(self, service) -> None:
        report = await service.run(FakeAdapter([ORDERS], self.SAMPLES), source="w", scan=True)
        assert report.outcomes[0].labels_scanned == ()
        assert report.outcomes[0].sampled is True

    async def test_only_previews_are_stored(self, service, session) -> None:
        await service.run(FakeAdapter([CUSTOMERS], self.SAMPLES), source="w", scan=True)
        rows = (await session.execute(select(AssetClassification))).scalars().all()
        evidence = str([r.evidence for r in rows])
        assert "jane.doe@acme.com" not in evidence
        assert "536-90-4432" not in evidence

    async def test_a_partial_sample_is_flagged(self, service) -> None:
        """A clean scan of part of a table is not proof the table is clean."""
        report = await service.run(
            FakeAdapter([ORDERS], self.SAMPLES, partial=True), source="w", scan=True
        )
        assert report.outcomes[0].partial_sample is True

    async def test_confidence_threshold_is_honoured(self, service) -> None:
        report = await service.run(
            FakeAdapter([ORDERS], {"pg://public.orders": [{"host": "203.0.113.9"}]}),
            source="w",
            scan=True,
            min_confidence=0.95,
        )
        assert report.outcomes[0].labels_scanned == ()


class TestSelection:
    async def test_exclude_keeps_discovery_away_from_a_table(self, service) -> None:
        report = await service.run(
            FakeAdapter([CUSTOMERS, AUDIT]), source="w", exclude=["pg://audit.*"]
        )
        assert [o.urn for o in report.outcomes] == ["pg://public.customers"]

    async def test_an_excluded_asset_is_never_sampled(self, service) -> None:
        """Exclusion is the control that keeps a scanner out of a secrets table."""
        adapter = FakeAdapter([CUSTOMERS, AUDIT], {"pg://audit.events": [{"x": 1}]})
        await service.run(adapter, source="w", scan=True, exclude=["pg://audit.*"])
        assert "pg://audit.events" not in adapter.sampled

    async def test_include_narrows_to_a_subset(self, service) -> None:
        report = await service.run(
            FakeAdapter([CUSTOMERS, ORDERS, AUDIT]), source="w", include=["pg://public.*"]
        )
        assert len(report.outcomes) == 2

    async def test_exclusion_beats_inclusion(self, service) -> None:
        report = await service.run(
            FakeAdapter([CUSTOMERS, ORDERS]),
            source="w",
            include=["pg://public.*"],
            exclude=["*.customers"],
        )
        assert [o.urn for o in report.outcomes] == ["pg://public.orders"]

    async def test_a_runaway_discovery_is_capped_and_says_so(self, service) -> None:
        many = [asset(f"pg://public.t{i}") for i in range(20)]
        report = await service.run(FakeAdapter(many), source="w", max_assets=5)
        assert report.discovered == 5
        assert report.truncated is True


class TestDryRun:
    async def test_it_writes_nothing(self, service, session) -> None:
        report = await service.run(
            FakeAdapter([CUSTOMERS], TestSampling.SAMPLES), source="w", scan=True, dry_run=True
        )
        assert report.dry_run is True
        assert (await session.execute(select(DataAsset))).scalars().all() == []
        assert (await session.execute(select(AssetClassification))).scalars().all() == []

    async def test_it_does_not_read_the_data_either(self, service) -> None:
        adapter = FakeAdapter([CUSTOMERS], TestSampling.SAMPLES)
        await service.run(adapter, source="w", scan=True, dry_run=True)
        assert adapter.sampled == []

    async def test_it_still_previews_what_would_change(self, service, session) -> None:
        await CatalogService(session).upsert_asset("pg://public.orders")
        report = await service.run(FakeAdapter([CUSTOMERS, ORDERS]), source="w", dry_run=True)
        assert report.created == ("pg://public.customers",)
        assert report.updated == ("pg://public.orders",)

    async def test_it_seals_no_audit_record(self, service, session, audit_key) -> None:
        await service.run(FakeAdapter([CUSTOMERS]), source="w", dry_run=True)
        assert await AuditService(session, key=audit_key).count() == 0


class TestFailureIsolation:
    async def test_an_unreachable_source_reports_rather_than_raises(self, service) -> None:
        report = await service.run(
            FakeAdapter(discover_error="connection refused"), source="warehouse"
        )
        assert report.discovered == 0
        assert "connection refused" in report.errors[0]

    async def test_one_unreadable_table_does_not_stop_the_run(self, service, session) -> None:
        adapter = FakeAdapter(
            [CUSTOMERS, ORDERS],
            TestSampling.SAMPLES,
            sample_errors=["pg://public.customers"],
        )
        report = await service.run(adapter, source="w", scan=True)

        assert len(report.failed) == 1
        assert "sampling failed" in report.failed[0].error
        assert report.outcomes[1].ok is True
        # The unreadable asset is still catalogued: knowing it exists matters.
        stored = {a.urn for a in (await session.execute(select(DataAsset))).scalars().all()}
        assert "pg://public.customers" in stored


class TestReporting:
    async def test_the_summary_aggregates_labels_and_regulations(self, service) -> None:
        report = await service.run(FakeAdapter([CUSTOMERS]), source="w")
        summary = report.summary()
        assert summary["label_counts"] == {"pii.email": 1, "pii.ssn": 1}
        assert "GDPR" in summary["regulations"]

    async def test_one_audit_record_per_run_not_per_asset(
        self, service, session, audit_key
    ) -> None:
        """Registering four hundred tables is one operator action."""
        await service.run(FakeAdapter([asset(f"pg://p.t{i}") for i in range(10)]), source="w")

        audit = AuditService(session, key=audit_key)
        records = await audit.list_records(limit=50)
        assert len(records) == 1
        assert records[0].event == "catalog.discovered"
        assert records[0].payload["discovered"] == 10
        assert (await audit.verify()).valid is True

    async def test_the_audit_record_names_what_became_classified(
        self, service, session, audit_key
    ) -> None:
        await service.run(FakeAdapter([CUSTOMERS, ORDERS]), source="warehouse")
        record = (await AuditService(session, key=audit_key).list_records(limit=1))[0]
        assert record.subject == "warehouse"
        assert record.payload["classified_urns"] == ["pg://public.customers"]
