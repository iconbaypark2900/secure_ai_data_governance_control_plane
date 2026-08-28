"""The Postgres adapter against a real Postgres.

These exist because the adapter was written, unit-tested, and shipped without
anything ever calling ``discover()`` -- and the first real call failed on a bind
parameter. Query construction is not something a fake can check.

Skipped unless CP_TEST_POSTGRES_URL points at a database this suite may destroy.
"""

from __future__ import annotations

import pytest
from sqlalchemy import text

from control_plane.adapters.postgres import PostgresAdapter

pytestmark = pytest.mark.integration

SCHEMA = """
CREATE TABLE public.customers (
  id serial PRIMARY KEY,
  full_name text,
  email text,
  ssn text
);
COMMENT ON TABLE public.customers IS 'One row per customer.';
COMMENT ON COLUMN public.customers.ssn IS 'sensitive: pii.ssn';

CREATE TABLE public.orders (id serial PRIMARY KEY, sku text, quantity int);
CREATE VIEW public.recent_orders AS SELECT * FROM public.orders;

INSERT INTO public.customers (full_name, email, ssn)
VALUES ('Jane Doe', 'jane.doe@acme.com', '536-90-4432'),
       ('Sam Patel', 'sam.patel@example.org', '457-55-5462');
INSERT INTO public.orders (sku, quantity) VALUES ('ABC-1', 2), ('XYZ-9', 1);
"""


@pytest.fixture
async def warehouse(pg_engine):
    """A small warehouse to point the adapter at."""
    async with pg_engine.begin() as connection:
        # Drop every non-system schema, not just public: the adapter enumerates
        # the whole database, so anything left behind by another run would show
        # up in the results and make this test depend on execution order.
        leftovers = (
            (
                await connection.execute(
                    text(
                        "SELECT nspname FROM pg_namespace "
                        "WHERE nspname NOT LIKE 'pg\\_%' AND nspname <> 'information_schema'"
                    )
                )
            )
            .scalars()
            .all()
        )
        for schema in leftovers:
            await connection.execute(text(f'DROP SCHEMA IF EXISTS "{schema}" CASCADE'))
        await connection.execute(text("CREATE SCHEMA public"))
        for statement in filter(None, (s.strip() for s in SCHEMA.split(";"))):
            await connection.execute(text(statement))
    return PostgresAdapter(engine=pg_engine)


class TestDiscovery:
    async def test_health(self, warehouse) -> None:
        assert await warehouse.health() is True

    async def test_it_enumerates_tables_and_views(self, warehouse) -> None:
        """The regression: NOT IN over a tuple needs an expanding bind."""
        found = {a.urn: a for a in await warehouse.discover()}
        assert "pg://public.customers" in found
        assert "pg://public.orders" in found
        assert "pg://public.recent_orders" in found

    async def test_system_schemas_are_excluded(self, warehouse) -> None:
        urns = [a.urn for a in await warehouse.discover()]
        assert not any(".pg_" in urn or "information_schema" in urn for urn in urns)

    async def test_kinds_are_distinguished(self, warehouse) -> None:
        found = {a.urn: a for a in await warehouse.discover()}
        assert found["pg://public.customers"].kind == "table"
        assert found["pg://public.recent_orders"].kind == "view"

    async def test_table_comments_become_descriptions(self, warehouse) -> None:
        found = {a.urn: a for a in await warehouse.discover()}
        assert found["pg://public.customers"].description == "One row per customer."

    async def test_columns_are_recorded(self, warehouse) -> None:
        found = {a.urn: a for a in await warehouse.discover()}
        assert set(found["pg://public.customers"].attributes["columns"]) == {
            "id",
            "full_name",
            "email",
            "ssn",
        }

    async def test_column_names_and_comments_suggest_labels(self, warehouse) -> None:
        found = {a.urn: a for a in await warehouse.discover()}
        assert set(found["pg://public.customers"].suggested_labels) == {"pii.email", "pii.ssn"}
        assert found["pg://public.orders"].suggested_labels == ()


class TestSampling:
    async def test_rows_come_back_as_dictionaries(self, warehouse) -> None:
        samples = [s async for s in warehouse.sample("pg://public.customers", limit=10)]
        assert len(samples) == 1
        rows = samples[0].content
        assert samples[0].record_count == 2
        assert {row["email"] for row in rows} == {"jane.doe@acme.com", "sam.patel@example.org"}

    async def test_a_full_read_is_not_marked_partial(self, warehouse) -> None:
        """A clean scan of a whole table is proof; of part of one, it is not."""
        samples = [s async for s in warehouse.sample("pg://public.customers", limit=10)]
        assert samples[0].partial is False

    async def test_a_truncated_read_is_marked_partial(self, warehouse) -> None:
        samples = [s async for s in warehouse.sample("pg://public.customers", limit=1)]
        assert samples[0].partial is True

    async def test_a_malformed_urn_is_rejected(self, warehouse) -> None:
        with pytest.raises(ValueError, match="schema and table"):
            [s async for s in warehouse.sample("pg://noschema")]

    async def test_a_missing_table_reports_rather_than_crashes(self, warehouse) -> None:
        from control_plane.adapters.base import AdapterUnavailable

        with pytest.raises(AdapterUnavailable, match="cannot sample"):
            [s async for s in warehouse.sample("pg://public.nonexistent")]


class TestEndToEnd:
    async def test_discovery_populates_the_catalog_from_a_real_database(
        self, warehouse, session
    ) -> None:
        """The whole point: an adapter, reachable, filling the catalog."""
        from control_plane.catalog.discovery import DiscoveryService
        from control_plane.catalog.service import CatalogService

        report = await DiscoveryService(session=session).run(
            warehouse, source="warehouse", scan=True, exclude=["*.recent_orders"]
        )
        assert report.discovered == 2
        assert not report.failed

        resolved = await CatalogService(session).resolve("pg://public.customers")
        assert {"pii.email", "pii.ssn"} <= set(resolved.label_keys)
        assert "GDPR" in resolved.to_dict()["regulations"]

    async def test_no_sampled_value_reaches_the_catalog(self, warehouse, session) -> None:
        from sqlalchemy import select

        from control_plane.catalog.discovery import DiscoveryService
        from control_plane.models.catalog import AssetClassification

        await DiscoveryService(session=session).run(warehouse, source="w", scan=True)
        rows = (await session.execute(select(AssetClassification))).scalars().all()
        stored = str([r.evidence for r in rows])
        assert "jane.doe@acme.com" not in stored
        assert "536-90-4432" not in stored
