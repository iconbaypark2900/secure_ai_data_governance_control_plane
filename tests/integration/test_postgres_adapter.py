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

-- The other two relkinds the adapter enumerates. Both are shapes a real
-- warehouse has and neither was covered: a partitioned table reports relkind 'p'
-- and its partitions report 'r', and a materialized view reports 'm' while
-- holding a physical copy of whatever it selected -- which is the governance
-- point, because that copy inherits the source's sensitivity without inheriting
-- its controls.
CREATE TABLE public.events (
  id bigserial,
  occurred_at date NOT NULL,
  patient_email text
) PARTITION BY RANGE (occurred_at);
CREATE TABLE public.events_2026 PARTITION OF public.events
  FOR VALUES FROM ('2026-01-01') TO ('2027-01-01');
COMMENT ON COLUMN public.events.patient_email IS 'sensitive: pii.email';

CREATE MATERIALIZED VIEW public.customer_digest AS
  SELECT full_name, email, ssn FROM public.customers;

INSERT INTO public.customers (full_name, email, ssn)
VALUES ('Jane Doe', 'jane.doe@acme.com', '536-90-4432'),
       ('Sam Patel', 'sam.patel@example.org', '457-55-5462');
INSERT INTO public.orders (sku, quantity) VALUES ('ABC-1', 2), ('XYZ-9', 1);
INSERT INTO public.events (occurred_at, patient_email)
VALUES ('2026-03-04', 'ana.ruiz@clinic.example'), ('2026-07-19', 'lee.park@clinic.example');
REFRESH MATERIALIZED VIEW public.customer_digest;
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
        """All four relkinds the query selects, not just the two that are easy.

        relkind is where this adapter's last bug lived -- asyncpg returns it as
        bytes, so every view was catalogued as a table -- and 'p' and 'm' were
        enumerated by the query but never exercised by a test.
        """
        found = {a.urn: a for a in await warehouse.discover()}
        assert found["pg://public.customers"].kind == "table"
        assert found["pg://public.recent_orders"].kind == "view"
        assert found["pg://public.events"].kind == "partitioned_table"
        assert found["pg://public.customer_digest"].kind == "materialized_view"

    async def test_a_partition_is_catalogued_in_its_own_right(self, warehouse) -> None:
        """It holds the rows, so a scan that skipped it would scan nothing."""
        found = {a.urn: a for a in await warehouse.discover()}
        assert found["pg://public.events_2026"].kind == "table"

    async def test_a_materialized_view_carries_its_own_columns(self, warehouse) -> None:
        found = {a.urn: a for a in await warehouse.discover()}
        assert set(found["pg://public.customer_digest"].attributes["columns"]) == {
            "full_name",
            "email",
            "ssn",
        }

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

    async def test_a_partitioned_parent_samples_across_its_partitions(self, warehouse) -> None:
        """The parent holds no rows itself; a read has to reach the partitions."""
        samples = [s async for s in warehouse.sample("pg://public.events", limit=10)]
        assert samples[0].record_count == 2
        assert {row["patient_email"] for row in samples[0].content} == {
            "ana.ruiz@clinic.example",
            "lee.park@clinic.example",
        }

    async def test_a_large_table_never_samples_to_nothing(self, pg_engine) -> None:
        """The branch that was actually untested, and the bug in it.

        Sampling only takes the TABLESAMPLE path above 10,000 rows, and every
        existing fixture is tiny, so that statement had never run at all. Two
        things came out of running it. PostgreSQL 17 does support TABLESAMPLE on
        a partitioned parent, which I had assumed it did not. And SYSTEM
        sampling selects whole blocks, so on a 12,000-row table 12 of 40 samples
        returned *nothing* -- the asset would be scanned, found to hold no
        labels, and reported clean.

        Repeated, because a single pass had a seventy percent chance of passing
        against the broken code.
        """
        async with pg_engine.begin() as connection:
            await connection.execute(text("DROP TABLE IF EXISTS public.big_events CASCADE"))
            await connection.execute(
                text(
                    "CREATE TABLE public.big_events (id bigint, d date, note text) "
                    "PARTITION BY RANGE (d)"
                )
            )
            await connection.execute(
                text(
                    "CREATE TABLE public.big_events_a PARTITION OF public.big_events "
                    "FOR VALUES FROM ('2026-01-01') TO ('2026-07-01')"
                )
            )
            await connection.execute(
                text(
                    "CREATE TABLE public.big_events_b PARTITION OF public.big_events "
                    "FOR VALUES FROM ('2026-07-01') TO ('2027-01-01')"
                )
            )
            await connection.execute(
                text(
                    "INSERT INTO public.big_events "
                    "SELECT g, '2026-03-01'::date + (g % 300), 'note ' || g "
                    "FROM generate_series(1, 12000) g"
                )
            )
        adapter = PostgresAdapter(engine=pg_engine)
        for _ in range(12):
            samples = [s async for s in adapter.sample("pg://public.big_events", limit=50)]
            # Never zero is the property. Not "always fifty": how many rows a
            # selected block holds depends on the page layout, and asserting the
            # full page passed on PostgreSQL 17 and failed on 15.
            assert 0 < samples[0].record_count <= 50
            assert samples[0].partial is True
            assert samples[0].content[0]["note"].startswith("note ")

    async def test_a_materialized_view_can_be_sampled(self, warehouse) -> None:
        """It is a physical copy of sensitive rows; not scanning it hides them."""
        samples = [s async for s in warehouse.sample("pg://public.customer_digest", limit=10)]
        assert samples[0].record_count == 2
        assert {row["ssn"] for row in samples[0].content} == {"536-90-4432", "457-55-5462"}

    async def test_a_malformed_urn_is_rejected(self, warehouse) -> None:
        with pytest.raises(ValueError, match="schema and table"):
            [s async for s in warehouse.sample("pg://noschema")]

    async def test_a_missing_table_reports_rather_than_crashes(self, warehouse) -> None:
        from control_plane.adapters.base import AdapterUnavailable

        with pytest.raises(AdapterUnavailable, match="cannot sample"):
            [s async for s in warehouse.sample("pg://public.nonexistent")]


class TestVectorStores:
    """A pgvector store is the case the catalog exists for, and it needs pgvector.

    Skipped unless the target database has the extension available. Everything
    here came from pointing the adapter at a real langchain/pgvector store: the
    schema rag_api creates for uploaded files, where the interesting column is a
    varchar next to an embedding three hundred times its size.
    """

    @pytest.fixture
    async def vectors(self, pg_engine):
        async with pg_engine.begin() as connection:
            try:
                await connection.execute(text("CREATE EXTENSION IF NOT EXISTS vector"))
            except Exception:
                pytest.skip("pgvector is not available on this database")
            await connection.execute(text("DROP TABLE IF EXISTS public.embeddings CASCADE"))
            await connection.execute(
                text(
                    "CREATE TABLE public.embeddings ("
                    "  uuid uuid PRIMARY KEY,"
                    "  embedding vector(3),"
                    "  document varchar,"
                    "  cmetadata jsonb)"
                )
            )
            await connection.execute(
                text(
                    "INSERT INTO public.embeddings VALUES"
                    " (gen_random_uuid(), '[0.1,0.2,0.3]',"
                    "  'Maria Alvarez, SSN 501-72-9384.', '{\"file\":\"a\"}'),"
                    " (gen_random_uuid(), '[0.4,0.5,0.6]',"
                    "  'Quarterly revenue rose.', '{\"file\":\"b\"}')"
                )
            )
        return PostgresAdapter(engine=pg_engine)

    async def test_the_embedding_column_is_catalogued(self, vectors) -> None:
        """Knowing a table is a vector store is worth knowing about the asset."""
        found = {a.urn: a for a in await vectors.discover()}
        assert "embedding" in found["pg://public.embeddings"].attributes["columns"]

    async def test_the_embedding_column_is_not_sampled(self, vectors) -> None:
        """Measured on a 1536-dimension store: 99.4% of a row is float text, and
        scanning 200 rows took 3,166 ms against 10 ms without it. A classifier
        cannot learn anything from an embedding -- the Qdrant adapter had said so
        since it was written, and this one predated pgvector being in view.
        """
        samples = [s async for s in vectors.sample("pg://public.embeddings", limit=10)]
        assert "embedding" not in samples[0].content[0]
        assert "document" in samples[0].content[0]

    async def test_the_documents_beside_it_are_still_classified(self, vectors) -> None:
        """Skipping the vector must not skip what the vector was built from."""
        from control_plane.classification.scanner import Scanner

        samples = [s async for s in vectors.sample("pg://public.embeddings", limit=10)]
        labels = {f.label for f in Scanner().scan_structured(samples[0].content).findings}
        assert "pii.ssn" in labels

    async def test_row_counts_are_unaffected(self, vectors) -> None:
        """Narrowing the projection must not narrow what was read."""
        samples = [s async for s in vectors.sample("pg://public.embeddings", limit=10)]
        assert samples[0].record_count == 2
        assert samples[0].partial is False


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
        assert report.discovered == 5
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
