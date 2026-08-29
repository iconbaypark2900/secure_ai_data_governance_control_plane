"""Postgres adapter.

Enumerates tables and views and samples rows. Two choices are worth naming:

The sample is taken with ``TABLESAMPLE`` where the table is large enough for it
to help, because ``LIMIT`` without ``ORDER BY`` reads the physically first rows,
which on an append-ordered table are the oldest -- and the oldest rows are the
least representative of what a table holds today.

Column comments are read and offered as ``suggested_labels``. A team that has
already documented ``ssn -- do not export`` has done the classification work;
the catalog should not make them do it twice.
"""

from __future__ import annotations

from collections.abc import AsyncIterator, Sequence
from typing import Any

from sqlalchemy import bindparam, text
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.ext.asyncio import AsyncEngine, create_async_engine

from control_plane.adapters.base import AdapterUnavailable, DiscoveredAsset, Sample
from control_plane.classification import taxonomy

__all__ = ["PostgresAdapter"]

#: Column names that reliably indicate a label. Only used as a suggestion --
#: a human or a scan confirms it before it becomes an assertion.
COLUMN_NAME_HINTS: dict[str, str] = {
    "ssn": "pii.ssn",
    "social_security": "pii.ssn",
    "email": "pii.email",
    "email_address": "pii.email",
    "phone": "pii.phone",
    "phone_number": "pii.phone",
    "date_of_birth": "pii.dob",
    "dob": "pii.dob",
    "birth_date": "pii.dob",
    "address": "pii.address",
    "street_address": "pii.address",
    "passport": "pii.passport",
    "passport_number": "pii.passport",
    "card_number": "pci.card_number",
    "credit_card": "pci.card_number",
    "pan": "pci.card_number",
    "iban": "pci.iban",
    "mrn": "phi.mrn",
    "medical_record_number": "phi.mrn",
    "npi": "phi.npi",
    "icd10": "phi.icd10",
    "diagnosis_code": "phi.icd10",
    "password": "secret.password",
    "api_key": "secret.generic_api_key",
    "access_token": "secret.generic_api_key",
    "ip_address": "pii.ip_address",
}

SYSTEM_SCHEMAS = ("pg_catalog", "information_schema", "pg_toast")

_LIST_TABLES = text(
    """
    SELECT c.relname          AS table_name,
           n.nspname          AS schema_name,
           -- ::text because relkind is PostgreSQL's internal "char" type, which
           -- asyncpg hands back as bytes. Without the cast every view arrives as
           -- b'v', misses the lookup, and is catalogued as a plain table -- and a
           -- view over a PII table is not the same governance object as a table.
           c.relkind::text    AS kind,
           c.reltuples        AS approx_rows,
           obj_description(c.oid) AS table_comment
    FROM pg_class c
    JOIN pg_namespace n ON n.oid = c.relnamespace
    WHERE c.relkind IN ('r', 'p', 'v', 'm')
      AND n.nspname NOT IN :system_schemas
    ORDER BY n.nspname, c.relname
    """
).bindparams(
    # expanding=True renders the tuple as a parameter list. Without it the
    # driver is handed a single placeholder for a sequence and the query fails
    # at execution rather than at construction.
    bindparam("system_schemas", value=SYSTEM_SCHEMAS, expanding=True)
)

_LIST_COLUMNS = text(
    """
    SELECT a.attname AS column_name,
           col_description(a.attrelid, a.attnum) AS column_comment
    FROM pg_attribute a
    JOIN pg_class c ON c.oid = a.attrelid
    JOIN pg_namespace n ON n.oid = c.relnamespace
    WHERE n.nspname = :schema AND c.relname = :table
      AND a.attnum > 0 AND NOT a.attisdropped
    ORDER BY a.attnum
    """
)

_SAMPLEABLE_COLUMNS = text(
    """
    SELECT a.attname AS column_name
    FROM pg_attribute a
    JOIN pg_class c ON c.oid = a.attrelid
    JOIN pg_namespace n ON n.oid = c.relnamespace
    JOIN pg_type t ON t.oid = a.atttypid
    WHERE n.nspname = :schema AND c.relname = :table
      AND a.attnum > 0 AND NOT a.attisdropped
      AND t.typname <> ALL(:skip_types)
    ORDER BY a.attnum
    """
)

#: Column types excluded from a sample because a classifier cannot learn
#: anything from them, and reading them is expensive enough to matter.
#:
#: Embeddings are the case that forced this. On a langchain/pgvector store with
#: 1536 dimensions a row is ~13,700 bytes of float text carrying ~50 bytes of
#: document -- 99.4% of a sample is noise, and scanning 200 rows took 3,166 ms
#: instead of 10 ms. Measured, not estimated. The Qdrant adapter had excluded
#: vectors from the start for the same reason; this one predated pgvector being
#: in view.
#:
#: These are skipped in *sampling* only. Discovery still records them as
#: columns, because a table with an embedding column is a vector store and that
#: is worth knowing about the asset.
UNSAMPLEABLE_TYPES: tuple[str, ...] = ("vector", "halfvec", "sparsevec", "tsvector")

KIND_NAMES = {"r": "table", "p": "partitioned_table", "v": "view", "m": "materialized_view"}


class PostgresAdapter:
    """Discovers and samples relational assets."""

    name = "postgres"

    def __init__(self, dsn: str | None = None, *, engine: AsyncEngine | None = None) -> None:
        if engine is None and dsn is None:
            raise ValueError("PostgresAdapter needs either a dsn or an engine")
        self._engine = engine or create_async_engine(str(dsn), pool_pre_ping=True)
        self._owns_engine = engine is None

    async def aclose(self) -> None:
        if self._owns_engine:
            await self._engine.dispose()

    @staticmethod
    def urn_for(schema: str, table: str) -> str:
        return f"pg://{schema}.{table}"

    async def health(self) -> bool:
        try:
            async with self._engine.connect() as connection:
                await connection.execute(text("SELECT 1"))
            return True
        except SQLAlchemyError:
            return False

    async def discover(self) -> Sequence[DiscoveredAsset]:
        """Enumerate every non-system table and view."""
        try:
            async with self._engine.connect() as connection:
                rows = (await connection.execute(_LIST_TABLES)).all()
                discovered: list[DiscoveredAsset] = []
                for row in rows:
                    columns = (
                        await connection.execute(
                            _LIST_COLUMNS,
                            {"schema": row.schema_name, "table": row.table_name},
                        )
                    ).all()
                    suggested = _suggest_labels(columns)
                    discovered.append(
                        DiscoveredAsset(
                            urn=self.urn_for(row.schema_name, row.table_name),
                            name=row.table_name,
                            kind=KIND_NAMES.get(row.kind, "table"),
                            description=row.table_comment or "",
                            attributes={
                                "schema": row.schema_name,
                                "approx_rows": int(row.approx_rows or 0),
                                "columns": [column.column_name for column in columns],
                            },
                            suggested_labels=suggested,
                        )
                    )
                return discovered
        except SQLAlchemyError as exc:
            raise AdapterUnavailable(f"postgres is unreachable: {exc}") from exc

    async def sample(self, urn: str, *, limit: int = 100) -> AsyncIterator[Sample]:
        """Read a sample of rows as dictionaries."""
        schema, _, table = urn.removeprefix("pg://").partition(".")
        if not schema or not table:
            raise ValueError(f"cannot parse a schema and table out of {urn!r}")
        # Identifiers cannot be bound as parameters, so they are quoted instead.
        # The values come from pg_class, not from a caller.
        qualified = f'"{_quote(schema)}"."{_quote(table)}"'
        try:
            async with self._engine.connect() as connection:
                columns = (
                    (
                        await connection.execute(
                            _SAMPLEABLE_COLUMNS.bindparams(
                                bindparam("skip_types", expanding=False)
                            ),
                            {
                                "schema": schema,
                                "table": table,
                                "skip_types": list(UNSAMPLEABLE_TYPES),
                            },
                        )
                    )
                    .scalars()
                    .all()
                )
                # An empty list means every column was excluded, which is not a
                # reason to select nothing at all: SELECT * at least reports the
                # asset was read. It also means a table of pure embeddings still
                # samples, and honestly finds nothing.
                projection = ", ".join(f'"{_quote(c)}"' for c in columns) if columns else "*"
                total = (
                    await connection.execute(text(f"SELECT count(*) FROM {qualified}"))  # noqa: S608
                ).scalar_one()
                head = text(f"SELECT {projection} FROM {qualified} LIMIT :limit")  # noqa: S608
                # TABLESAMPLE spreads the read across the whole heap; on a small
                # table its granularity is worse than just reading everything.
                if total > 10_000:
                    fraction = min(100.0, max(0.01, (limit / total) * 100 * 3))
                    spread = text(
                        f"SELECT {projection} FROM {qualified} "  # noqa: S608
                        f"TABLESAMPLE SYSTEM ({fraction}) "
                        f"LIMIT :limit"
                    )
                    rows = (await connection.execute(spread, {"limit": limit})).mappings().all()
                    if not rows:
                        # SYSTEM sampling selects whole blocks, so a small
                        # fraction can select none at all and return nothing from
                        # a table that is not remotely empty. Measured on a
                        # 12,000-row table: 12 of 40 samples came back empty, and
                        # the result is bimodal -- zero rows or a full page,
                        # never in between. An empty sample would be scanned and
                        # classified as holding nothing, which is how a table
                        # full of personal data gets a clean bill of health.
                        # Reading the head is unrepresentative; it is still
                        # incomparably better than reading nothing.
                        rows = (await connection.execute(head, {"limit": limit})).mappings().all()
                else:
                    rows = (await connection.execute(head, {"limit": limit})).mappings().all()
        except SQLAlchemyError as exc:
            raise AdapterUnavailable(f"cannot sample {urn}: {exc}") from exc

        yield Sample(
            urn=urn,
            content=[dict(row) for row in rows],
            record_count=len(rows),
            partial=len(rows) < int(total),
        )


def _suggest_labels(columns: Sequence[Any]) -> tuple[str, ...]:
    """Infer labels from column names and comments."""
    found: set[str] = set()
    for column in columns:
        name = str(column.column_name).lower()
        if name in COLUMN_NAME_HINTS:
            found.add(COLUMN_NAME_HINTS[name])
            continue
        for hint, label in COLUMN_NAME_HINTS.items():
            if hint in name:
                found.add(label)
                break
        comment = str(getattr(column, "column_comment", "") or "").lower()
        for token in comment.replace(",", " ").split():
            if taxonomy.is_known(token) and token in taxonomy.BY_KEY:
                found.add(token)
    return tuple(sorted(found))


def _quote(identifier: str) -> str:
    """Escape an embedded double quote, per SQL identifier rules."""
    return identifier.replace('"', '""')
