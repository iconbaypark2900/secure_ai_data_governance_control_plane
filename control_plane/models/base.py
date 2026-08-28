"""Shared declarative base and column types.

The same models run on Postgres in deployment and SQLite in the test suite, so
every column type here is chosen to behave identically on both. ``JSONVariant``
is the one place that differs: Postgres gets real JSONB with its indexes, SQLite
gets plain JSON, and application code never has to know which.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime
from typing import Any

from sqlalchemy import DateTime, Uuid, func
from sqlalchemy.dialects import postgresql
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column
from sqlalchemy.types import JSON, TypeEngine

#: JSONB where available, JSON elsewhere.
JSONVariant: TypeEngine[Any] = JSON().with_variant(postgresql.JSONB(), "postgresql")

#: Timezone-aware timestamps everywhere. Naive datetimes in an audit trail are
#: a defect waiting for a daylight-saving transition.
TZDateTime = DateTime(timezone=True)


def utcnow() -> datetime:
    """The single clock every timestamp in the system comes from."""
    return datetime.now(UTC)


class Base(DeclarativeBase):
    """Declarative base for every table."""

    type_annotation_map = {
        dict[str, Any]: JSONVariant,
        list[str]: JSONVariant,
        list[dict[str, Any]]: JSONVariant,
        datetime: TZDateTime,
        uuid.UUID: Uuid(as_uuid=True),
    }

    def as_dict(self) -> dict[str, Any]:
        """Column values as a plain dict, for serialisation and diffing."""
        return {c.name: getattr(self, c.name) for c in self.__table__.columns}


class TimestampMixin:
    """created_at / updated_at, supplied by the application.

    Both carry a server default as a backstop for rows inserted by a migration
    or a maintenance script, but the value normally comes from Python. That is
    deliberate: a server-side ``onupdate`` makes SQLAlchemy expire the column
    after every UPDATE, and reading it back then issues a lazy refresh -- which
    under asyncio is not a slow path but a ``MissingGreenlet`` error, raised
    only on the update path and only when something serialises the row.
    Generating the timestamp here keeps it known to the session and keeps every
    timestamp in the system UTC-aware and produced by one clock.
    """

    created_at: Mapped[datetime] = mapped_column(
        TZDateTime,
        default=utcnow,
        server_default=func.now(),
        nullable=False,
        index=True,
    )
    updated_at: Mapped[datetime] = mapped_column(
        TZDateTime,
        default=utcnow,
        onupdate=utcnow,
        server_default=func.now(),
        nullable=False,
    )


class UUIDPrimaryKey:
    """A client-generatable primary key.

    UUIDs rather than serial integers, because decision identifiers are handed to
    enforcement points and appear in logs the control plane does not own. A
    sequential identifier would leak decision volume to anyone holding one.
    """

    id: Mapped[uuid.UUID] = mapped_column(Uuid(as_uuid=True), primary_key=True, default=uuid.uuid4)
