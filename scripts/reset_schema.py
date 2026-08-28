#!/usr/bin/env python
"""Drop and recreate the ``public`` schema of the configured database.

Used before the migration check in CI: the test suite creates its tables with
``Base.metadata.create_all``, so running Alembic afterwards would fail on tables
that already exist without any migration having been verified.

Destructive by design, and it refuses to run against a production environment or
a database whose name does not look like a test database. A script whose whole
job is dropping things should be hard to point at the wrong thing.
"""

from __future__ import annotations

import asyncio
import sys

from sqlalchemy import text
from sqlalchemy.ext.asyncio import create_async_engine

from control_plane.config import Environment, get_settings

SAFE_NAME_MARKERS = ("test", "ci", "scratch", "tmp")


async def main() -> int:
    settings = get_settings()

    if settings.environment is Environment.PRODUCTION:
        print("refusing to reset a production database", file=sys.stderr)
        return 2

    database = settings.database_url.rsplit("/", 1)[-1].split("?", 1)[0]
    if not any(marker in database.lower() for marker in SAFE_NAME_MARKERS):
        print(
            f"refusing to reset {database!r}: the name contains none of "
            f"{', '.join(SAFE_NAME_MARKERS)}. Rename the database or drop it by hand.",
            file=sys.stderr,
        )
        return 2

    engine = create_async_engine(settings.database_url)
    try:
        async with engine.begin() as connection:
            if connection.dialect.name != "postgresql":
                print(f"reset_schema only supports postgres, not {connection.dialect.name}")
                return 1
            await connection.execute(text("DROP SCHEMA IF EXISTS public CASCADE"))
            await connection.execute(text("CREATE SCHEMA public"))
    finally:
        await engine.dispose()

    print(f"reset schema public in {database}")
    return 0


if __name__ == "__main__":
    raise SystemExit(asyncio.run(main()))
