"""Database engine, session factory, and the FastAPI session dependency."""

from __future__ import annotations

from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

from sqlalchemy.ext.asyncio import (
    AsyncEngine,
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)

from control_plane.config import Settings, get_settings
from control_plane.models import Base

__all__ = [
    "create_all",
    "create_engine",
    "dispose_engine",
    "get_engine",
    "get_session",
    "get_sessionmaker",
    "is_postgres",
    "session_scope",
]

_engine: AsyncEngine | None = None
_sessionmaker: async_sessionmaker[AsyncSession] | None = None


def create_engine(settings: Settings | None = None) -> AsyncEngine:
    """Build an engine configured for the active dialect.

    SQLite ignores pooling arguments that Postgres needs, so they are only
    passed where they mean something. This is the single place that has to know
    which database is underneath.
    """
    settings = settings or get_settings()
    url = settings.database_url
    kwargs: dict[str, object] = {"echo": settings.db_echo, "future": True}
    if not url.startswith("sqlite"):
        kwargs.update(
            pool_size=settings.db_pool_size,
            max_overflow=settings.db_max_overflow,
            pool_pre_ping=True,
            pool_recycle=1800,
        )
    return create_async_engine(url, **kwargs)


def get_engine(settings: Settings | None = None) -> AsyncEngine:
    """The process-wide engine, created on first use."""
    global _engine
    if _engine is None:
        _engine = create_engine(settings)
    return _engine


def get_sessionmaker(settings: Settings | None = None) -> async_sessionmaker[AsyncSession]:
    """The process-wide session factory."""
    global _sessionmaker
    if _sessionmaker is None:
        _sessionmaker = async_sessionmaker(
            bind=get_engine(settings),
            expire_on_commit=False,
            autoflush=False,
        )
    return _sessionmaker


async def dispose_engine() -> None:
    """Close pooled connections. Called on application shutdown and in tests."""
    global _engine, _sessionmaker
    if _engine is not None:
        await _engine.dispose()
    _engine = None
    _sessionmaker = None


def is_postgres(session: AsyncSession) -> bool:
    """True when the session is bound to Postgres.

    A handful of operations -- advisory locks, JSONB containment -- exist only
    there, and the code that uses them degrades deliberately rather than
    crashing on SQLite.
    """
    bind = session.get_bind()
    return bind.dialect.name == "postgresql"


@asynccontextmanager
async def session_scope() -> AsyncIterator[AsyncSession]:
    """A transactional session for use outside a request."""
    factory = get_sessionmaker()
    async with factory() as session:
        try:
            yield session
            await session.commit()
        except Exception:
            await session.rollback()
            raise


async def get_session() -> AsyncIterator[AsyncSession]:
    """FastAPI dependency yielding a session committed on success.

    Commit happens here rather than in each endpoint so that a handler which
    raises leaves nothing half-written -- including, importantly, no audit
    record for an operation that did not complete.
    """
    factory = get_sessionmaker()
    async with factory() as session:
        try:
            yield session
            await session.commit()
        except Exception:
            await session.rollback()
            raise


async def create_all(engine: AsyncEngine | None = None) -> None:
    """Create every table directly.

    For tests and the local demo only. Deployments run Alembic, which also
    installs the append-only trigger on the audit table that this path skips.
    """
    target = engine or get_engine()
    async with target.begin() as connection:
        await connection.run_sync(Base.metadata.create_all)
