"""Shared fixtures.

The suite runs against SQLite in memory. That keeps it fast and dependency-free,
and it is honest about its limits: anything that depends on Postgres-specific
behaviour (the advisory lock in the audit service, the append-only trigger) is
marked ``integration`` and skipped unless a real database is configured.
"""

from __future__ import annotations

import os
from collections.abc import AsyncIterator

import pytest
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine
from sqlalchemy.pool import NullPool, StaticPool

os.environ.setdefault("CP_ENVIRONMENT", "test")
os.environ.setdefault("CP_DATABASE_URL", "sqlite+aiosqlite:///:memory:")
os.environ.setdefault("CP_AUDIT_HMAC_KEY", "test-audit-key")
os.environ.setdefault("CP_REDACTION_HMAC_KEY", "test-redaction-key")

from control_plane import db as db_module
from control_plane.config import get_settings, reset_settings_cache
from control_plane.models import Base
from control_plane.policy.store import invalidate_engine_cache


@pytest.fixture(autouse=True)
def _clean_caches() -> None:
    """Policies and settings are cached per process; tests must not share them."""
    reset_settings_cache()
    invalidate_engine_cache()


@pytest.fixture
def settings():
    return get_settings()


@pytest.fixture
def audit_key() -> bytes:
    """The key the application is actually signing with.

    Read from settings rather than hardcoded: a literal here silently disagrees
    with the environment the moment CP_AUDIT_HMAC_KEY is set to anything else --
    a shell export, or CI -- and the failure looks like a broken hash chain
    rather than a broken fixture.
    """
    return get_settings().audit_key_bytes()


@pytest.fixture
async def engine() -> AsyncIterator:
    """A fresh in-memory database per test.

    StaticPool keeps every connection pointed at the same in-memory database;
    without it each connection would get its own empty one.
    """
    engine = create_async_engine(
        "sqlite+aiosqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    async with engine.begin() as connection:
        await connection.run_sync(Base.metadata.create_all)
    yield engine
    await engine.dispose()


@pytest.fixture
async def session(engine) -> AsyncIterator[AsyncSession]:
    factory = async_sessionmaker(bind=engine, expire_on_commit=False, autoflush=False)
    async with factory() as session:
        yield session
        await session.rollback()


@pytest.fixture
async def app_session(engine, monkeypatch) -> AsyncIterator[AsyncSession]:
    """A session that is also wired into the module-level factory the app uses."""
    factory = async_sessionmaker(bind=engine, expire_on_commit=False, autoflush=False)
    monkeypatch.setattr(db_module, "_engine", engine)
    monkeypatch.setattr(db_module, "_sessionmaker", factory)
    async with factory() as session:
        yield session
        await session.rollback()


@pytest.fixture
async def client(engine, monkeypatch) -> AsyncIterator:
    """An HTTP client bound to the test database, with authentication disabled.

    Authentication is exercised separately by the ``authed_client`` fixture;
    disabling it here keeps every other test focused on what it is actually
    about.
    """
    from httpx import ASGITransport, AsyncClient

    from control_plane.api.deps import get_db
    from control_plane.main import create_app

    monkeypatch.setenv("CP_AUTH_DISABLED", "true")
    reset_settings_cache()

    factory = async_sessionmaker(bind=engine, expire_on_commit=False, autoflush=False)

    async def override_db() -> AsyncIterator[AsyncSession]:
        async with factory() as session:
            try:
                yield session
                await session.commit()
            except Exception:
                await session.rollback()
                raise

    app = create_app()
    app.dependency_overrides[get_db] = override_db
    async with AsyncClient(
        transport=ASGITransport(app=app), base_url="http://control-plane.test"
    ) as http:
        yield http
    reset_settings_cache()


@pytest.fixture
async def authed_client(engine, monkeypatch) -> AsyncIterator[tuple]:
    """A client with authentication ON, plus a freshly issued admin key.

    Yields ``(client, admin_key, issue)`` where ``issue`` mints further keys with
    chosen scopes, so scope enforcement can be tested directly.
    """
    from httpx import ASGITransport, AsyncClient

    from control_plane.api.deps import get_db
    from control_plane.auth.keys import Scope
    from control_plane.auth.service import ApiKeyService
    from control_plane.main import create_app

    monkeypatch.setenv("CP_AUTH_DISABLED", "false")
    reset_settings_cache()

    factory = async_sessionmaker(bind=engine, expire_on_commit=False, autoflush=False)

    async def override_db() -> AsyncIterator[AsyncSession]:
        async with factory() as session:
            try:
                yield session
                await session.commit()
            except Exception:
                await session.rollback()
                raise

    async with factory() as setup:
        _, admin = await ApiKeyService(setup).issue(name="admin", scopes=[Scope.ADMIN])
        await setup.commit()

    async def issue(scopes, **kwargs) -> str:
        async with factory() as scoped:
            _, key = await ApiKeyService(scoped).issue(
                name=kwargs.pop("name", "scoped"), scopes=list(scopes), **kwargs
            )
            await scoped.commit()
            return key.plaintext

    app = create_app()
    app.dependency_overrides[get_db] = override_db
    async with AsyncClient(
        transport=ASGITransport(app=app), base_url="http://control-plane.test"
    ) as http:
        yield http, admin.plaintext, issue
    reset_settings_cache()


POSTGRES_URL = os.environ.get("CP_TEST_POSTGRES_URL", "")


@pytest.fixture
async def pg_engine() -> AsyncIterator:
    """A real Postgres database, or a skip.

    Some behaviour cannot be exercised on SQLite: the advisory lock that
    serialises audit appends, the append-only trigger, JSONB containment. Those
    tests are marked ``integration`` and run only when CP_TEST_POSTGRES_URL is
    set, so the default suite stays dependency-free.
    """
    if not POSTGRES_URL:
        pytest.skip("set CP_TEST_POSTGRES_URL to run Postgres integration tests")

    from sqlalchemy import text as sa_text

    engine = create_async_engine(POSTGRES_URL, poolclass=NullPool)
    async with engine.begin() as connection:
        await connection.execute(sa_text("DROP SCHEMA IF EXISTS public CASCADE"))
        await connection.execute(sa_text("CREATE SCHEMA public"))
        await connection.run_sync(Base.metadata.create_all)
        await connection.execute(
            sa_text(
                """
                CREATE OR REPLACE FUNCTION control_plane_audit_append_only()
                RETURNS trigger LANGUAGE plpgsql AS $$
                BEGIN
                    RAISE EXCEPTION 'audit_records is append-only; % was rejected for seq %',
                        TG_OP, COALESCE(OLD.seq, NEW.seq)
                        USING ERRCODE = 'restrict_violation';
                END; $$;
                """
            )
        )
        await connection.execute(
            sa_text(
                """
                CREATE TRIGGER audit_records_append_only
                BEFORE UPDATE OR DELETE ON audit_records
                FOR EACH ROW EXECUTE FUNCTION control_plane_audit_append_only();
                """
            )
        )
    yield engine
    await engine.dispose()
