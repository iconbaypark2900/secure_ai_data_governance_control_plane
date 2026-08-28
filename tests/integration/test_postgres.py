"""Behaviour that only a real Postgres can demonstrate.

Skipped unless ``CP_TEST_POSTGRES_URL`` points at a database this suite may
destroy -- it drops and recreates the public schema.
"""

from __future__ import annotations

import asyncio

import pytest
from sqlalchemy import select, text
from sqlalchemy.exc import DBAPIError, IntegrityError
from sqlalchemy.ext.asyncio import async_sessionmaker

from control_plane.audit.chain import AuditEvent
from control_plane.audit.service import AuditService
from control_plane.catalog.service import CatalogService
from control_plane.models.audit import AuditRecordRow
from control_plane.models.decision import DecisionRecord
from control_plane.pdp import PolicyDecisionPoint
from control_plane.policy.model import Policy
from control_plane.policy.store import PolicyStore
from control_plane.schemas.decision import DecideRequest

pytestmark = pytest.mark.integration


@pytest.fixture
def factory(pg_engine):
    return async_sessionmaker(bind=pg_engine, expire_on_commit=False, autoflush=False)


class TestAppendOnlyStorage:
    async def test_the_database_refuses_to_update_an_audit_record(self, factory, audit_key) -> None:
        async with factory() as session:
            await AuditService(session, key=audit_key).append(
                AuditEvent.DECISION, actor="a", subject="s", payload={"n": 1}
            )
            await session.commit()

        async with factory() as session:
            with pytest.raises(DBAPIError, match="append-only"):
                await session.execute(
                    text("UPDATE audit_records SET actor = 'mallory' WHERE seq = 1")
                )
                await session.commit()

    async def test_the_database_refuses_to_delete_an_audit_record(self, factory, audit_key) -> None:
        async with factory() as session:
            await AuditService(session, key=audit_key).append(
                AuditEvent.DECISION, actor="a", subject="s"
            )
            await session.commit()

        async with factory() as session:
            with pytest.raises(DBAPIError, match="append-only"):
                await session.execute(text("DELETE FROM audit_records WHERE seq = 1"))
                await session.commit()


class TestConcurrentAppends:
    async def test_parallel_appends_produce_one_unbroken_chain(self, factory, audit_key) -> None:
        """The advisory lock is what stops the chain forking under concurrency.

        Without it, two transactions read the same head and write two records
        claiming the same predecessor -- each valid alone, and together not a
        history.
        """

        async def append(index: int) -> None:
            async with factory() as session:
                await AuditService(session, key=audit_key).append(
                    AuditEvent.DECISION,
                    actor=f"writer-{index}",
                    subject="concurrent",
                    payload={"index": index},
                )
                await session.commit()

        await asyncio.gather(*(append(index) for index in range(12)))

        async with factory() as session:
            audit = AuditService(session, key=audit_key)
            assert await audit.count() == 12
            result = await audit.verify()
            assert result.valid is True, result.message

            rows = (
                (await session.execute(select(AuditRecordRow).order_by(AuditRecordRow.seq)))
                .scalars()
                .all()
            )
            assert [row.seq for row in rows] == list(range(1, 13))
            assert len({row.prev_hash for row in rows}) == 12

    async def test_concurrent_decisions_all_persist(self, factory, audit_key) -> None:
        async with factory() as session:
            await PolicyStore(session).create(
                Policy(
                    key="allow-all-reads",
                    name="Allow reads",
                    effect="allow",
                    match={"action": "read"},
                ),
                actor="test",
            )
            await session.commit()

        async def decide(index: int) -> str:
            async with factory() as session:
                response = await PolicyDecisionPoint(session).decide(
                    DecideRequest.model_validate(
                        {
                            "principal": {"id": f"agent:{index}", "type": "agent"},
                            "action": "read",
                            "resource": {"urn": "qdrant://kb"},
                        }
                    )
                )
                await session.commit()
                return response.effect

        effects = await asyncio.gather(*(decide(i) for i in range(10)))
        assert set(effects) == {"allow"}

        async with factory() as session:
            count = len((await session.execute(select(DecisionRecord))).scalars().all())
            assert count == 10
            assert (await AuditService(session, key=audit_key).verify()).valid is True


class TestPostgresSchema:
    async def test_timestamps_round_trip_as_utc(self, factory, audit_key) -> None:
        """The chain must verify after a real storage round trip."""
        async with factory() as session:
            await AuditService(session, key=audit_key).append(
                AuditEvent.POLICY_CREATED, actor="admin", subject="p"
            )
            await session.commit()

        async with factory() as session:
            row = (await session.execute(select(AuditRecordRow))).scalars().one()
            assert row.timestamp.tzinfo is not None
            assert row.to_record().verify(audit_key) is True

    async def test_jsonb_columns_are_queryable(self, factory) -> None:
        async with factory() as session:
            session.add(
                DecisionRecord(
                    principal_id="agent:x",
                    action="read",
                    effect="allow",
                    classifications=["phi.mrn", "pii.email"],
                    matched_policies=["deny-phi"],
                )
            )
            await session.commit()

        async with factory() as session:
            found = (
                await session.execute(
                    text(
                        "SELECT count(*) FROM decisions "
                        "WHERE classifications @> '[\"phi.mrn\"]'::jsonb"
                    )
                )
            ).scalar_one()
            assert found == 1

    async def test_unique_urn_is_enforced(self, factory) -> None:
        async with factory() as session:
            await CatalogService(session).upsert_asset("pg://dup")
            await session.commit()

        async with factory() as session:
            from control_plane.models.catalog import DataAsset

            session.add(DataAsset(urn="pg://dup", name="duplicate"))
            with pytest.raises(IntegrityError):
                await session.commit()
