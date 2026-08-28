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


class TestShardedAppends:
    """The reason for streams: one lock per chain, not one for the system."""

    async def test_appends_to_different_streams_do_not_serialise(self, factory, audit_key) -> None:
        async def append(index: int) -> None:
            async with factory() as session:
                await AuditService(session, key=audit_key, partitions=8).append(
                    AuditEvent.DECISION,
                    actor=f"agent:{index}",
                    subject="qdrant://kb",
                    payload={"index": index},
                )
                await session.commit()

        await asyncio.gather(*(append(i) for i in range(48)))

        async with factory() as session:
            audit = AuditService(session, key=audit_key, partitions=8)
            streams = await audit.streams()
            assert len(streams) > 1, "48 distinct actors should reach several streams"
            assert await audit.count() == 48

            result = await audit.verify_all()
            assert result["valid"] is True, result["message"]

    async def test_each_stream_numbers_from_one(self, factory, audit_key) -> None:
        async def append(index: int) -> None:
            async with factory() as session:
                await AuditService(session, key=audit_key, partitions=4).append(
                    AuditEvent.DECISION, actor=f"agent:{index}", subject="s"
                )
                await session.commit()

        await asyncio.gather(*(append(i) for i in range(24)))

        async with factory() as session:
            audit = AuditService(session, key=audit_key, partitions=4)
            for stream in await audit.streams():
                first = await audit.verify(stream=stream)
                assert first.valid is True

    async def test_an_explicit_stream_overrides_partitioning(self, factory, audit_key) -> None:
        """How a tenant or a period gets its own independently verifiable slice."""
        async with factory() as session:
            audit = AuditService(session, key=audit_key, partitions=8)
            await audit.append(
                AuditEvent.DECISION, actor="agent:x", subject="s", stream="tenant-acme"
            )
            await session.commit()

        async with factory() as session:
            audit = AuditService(session, key=audit_key, partitions=8)
            assert "tenant-acme" in await audit.streams()
            assert (await audit.verify(stream="tenant-acme")).valid is True


class TestCheckpointsOverStorage:
    async def test_a_checkpoint_records_every_stream(self, factory, audit_key) -> None:
        async with factory() as session:
            audit = AuditService(session, key=audit_key, partitions=4)
            for i in range(12):
                await audit.append(AuditEvent.DECISION, actor=f"agent:{i}", subject="s")
            record = await audit.checkpoint()
            await session.commit()

        assert record.payload["stream_count"] >= 1
        assert record.payload["total_records"] == 12

    async def test_verify_all_holds_the_streams_against_it(self, factory, audit_key) -> None:
        async with factory() as session:
            audit = AuditService(session, key=audit_key, partitions=4)
            for i in range(12):
                await audit.append(AuditEvent.DECISION, actor=f"agent:{i}", subject="s")
            await audit.checkpoint()
            await session.commit()

        async with factory() as session:
            result = await AuditService(session, key=audit_key, partitions=4).verify_all()
            assert result["valid"] is True
            assert result["checkpoint"]["valid"] is True

    async def test_a_stream_deleted_after_a_checkpoint_is_caught(self, factory, audit_key) -> None:
        """What per-stream verification alone cannot see.

        The append-only trigger makes this impossible through the application,
        so it is done here with the trigger disabled -- which is exactly the
        privilege level the hash chain exists to defend against.
        """
        async with factory() as session:
            audit = AuditService(session, key=audit_key, partitions=8)
            for i in range(24):
                await audit.append(AuditEvent.DECISION, actor=f"agent:{i}", subject="s")
            await audit.checkpoint()
            await session.commit()

        async with factory() as session:
            victim = (await AuditService(session, key=audit_key).streams())[0]
            await session.execute(
                text("ALTER TABLE audit_records DISABLE TRIGGER audit_records_append_only")
            )
            await session.execute(
                text("DELETE FROM audit_records WHERE stream = :s"), {"s": victim}
            )
            await session.execute(
                text("ALTER TABLE audit_records ENABLE TRIGGER audit_records_append_only")
            )
            await session.commit()

        async with factory() as session:
            audit = AuditService(session, key=audit_key, partitions=8)
            # Every chain that survives still verifies perfectly on its own.
            for stream in await audit.streams():
                assert (await audit.verify(stream=stream)).valid is True
            # The checkpoint is what notices one is gone.
            result = await audit.verify_all()
            assert result["valid"] is False
            assert victim in result["checkpoint"]["missing"]


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
