"""Persisting the audit chain.

Appending must be serialised *within a chain*. Two concurrent appends that both
read the same head would produce two records claiming the same predecessor, and
the chain would fork -- verifiable in isolation, meaningless as a history.

Serialising across the *whole system* is a different and much more expensive
claim, and it is the one a single global lock makes. So the log is split into
streams, each an independent chain with its own lock. Appends to different
streams proceed concurrently; appends within one still do not.

What that gives up, and how it is bought back: per-stream verification cannot
notice a stream that is *gone*. Every surviving chain verifies perfectly and
nothing says how many there should have been. Checkpoints close that -- a record
of where every stream had reached, sealed into a chain of its own, so removing or
truncating a stream contradicts something already written.

On Postgres the lock is transaction-scoped and keyed by stream, released
automatically at commit or rollback. SQLite serialises writers already, so it
takes the no-op path.
"""

from __future__ import annotations

import zlib
from collections.abc import Mapping, Sequence
from typing import Any

from sqlalchemy import func, select, text
from sqlalchemy.ext.asyncio import AsyncSession

from control_plane.audit.chain import (
    CHECKPOINT_STREAM,
    DEFAULT_STREAM,
    GENESIS_HASH,
    AuditChain,
    AuditEvent,
    AuditRecord,
    ChainVerification,
    CheckpointVerification,
    StreamHead,
    checkpoint_payload,
    verify_against_checkpoint,
    verify_chain,
)
from control_plane.config import get_settings
from control_plane.db import is_postgres
from control_plane.models.audit import AuditRecordRow

__all__ = ["AUDIT_LOCK_ID", "AuditService"]

#: Namespace for the append locks. Any other component taking advisory locks
#: must not reuse it. The second key is derived from the stream, so streams do
#: not contend with each other.
AUDIT_LOCK_ID = 0x5AD6_C0DE


def stream_lock_key(stream: str) -> int:
    """A stable 32-bit lock key for a stream name.

    Signed, because Postgres advisory lock keys are signed 32-bit integers and a
    value past 2^31 is an error rather than a wraparound.
    """
    return zlib.crc32(stream.encode("utf-8")) - 2**31


def partition_for(actor: str, partitions: int) -> str:
    """Which stream an actor's records belong to.

    Partitioned by actor rather than at random so that one principal's history
    stays in one chain -- an investigator following a single agent reads one
    stream, not all of them. The trade is that a single dominant caller does not
    spread: sharding helps a system with many callers, not one with a hot one.
    """
    if partitions <= 1:
        return DEFAULT_STREAM
    return f"p{zlib.crc32(actor.encode('utf-8')) % partitions}"


class AuditService:
    """Reads and appends audit records for one session."""

    def __init__(
        self,
        session: AsyncSession,
        key: bytes | None = None,
        *,
        partitions: int | None = None,
    ) -> None:
        self._session = session
        settings = get_settings()
        self._key = key if key is not None else settings.audit_key_bytes()
        self._partitions = partitions if partitions is not None else settings.audit_partitions

    async def _lock(self, stream: str) -> None:
        if is_postgres(self._session):
            await self._session.execute(
                text("SELECT pg_advisory_xact_lock(:namespace, :stream_key)"),
                {"namespace": AUDIT_LOCK_ID, "stream_key": stream_lock_key(stream)},
            )

    async def head(self, stream: str = DEFAULT_STREAM) -> tuple[int, str]:
        """One stream's current ``(next_seq, head_hash)``."""
        row = (
            await self._session.execute(
                select(AuditRecordRow.seq, AuditRecordRow.record_hash)
                .where(AuditRecordRow.stream == stream)
                .order_by(AuditRecordRow.seq.desc())
                .limit(1)
            )
        ).first()
        if row is None:
            return 1, GENESIS_HASH
        return row.seq + 1, row.record_hash

    async def streams(self, *, include_checkpoints: bool = False) -> list[str]:
        """Every stream that has records."""
        rows = (
            (
                await self._session.execute(
                    select(AuditRecordRow.stream).distinct().order_by(AuditRecordRow.stream)
                )
            )
            .scalars()
            .all()
        )
        if include_checkpoints:
            return list(rows)
        return [name for name in rows if name != CHECKPOINT_STREAM]

    async def stream_heads(self) -> list[StreamHead]:
        """Where each stream has reached."""
        heads: list[StreamHead] = []
        for stream in await self.streams():
            next_seq, head_hash = await self.head(stream)
            if next_seq > 1:
                heads.append(StreamHead(stream=stream, seq=next_seq - 1, head_hash=head_hash))
        return heads

    async def append(
        self,
        event: str | AuditEvent,
        *,
        actor: str,
        subject: str,
        payload: Mapping[str, Any] | None = None,
        note: str = "",
        stream: str | None = None,
    ) -> AuditRecord:
        """Seal and store one record.

        The row is added to the session but not committed: the caller's
        transaction decides whether the event happened. An audit record for a
        rolled-back operation would be a lie in the other direction.

        ``stream`` overrides the partitioning -- pass a tenant or a period to
        keep that slice of the log independently verifiable.
        """
        target = stream or partition_for(actor, self._partitions)
        await self._lock(target)
        next_seq, head_hash = await self.head(target)
        chain = AuditChain.resuming(
            self._key, head_hash=head_hash, next_seq=next_seq, stream=target
        )
        record = chain.append(event, actor=actor, subject=subject, payload=payload)
        self._session.add(AuditRecordRow.from_record(record, note=note))
        await self._session.flush()
        return record

    async def checkpoint(self, *, actor: str = "system") -> AuditRecord:
        """Seal a record of where every stream has reached.

        The answer to what sharding gives up. Per-stream verification proves each
        chain is internally consistent and says nothing about how many chains
        there should be; a checkpoint makes a stream's later disappearance
        contradict something already written.
        """
        heads = await self.stream_heads()
        return await self.append(
            AuditEvent.CHECKPOINT,
            actor=actor,
            subject=CHECKPOINT_STREAM,
            payload=checkpoint_payload(heads),
            stream=CHECKPOINT_STREAM,
        )

    async def list_records(
        self,
        *,
        limit: int = 100,
        offset: int = 0,
        event: str | None = None,
        actor: str | None = None,
        subject: str | None = None,
        stream: str | None = None,
    ) -> Sequence[AuditRecordRow]:
        """A page of records, newest first.

        Ordered by time rather than sequence: with several streams a sequence
        number no longer orders the log, and what a reader wants is what happened
        when.
        """
        statement = select(AuditRecordRow).order_by(
            AuditRecordRow.timestamp.desc(), AuditRecordRow.stream, AuditRecordRow.seq.desc()
        )
        if stream:
            statement = statement.where(AuditRecordRow.stream == stream)
        if event:
            statement = statement.where(AuditRecordRow.event == event)
        if actor:
            statement = statement.where(AuditRecordRow.actor == actor)
        if subject:
            statement = statement.where(AuditRecordRow.subject == subject)
        statement = statement.limit(min(limit, 1000)).offset(max(0, offset))
        return (await self._session.execute(statement)).scalars().all()

    async def count(self) -> int:
        return int(
            (await self._session.execute(select(func.count(AuditRecordRow.seq)))).scalar_one()
        )

    async def verify(
        self,
        *,
        stream: str = DEFAULT_STREAM,
        start_seq: int = 1,
        end_seq: int | None = None,
    ) -> ChainVerification:
        """Recompute a contiguous range of one stream.

        Verifying a slice that does not begin at the genesis record needs the
        preceding record's digest as its expected starting link; otherwise every
        partial verification would report a false break at its first row.
        """
        statement = (
            select(AuditRecordRow)
            .where(AuditRecordRow.stream == stream, AuditRecordRow.seq >= start_seq)
            .order_by(AuditRecordRow.seq.asc())
        )
        if end_seq is not None:
            statement = statement.where(AuditRecordRow.seq <= end_seq)
        rows = (await self._session.execute(statement)).scalars().all()

        expected_first_prev = GENESIS_HASH
        if start_seq > 1:
            predecessor = (
                await self._session.execute(
                    select(AuditRecordRow.record_hash).where(
                        AuditRecordRow.stream == stream,
                        AuditRecordRow.seq == start_seq - 1,
                    )
                )
            ).scalar_one_or_none()
            if predecessor is None:
                return ChainVerification(
                    valid=False,
                    checked=len(rows),
                    sequence_errors=(start_seq,),
                    message=(
                        f"cannot verify {stream} from seq {start_seq}: record "
                        f"{start_seq - 1} is missing, so the starting link is unknown"
                    ),
                )
            expected_first_prev = predecessor

        return verify_chain(
            (row.to_record() for row in rows),
            self._key,
            expected_first_prev=expected_first_prev,
        )

    async def verify_all(self) -> dict[str, Any]:
        """Verify every stream, then hold them against the last checkpoint.

        Two questions, and both have to be asked. Per-stream verification proves
        each chain is internally consistent. The checkpoint proves the set of
        chains is the set there is supposed to be -- without it, deleting a whole
        stream leaves everything that remains verifying perfectly.
        """
        results: dict[str, ChainVerification] = {}
        for stream in await self.streams(include_checkpoints=True):
            results[stream] = await self.verify(stream=stream)

        checkpoint = await self._verify_last_checkpoint()
        chains_valid = all(result.valid for result in results.values())
        valid = chains_valid and checkpoint.valid

        if valid:
            message = (
                f"{len(results)} stream(s) intact across "
                f"{sum(r.checked for r in results.values())} record(s)"
                + ("; checkpoint matches" if checkpoint.checked else "; no checkpoint yet")
            )
        else:
            broken = sorted(name for name, r in results.items() if not r.valid)
            parts = []
            if broken:
                parts.append(f"stream(s) failing verification: {', '.join(broken)}")
            if not checkpoint.valid:
                parts.append(checkpoint.message)
            message = "; ".join(parts)

        return {
            "valid": valid,
            "streams": {name: result.to_dict() for name, result in results.items()},
            "checkpoint": checkpoint.to_dict(),
            "message": message,
        }

    async def _verify_last_checkpoint(self) -> CheckpointVerification:
        """Hold the most recent checkpoint against the streams as they are now."""
        latest = (
            await self._session.execute(
                select(AuditRecordRow)
                .where(AuditRecordRow.stream == CHECKPOINT_STREAM)
                .order_by(AuditRecordRow.seq.desc())
                .limit(1)
            )
        ).scalar_one_or_none()
        if latest is None:
            return CheckpointVerification(
                valid=True, checked=0, message="no checkpoint has been taken yet"
            )

        recorded = [
            StreamHead.from_dict(entry) for entry in (latest.payload or {}).get("streams", [])
        ]
        observed: dict[str, tuple[int, str]] = {}
        for head in recorded:
            row = (
                await self._session.execute(
                    select(AuditRecordRow.seq, AuditRecordRow.record_hash).where(
                        AuditRecordRow.stream == head.stream,
                        AuditRecordRow.seq == head.seq,
                    )
                )
            ).first()
            if row is not None:
                observed[head.stream] = (row.seq, row.record_hash)
            else:
                # Either the stream is gone or it is shorter than it was. Report
                # the length we can still see so the difference is nameable.
                current, _ = await self.head(head.stream)
                if current > 1:
                    observed[head.stream] = (current - 1, "")
        return verify_against_checkpoint(recorded, observed)
