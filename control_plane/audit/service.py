"""Persisting the audit chain.

Appending is the one operation in the system that must be serialised. Two
concurrent appends that both read the same head would produce two records
claiming the same predecessor, and the chain would fork -- verifiable in
isolation, meaningless as a history.

On Postgres this is handled with a transaction-scoped advisory lock, which is
released automatically at commit or rollback and costs one round trip. SQLite
serialises writers already, so it takes the no-op path.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from typing import Any

from sqlalchemy import func, select, text
from sqlalchemy.ext.asyncio import AsyncSession

from control_plane.audit.chain import (
    GENESIS_HASH,
    AuditChain,
    AuditEvent,
    AuditRecord,
    ChainVerification,
    verify_chain,
)
from control_plane.config import get_settings
from control_plane.db import is_postgres
from control_plane.models.audit import AuditRecordRow

__all__ = ["AUDIT_LOCK_ID", "AuditService"]

#: Arbitrary but fixed identifier for the append lock. Any other component
#: taking advisory locks must not reuse it.
AUDIT_LOCK_ID = 0x5AD6_C0DE


class AuditService:
    """Reads and appends audit records for one session."""

    def __init__(self, session: AsyncSession, key: bytes | None = None) -> None:
        self._session = session
        self._key = key if key is not None else get_settings().audit_key_bytes()

    async def _lock(self) -> None:
        if is_postgres(self._session):
            await self._session.execute(
                text("SELECT pg_advisory_xact_lock(:lock_id)"), {"lock_id": AUDIT_LOCK_ID}
            )

    async def head(self) -> tuple[int, str]:
        """The current ``(next_seq, head_hash)``."""
        row = (
            await self._session.execute(
                select(AuditRecordRow.seq, AuditRecordRow.record_hash)
                .order_by(AuditRecordRow.seq.desc())
                .limit(1)
            )
        ).first()
        if row is None:
            return 1, GENESIS_HASH
        return row.seq + 1, row.record_hash

    async def append(
        self,
        event: str | AuditEvent,
        *,
        actor: str,
        subject: str,
        payload: Mapping[str, Any] | None = None,
        note: str = "",
    ) -> AuditRecord:
        """Seal and store one record.

        The row is added to the session but not committed: the caller's
        transaction decides whether the event happened. An audit record for a
        rolled-back operation would be a lie in the other direction.
        """
        await self._lock()
        next_seq, head_hash = await self.head()
        chain = AuditChain.resuming(self._key, head_hash=head_hash, next_seq=next_seq)
        record = chain.append(event, actor=actor, subject=subject, payload=payload)
        self._session.add(AuditRecordRow.from_record(record, note=note))
        await self._session.flush()
        return record

    async def list_records(
        self,
        *,
        limit: int = 100,
        offset: int = 0,
        event: str | None = None,
        actor: str | None = None,
        subject: str | None = None,
    ) -> Sequence[AuditRecordRow]:
        """A page of records, newest first."""
        statement = select(AuditRecordRow).order_by(AuditRecordRow.seq.desc())
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

    async def verify(self, *, start_seq: int = 1, end_seq: int | None = None) -> ChainVerification:
        """Recompute a contiguous range of the chain.

        Verifying a slice that does not begin at the genesis record needs the
        preceding record's digest as its expected starting link; otherwise every
        partial verification would report a false break at its first row.
        """
        statement = (
            select(AuditRecordRow)
            .where(AuditRecordRow.seq >= start_seq)
            .order_by(AuditRecordRow.seq.asc())
        )
        if end_seq is not None:
            statement = statement.where(AuditRecordRow.seq <= end_seq)
        rows = (await self._session.execute(statement)).scalars().all()

        expected_first_prev = GENESIS_HASH
        if start_seq > 1:
            predecessor = (
                await self._session.execute(
                    select(AuditRecordRow.record_hash).where(AuditRecordRow.seq == start_seq - 1)
                )
            ).scalar_one_or_none()
            if predecessor is None:
                return ChainVerification(
                    valid=False,
                    checked=len(rows),
                    sequence_errors=(start_seq,),
                    message=(
                        f"cannot verify from seq {start_seq}: record "
                        f"{start_seq - 1} is missing, so the starting link is unknown"
                    ),
                )
            expected_first_prev = predecessor

        return verify_chain(
            (row.to_record() for row in rows),
            self._key,
            expected_first_prev=expected_first_prev,
        )
