"""The audit chain's storage row.

Nothing in this table may be updated. The application never issues an UPDATE
against it, and the migration adds a database-level trigger enforcing that, so
an accidental ORM flush cannot quietly rewrite history.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any

from sqlalchemy import BigInteger, Index, String, Text, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column

from control_plane.audit.chain import AuditRecord
from control_plane.models.base import Base, TZDateTime


class AuditRecordRow(Base):
    """One sealed audit record."""

    __tablename__ = "audit_records"
    __table_args__ = (
        UniqueConstraint("seq", name="uq_audit_records_seq"),
        Index("ix_audit_records_event_ts", "event", "timestamp"),
        Index("ix_audit_records_subject", "subject"),
        Index("ix_audit_records_actor", "actor"),
    )

    seq: Mapped[int] = mapped_column(BigInteger, primary_key=True, autoincrement=False)
    timestamp: Mapped[datetime] = mapped_column(TZDateTime, nullable=False, index=True)
    event: Mapped[str] = mapped_column(String(64), nullable=False)
    actor: Mapped[str] = mapped_column(String(255), nullable=False, default="")
    subject: Mapped[str] = mapped_column(String(512), nullable=False, default="")
    payload: Mapped[dict[str, Any]] = mapped_column(nullable=False, default=dict)
    prev_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    record_hash: Mapped[str] = mapped_column(String(64), nullable=False, unique=True)
    #: Free-text note about why the record exists; never sensitive content.
    note: Mapped[str] = mapped_column(Text, nullable=False, default="")

    def to_record(self) -> AuditRecord:
        """Convert back to the pure form the verifier works with."""
        return AuditRecord(
            seq=self.seq,
            timestamp=self.timestamp,
            event=self.event,
            actor=self.actor,
            subject=self.subject,
            payload=self.payload,
            prev_hash=self.prev_hash,
            record_hash=self.record_hash,
        )

    @classmethod
    def from_record(cls, record: AuditRecord, note: str = "") -> AuditRecordRow:
        return cls(
            seq=record.seq,
            timestamp=record.timestamp,
            event=record.event,
            actor=record.actor,
            subject=record.subject,
            payload=dict(record.payload),
            prev_hash=record.prev_hash,
            record_hash=record.record_hash,
            note=note,
        )
