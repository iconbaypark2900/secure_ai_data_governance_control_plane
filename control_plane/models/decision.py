"""Decision records and the approval queue."""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any

from sqlalchemy import Float, ForeignKey, Index, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from control_plane.models.base import Base, TimestampMixin, TZDateTime, UUIDPrimaryKey


class DecisionRecord(Base, UUIDPrimaryKey, TimestampMixin):
    """One evaluated access request.

    This is the operational record: it answers "what did we decide, for whom,
    about what, and how long did it take". The tamper-evident proof of the same
    event lives in the audit chain; this table exists so the same facts can be
    queried, aggregated, and indexed without weakening that chain.

    No payload content is stored -- only the labels found in it and a keyed
    digest, so an investigator can match a decision to a document they already
    hold without the control plane retaining a copy.
    """

    __tablename__ = "decisions"
    __table_args__ = (
        Index("ix_decisions_principal_created", "principal_id", "created_at"),
        Index("ix_decisions_effect_created", "effect", "created_at"),
        Index("ix_decisions_resource", "resource_urn"),
    )

    principal_id: Mapped[str] = mapped_column(String(255), nullable=False)
    principal_type: Mapped[str] = mapped_column(String(32), nullable=False, default="unknown")
    action: Mapped[str] = mapped_column(String(64), nullable=False)
    resource_urn: Mapped[str] = mapped_column(String(512), nullable=False, default="")
    resource_kind: Mapped[str] = mapped_column(String(64), nullable=False, default="")

    effect: Mapped[str] = mapped_column(String(32), nullable=False)
    reason: Mapped[str] = mapped_column(Text, nullable=False, default="")
    determining_policy: Mapped[str | None] = mapped_column(String(128), nullable=True)
    matched_policies: Mapped[list[str]] = mapped_column(nullable=False, default=list)
    obligations: Mapped[list[dict[str, Any]]] = mapped_column(nullable=False, default=list)

    #: Labels the request carried or the scanner found, for aggregate reporting.
    classifications: Mapped[list[str]] = mapped_column(nullable=False, default=list)
    finding_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    redaction_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    #: Keyed digest of the request payload; not reversible to content.
    payload_digest: Mapped[str | None] = mapped_column(String(64), nullable=True)

    context: Mapped[dict[str, Any]] = mapped_column(nullable=False, default=dict)
    trace: Mapped[dict[str, Any]] = mapped_column(nullable=False, default=dict)
    latency_ms: Mapped[float] = mapped_column(Float, nullable=False, default=0.0)
    #: Correlates a decision with the caller's own request/trace id.
    correlation_id: Mapped[str | None] = mapped_column(String(128), nullable=True, index=True)

    approval: Mapped[ApprovalRequest | None] = relationship(
        back_populates="decision", uselist=False, cascade="all, delete-orphan"
    )


class ApprovalRequest(Base, UUIDPrimaryKey, TimestampMixin):
    """A decision parked awaiting a human.

    The ``require_approval`` effect exists so that a policy can express "not
    without a person" rather than being forced to choose between blocking a
    legitimate need and waving through a risky one.
    """

    __tablename__ = "approval_requests"
    __table_args__ = (Index("ix_approval_status_created", "status", "created_at"),)

    decision_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("decisions.id", ondelete="CASCADE"), nullable=False, unique=True
    )
    #: pending | granted | denied | expired
    status: Mapped[str] = mapped_column(String(32), nullable=False, default="pending")
    requested_by: Mapped[str] = mapped_column(String(255), nullable=False, default="")
    justification: Mapped[str] = mapped_column(Text, nullable=False, default="")
    decided_by: Mapped[str | None] = mapped_column(String(255), nullable=True)
    decision_note: Mapped[str] = mapped_column(Text, nullable=False, default="")
    resolved_at: Mapped[datetime | None] = mapped_column(TZDateTime, nullable=True)
    expires_at: Mapped[datetime | None] = mapped_column(TZDateTime, nullable=True)

    decision: Mapped[DecisionRecord] = relationship(back_populates="approval")

    @property
    def is_pending(self) -> bool:
        return self.status == "pending"
