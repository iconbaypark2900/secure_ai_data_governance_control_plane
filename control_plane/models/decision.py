"""Decision records and the approval queue."""

from __future__ import annotations

import hmac
import uuid
from datetime import UTC, datetime
from typing import Any

from sqlalchemy import Float, ForeignKey, Index, Integer, String, Text, Uuid
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
    """A decision parked awaiting a human, and the record of it being redeemed.

    The ``require_approval`` effect exists so that a policy can express "not
    without a person" rather than being forced to choose between blocking a
    legitimate need and waving through a risky one.

    An approval is a capability, and it is scoped like one. It authorises *the
    request it was granted for* and nothing else: ``request_fingerprint`` binds
    it to the principal, action, resource, labels, payload, and context that a
    human actually saw. It is single-use, it expires, and redeeming it can only
    turn ``require_approval`` into ``allow`` -- never a ``deny`` into anything.
    Without those four properties, "approve this one export" quietly becomes
    "approve any request whose approval id you happen to know".
    """

    __tablename__ = "approval_requests"
    __table_args__ = (
        Index("ix_approval_status_created", "status", "created_at"),
        Index("ix_approval_fingerprint", "request_fingerprint"),
    )

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

    #: Keyed digest of the policy-relevant request inputs. Recomputed at
    #: redemption and compared; a mismatch means this approval was granted for
    #: a different question.
    request_fingerprint: Mapped[str] = mapped_column(String(64), nullable=False, default="")

    redeemed_at: Mapped[datetime | None] = mapped_column(TZDateTime, nullable=True)
    redeemed_by: Mapped[str | None] = mapped_column(String(255), nullable=True)
    #: The decision this approval was spent on. Not a foreign key: the approval
    #: must outlive a decision row that retention policy later removes, because
    #: "this was approved and then used" is the fact worth keeping.
    redeemed_decision_id: Mapped[uuid.UUID | None] = mapped_column(
        Uuid(as_uuid=True), nullable=True
    )

    decision: Mapped[DecisionRecord] = relationship(back_populates="approval")

    @property
    def is_pending(self) -> bool:
        return self.status == "pending"

    @property
    def is_redeemed(self) -> bool:
        return self.redeemed_at is not None

    def redemption_error(self, fingerprint: str, now: datetime) -> str | None:
        """Why this approval cannot be redeemed for ``fingerprint``, or None.

        Returns a reason rather than a bare boolean because the enforcement
        point has to tell the difference between "wait, still pending" and
        "stop, this will never work".
        """
        if self.status == "pending":
            return "the approval request is still awaiting a decision"
        if self.status == "denied":
            return "the approval request was denied"
        if self.status != "granted":
            return f"the approval request is {self.status}"
        if self.is_redeemed:
            return (
                f"the approval was already redeemed at "
                f"{_iso(self.redeemed_at)} by {self.redeemed_by or 'an unknown caller'}"
            )
        if self.expires_at is not None and _as_utc(self.expires_at) <= now:
            return f"the approval expired at {_iso(self.expires_at)}"
        if not self.request_fingerprint:
            # Granted before fingerprinting existed. Refusing is the safe
            # reading: an unbound approval is a capability with no scope.
            return "the approval carries no request binding and cannot be redeemed"
        if not hmac.compare_digest(self.request_fingerprint, fingerprint):
            return (
                "the approval was granted for a different request; approvals "
                "authorise only the exact request a human reviewed"
            )
        return None


def _as_utc(value: datetime) -> datetime:
    return value if value.tzinfo is not None else value.replace(tzinfo=UTC)


def _iso(value: datetime | None) -> str:
    return _as_utc(value).isoformat() if value is not None else "an unknown time"
