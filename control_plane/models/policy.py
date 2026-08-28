"""Stored policies and their version history."""

from __future__ import annotations

import uuid
from typing import Any

from sqlalchemy import Boolean, ForeignKey, Index, Integer, String, Text, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column, relationship

from control_plane.models.base import Base, TimestampMixin, UUIDPrimaryKey


class PolicyRecord(Base, UUIDPrimaryKey, TimestampMixin):
    """The current state of one authored policy.

    ``document`` holds the whole normalised policy as JSON. The engine consumes
    that document directly, so what is evaluated is exactly what was stored --
    there is no second, drifting representation assembled from columns. The
    columns that are broken out exist only so the database can filter and sort
    without parsing JSON.
    """

    __tablename__ = "policies"
    __table_args__ = (
        UniqueConstraint("key", name="uq_policies_key"),
        Index("ix_policies_enabled_priority", "enabled", "priority"),
    )

    key: Mapped[str] = mapped_column(String(128), nullable=False)
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    description: Mapped[str] = mapped_column(Text, nullable=False, default="")
    effect: Mapped[str] = mapped_column(String(32), nullable=False)
    priority: Mapped[int] = mapped_column(Integer, nullable=False, default=100)
    enabled: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    version: Mapped[int] = mapped_column(Integer, nullable=False, default=1)
    document: Mapped[dict[str, Any]] = mapped_column(nullable=False)
    tags: Mapped[list[str]] = mapped_column(nullable=False, default=list)
    created_by: Mapped[str] = mapped_column(String(255), nullable=False, default="")
    updated_by: Mapped[str] = mapped_column(String(255), nullable=False, default="")

    versions: Mapped[list[PolicyVersion]] = relationship(
        back_populates="policy",
        cascade="all, delete-orphan",
        order_by="PolicyVersion.version.desc()",
    )


class PolicyVersion(Base, UUIDPrimaryKey, TimestampMixin):
    """An immutable snapshot of a policy as it was at one version.

    Kept so that a decision made six months ago can be re-evaluated against the
    policy text that actually governed it, rather than against today's.
    """

    __tablename__ = "policy_versions"
    __table_args__ = (
        UniqueConstraint("policy_id", "version", name="uq_policy_versions_policy_version"),
    )

    policy_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("policies.id", ondelete="CASCADE"), nullable=False, index=True
    )
    policy_key: Mapped[str] = mapped_column(String(128), nullable=False, index=True)
    version: Mapped[int] = mapped_column(Integer, nullable=False)
    document: Mapped[dict[str, Any]] = mapped_column(nullable=False)
    change_note: Mapped[str] = mapped_column(Text, nullable=False, default="")
    changed_by: Mapped[str] = mapped_column(String(255), nullable=False, default="")

    policy: Mapped[PolicyRecord] = relationship(back_populates="versions")
