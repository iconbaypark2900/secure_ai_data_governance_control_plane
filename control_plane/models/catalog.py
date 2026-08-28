"""Principals and data assets: the nouns policies talk about."""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any

from sqlalchemy import Float, ForeignKey, Index, String, Text, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column, relationship

from control_plane.models.base import Base, TimestampMixin, TZDateTime, UUIDPrimaryKey


class Principal(Base, UUIDPrimaryKey, TimestampMixin):
    """A user, agent, or service that can make requests.

    ``external_id`` is the identity the enforcement point actually presents --
    an OIDC subject, a service account name, an agent slug. The control plane
    does not issue identities; it recognises them.
    """

    __tablename__ = "principals"
    __table_args__ = (
        UniqueConstraint("external_id", name="uq_principals_external_id"),
        Index("ix_principals_type_disabled", "type", "disabled_at"),
    )

    external_id: Mapped[str] = mapped_column(String(255), nullable=False)
    type: Mapped[str] = mapped_column(String(32), nullable=False, default="unknown")
    display_name: Mapped[str] = mapped_column(String(255), nullable=False, default="")
    description: Mapped[str] = mapped_column(Text, nullable=False, default="")
    #: Free-form ABAC attributes: team, trust_tier, clearance, region, ...
    attributes: Mapped[dict[str, Any]] = mapped_column(nullable=False, default=dict)
    disabled_at: Mapped[datetime | None] = mapped_column(TZDateTime, nullable=True)

    @property
    def enabled(self) -> bool:
        return self.disabled_at is None


class DataAsset(Base, UUIDPrimaryKey, TimestampMixin):
    """Something that holds data: a table, a vector collection, a bucket, a model.

    Identified by a URN so that one namespace covers every backing store:
    ``pg://public.customers``, ``qdrant://kb_docs``, ``s3://exports/2026``.
    """

    __tablename__ = "data_assets"
    __table_args__ = (
        UniqueConstraint("urn", name="uq_data_assets_urn"),
        Index("ix_data_assets_kind", "kind"),
        Index("ix_data_assets_owner", "owner"),
    )

    urn: Mapped[str] = mapped_column(String(512), nullable=False)
    name: Mapped[str] = mapped_column(String(255), nullable=False, default="")
    kind: Mapped[str] = mapped_column(String(64), nullable=False, default="unknown")
    owner: Mapped[str] = mapped_column(String(255), nullable=False, default="")
    description: Mapped[str] = mapped_column(Text, nullable=False, default="")
    attributes: Mapped[dict[str, Any]] = mapped_column(nullable=False, default=dict)
    #: Set when a scan last ran, so staleness is visible in the catalog.
    last_scanned_at: Mapped[datetime | None] = mapped_column(TZDateTime, nullable=True)

    classifications: Mapped[list[AssetClassification]] = relationship(
        back_populates="asset",
        cascade="all, delete-orphan",
        lazy="selectin",
    )

    @property
    def label_keys(self) -> list[str]:
        """Distinct label keys currently attached to this asset."""
        return sorted({c.label for c in self.classifications})


class AssetClassification(Base, UUIDPrimaryKey, TimestampMixin):
    """A sensitivity label attached to an asset, with its provenance.

    Provenance matters: a label a scanner inferred at 0.6 confidence and a label
    a data steward asserted are both true statements about the asset, but only
    one of them should survive a disagreement. ``source`` and ``confidence``
    keep that distinction visible instead of collapsing it.
    """

    __tablename__ = "asset_classifications"
    __table_args__ = (
        UniqueConstraint("asset_id", "label", "source", name="uq_asset_label_source"),
        Index("ix_asset_classifications_label", "label"),
    )

    asset_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("data_assets.id", ondelete="CASCADE"), nullable=False, index=True
    )
    label: Mapped[str] = mapped_column(String(128), nullable=False)
    #: manual | scan | inherited | imported
    source: Mapped[str] = mapped_column(String(32), nullable=False, default="manual")
    confidence: Mapped[float] = mapped_column(Float, nullable=False, default=1.0)
    #: Masked previews and counts only. Never the matched values.
    evidence: Mapped[dict[str, Any]] = mapped_column(nullable=False, default=dict)
    asserted_by: Mapped[str] = mapped_column(String(255), nullable=False, default="")
    expires_at: Mapped[datetime | None] = mapped_column(TZDateTime, nullable=True)

    asset: Mapped[DataAsset] = relationship(back_populates="classifications")
