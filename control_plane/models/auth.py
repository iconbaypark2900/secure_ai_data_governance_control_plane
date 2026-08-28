"""API credentials.

Keys are stored as Argon2id hashes. The plaintext is shown once at issue time
and never again, so a database compromise yields no usable credential.

Lookup uses a short non-secret prefix carried in the key itself, which keeps
authentication to a single indexed row read rather than a hash comparison
against every key in the table.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any

from sqlalchemy import Index, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from control_plane.models.base import Base, TimestampMixin, TZDateTime, UUIDPrimaryKey


class ApiKey(Base, UUIDPrimaryKey, TimestampMixin):
    """A credential presented by an enforcement point or an operator."""

    __tablename__ = "api_keys"
    __table_args__ = (
        Index("ix_api_keys_prefix", "prefix", unique=True),
        Index("ix_api_keys_revoked", "revoked_at"),
    )

    name: Mapped[str] = mapped_column(String(255), nullable=False)
    description: Mapped[str] = mapped_column(Text, nullable=False, default="")
    #: Non-secret lookup handle, e.g. "cpk_7f3a91c2".
    prefix: Mapped[str] = mapped_column(String(32), nullable=False)
    key_hash: Mapped[str] = mapped_column(String(255), nullable=False)
    #: e.g. ["decide", "catalog:read", "policy:write", "audit:read"]
    scopes: Mapped[list[str]] = mapped_column(nullable=False, default=list)
    #: The principal an enforcement point is allowed to assert requests for.
    #: Empty means the key may speak for any principal, which should be rare.
    allowed_principals: Mapped[list[str]] = mapped_column(nullable=False, default=list)
    attributes: Mapped[dict[str, Any]] = mapped_column(nullable=False, default=dict)
    created_by: Mapped[str] = mapped_column(String(255), nullable=False, default="")
    last_used_at: Mapped[datetime | None] = mapped_column(TZDateTime, nullable=True)
    expires_at: Mapped[datetime | None] = mapped_column(TZDateTime, nullable=True)
    revoked_at: Mapped[datetime | None] = mapped_column(TZDateTime, nullable=True)

    def is_active(self, now: datetime) -> bool:
        if self.revoked_at is not None:
            return False
        return not (self.expires_at is not None and self.expires_at <= now)
