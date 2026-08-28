"""API key storage and authentication."""

from __future__ import annotations

from collections.abc import Sequence
from datetime import UTC, datetime
from typing import Any

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from control_plane.auth.keys import IssuedKey, generate_key, is_expired, split_key, verify_key
from control_plane.models.auth import ApiKey

__all__ = ["ApiKeyService", "AuthenticatedKey"]


class AuthenticatedKey:
    """The result of a successful authentication."""

    __slots__ = ("record", "scopes")

    def __init__(self, record: ApiKey) -> None:
        self.record = record
        self.scopes: frozenset[str] = frozenset(record.scopes or [])

    @property
    def name(self) -> str:
        return self.record.name

    @property
    def allowed_principals(self) -> list[str]:
        return list(self.record.allowed_principals or [])

    def may_act_for(self, principal_id: str) -> bool:
        """Whether this key may submit decisions on behalf of ``principal_id``.

        An empty allowlist means "any principal", which suits a shared gateway.
        A key issued to one agent should name that agent, so that a stolen key
        cannot be used to impersonate a more privileged one.
        """
        allowed = self.allowed_principals
        if not allowed:
            return True
        return any(
            principal_id == entry or (entry.endswith("*") and principal_id.startswith(entry[:-1]))
            for entry in allowed
        )


class ApiKeyService:
    """Key issuance, listing, revocation, and authentication."""

    def __init__(self, session: AsyncSession) -> None:
        self._session = session

    async def issue(
        self,
        *,
        name: str,
        scopes: Sequence[str],
        description: str = "",
        allowed_principals: Sequence[str] = (),
        attributes: dict[str, Any] | None = None,
        created_by: str = "",
        expires_at: datetime | None = None,
    ) -> tuple[ApiKey, IssuedKey]:
        """Mint and store a key. The plaintext is returned once and not kept."""
        issued = generate_key()
        record = ApiKey(
            name=name,
            description=description,
            prefix=issued.prefix,
            key_hash=issued.key_hash,
            scopes=list(scopes),
            allowed_principals=list(allowed_principals),
            attributes=dict(attributes or {}),
            created_by=created_by,
            expires_at=expires_at,
        )
        self._session.add(record)
        await self._session.flush()
        return record, issued

    async def authenticate(self, presented: str) -> AuthenticatedKey | None:
        """Resolve a presented key, or None if it is unusable for any reason.

        Every failure returns the same None. Distinguishing "no such key" from
        "revoked" from "expired" in the response would tell an attacker which
        guesses were close.
        """
        parts = split_key(presented)
        if parts is None:
            return None
        prefix, _ = parts

        record = (
            await self._session.execute(select(ApiKey).where(ApiKey.prefix == prefix))
        ).scalar_one_or_none()
        if record is None:
            return None
        if record.revoked_at is not None or is_expired(record.expires_at):
            return None
        if not verify_key(presented, record.key_hash):
            return None

        record.last_used_at = datetime.now(UTC)
        return AuthenticatedKey(record)

    async def list_keys(self, *, include_revoked: bool = False) -> Sequence[ApiKey]:
        statement = select(ApiKey).order_by(ApiKey.created_at.desc())
        if not include_revoked:
            statement = statement.where(ApiKey.revoked_at.is_(None))
        return (await self._session.execute(statement)).scalars().all()

    async def get(self, prefix: str) -> ApiKey | None:
        return (
            await self._session.execute(select(ApiKey).where(ApiKey.prefix == prefix))
        ).scalar_one_or_none()

    async def revoke(self, prefix: str) -> ApiKey | None:
        record = await self.get(prefix)
        if record is None or record.revoked_at is not None:
            return None
        record.revoked_at = datetime.now(UTC)
        await self._session.flush()
        return record

    async def count_active(self) -> int:
        return len(await self.list_keys())
