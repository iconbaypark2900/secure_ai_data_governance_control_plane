"""Storing, versioning, and loading policies.

Every write snapshots the full policy document into ``policy_versions`` before
returning. That is what makes a decision reproducible: the decision record names
the policy version that governed it, and the version table still holds the exact
text of that version even after the policy has been rewritten.

Policies are read on nearly every decision, so the compiled engine is cached.
The cache is invalidated explicitly on write and bounded by a TTL, which keeps a
second process's edits from being invisible for longer than that TTL.
"""

from __future__ import annotations

import time
from collections.abc import Iterable, Sequence
from typing import Any

import structlog
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from control_plane.config import get_settings
from control_plane.metrics import get_metrics
from control_plane.models.policy import PolicyRecord, PolicyVersion
from control_plane.policy.engine import PolicyEngine
from control_plane.policy.model import CombiningAlgorithm, Effect, Policy

__all__ = ["PolicyConflict", "PolicyNotFound", "PolicyStore", "invalidate_engine_cache"]

log = structlog.get_logger(__name__)


class PolicyNotFound(LookupError):
    """No policy exists with the requested key."""


class PolicyConflict(ValueError):
    """A policy with that key already exists."""


class _EngineCache:
    """A process-local cache of the compiled engine."""

    __slots__ = ("engine", "expires_at", "generation")

    def __init__(self) -> None:
        self.engine: PolicyEngine | None = None
        self.expires_at: float = 0.0
        self.generation: int = 0

    def invalidate(self) -> None:
        self.engine = None
        self.expires_at = 0.0
        self.generation += 1

    def get(self) -> PolicyEngine | None:
        if self.engine is None or time.monotonic() >= self.expires_at:
            return None
        return self.engine

    def set(self, engine: PolicyEngine, ttl: float) -> None:
        self.engine = engine
        self.expires_at = time.monotonic() + max(0.0, ttl)


_CACHE = _EngineCache()


def invalidate_engine_cache() -> None:
    """Force the next decision to rebuild the engine from the database."""
    _CACHE.invalidate()


class PolicyStore:
    """Policy persistence for one session."""

    def __init__(self, session: AsyncSession) -> None:
        self._session = session

    # --- reads -------------------------------------------------------------- #

    async def get_record(self, key: str) -> PolicyRecord | None:
        return (
            await self._session.execute(select(PolicyRecord).where(PolicyRecord.key == key))
        ).scalar_one_or_none()

    async def require_record(self, key: str) -> PolicyRecord:
        record = await self.get_record(key)
        if record is None:
            raise PolicyNotFound(f"no policy with key {key!r}")
        return record

    async def list_records(
        self,
        *,
        enabled: bool | None = None,
        effect: str | None = None,
        tag: str | None = None,
        limit: int = 200,
        offset: int = 0,
    ) -> Sequence[PolicyRecord]:
        statement = select(PolicyRecord).order_by(PolicyRecord.priority.desc(), PolicyRecord.key)
        if enabled is not None:
            statement = statement.where(PolicyRecord.enabled == enabled)
        if effect:
            statement = statement.where(PolicyRecord.effect == effect)
        statement = statement.limit(min(limit, 1000)).offset(max(0, offset))
        records = (await self._session.execute(statement)).scalars().all()
        if tag:
            records = [r for r in records if tag in (r.tags or [])]
        return records

    async def list_versions(self, key: str, *, limit: int = 50) -> Sequence[PolicyVersion]:
        return (
            (
                await self._session.execute(
                    select(PolicyVersion)
                    .where(PolicyVersion.policy_key == key)
                    .order_by(PolicyVersion.version.desc())
                    .limit(min(limit, 200))
                )
            )
            .scalars()
            .all()
        )

    async def get_version(self, key: str, version: int) -> PolicyVersion | None:
        return (
            await self._session.execute(
                select(PolicyVersion).where(
                    PolicyVersion.policy_key == key, PolicyVersion.version == version
                )
            )
        ).scalar_one_or_none()

    async def load_policies(self, *, enabled_only: bool = True) -> list[Policy]:
        """Parse stored documents back into validated policy objects.

        A document that fails to parse is skipped rather than fatal, and the
        failure is raised as a warning through the return of
        :meth:`load_policies_with_errors`. One malformed row must not take the
        whole decision path down.
        """
        policies, _ = await self.load_policies_with_errors(enabled_only=enabled_only)
        return policies

    async def load_policies_with_errors(
        self, *, enabled_only: bool = True
    ) -> tuple[list[Policy], list[str]]:
        records = await self.list_records(enabled=True if enabled_only else None, limit=1000)
        policies: list[Policy] = []
        errors: list[str] = []
        for record in records:
            try:
                policies.append(Policy.model_validate(record.document))
            except Exception as exc:
                errors.append(f"policy {record.key!r} (v{record.version}) is invalid: {exc}")
        return policies, errors

    async def build_engine(
        self,
        *,
        algorithm: CombiningAlgorithm | None = None,
        use_cache: bool = True,
    ) -> PolicyEngine:
        """The compiled engine, from cache when warm."""
        settings = get_settings()
        if use_cache:
            cached = _CACHE.get()
            if cached is not None:
                return cached

        policies, errors = await self.load_policies_with_errors(enabled_only=True)
        if errors:
            for message in errors:
                log.error("policy_failed_to_load", detail=message)
        engine = PolicyEngine(
            policies,
            algorithm=algorithm or CombiningAlgorithm.DENY_OVERRIDES,
            default_effect=Effect(settings.default_effect),
            load_errors=errors,
        )
        get_metrics().observe_policy_set(loaded=len(engine), errors=len(errors))
        if use_cache:
            _CACHE.set(engine, settings.policy_cache_ttl_seconds)
        return engine

    # --- writes ------------------------------------------------------------- #

    async def create(self, policy: Policy, *, actor: str = "", note: str = "") -> PolicyRecord:
        """Store a new policy at version 1."""
        if await self.get_record(policy.key) is not None:
            raise PolicyConflict(f"policy {policy.key!r} already exists")
        document = policy.to_document()
        document["version"] = 1
        record = PolicyRecord(
            key=policy.key,
            name=policy.name,
            description=policy.description,
            effect=str(policy.effect),
            priority=policy.priority,
            enabled=policy.enabled,
            version=1,
            document=document,
            tags=list(policy.tags),
            created_by=actor,
            updated_by=actor,
        )
        self._session.add(record)
        await self._session.flush()
        self._snapshot(record, note=note or "created", actor=actor)
        await self._session.flush()
        invalidate_engine_cache()
        return record

    async def update(
        self, key: str, policy: Policy, *, actor: str = "", note: str = ""
    ) -> PolicyRecord:
        """Replace a policy's content, bumping its version."""
        record = await self.require_record(key)
        if policy.key != key:
            raise PolicyConflict(
                f"cannot change a policy key: stored {key!r}, submitted {policy.key!r}"
            )
        new_version = record.version + 1
        document = policy.to_document()
        document["version"] = new_version

        record.name = policy.name
        record.description = policy.description
        record.effect = str(policy.effect)
        record.priority = policy.priority
        record.enabled = policy.enabled
        record.version = new_version
        record.document = document
        record.tags = list(policy.tags)
        record.updated_by = actor
        await self._session.flush()
        self._snapshot(record, note=note or "updated", actor=actor)
        await self._session.flush()
        invalidate_engine_cache()
        return record

    async def set_enabled(
        self, key: str, enabled: bool, *, actor: str = "", note: str = ""
    ) -> PolicyRecord:
        """Toggle a policy without rewriting it.

        Still a versioned change: disabling a control is exactly the kind of
        edit an auditor comes looking for.
        """
        record = await self.require_record(key)
        if record.enabled == enabled:
            return record
        record.enabled = enabled
        record.version += 1
        document = dict(record.document)
        document["enabled"] = enabled
        document["version"] = record.version
        record.document = document
        record.updated_by = actor
        await self._session.flush()
        self._snapshot(record, note=note or ("enabled" if enabled else "disabled"), actor=actor)
        await self._session.flush()
        invalidate_engine_cache()
        return record

    async def delete(self, key: str) -> bool:
        record = await self.get_record(key)
        if record is None:
            return False
        await self._session.delete(record)
        await self._session.flush()
        invalidate_engine_cache()
        return True

    def _snapshot(self, record: PolicyRecord, *, note: str, actor: str) -> None:
        self._session.add(
            PolicyVersion(
                policy_id=record.id,
                policy_key=record.key,
                version=record.version,
                document=dict(record.document),
                change_note=note,
                changed_by=actor,
            )
        )

    # --- bulk loading -------------------------------------------------------- #

    async def sync(
        self, policies: Iterable[Policy], *, actor: str = "sync", prune: bool = False
    ) -> dict[str, Any]:
        """Reconcile the stored set with a declared set.

        The path a GitOps-style deployment takes: policies live in a repository,
        this brings the database in line with them. ``prune`` removes stored
        policies absent from the declaration -- off by default, because deleting
        controls should be a deliberate act.
        """
        incoming = {policy.key: policy for policy in policies}
        existing = {record.key: record for record in await self.list_records(limit=1000)}

        created: list[str] = []
        updated: list[str] = []
        unchanged: list[str] = []
        removed: list[str] = []

        for key, policy in incoming.items():
            record = existing.get(key)
            if record is None:
                await self.create(policy, actor=actor, note="synced")
                created.append(key)
                continue
            candidate = policy.to_document()
            current = dict(record.document)
            # Version is bookkeeping, not content; comparing it would make every
            # sync look like a change.
            candidate.pop("version", None)
            current.pop("version", None)
            if candidate == current:
                unchanged.append(key)
                continue
            await self.update(key, policy, actor=actor, note="synced")
            updated.append(key)

        if prune:
            for key in existing.keys() - incoming.keys():
                await self.delete(key)
                removed.append(key)

        invalidate_engine_cache()
        return {
            "created": sorted(created),
            "updated": sorted(updated),
            "unchanged": sorted(unchanged),
            "removed": sorted(removed),
        }
