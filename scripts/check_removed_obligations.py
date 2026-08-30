#!/usr/bin/env python
"""Report stored policies that use an obligation type this build no longer has.

Removing an obligation type is a breaking change, and it breaks the way this
codebase prefers: a stored policy carrying one fails to parse, the engine
reports the failure on every decision, and the default effect is deny. Loud and
closed. But a skipped *allow* policy denies traffic that used to be permitted,
so the loudness arrives as an outage rather than as a warning.

This answers the question beforehand instead. Point it at the database you are
about to upgrade::

    CP_DATABASE_URL=... .venv/bin/python scripts/check_removed_obligations.py

Exit 0 when nothing is affected, 1 when something is, so it can gate a deploy.
Read-only: it reports, it does not edit. Which policy to rewrite, and into what,
is not a decision a migration should make on an operator's behalf.

Written for the removal of ``annotate``, ``log`` and ``ttl`` (ADR 0017), but it
takes the surviving set from the code rather than naming those three, so it
stays useful for the next one.
"""

from __future__ import annotations

import asyncio
from typing import Any

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine

from control_plane.config import get_settings
from control_plane.models.policy import PolicyRecord
from control_plane.policy.model import KNOWN_OBLIGATIONS


def unknown_types(document: dict[str, Any]) -> list[str]:
    """Obligation types in a stored document that this build does not know.

    Reads the raw document rather than validating it into a ``Policy``: the
    whole point is to look at rows that no longer validate.
    """
    obligations = document.get("obligations") or []
    if not isinstance(obligations, list):
        return []
    found = []
    for obligation in obligations:
        if not isinstance(obligation, dict):
            continue
        name = str(obligation.get("type", "")).strip().lower()
        if name and name not in KNOWN_OBLIGATIONS:
            found.append(name)
    return sorted(set(found))


async def main() -> int:
    engine = create_async_engine(get_settings().database_url)
    try:
        async with AsyncSession(engine) as session:
            records = (await session.scalars(select(PolicyRecord))).all()
    finally:
        await engine.dispose()

    affected = [(r, unknown_types(r.document)) for r in records]
    affected = [(r, types) for r, types in affected if types]

    if not affected:
        print(f"{len(records)} stored policies, none using a removed obligation type.")
        return 0

    print(
        f"{len(affected)} of {len(records)} stored policies use an obligation type this "
        f"build does not have. Each will fail to load, and every decision made while "
        f"it does will report the failure and fall through to the default effect.\n"
    )
    for record, types in sorted(affected, key=lambda item: item[0].key):
        state = "enabled" if record.enabled else "disabled"
        # An allow is called out separately: losing one takes away a permission
        # that traffic depends on, which is the case that surprises people.
        weight = (
            "  <-- an enabled allow: traffic it permits will stop"
            if (record.enabled and record.effect == "allow")
            else ""
        )
        print(f"  {record.key} ({record.effect}, {state}): {', '.join(types)}{weight}")

    print(
        "\nRewrite or disable these before upgrading. A `log` obligation can be "
        "dropped outright -- the decision record and audit event were never "
        "produced by it -- and an `annotate` note belongs in the policy's "
        "description. See docs/adr/0017-the-control-plane-executes-one-obligation.md."
    )
    return 1


if __name__ == "__main__":
    raise SystemExit(asyncio.run(main()))
