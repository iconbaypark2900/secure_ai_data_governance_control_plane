#!/usr/bin/env python
"""Generate the cross-language SDK contract fixture.

The TypeScript tests assert that their request bodies equal these, and these are
produced by calling the Python SDK's own body builder. That direction matters: a
fixture written by hand from the documentation tests whether two people read the
same prose the same way, which is not the question. The question is whether two
clients put the same thing on the wire, because two that disagree get different
decisions out of the same policy -- and the one used less is the one that stays
wrong.

    python tools/generate_sdk_contract.py

Run it after changing either client, and commit the result.
"""

from __future__ import annotations

import json
import pathlib
import sys

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "sdk" / "python"))

from control_plane_sdk import Outcome  # noqa: E402
from control_plane_sdk.client import (  # noqa: E402
    SATISFIED_BY_CONTROL_PLANE,
    _build_body,
    _cache_key,
)

OUTPUT = ROOT / "sdk" / "typescript" / "test" / "contract.json"

DEFAULTS: dict[str, object] = {
    "principal_type": "service",
    "principal_attributes": None,
    "resource_urn": None,
    "resource_kind": None,
    "classifications": None,
    "resource_attributes": None,
    "context": None,
    "payload": None,
    "correlation_id": None,
    "approval_id": None,
    "explain": False,
    "apply_obligations": True,
    "persist": True,
}

#: Chosen to cover every branch in _build_body: each optional field present and
#: absent, and the collections both empty and populated.
CASES: list[tuple[str, dict[str, object]]] = [
    ("minimal", {"principal_id": "svc://a", "action": "read"}),
    (
        "full",
        {
            "principal_id": "agent://analyst",
            "action": "infer",
            "principal_type": "agent",
            "principal_attributes": {"trust": "low", "reviewed": True},
            "resource_urn": "pg://public.customers",
            "resource_kind": "table",
            "classifications": ["pii.email", "phi"],
            "resource_attributes": {"owner": "clinical"},
            "context": {"destination": "external", "purpose": "support", "region": "eu"},
            "correlation_id": "conv-1",
            "explain": True,
            "apply_obligations": False,
            "persist": False,
        },
    ),
    (
        "with_payload",
        {
            "principal_id": "agent://x",
            "action": "return",
            "payload": {"text": "SSN 501-72-9384"},
            "resource_urn": "mcp://srv/read_file",
            "resource_kind": "tool",
        },
    ),
    ("with_approval", {"principal_id": "u://1", "action": "export", "approval_id": "ap_9"}),
    (
        "empty_collections",
        {
            "principal_id": "svc://b",
            "action": "write",
            "classifications": [],
            "context": {},
            "principal_attributes": {},
            "resource_attributes": {},
        },
    ),
    (
        "context_ordering",
        {
            "principal_id": "svc://c",
            "action": "read",
            "context": {"z": 1, "a": "two", "m": False},
            "classifications": ["z.label", "a.label", "m.label"],
        },
    ),
]


def main() -> int:
    cases = []
    for name, overrides in CASES:
        body = _build_body(**{**DEFAULTS, **overrides})  # type: ignore[arg-type]
        cases.append(
            {
                "name": name,
                "input": overrides,
                "body": body,
                # Recorded for reference only. The TypeScript client is not
                # expected to reproduce these: the two languages format floats
                # and escape non-ASCII differently, and the cache is
                # process-local, so only internal consistency matters there.
                "cache_key": _cache_key(body),
            }
        )

    OUTPUT.write_text(
        json.dumps(
            {
                "generated_by": "tools/generate_sdk_contract.py",
                "source": "sdk/python/control_plane_sdk/client.py",
                "satisfied_by_control_plane": sorted(SATISFIED_BY_CONTROL_PLANE),
                "outcomes": [Outcome.ENFORCED, Outcome.REFUSED, Outcome.PARTIAL],
                "cases": cases,
            },
            indent=2,
        )
        + "\n"
    )
    print(f"wrote {OUTPUT.relative_to(ROOT)}: {len(cases)} cases")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
