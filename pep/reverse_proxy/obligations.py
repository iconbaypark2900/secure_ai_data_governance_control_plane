"""Carrying out the obligations the control plane hands to an enforcement point.

Three of the seven obligation types are the enforcement point's job, because
they act on the transport rather than on the data:

``require_purpose``  the purpose asserted at decision time is re-checked here,
                     at the point of use. Duplicating a policy's own
                     ``context.purpose`` condition is the point: the proxy stops
                     trusting what it itself declared a moment earlier.
``limit``            caps how much may flow -- tokens on the way in, bytes and
                     choices on the way back.
``watermark``        marks the delivered content, so its origin survives being
                     pasted somewhere else.

Pure functions over plain dictionaries, so they can be tested without an HTTP
server or a live control plane. Each returns what it did, because an obligation
carried out silently is indistinguishable from one skipped.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass, field
from typing import Any

__all__ = [
    "SATISFIABLE",
    "AppliedObligations",
    "apply_request_obligations",
    "apply_response_obligations",
    "check_purpose",
    "obligations_of",
    "token_cap",
]

#: What this enforcement point tells the SDK it can discharge. Anything else in a
#: decision turns the allow into a refusal rather than being quietly ignored.
SATISFIABLE: frozenset[str] = frozenset({"limit", "watermark", "require_purpose"})


@dataclass
class AppliedObligations:
    """What was actually done to a response."""

    truncated_bytes: int | None = None
    dropped_choices: int | None = None
    watermarked: bool = False
    notes: list[str] = field(default_factory=list)

    @property
    def changed(self) -> bool:
        return bool(self.notes)

    def to_dict(self) -> dict[str, Any]:
        return {
            "truncated_bytes": self.truncated_bytes,
            "dropped_choices": self.dropped_choices,
            "watermarked": self.watermarked,
            "notes": list(self.notes),
        }


def obligations_of(obligations: Iterable[Mapping[str, Any]], kind: str) -> list[Mapping[str, Any]]:
    """Every obligation of one type."""
    return [o for o in obligations if str(o.get("type", "")).lower() == kind]


def check_purpose(obligations: Iterable[Mapping[str, Any]], declared: str) -> str | None:
    """Return a refusal reason if the declared purpose is not permitted.

    Every ``require_purpose`` obligation must be satisfied, not merely one: two
    policies each narrowing the acceptable purposes should intersect, not race.
    """
    for obligation in obligations_of(obligations, "require_purpose"):
        raw = obligation.get("purposes") or []
        permitted = [str(p) for p in ([raw] if isinstance(raw, str) else raw)]
        if declared not in permitted:
            return (
                f"the declared purpose {declared!r} is not among the purposes this "
                f"policy permits ({', '.join(permitted) or 'none'})"
            )
    return None


def token_cap(obligations: Iterable[Mapping[str, Any]]) -> int | None:
    """The tightest ``max_tokens`` any limit obligation imposes."""
    caps = [
        int(o["max_tokens"])
        for o in obligations_of(obligations, "limit")
        if isinstance(o.get("max_tokens"), int) and not isinstance(o.get("max_tokens"), bool)
    ]
    return min(caps) if caps else None


def _tightest(obligations: Iterable[Mapping[str, Any]], key: str) -> int | None:
    values = [
        int(o[key])
        for o in obligations_of(obligations, "limit")
        if isinstance(o.get(key), int) and not isinstance(o.get(key), bool)
    ]
    return min(values) if values else None


def apply_request_obligations(
    body: dict[str, Any], obligations: Sequence[Mapping[str, Any]]
) -> tuple[dict[str, Any], list[str]]:
    """Tighten the upstream request. Never loosens what the caller asked for."""
    notes: list[str] = []
    updated = dict(body)

    cap = token_cap(obligations)
    if cap is not None:
        requested = updated.get("max_tokens")
        effective = cap if not isinstance(requested, int) else min(int(requested), cap)
        if effective != requested:
            updated["max_tokens"] = effective
            notes.append(f"max_tokens capped at {effective}")
    return updated, notes


def apply_response_obligations(
    completion: dict[str, Any], obligations: Sequence[Mapping[str, Any]]
) -> tuple[dict[str, Any], AppliedObligations]:
    """Cap and mark a completion on its way back to the caller."""
    applied = AppliedObligations()
    updated = dict(completion)
    choices = list(updated.get("choices") or [])

    max_results = _tightest(obligations, "max_results")
    if max_results is not None and len(choices) > max_results:
        applied.dropped_choices = len(choices) - max_results
        applied.notes.append(
            f"dropped {applied.dropped_choices} of {len(choices)} choices "
            f"(max_results={max_results})"
        )
        choices = choices[:max_results]

    max_bytes = _tightest(obligations, "max_bytes")
    watermarks = [
        str(o.get("text", "")).strip()
        for o in obligations_of(obligations, "watermark")
        if str(o.get("text", "")).strip()
    ]

    rebuilt = []
    for choice in choices:
        message = dict(choice.get("message") or {})
        content = message.get("content")
        if isinstance(content, str):
            if max_bytes is not None:
                encoded = content.encode("utf-8")
                if len(encoded) > max_bytes:
                    # Cut on a character boundary: a response sliced mid-codepoint
                    # is not a smaller response, it is a broken one.
                    content = encoded[:max_bytes].decode("utf-8", errors="ignore")
                    applied.truncated_bytes = len(encoded) - max_bytes
                    content += "\n\n[truncated by data governance policy]"
            for text in watermarks:
                content = f"{content}\n\n{text}"
                applied.watermarked = True
            message["content"] = content
        rebuilt.append({**choice, "message": message})

    if applied.truncated_bytes:
        applied.notes.append(f"truncated {applied.truncated_bytes} bytes (max_bytes={max_bytes})")
    if applied.watermarked:
        applied.notes.append(f"watermarked with {len(watermarks)} marking(s)")

    updated["choices"] = rebuilt
    return updated, applied
