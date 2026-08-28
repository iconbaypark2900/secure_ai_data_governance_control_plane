"""Turning findings into a safe payload.

Redaction is where a policy decision becomes a concrete edit. The obligations a
policy attaches to an ``allow`` -- "mask every SSN, keep the last four of a card"
-- are executed here.

The strategies differ in what they preserve:

``mask``       destroys the value; keeps the fact that something was there.
``partial``    keeps a suffix so a human can still recognise their own record.
``hash``       keyed HMAC, so the same input yields the same pseudonym forever;
               joins survive, the value does not.
``tokenize``   reversible through a vault, for pipelines that must re-identify.
``synthetic``  substitutes a same-shaped fake, so downstream parsers still work.
``drop``       removes the span entirely.

Replacements are applied right-to-left so that earlier offsets stay valid while
later ones are being rewritten.
"""

from __future__ import annotations

import hashlib
import hmac
import re
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any, Protocol

from control_plane.classification import taxonomy
from control_plane.classification.scanner import Finding
from control_plane.redaction.tokenization import TokenizationUnavailable

__all__ = [
    "AppliedRedaction",
    "InMemoryTokenVault",
    "RedactionResult",
    "RedactionRule",
    "Redactor",
    "Strategy",
    "TokenVault",
]


class Strategy(StrEnum):
    MASK = "mask"
    PARTIAL = "partial"
    HASH = "hash"
    TOKENIZE = "tokenize"
    SYNTHETIC = "synthetic"
    DROP = "drop"


class TokenVault(Protocol):
    """Storage for reversible tokenisation."""

    def tokenize(self, label: str, value: str) -> str:
        """Return a stable surrogate for ``value``, minting one if needed."""

    def detokenize(self, token: str) -> str | None:
        """Return the original value for ``token``, or None if unknown."""


class InMemoryTokenVault:
    """A process-local mapping vault.

    Kept for tests and for anyone who genuinely wants mapping-backed
    tokenisation. It is *not* what the control plane uses:
    :class:`~control_plane.redaction.tokenization.DeterministicTokenizer` makes
    the token the ciphertext, so there is no table of sensitive values to hold
    -- see `ADR 0009`.

    Anything implementing :class:`TokenVault` with real storage is a
    re-identification capability, and deserves to be governed at least as
    tightly as the data it protects.
    """

    def __init__(self, key: bytes = b"") -> None:
        self._key = key or b"in-memory-token-vault"
        self._forward: dict[tuple[str, str], str] = {}
        self._reverse: dict[str, str] = {}

    def tokenize(self, label: str, value: str) -> str:
        cache_key = (label, value)
        if cache_key in self._forward:
            return self._forward[cache_key]
        digest = hmac.new(self._key, f"{label}:{value}".encode(), hashlib.sha256).hexdigest()
        token = f"tok_{taxonomy.get(label).category}_{digest[:20]}"
        self._forward[cache_key] = token
        self._reverse[token] = value
        return token

    def detokenize(self, token: str) -> str | None:
        return self._reverse.get(token)

    def __len__(self) -> int:
        return len(self._reverse)


@dataclass(frozen=True, slots=True)
class RedactionRule:
    """How to treat one family of labels."""

    #: Label patterns this rule covers; "pii" matches every pii.* label.
    labels: tuple[str, ...]
    strategy: Strategy = Strategy.MASK
    #: For PARTIAL: how many trailing characters survive.
    keep_last: int = 4
    #: For HASH: how many hex characters of the digest to emit.
    hash_length: int = 16

    def matches(self, label: str) -> bool:
        return any(taxonomy.covers(pattern, label) for pattern in self.labels)

    @classmethod
    def from_obligation(cls, obligation: Mapping[str, Any]) -> RedactionRule:
        """Build a rule from a policy obligation document."""
        raw_labels = obligation.get("labels") or obligation.get("classifications") or ["*"]
        if isinstance(raw_labels, str):
            raw_labels = [raw_labels]
        strategy = Strategy(str(obligation.get("strategy", "mask")).lower())
        return cls(
            labels=tuple(str(label) for label in raw_labels),
            strategy=strategy,
            keep_last=int(obligation.get("keep_last", 4)),
            hash_length=int(obligation.get("hash_length", 16)),
        )


@dataclass(frozen=True, slots=True)
class AppliedRedaction:
    """The record of one edit, safe to store in an audit log."""

    label: str
    strategy: Strategy
    start: int
    end: int
    path: str
    replacement: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "label": self.label,
            "strategy": str(self.strategy),
            "start": self.start,
            "end": self.end,
            "path": self.path,
            "replacement": self.replacement,
        }


@dataclass(frozen=True, slots=True)
class RedactionResult:
    """The rewritten payload plus a description of what changed."""

    payload: Any
    applied: tuple[AppliedRedaction, ...] = ()
    #: Findings no rule covered, and which therefore survived untouched.
    unhandled: tuple[Finding, ...] = ()

    @property
    def changed(self) -> bool:
        return bool(self.applied)

    def summary(self) -> dict[str, Any]:
        by_strategy: dict[str, int] = {}
        for item in self.applied:
            by_strategy[str(item.strategy)] = by_strategy.get(str(item.strategy), 0) + 1
        return {
            "redaction_count": len(self.applied),
            "by_strategy": by_strategy,
            "labels_redacted": sorted({a.label for a in self.applied}),
            "unhandled_labels": sorted({f.label for f in self.unhandled}),
        }


# Wildcard rule used when an obligation names no labels.
_ANY = "*"

_DIGIT_RUN = re.compile(r"\d")


@dataclass
class Redactor:
    """Applies a set of rules to findings."""

    rules: tuple[RedactionRule, ...] = ()
    key: bytes = b""
    vault: TokenVault | None = None
    #: Emitted when a rule matches nothing more specific.
    mask_token: str = "[REDACTED:{label}]"  # noqa: S105 - a format string, not a secret

    _rule_cache: dict[str, RedactionRule | None] = field(
        init=False, repr=False, default_factory=dict
    )

    @classmethod
    def from_obligations(
        cls,
        obligations: Iterable[Mapping[str, Any]],
        *,
        key: bytes = b"",
        vault: TokenVault | None = None,
    ) -> Redactor:
        """Build a redactor from the obligations attached to a policy decision."""
        rules = tuple(
            RedactionRule.from_obligation(o)
            for o in obligations
            if str(o.get("type", "redact")).lower()
            in {"redact", "mask", "hash", "tokenize", "partial", "synthetic", "drop"}
        )
        return cls(rules=rules, key=key, vault=vault)

    def rule_for(self, label: str) -> RedactionRule | None:
        """The first rule covering ``label``, or None if the label is untouched."""
        if label in self._rule_cache:
            return self._rule_cache[label]
        found: RedactionRule | None = None
        for rule in self.rules:
            if _ANY in rule.labels or rule.matches(label):
                found = rule
                break
        self._rule_cache[label] = found
        return found

    # --- replacement construction ----------------------------------------- #

    def _replacement(self, finding: Finding, rule: RedactionRule) -> str:
        value = finding.value
        match rule.strategy:
            case Strategy.DROP:
                return ""
            case Strategy.MASK:
                return self.mask_token.format(label=finding.label)
            case Strategy.PARTIAL:
                return self._partial(value, rule.keep_last)
            case Strategy.HASH:
                return self._hash(finding.label, value, rule.hash_length)
            case Strategy.TOKENIZE:
                if self.vault is None:
                    # Refuse rather than substitute. Emitting a hash here would
                    # satisfy the shape of the obligation and not its meaning: a
                    # policy asked for something reversible and would receive
                    # something that is not, with nobody finding out until
                    # somebody needed to reverse one.
                    raise TokenizationUnavailable(
                        f"policy requires the 'tokenize' strategy for "
                        f"{finding.label!r}, but no tokeniser is configured; "
                        f"set CP_TOKENIZATION_KEY"
                    )
                return self.vault.tokenize(finding.label, value)
            case Strategy.SYNTHETIC:
                return self._synthetic(finding.label, value)
        raise ValueError(f"unhandled strategy {rule.strategy!r}")  # pragma: no cover

    @staticmethod
    def _partial(value: str, keep_last: int) -> str:
        keep = max(0, min(keep_last, len(value)))
        if keep == 0:
            return "*" * len(value)
        head = value[:-keep] if keep else value
        masked = _DIGIT_RUN.sub("*", head)
        masked = "".join("*" if c.isalnum() else c for c in masked)
        return f"{masked}{value[-keep:]}"

    def _hash(self, label: str, value: str, length: int) -> str:
        digest = hmac.new(
            self.key or b"unkeyed-redactor", f"{label}:{value}".encode(), hashlib.sha256
        ).hexdigest()
        return f"<{label}:{digest[: max(4, min(length, 64))]}>"

    def _synthetic(self, label: str, value: str) -> str:
        """A same-shaped placeholder, derived deterministically from the value."""
        seed = hmac.new(
            self.key or b"unkeyed-redactor", f"synth:{label}:{value}".encode(), hashlib.sha256
        ).digest()
        digits = "".join(str(byte % 10) for byte in seed)
        match label:
            case "pii.email":
                return f"user{digits[:6]}@example.invalid"
            case "pii.phone":
                return f"+1555{digits[:7]}"
            case "pii.ssn":
                return f"900-{digits[:2]}-{digits[2:6]}"
            case "pci.card_number":
                return f"4000{digits[:12]}"
            case _:
                shaped = "".join(
                    digits[i % len(digits)] if c.isdigit() else ("x" if c.isalpha() else c)
                    for i, c in enumerate(value)
                )
                return shaped

    # --- application ------------------------------------------------------- #

    def apply_to_text(self, text: str, findings: Sequence[Finding]) -> RedactionResult:
        """Rewrite ``text``, replacing each covered finding."""
        applied: list[AppliedRedaction] = []
        unhandled: list[Finding] = []
        # Right-to-left, so each replacement leaves earlier offsets untouched.
        ordered = sorted(findings, key=lambda f: (f.start, f.end), reverse=True)
        buffer = text
        for finding in ordered:
            rule = self.rule_for(finding.label)
            if rule is None:
                unhandled.append(finding)
                continue
            replacement = self._replacement(finding, rule)
            buffer = buffer[: finding.start] + replacement + buffer[finding.end :]
            applied.append(
                AppliedRedaction(
                    label=finding.label,
                    strategy=rule.strategy,
                    start=finding.start,
                    end=finding.end,
                    path=finding.path,
                    replacement=replacement,
                )
            )
        applied.reverse()
        unhandled.reverse()
        return RedactionResult(payload=buffer, applied=tuple(applied), unhandled=tuple(unhandled))

    def apply_to_structured(self, payload: Any, findings: Sequence[Finding]) -> RedactionResult:
        """Rewrite the string leaves of a JSON-like structure."""
        by_path: dict[str, list[Finding]] = {}
        for finding in findings:
            by_path.setdefault(finding.path, []).append(finding)

        applied: list[AppliedRedaction] = []
        unhandled: list[Finding] = []

        def rewrite(node: Any, pointer: str) -> Any:
            if isinstance(node, str):
                local = by_path.get(pointer)
                if not local:
                    return node
                result = self.apply_to_text(node, local)
                applied.extend(result.applied)
                unhandled.extend(result.unhandled)
                return result.payload
            if isinstance(node, dict):
                return {
                    key: rewrite(value, f"{pointer}/{_escape(str(key))}")
                    for key, value in node.items()
                }
            if isinstance(node, list):
                return [rewrite(value, f"{pointer}/{index}") for index, value in enumerate(node)]
            if isinstance(node, tuple):
                return tuple(
                    rewrite(value, f"{pointer}/{index}") for index, value in enumerate(node)
                )
            return node

        rewritten = rewrite(payload, "")
        return RedactionResult(
            payload=rewritten, applied=tuple(applied), unhandled=tuple(unhandled)
        )


def _escape(token: str) -> str:
    return token.replace("~", "~0").replace("/", "~1")
