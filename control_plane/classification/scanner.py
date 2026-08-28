"""Runs every detector over a payload and reconciles the results.

Detectors are deliberately allowed to overlap -- ``sk-ant-api03-...`` matches both
the Anthropic and the generic OpenAI pattern -- so the scanner's real job is
arbitration. It keeps the finding that a human would call correct: the most
severe label, then the longest span, then the highest confidence.

Findings carry the matched value because redaction needs it. They also carry a
masked ``preview``, and that is the only form the API and the audit log ever
serialise. Sensitive text must not leak into the record of having detected it.
"""

from __future__ import annotations

from collections.abc import Iterable, Sequence
from dataclasses import dataclass, field
from typing import Any

from control_plane.classification import taxonomy
from control_plane.classification.detectors import DETECTORS, Detector, RawMatch, run_detector
from control_plane.classification.taxonomy import SEVERITY_RANK, Severity

__all__ = ["Finding", "ScanResult", "Scanner", "scan_structured", "scan_text"]

#: Hard ceiling on a single scan, so an oversized payload cannot pin a worker.
DEFAULT_MAX_CHARS = 1_000_000


def mask_preview(value: str) -> str:
    """A non-reversible hint at what was found, safe to log.

    Shows at most the first and last character and never more than a quarter of
    a short value, so a preview cannot be assembled back into the secret.
    """
    if not value:
        return ""
    stripped = value.strip()
    if len(stripped) <= 4:
        return "*" * len(stripped)
    if "@" in stripped and stripped.count("@") == 1:
        local, _, domain = stripped.partition("@")
        head = local[0] if local else ""
        return f"{head}{'*' * max(1, len(local) - 1)}@{domain}"
    return f"{stripped[0]}{'*' * (len(stripped) - 2)}{stripped[-1]}"


@dataclass(frozen=True, slots=True)
class Finding:
    """One confirmed piece of sensitive data at a known location."""

    label: str
    detector: str
    start: int
    end: int
    confidence: float
    value: str
    #: JSON pointer to the containing field for structured scans; "" for plain text.
    path: str = ""

    @property
    def preview(self) -> str:
        return mask_preview(self.value)

    @property
    def severity(self) -> Severity:
        return taxonomy.severity_of(self.label)

    @property
    def length(self) -> int:
        return self.end - self.start

    def redacted_dict(self) -> dict[str, Any]:
        """Serialisable form with the sensitive value removed."""
        return {
            "label": self.label,
            "detector": self.detector,
            "start": self.start,
            "end": self.end,
            "confidence": self.confidence,
            "path": self.path,
            "preview": self.preview,
            "severity": str(self.severity),
        }


@dataclass(frozen=True, slots=True)
class ScanResult:
    """Everything one scan learned about a payload."""

    findings: tuple[Finding, ...] = ()
    scanned_chars: int = 0
    truncated: bool = False
    detectors_run: int = 0

    @property
    def labels(self) -> frozenset[str]:
        """Distinct concrete label keys observed."""
        return frozenset(f.label for f in self.findings)

    @property
    def label_counts(self) -> dict[str, int]:
        counts: dict[str, int] = {}
        for finding in self.findings:
            counts[finding.label] = counts.get(finding.label, 0) + 1
        return dict(sorted(counts.items()))

    @property
    def max_severity(self) -> Severity | None:
        if not self.findings:
            return None
        return max((f.severity for f in self.findings), key=lambda s: SEVERITY_RANK[s])

    @property
    def regulations(self) -> tuple[str, ...]:
        return taxonomy.regulations_for(self.labels)

    def by_label(self, pattern: str) -> tuple[Finding, ...]:
        """Findings whose label is, or sits beneath, ``pattern``."""
        return tuple(f for f in self.findings if taxonomy.covers(pattern, f.label))

    def summary(self) -> dict[str, Any]:
        return {
            "labels": sorted(self.labels),
            "label_counts": self.label_counts,
            "max_severity": str(self.max_severity) if self.max_severity else None,
            "regulations": list(self.regulations),
            "finding_count": len(self.findings),
            "scanned_chars": self.scanned_chars,
            "truncated": self.truncated,
        }


def _rank(match: RawMatch) -> tuple[int, int, float, str]:
    """Sort key deciding which of two overlapping matches survives.

    Severity first: calling a string a private key rather than a generic API key
    is the safer error. Then span length, which resolves prefix collisions such as
    ``sk-ant-...`` versus ``sk-...`` in favour of the more specific detector.
    """
    severity = SEVERITY_RANK[taxonomy.severity_of(match.label)]
    return (severity, match.end - match.start, match.confidence, match.detector)


def _resolve_overlaps(matches: Sequence[RawMatch]) -> list[RawMatch]:
    """Greedily keep the best match at each position, dropping anything it covers."""
    kept: list[RawMatch] = []
    occupied: list[tuple[int, int]] = []
    for match in sorted(matches, key=_rank, reverse=True):
        if any(match.start < end and start < match.end for start, end in occupied):
            continue
        kept.append(match)
        occupied.append((match.start, match.end))
    kept.sort(key=lambda m: (m.start, m.end))
    return kept


@dataclass
class Scanner:
    """A configured set of detectors.

    Holding this as an object rather than a module function lets a caller narrow
    the detector set -- a pipeline that only cares about credentials should not
    pay for address matching -- and lets tests build a scanner with one rule.
    """

    detectors: tuple[Detector, ...] = DETECTORS
    max_chars: int = DEFAULT_MAX_CHARS
    #: Findings below this confidence are discarded before overlap resolution.
    min_confidence: float = 0.0
    _index: dict[str, Detector] = field(init=False, repr=False, default_factory=dict)

    def __post_init__(self) -> None:
        self._index = {d.name: d for d in self.detectors}

    @classmethod
    def for_labels(cls, patterns: Iterable[str], **kwargs: Any) -> Scanner:
        """A scanner restricted to detectors producing labels under ``patterns``."""
        wanted = tuple(patterns)
        selected = tuple(d for d in DETECTORS if any(taxonomy.covers(p, d.label) for p in wanted))
        return cls(detectors=selected, **kwargs)

    def scan_text(self, text: str, *, context_hint: str = "", path: str = "") -> ScanResult:
        """Scan a single string."""
        if not text:
            return ScanResult(detectors_run=len(self.detectors))
        truncated = len(text) > self.max_chars
        body = text[: self.max_chars] if truncated else text

        raw: list[RawMatch] = []
        for detector in self.detectors:
            raw.extend(run_detector(detector, body, context_hint))

        if self.min_confidence > 0:
            raw = [m for m in raw if m.confidence >= self.min_confidence]

        findings = tuple(
            Finding(
                label=m.label,
                detector=m.detector,
                start=m.start,
                end=m.end,
                confidence=m.confidence,
                value=m.value,
                path=path,
            )
            for m in _resolve_overlaps(raw)
        )
        return ScanResult(
            findings=findings,
            scanned_chars=len(body),
            truncated=truncated,
            detectors_run=len(self.detectors),
        )

    def scan_structured(self, payload: Any, *, max_depth: int = 24) -> ScanResult:
        """Walk a JSON-like structure, scanning every string leaf.

        Each leaf is scanned with its own field name as a context hint, so
        ``{"ssn": "536904432"}`` is recognised even though the digits alone carry
        no evidence of what they are. Offsets in the returned findings are
        relative to the leaf string, and ``path`` is the JSON pointer to it.
        """
        findings: list[Finding] = []
        scanned = 0
        truncated = False

        def walk(node: Any, pointer: str, hint: str, depth: int) -> None:
            nonlocal scanned, truncated
            if depth > max_depth:
                return
            if isinstance(node, str):
                result = self.scan_text(node, context_hint=hint, path=pointer)
                findings.extend(result.findings)
                scanned += result.scanned_chars
                truncated = truncated or result.truncated
            elif isinstance(node, dict):
                for key, value in node.items():
                    walk(value, f"{pointer}/{_escape(str(key))}", str(key), depth + 1)
            elif isinstance(node, (list, tuple)):
                for index, value in enumerate(node):
                    walk(value, f"{pointer}/{index}", hint, depth + 1)

        walk(payload, "", "", 0)
        return ScanResult(
            findings=tuple(findings),
            scanned_chars=scanned,
            truncated=truncated,
            detectors_run=len(self.detectors),
        )


def _escape(token: str) -> str:
    """JSON Pointer escaping (RFC 6901)."""
    return token.replace("~", "~0").replace("/", "~1")


#: Shared default scanner. Detectors are stateless, so this is safe to reuse.
DEFAULT_SCANNER = Scanner()


def scan_text(text: str, *, context_hint: str = "") -> ScanResult:
    """Scan a string with the default detector set."""
    return DEFAULT_SCANNER.scan_text(text, context_hint=context_hint)


def scan_structured(payload: Any) -> ScanResult:
    """Scan a JSON-like structure with the default detector set."""
    return DEFAULT_SCANNER.scan_structured(payload)
