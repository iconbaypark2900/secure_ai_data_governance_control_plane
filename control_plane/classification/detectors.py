"""Deterministic detectors for sensitive values in text.

Each detector pairs a regular expression with an optional structural validator
(Luhn, IBAN mod-97, SSN allocation rules). The validator is what separates this
from a naive regex scanner: ``4111 1111 1111 1111`` is a card number and
``4111 1111 1111 1112`` is not, and only a checksum can tell them apart.

Detectors report a *confidence*, adjusted by the words surrounding the match. A
nine-digit number is weak evidence of an SSN on its own and strong evidence when
it follows the word "SSN". Detectors marked ``requires_context`` produce nothing
at all without a supporting keyword, because their patterns are too generic to
stand alone.

Every pattern here is linear-time: no nested quantifiers over overlapping
character classes, so a hostile input cannot force catastrophic backtracking.
"""

from __future__ import annotations

import math
import re
from collections.abc import Callable
from dataclasses import dataclass, field

__all__ = ["DETECTORS", "Detector", "RawMatch", "run_detector", "shannon_entropy"]

# How far to look on either side of a match for a supporting keyword.
CONTEXT_WINDOW = 48
CONTEXT_BOOST = 0.18
NO_CONTEXT_PENALTY = 0.12
MAX_CONFIDENCE = 0.99


@dataclass(frozen=True, slots=True)
class RawMatch:
    """A candidate hit from one detector, before overlap resolution."""

    label: str
    detector: str
    start: int
    end: int
    value: str
    confidence: float


@dataclass(frozen=True, slots=True)
class Detector:
    """A named rule that finds one class of sensitive value."""

    name: str
    label: str
    pattern: re.Pattern[str]
    base_confidence: float
    #: Capture group holding the sensitive value; 0 means the whole match.
    group: int = 0
    #: Returns False to reject a syntactic match that fails a structural check.
    validator: Callable[[str], bool] | None = None
    #: Words near the match that raise confidence.
    context_keywords: tuple[str, ...] = field(default_factory=tuple)
    #: When True, a match with no nearby keyword is discarded entirely.
    requires_context: bool = False


# --------------------------------------------------------------------------- #
# Structural validators
# --------------------------------------------------------------------------- #


def _digits(value: str) -> str:
    return "".join(c for c in value if c.isdigit())


def luhn(value: str) -> bool:
    """Luhn (mod-10) checksum, used by payment cards and NPIs."""
    digits = _digits(value)
    if len(digits) < 12:
        return False
    total = 0
    for index, char in enumerate(reversed(digits)):
        digit = ord(char) - 48
        if index % 2 == 1:
            digit *= 2
            if digit > 9:
                digit -= 9
        total += digit
    return total % 10 == 0


def valid_card_number(value: str) -> bool:
    """A payment card number: right length, known brand prefix, valid Luhn."""
    digits = _digits(value)
    if not 13 <= len(digits) <= 19:
        return False
    # A single repeated digit is padding, not a card. Note that real-shaped test
    # PANs such as 4111111111111111 use only two distinct digits and must pass:
    # they are exactly what a leak of card data looks like in a fixture.
    if len(set(digits)) == 1:
        return False
    brands = (
        ("4",),  # Visa
        tuple(str(n) for n in range(51, 56)),  # Mastercard
        tuple(str(n) for n in range(2221, 2721)),  # Mastercard (2-series)
        ("34", "37"),  # Amex
        ("6011", "65"),
        tuple(str(n) for n in range(644, 650)),  # Discover
        ("35",),  # JCB
        ("36", "38", "39", "300", "301", "302", "303", "304", "305"),  # Diners
    )
    if not any(digits.startswith(prefix) for group in brands for prefix in group):
        return False
    return luhn(digits)


def valid_ssn(value: str) -> bool:
    """US SSN allocation rules: no 000/666/9xx area, no 00 group, no 0000 serial."""
    digits = _digits(value)
    if len(digits) != 9:
        return False
    area, group, serial = digits[:3], digits[3:5], digits[5:]
    if area in {"000", "666"} or area[0] == "9":
        return False
    if group == "00" or serial == "0000":
        return False
    # Well-known placeholders that appear in documentation and test fixtures.
    return digits not in {"123456789", "111111111", "078051120", "219099999"}


def valid_npi(value: str) -> bool:
    """NPI check digit: Luhn over the number prefixed with the 80840 issuer code."""
    digits = _digits(value)
    if len(digits) != 10:
        return False
    return luhn("80840" + digits)


def valid_iban(value: str) -> bool:
    """IBAN mod-97 check (ISO 13616)."""
    compact = "".join(value.split()).upper()
    if not 15 <= len(compact) <= 34 or not compact[:2].isalpha() or not compact[2:4].isdigit():
        return False
    rearranged = compact[4:] + compact[:4]
    try:
        numeric = "".join(str(ord(c) - 55) if c.isalpha() else c for c in rearranged)
    except TypeError:  # pragma: no cover - defensive
        return False
    if not numeric.isdigit():
        return False
    return int(numeric) % 97 == 1


def shannon_entropy(value: str) -> float:
    """Bits of entropy per character. High-entropy strings look like keys."""
    if not value:
        return 0.0
    counts: dict[str, int] = {}
    for char in value:
        counts[char] = counts.get(char, 0) + 1
    length = len(value)
    return -sum((count / length) * math.log2(count / length) for count in counts.values())


def high_entropy(value: str) -> bool:
    """True for values random enough to be a machine-generated credential."""
    stripped = value.strip("\"'`")
    if len(stripped) < 16:
        return False
    if stripped.lower() in {"changeme", "placeholder", "your_api_key_here"}:
        return False
    return shannon_entropy(stripped) >= 3.2


def plausible_password(value: str) -> bool:
    """Reject the obvious non-secrets that sit next to ``password=`` in templates."""
    stripped = value.strip("\"'`")
    if len(stripped) < 6:
        return False
    return stripped.lower() not in {
        "password",
        "changeme",
        "example",
        "redacted",
        "xxxxxx",
        "secret",
        "your_password",
        "<password>",
        "********",
        "hunter2",
    }


def not_reserved_ip(value: str) -> bool:
    """Drop loopback, unspecified, and documentation ranges: they identify nobody."""
    octets = value.split(".")
    if len(octets) != 4:
        return False
    try:
        first, second = int(octets[0]), int(octets[1])
    except ValueError:  # pragma: no cover - guarded by the pattern
        return False
    if first in {0, 127, 255}:
        return False
    if first == 192 and second == 0:  # 192.0.2.0/24 documentation range
        return False
    return not (first == 198 and second in {18, 19, 51})


# --------------------------------------------------------------------------- #
# Patterns
# --------------------------------------------------------------------------- #

_EMAIL = re.compile(
    r"\b[A-Za-z0-9._%+\-]{1,64}@[A-Za-z0-9](?:[A-Za-z0-9\-]{0,61}[A-Za-z0-9])?"
    r"(?:\.[A-Za-z0-9](?:[A-Za-z0-9\-]{0,61}[A-Za-z0-9])?)+\b"
)
# Requires punctuation or a country code so bare 10-digit integers do not match.
_PHONE = re.compile(
    r"(?<![\d\-])(?:\+\d{1,3}[ .\-]?)?"
    r"(?:\(\d{3}\)[ .\-]?\d{3}[ .\-]?\d{4}"
    r"|\d{3}[ .\-]\d{3}[ .\-]\d{4}"
    r"|\+\d{1,3}[ .\-]?\d{2,4}[ .\-]?\d{3,4}[ .\-]?\d{3,4})"
    r"(?![\d\-])"
)
# Separators are themselves evidence: "536-90-4432" is written the way an SSN
# is written. Nine bare digits are far more often an order or account number,
# so that form is handled by a separate, context-gated detector.
_SSN = re.compile(r"(?<![\d\-])\d{3}[ \-]\d{2}[ \-]\d{4}(?![\d\-])")
_SSN_COMPACT = re.compile(r"(?<![\d\-])\d{9}(?![\d\-])")
_CARD = re.compile(r"(?<![\d\-])(?:\d[ \-]?){12,18}\d(?![\d\-])")
_IBAN = re.compile(r"\b[A-Z]{2}\d{2}(?:[ ]?[A-Z0-9]{4}){2,7}(?:[ ]?[A-Z0-9]{1,4})?\b")
_IPV4 = re.compile(
    r"(?<![\w.])(?:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.){3}"
    r"(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(?![\w.])"
)
_MAC = re.compile(r"\b(?:[0-9A-Fa-f]{2}[:\-]){5}[0-9A-Fa-f]{2}\b")
_DOB = re.compile(
    r"\b(?:19|20)\d{2}[/\-](?:0?[1-9]|1[0-2])[/\-](?:0?[1-9]|[12]\d|3[01])\b"
    r"|\b(?:0?[1-9]|1[0-2])[/\-](?:0?[1-9]|[12]\d|3[01])[/\-](?:19|20)\d{2}\b"
)
_ADDRESS = re.compile(
    r"\b\d{1,6}\s+(?:[A-Z][A-Za-z.'\-]{1,20}\s+){1,4}"
    r"(?:Street|St|Avenue|Ave|Road|Rd|Boulevard|Blvd|Lane|Ln|Drive|Dr|Court|Ct"
    r"|Way|Circle|Cir|Place|Pl|Terrace|Ter|Parkway|Pkwy|Highway|Hwy)\b\.?",
    re.IGNORECASE,
)
_PASSPORT = re.compile(r"\b[A-Z]{0,2}\d{6,9}\b")
_DL = re.compile(r"\b[A-Z]{1,2}[\-]?\d{5,12}\b")
_MRN = re.compile(r"\b[A-Z]{0,3}\d{6,10}\b")
_NPI = re.compile(r"(?<!\d)\d{10}(?!\d)")
_ICD10 = re.compile(r"\b[A-TV-Z]\d{2}(?:\.[A-Z0-9]{1,4})?\b")
_PRIVATE_KEY = re.compile(r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP |ENCRYPTED )?PRIVATE KEY-----")
_AWS_ACCESS_KEY = re.compile(
    r"\b(?:AKIA|ASIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ABIA|ACCA)[A-Z0-9]{16}\b"
)
_AWS_SECRET = re.compile(
    r"(?i)aws[_\-. ]?(?:secret|private)[_\-. ]?(?:access[_\-. ]?)?key[\"' ]{0,4}"
    r"[:=][\"' ]{0,4}([A-Za-z0-9/+=]{40})"
)
_GCP_KEY = re.compile(r"\bAIza[0-9A-Za-z_\-]{35}\b")
_GITHUB = re.compile(r"\bgh[pousr]_[A-Za-z0-9]{36,251}\b")
_SLACK = re.compile(r"\bxox[abprs]-[A-Za-z0-9\-]{10,250}\b")
_STRIPE = re.compile(r"\b(?:sk|rk)_(?:live|test)_[A-Za-z0-9]{16,120}\b")
_ANTHROPIC = re.compile(r"\bsk-ant-(?:api\d{2}-)?[A-Za-z0-9_\-]{20,120}\b")
_OPENAI = re.compile(r"\bsk-(?:proj-|svcacct-)?[A-Za-z0-9_\-]{20,120}\b")
_JWT = re.compile(r"\beyJ[A-Za-z0-9_\-]{6,2000}\.[A-Za-z0-9_\-]{6,4000}\.[A-Za-z0-9_\-]{6,2000}\b")
_DB_URI = re.compile(
    r"\b(?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?|redis|amqp|mssql|clickhouse)"
    r"://[^\s:/@]{1,64}:([^\s/@]{1,128})@[^\s/]{1,255}"
)
_GENERIC_KEY = re.compile(
    r"(?i)\b(?:api[_\-. ]?key|access[_\-. ]?token|auth[_\-. ]?token|bearer"
    r"|client[_\-. ]?secret|secret[_\-. ]?key)\b[\"' ]{0,4}[:=][\"' ]{0,4}"
    r"([A-Za-z0-9_\-./+=]{16,200})"
)
_PASSWORD = re.compile(
    r"(?i)\b(?:password|passwd|pwd)\b[\"' ]{0,4}[:=][\"' ]{0,4}([^\s\"',;]{6,128})"
)


DETECTORS: tuple[Detector, ...] = (
    Detector(
        "email",
        "pii.email",
        _EMAIL,
        0.95,
        context_keywords=("email", "e-mail", "mail", "contact", "@"),
    ),
    Detector(
        "phone",
        "pii.phone",
        _PHONE,
        0.72,
        context_keywords=("phone", "tel", "mobile", "cell", "fax", "call"),
    ),
    Detector(
        "ssn",
        "pii.ssn",
        _SSN,
        0.85,
        validator=valid_ssn,
        context_keywords=(
            "ssn",
            "social security",
            "social-security",
            "taxpayer",
            "tin",
            "national id",
        ),
    ),
    Detector(
        "ssn_compact",
        "pii.ssn",
        _SSN_COMPACT,
        0.72,
        validator=valid_ssn,
        context_keywords=(
            "ssn",
            "social security",
            "social-security",
            "taxpayer",
            "tin",
            "national id",
        ),
        requires_context=True,
    ),
    Detector(
        "card_number",
        "pci.card_number",
        _CARD,
        0.90,
        validator=valid_card_number,
        context_keywords=(
            "card",
            "credit",
            "debit",
            "visa",
            "mastercard",
            "amex",
            "payment",
            "pan",
            "cc",
        ),
    ),
    Detector(
        "iban",
        "pci.iban",
        _IBAN,
        0.92,
        validator=valid_iban,
        context_keywords=("iban", "bank", "account", "swift", "bic", "transfer"),
    ),
    Detector(
        "ipv4",
        "pii.ip_address",
        _IPV4,
        0.55,
        validator=not_reserved_ip,
        context_keywords=("ip", "address", "client", "remote", "host", "origin"),
    ),
    Detector(
        "mac",
        "pii.mac_address",
        _MAC,
        0.75,
        context_keywords=("mac", "hardware", "device", "adapter", "bssid"),
    ),
    Detector(
        "dob",
        "pii.dob",
        _DOB,
        0.45,
        context_keywords=("dob", "date of birth", "birth", "born", "birthday"),
        requires_context=True,
    ),
    Detector(
        "address",
        "pii.address",
        _ADDRESS,
        0.70,
        context_keywords=("address", "street", "residence", "ship", "billing", "mailing", "home"),
    ),
    Detector(
        "passport",
        "pii.passport",
        _PASSPORT,
        0.55,
        context_keywords=("passport", "travel document"),
        requires_context=True,
    ),
    Detector(
        "drivers_license",
        "pii.drivers_license",
        _DL,
        0.55,
        context_keywords=("driver", "licence", "license", "dl number", "dln"),
        requires_context=True,
    ),
    Detector(
        "mrn",
        "phi.mrn",
        _MRN,
        0.60,
        context_keywords=("mrn", "medical record", "patient id", "chart number", "patient number"),
        requires_context=True,
    ),
    Detector(
        "npi",
        "phi.npi",
        _NPI,
        0.60,
        validator=valid_npi,
        context_keywords=("npi", "provider", "physician", "clinician", "prescriber"),
    ),
    Detector(
        "icd10",
        "phi.icd10",
        _ICD10,
        0.50,
        context_keywords=("icd", "diagnosis", "dx", "coded as", "condition", "billing code"),
        requires_context=True,
    ),
    Detector("private_key", "secret.private_key", _PRIVATE_KEY, 0.99),
    Detector("aws_access_key", "secret.aws_access_key", _AWS_ACCESS_KEY, 0.97),
    Detector("aws_secret_key", "secret.aws_secret_key", _AWS_SECRET, 0.95, group=1),
    Detector("gcp_api_key", "secret.gcp_api_key", _GCP_KEY, 0.93),
    Detector("github_token", "secret.github_token", _GITHUB, 0.97),
    Detector("slack_token", "secret.slack_token", _SLACK, 0.95),
    Detector("stripe_key", "secret.stripe_key", _STRIPE, 0.96),
    Detector("anthropic_key", "secret.anthropic_key", _ANTHROPIC, 0.96),
    Detector("openai_key", "secret.openai_key", _OPENAI, 0.90),
    Detector("jwt", "secret.jwt", _JWT, 0.90),
    Detector("db_connection_string", "secret.db_connection_string", _DB_URI, 0.94),
    Detector(
        "generic_api_key",
        "secret.generic_api_key",
        _GENERIC_KEY,
        0.80,
        group=1,
        validator=high_entropy,
    ),
    Detector("password", "secret.password", _PASSWORD, 0.85, group=1, validator=plausible_password),
)

BY_NAME: dict[str, Detector] = {d.name: d for d in DETECTORS}


# --------------------------------------------------------------------------- #
# Execution
# --------------------------------------------------------------------------- #


def _has_context(
    text: str,
    start: int,
    end: int,
    keywords: tuple[str, ...],
    hint: str = "",
) -> bool:
    if not keywords:
        return False
    window = text[max(0, start - CONTEXT_WINDOW) : min(len(text), end + CONTEXT_WINDOW)]
    lowered = f"{window} {hint}".lower()
    return any(keyword in lowered for keyword in keywords)


def run_detector(detector: Detector, text: str, context_hint: str = "") -> list[RawMatch]:
    """Apply one detector to ``text`` and return its surviving candidate matches.

    ``context_hint`` supplies out-of-band context that is not part of ``text`` --
    typically the field name a value was found under, so that scanning the value
    of a JSON key called ``ssn`` gets the same confidence boost as finding the
    word "SSN" beside it in prose.
    """
    matches: list[RawMatch] = []
    for match in detector.pattern.finditer(text):
        value = match.group(detector.group)
        if not value:
            continue
        start, end = match.span(detector.group)

        if detector.validator is not None and not detector.validator(value):
            continue

        supported = _has_context(
            text, match.start(), match.end(), detector.context_keywords, context_hint
        )
        if detector.requires_context and not supported:
            continue

        confidence = detector.base_confidence
        if supported:
            confidence = min(MAX_CONFIDENCE, confidence + CONTEXT_BOOST)
        elif detector.context_keywords:
            confidence = max(0.05, confidence - NO_CONTEXT_PENALTY)

        matches.append(
            RawMatch(
                label=detector.label,
                detector=detector.name,
                start=start,
                end=end,
                value=value,
                confidence=round(confidence, 4),
            )
        )
    return matches
