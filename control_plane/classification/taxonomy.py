"""The sensitivity-label taxonomy.

Labels are the vocabulary shared by every other subsystem: the catalog tags assets
with them, policies match on them, and redaction obligations name them. Keeping the
taxonomy in one place means a policy can never reference a label that the classifier
cannot produce.

Label keys are dotted and hierarchical (``pii.email``). Matching a parent key implies
matching its children, so a policy that says ``classifications: [pii]`` covers every
``pii.*`` label without enumerating them.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum


class Category(StrEnum):
    """Top-level regulatory family a label belongs to."""

    PII = "pii"
    PHI = "phi"
    PCI = "pci"
    SECRET = "secret"  # noqa: S105 - a category name, not a credential
    CONFIDENTIAL = "confidential"
    PUBLIC = "public"


class Severity(StrEnum):
    """How damaging disclosure of this class of data would be."""

    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


# Ordering used to break ties when two detectors claim overlapping spans.
SEVERITY_RANK: dict[Severity, int] = {
    Severity.LOW: 1,
    Severity.MEDIUM: 2,
    Severity.HIGH: 3,
    Severity.CRITICAL: 4,
}


@dataclass(frozen=True, slots=True)
class Label:
    """A single sensitivity class."""

    key: str
    name: str
    category: Category
    severity: Severity
    description: str
    regulations: tuple[str, ...] = field(default_factory=tuple)

    @property
    def parents(self) -> tuple[str, ...]:
        """Ancestor keys, broadest first: ``pii.card.number`` -> ``("pii", "pii.card")``."""
        parts = self.key.split(".")
        return tuple(".".join(parts[:i]) for i in range(1, len(parts)))


def _l(
    key: str,
    name: str,
    category: Category,
    severity: Severity,
    description: str,
    *regulations: str,
) -> Label:
    return Label(key, name, category, severity, description, tuple(regulations))


GDPR = "GDPR"
CCPA = "CCPA"
HIPAA = "HIPAA"
PCI_DSS = "PCI-DSS"
SOC2 = "SOC2"
GLBA = "GLBA"


LABELS: tuple[Label, ...] = (
    # --- Directly identifying personal data -------------------------------------
    _l(
        "pii.email",
        "Email address",
        Category.PII,
        Severity.MEDIUM,
        "An email address belonging to a natural person.",
        GDPR,
        CCPA,
    ),
    _l(
        "pii.phone",
        "Phone number",
        Category.PII,
        Severity.MEDIUM,
        "A telephone number that can reach a natural person.",
        GDPR,
        CCPA,
    ),
    _l(
        "pii.ssn",
        "US Social Security Number",
        Category.PII,
        Severity.CRITICAL,
        "A US SSN. Sufficient on its own to enable identity theft.",
        GDPR,
        CCPA,
        GLBA,
    ),
    _l(
        "pii.national_id",
        "National identity number",
        Category.PII,
        Severity.CRITICAL,
        "A government-issued national identity number outside the US.",
        GDPR,
    ),
    _l(
        "pii.passport",
        "Passport number",
        Category.PII,
        Severity.HIGH,
        "A passport number.",
        GDPR,
        CCPA,
    ),
    _l(
        "pii.drivers_license",
        "Driver's licence number",
        Category.PII,
        Severity.HIGH,
        "A driver's licence or state ID number.",
        GDPR,
        CCPA,
    ),
    _l(
        "pii.dob",
        "Date of birth",
        Category.PII,
        Severity.HIGH,
        "A date of birth. A quasi-identifier that re-identifies most records "
        "when combined with a postcode and gender.",
        GDPR,
        CCPA,
        HIPAA,
    ),
    _l(
        "pii.address",
        "Postal address",
        Category.PII,
        Severity.MEDIUM,
        "A street address.",
        GDPR,
        CCPA,
    ),
    _l(
        "pii.name",
        "Person name",
        Category.PII,
        Severity.LOW,
        "The name of a natural person. Requires a model-based detector; "
        "regex detection is not attempted.",
        GDPR,
        CCPA,
    ),
    _l(
        "pii.ip_address",
        "IP address",
        Category.PII,
        Severity.LOW,
        "An IP address. Personal data under GDPR when linkable to a subscriber.",
        GDPR,
    ),
    _l(
        "pii.mac_address",
        "MAC address",
        Category.PII,
        Severity.LOW,
        "A hardware address that persistently identifies a device.",
        GDPR,
    ),
    # --- Payment data -----------------------------------------------------------
    _l(
        "pci.card_number",
        "Payment card number",
        Category.PCI,
        Severity.CRITICAL,
        "A primary account number (PAN) for a payment card.",
        PCI_DSS,
        GLBA,
    ),
    _l(
        "pci.iban",
        "IBAN",
        Category.PCI,
        Severity.HIGH,
        "An international bank account number.",
        PCI_DSS,
        GDPR,
        GLBA,
    ),
    # --- Health data ------------------------------------------------------------
    _l(
        "phi.mrn",
        "Medical record number",
        Category.PHI,
        Severity.CRITICAL,
        "A medical record number. A HIPAA direct identifier.",
        HIPAA,
    ),
    _l(
        "phi.npi",
        "National Provider Identifier",
        Category.PHI,
        Severity.MEDIUM,
        "A US healthcare provider's NPI.",
        HIPAA,
    ),
    _l(
        "phi.icd10",
        "ICD-10 diagnosis code",
        Category.PHI,
        Severity.HIGH,
        "A diagnosis code, which reveals health condition.",
        HIPAA,
    ),
    # --- Machine credentials ----------------------------------------------------
    _l(
        "secret.private_key",
        "Private key",
        Category.SECRET,
        Severity.CRITICAL,
        "A PEM-encoded asymmetric private key.",
        SOC2,
    ),
    _l(
        "secret.aws_access_key",
        "AWS access key ID",
        Category.SECRET,
        Severity.CRITICAL,
        "An AWS access key identifier.",
        SOC2,
    ),
    _l(
        "secret.aws_secret_key",
        "AWS secret access key",
        Category.SECRET,
        Severity.CRITICAL,
        "An AWS secret access key.",
        SOC2,
    ),
    _l(
        "secret.gcp_api_key",
        "Google API key",
        Category.SECRET,
        Severity.HIGH,
        "A Google Cloud API key.",
        SOC2,
    ),
    _l(
        "secret.github_token",
        "GitHub token",
        Category.SECRET,
        Severity.CRITICAL,
        "A GitHub personal access, OAuth, or app token.",
        SOC2,
    ),
    _l(
        "secret.slack_token",
        "Slack token",
        Category.SECRET,
        Severity.HIGH,
        "A Slack bot, user, or app token.",
        SOC2,
    ),
    _l(
        "secret.stripe_key",
        "Stripe key",
        Category.SECRET,
        Severity.CRITICAL,
        "A Stripe secret or restricted API key.",
        SOC2,
        PCI_DSS,
    ),
    _l(
        "secret.anthropic_key",
        "Anthropic API key",
        Category.SECRET,
        Severity.HIGH,
        "An Anthropic API key.",
        SOC2,
    ),
    _l(
        "secret.openai_key",
        "OpenAI API key",
        Category.SECRET,
        Severity.HIGH,
        "An OpenAI API key.",
        SOC2,
    ),
    _l(
        "secret.jwt",
        "JSON Web Token",
        Category.SECRET,
        Severity.HIGH,
        "A JWT, which may carry a live session or bearer grant.",
        SOC2,
    ),
    _l(
        "secret.generic_api_key",
        "Generic API key",
        Category.SECRET,
        Severity.HIGH,
        "A high-entropy value assigned to a key- or token-named field.",
        SOC2,
    ),
    _l(
        "secret.password",
        "Password",
        Category.SECRET,
        Severity.CRITICAL,
        "A plaintext password assigned to a password-named field.",
        SOC2,
    ),
    _l(
        "secret.db_connection_string",
        "Database connection string",
        Category.SECRET,
        Severity.CRITICAL,
        "A database URI with embedded credentials.",
        SOC2,
    ),
    # --- Business sensitivity (assigned by humans, not detectors) ----------------
    _l(
        "confidential.internal",
        "Internal only",
        Category.CONFIDENTIAL,
        Severity.MEDIUM,
        "Business-confidential material not for external disclosure.",
    ),
    _l(
        "confidential.legal",
        "Legally privileged",
        Category.CONFIDENTIAL,
        Severity.HIGH,
        "Attorney-client privileged or litigation-hold material.",
    ),
    _l(
        "confidential.source_code",
        "Proprietary source code",
        Category.CONFIDENTIAL,
        Severity.MEDIUM,
        "Source code that must not leave the organisation.",
    ),
    _l("public.open", "Public", Category.PUBLIC, Severity.LOW, "Cleared for public release."),
)


BY_KEY: dict[str, Label] = {label.key: label for label in LABELS}


def get(key: str) -> Label:
    """Look up a label, raising a clear error for an unknown key."""
    try:
        return BY_KEY[key]
    except KeyError:
        raise KeyError(
            f"unknown classification label {key!r}; known labels: {', '.join(sorted(BY_KEY))}"
        ) from None


def is_known(key: str) -> bool:
    """True if ``key`` is a concrete label or a prefix covering at least one label."""
    return key in BY_KEY or any(k.startswith(f"{key}.") for k in BY_KEY)


def expand(key: str) -> frozenset[str]:
    """Every concrete label key covered by ``key``.

    ``expand("pii.email")`` is just that label; ``expand("pii")`` is every ``pii.*``.
    """
    if key in BY_KEY:
        return frozenset({key})
    prefix = f"{key}."
    return frozenset(k for k in BY_KEY if k.startswith(prefix))


def covers(pattern: str, label_key: str) -> bool:
    """True if ``pattern`` matches ``label_key`` exactly or as an ancestor."""
    return label_key == pattern or label_key.startswith(f"{pattern}.")


def severity_of(key: str) -> Severity:
    """Severity of a concrete label, or the highest severity beneath a prefix."""
    if key in BY_KEY:
        return BY_KEY[key].severity
    children = expand(key)
    if not children:
        return Severity.LOW
    return max((BY_KEY[c].severity for c in children), key=lambda s: SEVERITY_RANK[s])


def regulations_for(keys: object) -> tuple[str, ...]:
    """The union of regulations implicated by a set of label keys, sorted."""
    if not isinstance(keys, (list, tuple, set, frozenset)):
        raise TypeError("keys must be an iterable of label keys")
    found: set[str] = set()
    for key in keys:
        for concrete in expand(str(key)):
            found.update(BY_KEY[concrete].regulations)
    return tuple(sorted(found))
