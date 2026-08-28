"""Request and response shapes for the catalog."""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel, ConfigDict, Field, field_validator

from control_plane.classification import taxonomy

__all__ = [
    "AssetIn",
    "AssetOut",
    "ClassificationIn",
    "ClassificationOut",
    "PrincipalIn",
    "PrincipalOut",
    "ScanRequest",
    "ScanResponse",
]


class AssetIn(BaseModel):
    model_config = ConfigDict(extra="forbid")

    urn: str = Field(
        min_length=1,
        max_length=512,
        description="Stable identifier, e.g. 'pg://public.customers'. A trailing "
        "glob such as 'pg://clinical.*' registers a pattern that classifies every "
        "asset beneath it.",
    )
    name: str | None = Field(default=None, max_length=255)
    kind: str | None = Field(default=None, max_length=64)
    owner: str | None = Field(default=None, max_length=255)
    description: str | None = None
    attributes: dict[str, Any] | None = None


class ClassificationOut(BaseModel):
    label: str
    source: str
    confidence: float
    asserted_by: str = ""
    evidence: dict[str, Any] = Field(default_factory=dict)


class AssetOut(BaseModel):
    urn: str
    name: str
    kind: str
    owner: str
    description: str
    attributes: dict[str, Any] = Field(default_factory=dict)
    classifications: list[ClassificationOut] = Field(default_factory=list)
    labels: list[str] = Field(default_factory=list)
    regulations: list[str] = Field(default_factory=list)
    last_scanned_at: str | None = None
    created_at: str | None = None
    updated_at: str | None = None


class ClassificationIn(BaseModel):
    model_config = ConfigDict(extra="forbid")

    label: str
    source: str = Field(default="manual", pattern="^(manual|scan|inherited|imported)$")
    confidence: float = Field(default=1.0, ge=0.0, le=1.0)
    asserted_by: str = ""
    evidence: dict[str, Any] = Field(default_factory=dict)

    @field_validator("label")
    @classmethod
    def _known(cls, value: str) -> str:
        if not taxonomy.is_known(value):
            raise ValueError(f"unknown classification label {value!r}")
        return value


class PrincipalIn(BaseModel):
    model_config = ConfigDict(extra="forbid")

    external_id: str = Field(min_length=1, max_length=255)
    type: str = Field(default="unknown", pattern="^(user|agent|service|unknown)$")
    display_name: str | None = Field(default=None, max_length=255)
    description: str | None = None
    attributes: dict[str, Any] | None = Field(
        default=None,
        description="ABAC attributes the policy engine can match on: trust_tier, "
        "team, clearance, region. These override anything a caller asserts.",
    )


class PrincipalOut(BaseModel):
    external_id: str
    type: str
    display_name: str
    description: str
    attributes: dict[str, Any] = Field(default_factory=dict)
    enabled: bool = True
    created_at: str | None = None


class ScanRequest(BaseModel):
    """Classify a sample and record what it implies about an asset."""

    model_config = ConfigDict(extra="forbid")

    urn: str
    sample: Any = Field(
        description="Representative content: a row batch, a document, a chunk. "
        "Scanned in memory; only masked previews are retained as evidence."
    )
    min_confidence: float = Field(default=0.6, ge=0.0, le=1.0)
    asserted_by: str = "scanner"
    persist: bool = Field(default=True, description="Write the inferred labels onto the asset.")


class ScanResponse(BaseModel):
    urn: str
    labels_applied: list[str] = Field(default_factory=list)
    label_counts: dict[str, int] = Field(default_factory=dict)
    max_severity: str | None = None
    regulations: list[str] = Field(default_factory=list)
    finding_count: int = 0
    scanned_chars: int = 0
    truncated: bool = False
    persisted: bool = True
