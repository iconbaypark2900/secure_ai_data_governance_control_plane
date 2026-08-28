"""Request and response shapes for the decision endpoint.

This is the contract every enforcement point codes against, so it is written to
be stable and explicit. Two rules govern the response:

1. The payload comes back only on an ``allow``. A deny that echoes the data it
   denied is not a deny.
2. Findings are reported as labels, offsets, and masked previews -- never the
   matched values. The response travels to logs and dashboards the control plane
   does not own.
"""

from __future__ import annotations

import uuid
from enum import StrEnum
from typing import Any, Literal, Self

from pydantic import BaseModel, ConfigDict, Field, model_validator

from control_plane.policy.model import Principal, Resource

__all__ = [
    "ApprovalOut",
    "ClassifyRequest",
    "ClassifyResponse",
    "DecideOptions",
    "DecideRequest",
    "DecideResponse",
    "FindingOut",
    "Outcome",
    "OutcomeOut",
    "OutcomeReport",
    "RedactionOut",
    "SimulateRequest",
    "SimulateResponse",
]


class DecideOptions(BaseModel):
    """Per-request knobs. Defaults are the ones a careful caller would choose."""

    model_config = ConfigDict(extra="forbid")

    explain: bool = Field(
        default=False,
        description="Return the full per-policy evaluation trace. Verbose; "
        "intended for debugging and the policy simulator, not the hot path.",
    )
    apply_obligations: bool = Field(
        default=True,
        description="Have the control plane execute redaction obligations and "
        "return the rewritten payload. Set false to receive the obligations and "
        "carry them out at the enforcement point.",
    )
    scan_payload: bool = Field(
        default=True,
        description="Classify the payload in this request and merge what is found "
        "into the labels the policy sees.",
    )
    min_confidence: float = Field(
        default=0.5,
        ge=0.0,
        le=1.0,
        description="Discard findings below this confidence before policy evaluation.",
    )
    persist: bool = Field(
        default=True,
        description="Write the decision and its audit record. Disable only for "
        "simulation; a decision that is enforced but not recorded is a gap.",
    )


class DecideRequest(BaseModel):
    """One authorisation question."""

    model_config = ConfigDict(extra="forbid")

    principal: Principal
    action: str = Field(min_length=1, max_length=64)
    resource: Resource = Field(default_factory=Resource)
    context: dict[str, Any] = Field(
        default_factory=dict,
        description="Request circumstances a policy can match on: destination, "
        "purpose, network zone, model name, ticket reference.",
    )
    payload: Any = Field(
        default=None,
        description="The content in flight -- a prompt, a retrieved chunk, a row "
        "batch. Scanned in memory; never stored.",
    )
    correlation_id: str | None = Field(default=None, max_length=128)
    approval_id: uuid.UUID | None = Field(
        default=None,
        description="An approval to redeem. Present it by re-sending the request "
        "that was parked, unchanged, with this set. A granted approval can only "
        "turn 'require_approval' into 'allow'; it never overrides a deny, and it "
        "only applies to the exact request a human reviewed.",
    )
    options: DecideOptions = Field(default_factory=DecideOptions)


class FindingOut(BaseModel):
    """A detected value, described without disclosing it."""

    label: str
    detector: str
    start: int
    end: int
    confidence: float
    path: str = ""
    preview: str
    severity: str


class RedactionOut(BaseModel):
    """One edit the control plane made."""

    label: str
    strategy: str
    start: int
    end: int
    path: str = ""
    replacement: str


class ApprovalOut(BaseModel):
    """The parked-decision handle returned with ``require_approval``.

    Also returned on the redemption that consumes it, so a caller can see which
    approval was spent and who authorised it without a second lookup.
    """

    id: uuid.UUID
    status: str
    requested_by: str
    created_at: str
    expires_at: str | None = None
    decided_by: str | None = None
    decision_note: str = ""
    resolved_at: str | None = None
    redeemed_at: str | None = None
    redeemed_by: str | None = None


class DecideResponse(BaseModel):
    """The control plane's answer."""

    model_config = ConfigDict(extra="forbid")

    decision_id: uuid.UUID | None = None
    effect: Literal["allow", "deny", "require_approval"]
    reason: str
    determining_policy: str | None = None
    matched_policies: list[str] = Field(default_factory=list)
    obligations: list[dict[str, Any]] = Field(default_factory=list)

    classifications: list[str] = Field(
        default_factory=list,
        description="Every label in play: the resource's catalog labels plus "
        "anything found in the payload.",
    )
    findings: list[FindingOut] = Field(default_factory=list)
    payload_truncated: bool = Field(
        default=False,
        description="The payload exceeded the scan ceiling, so only its first "
        "CP_MAX_SCAN_CHARS characters were classified. An empty findings list "
        "then means 'nothing in the part we read', not 'nothing there'.",
    )
    regulations: list[str] = Field(
        default_factory=list,
        description="Regulatory regimes implicated by the labels in play.",
    )

    payload: Any = Field(
        default=None,
        description="The payload after obligations were applied. Present only on "
        "an allow, and only when apply_obligations was requested.",
    )
    redactions: list[RedactionOut] = Field(default_factory=list)
    unsupported_obligations: list[str] = Field(
        default_factory=list,
        description="Obligation types the control plane could not execute itself. "
        "The enforcement point must satisfy these or treat the decision as a deny.",
    )

    route: dict[str, Any] | None = Field(
        default=None,
        description="Where this request may go, when a policy constrained it. "
        "Carries the resolved model URN, what was asked for, whether that is a "
        "redirect, and which candidates were rejected and why.",
    )
    approval: ApprovalOut | None = None
    approval_redeemed: bool = Field(
        default=False,
        description="True when a granted approval was consumed to produce this allow.",
    )
    approval_error: str | None = Field(
        default=None,
        description="Why a presented approval_id could not be redeemed. Machine "
        "readable enough to tell 'still pending, keep waiting' apart from "
        "'this will never work, stop retrying'.",
    )
    explain: dict[str, Any] | None = None
    latency_ms: float = 0.0
    policy_errors: list[str] = Field(default_factory=list)

    @property
    def allowed(self) -> bool:
        return self.effect == "allow"


class ClassifyRequest(BaseModel):
    """Classify content without asking an authorisation question."""

    model_config = ConfigDict(extra="forbid")

    payload: Any
    labels: list[str] | None = Field(
        default=None,
        description="Restrict to detectors producing these labels. Omit for all.",
    )
    min_confidence: float = Field(default=0.0, ge=0.0, le=1.0)


class ClassifyResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    findings: list[FindingOut] = Field(default_factory=list)
    payload_truncated: bool = Field(
        default=False,
        description="The payload exceeded the scan ceiling, so only its first "
        "CP_MAX_SCAN_CHARS characters were classified. An empty findings list "
        "then means 'nothing in the part we read', not 'nothing there'.",
    )
    labels: list[str] = Field(default_factory=list)
    label_counts: dict[str, int] = Field(default_factory=dict)
    max_severity: str | None = None
    regulations: list[str] = Field(default_factory=list)
    scanned_chars: int = 0
    truncated: bool = False


class SimulateRequest(BaseModel):
    """Evaluate a request against a candidate policy set without enforcing it."""

    model_config = ConfigDict(extra="forbid")

    request: DecideRequest
    #: Policies to evaluate instead of the stored set. Omit to use what is stored.
    policies: list[dict[str, Any]] | None = None
    #: Additional policies layered on top of the stored set.
    additional_policies: list[dict[str, Any]] | None = None
    include_disabled: bool = False


class SimulateResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    decision: DecideResponse
    #: The decision the stored policy set would have produced, for comparison.
    baseline: DecideResponse | None = None
    changed: bool = False
    policies_evaluated: int = 0


class Outcome(StrEnum):
    """What an enforcement point did with a decision.

    ``partial`` is the one worth having. Without it a point that carried out
    three obligations and skipped the fourth has to report either "enforced",
    which is a lie, or "refused", which is also a lie -- and the useful signal,
    that a duty is going undischarged in production, disappears into whichever
    it picked.
    """

    #: The permitted action happened, and every obligation was carried out.
    ENFORCED = "enforced"
    #: The action did not happen. The decision permitted it; something here
    #: could not or would not proceed.
    REFUSED = "refused"
    #: The action happened, but not every obligation was discharged.
    PARTIAL = "partial"


class OutcomeReport(BaseModel):
    """What an enforcement point reports back after acting on a decision."""

    model_config = ConfigDict(extra="forbid")

    outcome: Outcome
    reason: str = Field(
        default="",
        max_length=1000,
        description="Why, when the action did not fully happen. Required for "
        "anything other than 'enforced': an unexplained refusal is a gap in the "
        "record rather than an entry in it.",
    )
    discharged: list[str] = Field(
        default_factory=list,
        description="Obligation types actually carried out.",
    )
    undischarged: list[str] = Field(
        default_factory=list,
        description="Obligation types that were not. What makes 'partial' legible.",
    )

    @model_validator(mode="after")
    def _explain_anything_short_of_enforced(self) -> Self:
        if self.outcome is not Outcome.ENFORCED and not self.reason.strip():
            raise ValueError(
                f"an outcome of {self.outcome!r} needs a reason; an unexplained "
                f"refusal is a gap in the record rather than an entry in it"
            )
        if self.outcome is Outcome.PARTIAL and not self.undischarged:
            raise ValueError(
                "a 'partial' outcome must name the obligations that were not "
                "discharged, or it says nothing a 'refused' would not"
            )
        return self


class OutcomeOut(BaseModel):
    """The recorded outcome of a decision."""

    decision_id: uuid.UUID
    outcome: str | None = None
    reason: str = ""
    discharged: list[str] = Field(default_factory=list)
    undischarged: list[str] = Field(default_factory=list)
    reported_at: str | None = None
    reported_by: str | None = None

    @property
    def reported(self) -> bool:
        return self.outcome is not None
