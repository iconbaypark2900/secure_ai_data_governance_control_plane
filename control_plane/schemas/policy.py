"""Request and response shapes for policy administration."""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel, ConfigDict, Field

__all__ = ["PolicyIn", "PolicyOut", "PolicySyncRequest", "PolicySyncResult", "PolicyVersionOut"]


class PolicyIn(BaseModel):
    """A policy document plus the note explaining the change.

    The note is not decoration. "Who relaxed this control, when, and why" is the
    first question asked after an incident, and the third part is the one that is
    never reconstructible afterwards.
    """

    model_config = ConfigDict(extra="forbid")

    policy: dict[str, Any] = Field(description="The policy document.")
    change_note: str = Field(default="", max_length=1000)


class PolicyOut(BaseModel):
    key: str
    name: str
    description: str
    effect: str
    priority: int
    enabled: bool
    version: int
    tags: list[str] = Field(default_factory=list)
    document: dict[str, Any] = Field(default_factory=dict)
    created_by: str = ""
    updated_by: str = ""
    created_at: str | None = None
    updated_at: str | None = None


class PolicyVersionOut(BaseModel):
    policy_key: str
    version: int
    document: dict[str, Any]
    change_note: str = ""
    changed_by: str = ""
    created_at: str | None = None


class PolicySyncRequest(BaseModel):
    """Reconcile the stored policy set with a declared one."""

    model_config = ConfigDict(extra="forbid")

    policies: list[dict[str, Any]]
    prune: bool = Field(
        default=False,
        description="Delete stored policies absent from this set. Off by default: "
        "removing a control should be deliberate.",
    )
    change_note: str = "synced"


class PolicySyncResult(BaseModel):
    created: list[str] = Field(default_factory=list)
    updated: list[str] = Field(default_factory=list)
    unchanged: list[str] = Field(default_factory=list)
    removed: list[str] = Field(default_factory=list)
