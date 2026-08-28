"""The policy document and the access request it is evaluated against.

A policy is data, not code. It is authored as YAML or JSON, stored as JSONB,
versioned, and diffable -- which is what makes "who changed the rule that let
this through?" an answerable question.

The match tree is deliberately small. Conditions are keyed by a dotted selector
into the request, and combined with ``all`` / ``any`` / ``not``::

    match:
      all:
        - principal.type: agent
        - principal.attributes.trust_tier: {in: [low, medium]}
        - resource.classifications: {any_of: [phi, pci]}
        - not:
            context.purpose: {eq: break_glass}

Scalars and lists are sugar: ``principal.type: agent`` means ``{eq: agent}`` and
``action: [read, embed]`` means ``{in: [read, embed]}``. Every form normalises to
the same operator mapping before evaluation, so there is one thing to test.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from enum import StrEnum
from typing import Annotated, Any, Literal, Self

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from control_plane.classification import taxonomy
from control_plane.policy.operators import PolicyError, validate_condition

__all__ = [
    "KNOWN_OBLIGATIONS",
    "ROOT_SELECTORS",
    "AccessRequest",
    "CombiningAlgorithm",
    "Effect",
    "Obligation",
    "Policy",
    "PolicySet",
    "Principal",
    "Resource",
]


class Effect(StrEnum):
    """What a matching policy asks the enforcement point to do."""

    ALLOW = "allow"
    DENY = "deny"
    REQUIRE_APPROVAL = "require_approval"


class CombiningAlgorithm(StrEnum):
    """How simultaneous, disagreeing policies are reconciled."""

    #: Any matching deny wins, regardless of priority. The safe default.
    DENY_OVERRIDES = "deny_overrides"
    #: The highest-priority matching policy wins, letting a deliberate
    #: high-priority allow act as a break-glass exception to a broad deny.
    PRIORITY_ORDERED = "priority_ordered"
    #: Any matching allow wins. For observation rollouts only.
    PERMIT_OVERRIDES = "permit_overrides"


#: Selector roots that may appear on the left of a condition.
ROOT_SELECTORS: frozenset[str] = frozenset(
    {"principal", "action", "resource", "context", "findings", "classifications", "env"}
)


class Executor(StrEnum):
    """Who is responsible for carrying an obligation out."""

    #: The control plane performs it and returns the result.
    CONTROL_PLANE = "control_plane"
    #: A duty handed to the enforcement point, which must satisfy it or treat
    #: the decision as a deny.
    ENFORCEMENT_POINT = "enforcement_point"


@dataclass(frozen=True, slots=True)
class ObligationSpec:
    """What an obligation type means and what it needs."""

    executor: Executor
    description: str
    #: At least one of these must be present.
    requires_any: tuple[str, ...] = ()


#: Every obligation type the system supports.
#:
#: The list is deliberately short. An obligation nothing implements is worse
#: than no obligation at all: it validates at authoring time, reaches the
#: enforcement point as a duty nobody can discharge, and so turns a policy
#: someone wrote in good faith into a way to deny their own traffic. Two earlier
#: entries -- ``notify`` and ``route`` -- were removed for exactly that reason.
#: They need infrastructure this system does not have, and pretending otherwise
#: was a promise in the schema that nothing behind it kept.
OBLIGATION_SPECS: dict[str, ObligationSpec] = {
    "redact": ObligationSpec(
        Executor.CONTROL_PLANE,
        "Rewrite matching values before the payload is returned.",
        requires_any=("labels", "classifications"),
    ),
    "annotate": ObligationSpec(
        Executor.CONTROL_PLANE,
        "Attach a note to the decision, for the record rather than the payload.",
    ),
    "log": ObligationSpec(
        Executor.CONTROL_PLANE,
        "Record this decision at a raised level.",
    ),
    "ttl": ObligationSpec(
        Executor.CONTROL_PLANE,
        "How long the permitted data may be retained downstream, in seconds.",
        requires_any=("seconds",),
    ),
    "limit": ObligationSpec(
        Executor.ENFORCEMENT_POINT,
        "Cap how much may flow: rows, bytes, tokens, or results.",
        requires_any=("max_rows", "max_bytes", "max_tokens", "max_results"),
    ),
    "watermark": ObligationSpec(
        Executor.ENFORCEMENT_POINT,
        "Mark the delivered content so its origin survives a copy-paste.",
        requires_any=("text",),
    ),
    "require_purpose": ObligationSpec(
        Executor.ENFORCEMENT_POINT,
        "The enforcement point must confirm its declared purpose is one of "
        "these. Duplicates what a context.purpose match condition can express, "
        "and deliberately so: it re-checks at the point of use rather than "
        "trusting the purpose asserted at the point of decision.",
        requires_any=("purposes",),
    ),
}

#: Obligation types the system supports, in a form policies validate against.
KNOWN_OBLIGATIONS: frozenset[str] = frozenset(OBLIGATION_SPECS)

#: Those the control plane discharges itself. Derived rather than duplicated, so
#: the decision pipeline and the policy schema cannot drift apart.
CONTROL_PLANE_OBLIGATIONS: frozenset[str] = frozenset(
    name for name, spec in OBLIGATION_SPECS.items() if spec.executor is Executor.CONTROL_PLANE
)


class Obligation(BaseModel):
    """A duty attached to a decision.

    An obligation is not advice. An enforcement point that cannot carry one out
    must treat the decision as a deny -- otherwise "allow, but redact the SSNs"
    silently degrades into "allow".
    """

    model_config = ConfigDict(extra="allow")

    type: str = Field(description="Obligation kind, e.g. 'redact'.")

    @field_validator("type")
    @classmethod
    def _normalise_type(cls, value: str) -> str:
        return value.strip().lower()

    @model_validator(mode="after")
    def _check_shape(self) -> Self:
        extras = self.model_extra or {}

        spec = OBLIGATION_SPECS.get(self.type)
        if spec is None:
            # Rejected here rather than ignored at decision time. A policy that
            # attaches a duty nothing understands has not been written safely,
            # and the author is the only person in a position to fix it.
            raise ValueError(
                f"unknown obligation type {self.type!r}; supported types are "
                f"{', '.join(sorted(KNOWN_OBLIGATIONS))}"
            )

        if spec.requires_any and not any(key in extras for key in spec.requires_any):
            raise ValueError(
                f"a {self.type!r} obligation must set at least one of "
                f"{', '.join(spec.requires_any)}"
            )

        if self.type == "redact":
            self._check_redact(extras)
        elif self.type == "require_purpose":
            purposes = extras.get("purposes")
            if isinstance(purposes, str) or not isinstance(purposes, (list, tuple)):
                raise ValueError("'require_purpose' needs 'purposes' as a list")
            if not purposes:
                raise ValueError("'require_purpose' with an empty list permits nothing")
        elif self.type == "ttl":
            seconds = extras.get("seconds")
            if not isinstance(seconds, int) or isinstance(seconds, bool) or seconds <= 0:
                raise ValueError("'ttl' needs 'seconds' as a positive integer")
        elif self.type == "limit":
            for key in ("max_rows", "max_bytes", "max_tokens", "max_results"):
                value = extras.get(key)
                if value is not None and (
                    not isinstance(value, int) or isinstance(value, bool) or value < 0
                ):
                    raise ValueError(f"'limit.{key}' must be a non-negative integer")
        return self

    @staticmethod
    def _check_redact(extras: dict[str, Any]) -> None:
        labels = extras.get("labels") or extras.get("classifications")
        names = [labels] if isinstance(labels, str) else list(labels or [])
        unknown = [name for name in names if name != "*" and not taxonomy.is_known(str(name))]
        if unknown:
            raise ValueError(
                f"'redact' obligation names unknown labels: {', '.join(map(str, unknown))}"
            )
        strategy = str(extras.get("strategy", "mask")).lower()
        allowed = {"mask", "partial", "hash", "tokenize", "synthetic", "drop"}
        if strategy not in allowed:
            raise ValueError(
                f"unknown redaction strategy {strategy!r}; expected one of "
                f"{', '.join(sorted(allowed))}"
            )

    def to_dict(self) -> dict[str, Any]:
        return self.model_dump(mode="json")

    @property
    def spec(self) -> ObligationSpec:
        return OBLIGATION_SPECS[self.type]

    @property
    def executed_by_control_plane(self) -> bool:
        return self.type in CONTROL_PLANE_OBLIGATIONS


def _normalise_condition(raw: Any) -> dict[str, Any]:
    """Expand sugar into an explicit operator mapping."""
    if isinstance(raw, Mapping):
        return dict(raw)
    if isinstance(raw, (list, tuple, set, frozenset)):
        return {"in": list(raw)}
    return {"eq": raw}


#: Structural keys in a match node. Anything else is read as a selector.
STRUCTURAL_KEYS: frozenset[str] = frozenset({"all", "any", "not", "conditions"})


def normalise_match(node: Any, *, path: str = "match") -> dict[str, Any]:
    """Validate a match tree and return it in canonical form.

    Idempotent: normalising an already-canonical tree returns it unchanged. That
    matters because policies round-trip through the database as their normalised
    documents, and a non-idempotent normaliser would make every stored policy
    fail to load -- silently removing a control rather than loudly breaking.

    Raises :class:`PolicyError` with a path into the document, because a policy
    that fails to parse at 3am should say exactly where.
    """
    if node is None:
        return {"all": []}
    if not isinstance(node, Mapping):
        raise PolicyError(f"{path} must be an object, got {type(node).__name__}")

    if "conditions" in node:
        # Already canonical. Re-validate rather than trust it: a document can
        # reach this path straight from the database.
        if len(node) > 1:
            raise PolicyError(
                f"{path} sets 'conditions' alongside "
                f"{', '.join(sorted(set(node) - {'conditions'}))}"
            )
        raw_conditions = node["conditions"]
        if not isinstance(raw_conditions, Mapping):
            raise PolicyError(f"{path}.conditions must be an object")
        return _validate_conditions(raw_conditions, path=f"{path}.conditions")

    combinators = {key for key in node if key in STRUCTURAL_KEYS}
    selectors = {key for key in node if key not in STRUCTURAL_KEYS}

    if combinators and selectors:
        raise PolicyError(
            f"{path} mixes combinators ({', '.join(sorted(combinators))}) with selectors "
            f"({', '.join(sorted(selectors))}); wrap the selectors in an explicit 'all'"
        )

    if combinators:
        if len(combinators) > 1:
            raise PolicyError(
                f"{path} sets more than one combinator: {', '.join(sorted(combinators))}"
            )
        key = combinators.pop()
        value = node[key]
        if key == "not":
            return {"not": normalise_match(value, path=f"{path}.not")}
        if not isinstance(value, Sequence) or isinstance(value, (str, bytes)):
            raise PolicyError(f"{path}.{key} must be a list of match nodes")
        return {
            key: [
                normalise_match(child, path=f"{path}.{key}[{index}]")
                for index, child in enumerate(value)
            ]
        }

    return _validate_conditions(node, path=path)


def _validate_conditions(node: Mapping[str, Any], *, path: str) -> dict[str, Any]:
    """Validate a flat selector -> condition mapping and canonicalise it."""
    conditions: dict[str, Any] = {}
    for selector, raw in node.items():
        selector_str = str(selector)
        root = selector_str.split(".", 1)[0]
        if root not in ROOT_SELECTORS:
            raise PolicyError(
                f"{path} selector {selector_str!r} must start with one of "
                f"{', '.join(sorted(ROOT_SELECTORS))}"
            )
        condition = _normalise_condition(raw)
        validate_condition(condition, where=f"{path}.{selector_str}")
        conditions[selector_str] = condition
    return {"conditions": conditions}


class Policy(BaseModel):
    """One authored rule."""

    model_config = ConfigDict(extra="forbid")

    key: Annotated[str, Field(pattern=r"^[a-z0-9][a-z0-9._\-]{0,126}$")]
    name: str
    description: str = ""
    effect: Effect
    priority: int = Field(default=100, ge=0, le=10_000)
    enabled: bool = True
    version: int = Field(default=1, ge=1)
    match: dict[str, Any] = Field(default_factory=lambda: {"conditions": {}})
    obligations: list[Obligation] = Field(default_factory=list)
    tags: list[str] = Field(default_factory=list)

    @field_validator("match", mode="before")
    @classmethod
    def _normalise(cls, value: Any) -> Any:
        return normalise_match(value)

    @model_validator(mode="after")
    def _check_obligation_placement(self) -> Self:
        if self.effect is Effect.DENY and self.obligations:
            raise ValueError(
                "a deny policy cannot carry obligations: there is no permitted "
                "action left for them to constrain"
            )
        return self

    @property
    def redaction_obligations(self) -> list[Obligation]:
        return [o for o in self.obligations if o.type == "redact"]

    def to_document(self) -> dict[str, Any]:
        """The canonical, storable form."""
        return self.model_dump(mode="json")


class PolicySet(BaseModel):
    """A named bundle of policies, as loaded from a file."""

    model_config = ConfigDict(extra="forbid")

    name: str = "default"
    description: str = ""
    combining_algorithm: CombiningAlgorithm = CombiningAlgorithm.DENY_OVERRIDES
    policies: list[Policy] = Field(default_factory=list)

    @model_validator(mode="after")
    def _unique_keys(self) -> Self:
        seen: set[str] = set()
        duplicates: set[str] = set()
        for policy in self.policies:
            if policy.key in seen:
                duplicates.add(policy.key)
            seen.add(policy.key)
        if duplicates:
            raise ValueError(f"duplicate policy keys: {', '.join(sorted(duplicates))}")
        return self

    @property
    def enabled_policies(self) -> list[Policy]:
        return [p for p in self.policies if p.enabled]


# --------------------------------------------------------------------------- #
# The access request
# --------------------------------------------------------------------------- #


class Principal(BaseModel):
    """Who or what is asking."""

    model_config = ConfigDict(extra="forbid")

    id: str
    type: Literal["user", "agent", "service", "unknown"] = "unknown"
    attributes: dict[str, Any] = Field(default_factory=dict)

    @property
    def trust_tier(self) -> str:
        return str(self.attributes.get("trust_tier", "unknown"))


class Resource(BaseModel):
    """What is being reached for."""

    model_config = ConfigDict(extra="forbid")

    urn: str | None = None
    kind: str | None = None
    #: Labels already known about this resource, from the catalog or the caller.
    classifications: list[str] = Field(default_factory=list)
    attributes: dict[str, Any] = Field(default_factory=dict)

    @field_validator("classifications")
    @classmethod
    def _known_labels(cls, value: list[str]) -> list[str]:
        unknown = [label for label in value if not taxonomy.is_known(label)]
        if unknown:
            raise ValueError(f"unknown classification labels: {', '.join(unknown)}")
        return value


class AccessRequest(BaseModel):
    """The complete question put to the policy engine."""

    model_config = ConfigDict(extra="forbid")

    principal: Principal
    action: str
    resource: Resource = Field(default_factory=Resource)
    context: dict[str, Any] = Field(default_factory=dict)
    #: Labels discovered by scanning the payload in this request, merged with the
    #: resource's catalog labels before evaluation.
    findings: list[str] = Field(default_factory=list)
    #: Facts about the evaluation itself rather than about the request. Chiefly
    #: ``payload_truncated``: when a payload exceeds the scan ceiling only its
    #: first CP_MAX_SCAN_CHARS characters were classified, so an empty
    #: ``findings`` means "nothing found in the part we read", not "nothing
    #: there". A policy that cares can refuse to guess::
    #:
    #:     - key: deny-unscannable-payloads
    #:       effect: deny
    #:       match:
    #:         env.payload_truncated: true
    env: dict[str, Any] = Field(default_factory=dict)

    def selector_root(self) -> dict[str, Any]:
        """The object dotted selectors are resolved against.

        Three label selectors, deliberately distinct, because they answer
        different questions and a policy usually means exactly one of them:

        ``resource.classifications``
            What the catalog says this asset holds. "Low-trust agents may not
            touch the clinical schema" is a statement about the store, and must
            not start firing because someone pasted an SSN into a prompt about
            an unrelated table.
        ``findings``
            What the classifier found in *this* payload. "Never transmit a
            credential" is a statement about content, and must fire wherever the
            content came from -- including a resource nobody registered.
        ``classifications``
            The union, for the common case of "anything sensitive is involved".

        Collapsing these into one selector makes policies read plausibly and
        behave surprisingly, which is the worst property a security control can
        have.
        """
        resource_labels = sorted(set(self.resource.classifications))
        payload_labels = sorted(set(self.findings))
        return {
            "principal": {
                "id": self.principal.id,
                "type": str(self.principal.type),
                "attributes": self.principal.attributes,
                **self.principal.attributes,
            },
            "action": self.action,
            "resource": {
                "urn": self.resource.urn,
                "kind": self.resource.kind,
                "classifications": resource_labels,
                "attributes": self.resource.attributes,
                **self.resource.attributes,
            },
            "context": self.context,
            "findings": payload_labels,
            "classifications": sorted(set(resource_labels) | set(payload_labels)),
            "env": dict(self.env),
        }
