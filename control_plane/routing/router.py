"""Resolving a routing obligation to a concrete backend.

Until now a policy's only answer to "this data must not reach that model" was
*no*. That makes the control plane a gate rather than a fabric, and a gate people
route around is worse than no gate at all -- the same argument that makes
redaction preferable to refusal for data applies to infrastructure.

Routing is the "yes, but" at the infrastructure layer. The policy says where the
request may go; the router works out which registered model satisfies that, and
the decision carries the answer.

**Models are catalog assets.** A model is registered like any other asset, under a
``model://`` URN with ``kind: model``, and its attributes describe where it runs::

    urn: model://internal/llama-3-70b
    kind: model
    attributes:
      region: eu
      hosting: on_prem
      provider: internal
      aliases: [eu-only-llm, internal-gpt]
      routing_priority: 10

That reuses the catalog's labelling, discovery, and audit rather than
introducing a second registry that drifts from it.

**The control plane picks the model; the enforcement point reaches it.** Which
backend is a governance decision and belongs in the decision record, because
"which model saw this data" is the first question asked after an incident. The
endpoint and credential for that backend are deployment configuration the
enforcement point holds, and the control plane has no business storing them.

**An unsatisfiable route is a denial.** If a policy says the request may only go
to an EU-resident model and none is registered, there is no permitted way to
proceed. Falling back to the requested model would invert the policy.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass, field
from typing import Any

__all__ = [
    "MODEL_KIND",
    "ModelCandidate",
    "ModelRouter",
    "RoutingDecision",
    "RoutingUnsatisfiable",
]

#: The catalog kind that marks an asset as routable.
MODEL_KIND = "model"

#: Lower sorts first. Absent means "least preferred", so an unranked model is
#: only chosen when nothing ranked qualifies.
DEFAULT_PRIORITY = 1_000_000


class RoutingUnsatisfiable(ValueError):
    """No registered model satisfies the constraints a policy imposed."""


@dataclass(frozen=True, slots=True)
class ModelCandidate:
    """A model the router may choose."""

    urn: str
    name: str = ""
    attributes: Mapping[str, Any] = field(default_factory=dict)
    labels: tuple[str, ...] = ()

    @property
    def aliases(self) -> tuple[str, ...]:
        """Logical names this model answers to, e.g. ``eu-only-llm``."""
        raw = self.attributes.get("aliases") or ()
        if isinstance(raw, str):
            return (raw,)
        return tuple(str(item) for item in raw)

    @property
    def priority(self) -> int:
        value = self.attributes.get("routing_priority", DEFAULT_PRIORITY)
        return (
            int(value)
            if isinstance(value, int) and not isinstance(value, bool)
            else (DEFAULT_PRIORITY)
        )

    @property
    def enabled(self) -> bool:
        return self.attributes.get("routing_enabled", True) is not False

    def answers_to(self, name: str) -> bool:
        """Whether ``name`` identifies this model, by URN, name, or alias."""
        return name in {self.urn, self.name, *self.aliases}

    def satisfies(self, requirements: Mapping[str, Any]) -> str | None:
        """None if every requirement holds, else why it does not.

        A requirement value may be a scalar or a list of acceptable values.
        Absent attributes fail: a model that does not say where it runs cannot
        be assumed to run somewhere acceptable.
        """
        for key, expected in requirements.items():
            actual = self.attributes.get(key)
            if actual is None:
                return f"declares no {key!r}"
            wanted = expected if isinstance(expected, (list, tuple, set)) else [expected]
            if actual not in wanted:
                allowed = ", ".join(str(w) for w in wanted)
                return f"{key} is {actual!r}, policy requires one of: {allowed}"
        return None

    def to_dict(self) -> dict[str, Any]:
        return {
            "urn": self.urn,
            "name": self.name,
            "attributes": dict(self.attributes),
            "labels": list(self.labels),
        }


@dataclass(frozen=True, slots=True)
class RoutingDecision:
    """Where a permitted request should be sent."""

    #: The model chosen, as a URN. None when routing could not be satisfied.
    target: str | None = None
    #: The logical name the policy asked for, if it named one.
    requested: str | None = None
    #: The model the caller originally addressed.
    original: str | None = None
    reason: str = ""
    #: Every model considered, and why the rejected ones lost. Kept because
    #: "why did my request go there?" is asked far more often than it is
    #: answerable.
    considered: tuple[str, ...] = ()
    rejected: Mapping[str, str] = field(default_factory=dict)

    @property
    def redirected(self) -> bool:
        """Whether the request must go somewhere other than where it was aimed."""
        return self.target is not None and self.target != self.original

    @property
    def satisfied(self) -> bool:
        return self.target is not None

    def to_dict(self) -> dict[str, Any]:
        return {
            "target": self.target,
            "requested": self.requested,
            "original": self.original,
            "redirected": self.redirected,
            "reason": self.reason,
            "considered": list(self.considered),
            "rejected": dict(self.rejected),
        }


class ModelRouter:
    """Selects among registered models. Pure: the catalog read happens outside."""

    __slots__ = ("_candidates",)

    def __init__(self, candidates: Iterable[ModelCandidate]) -> None:
        self._candidates = tuple(candidates)

    def __len__(self) -> int:
        return len(self._candidates)

    @property
    def candidates(self) -> tuple[ModelCandidate, ...]:
        return self._candidates

    def resolve(
        self,
        obligations: Sequence[Mapping[str, Any]],
        *,
        original: str | None = None,
    ) -> RoutingDecision | None:
        """Work out where a request should go, or None if no policy said.

        Several ``route`` obligations intersect rather than compete: two policies
        each narrowing where data may go should both hold, so their requirements
        are merged and a model must satisfy all of them.
        """
        routes = [o for o in obligations if str(o.get("type", "")).lower() == "route"]
        if not routes:
            return None

        requested: str | None = None
        requirements: dict[str, Any] = {}
        for route in routes:
            target = route.get("to")
            if target:
                if requested and str(target) != requested:
                    raise RoutingUnsatisfiable(
                        f"two policies name different routing targets: {requested!r} and {target!r}"
                    )
                requested = str(target)
            for key, value in (route.get("require") or {}).items():
                requirements[str(key)] = _intersect(requirements.get(str(key)), value)

        eligible = [c for c in self._candidates if c.enabled]
        rejected: dict[str, str] = {
            c.urn: "routing is disabled for this model" for c in self._candidates if not c.enabled
        }

        if requested:
            named = [c for c in eligible if c.answers_to(requested)]
            for c in eligible:
                if c not in named:
                    rejected[c.urn] = f"does not answer to {requested!r}"
            eligible = named

        viable: list[ModelCandidate] = []
        for candidate in eligible:
            failure = candidate.satisfies(requirements)
            if failure is None:
                viable.append(candidate)
            else:
                rejected[candidate.urn] = failure

        considered = tuple(c.urn for c in self._candidates)
        if not viable:
            return RoutingDecision(
                target=None,
                requested=requested,
                original=original,
                reason=self._explain_failure(requested, requirements),
                considered=considered,
                rejected=rejected,
            )

        # Prefer the model already addressed when it qualifies: a route
        # obligation is a constraint, not an instruction to move for its own sake.
        staying = next((c for c in viable if c.urn == original), None)
        chosen = staying or min(viable, key=lambda c: (c.priority, c.urn))

        return RoutingDecision(
            target=chosen.urn,
            requested=requested,
            original=original,
            reason=self._explain_choice(chosen, staying is not None, requested, requirements),
            considered=considered,
            rejected=rejected,
        )

    @staticmethod
    def _explain_failure(requested: str | None, requirements: Mapping[str, Any]) -> str:
        parts = []
        if requested:
            parts.append(f"named target {requested!r}")
        if requirements:
            parts.append(
                "requirements " + ", ".join(f"{k}={v!r}" for k, v in sorted(requirements.items()))
            )
        constraint = "; ".join(parts) or "the routing constraints"
        return f"no registered model satisfies {constraint}"

    @staticmethod
    def _explain_choice(
        chosen: ModelCandidate,
        stayed: bool,
        requested: str | None,
        requirements: Mapping[str, Any],
    ) -> str:
        why = []
        if requested:
            why.append(f"answers to {requested!r}")
        if requirements:
            why.append(
                "satisfies " + ", ".join(f"{k}={v!r}" for k, v in sorted(requirements.items()))
            )
        detail = "; ".join(why) or "no constraints applied"
        if stayed:
            return f"the requested model already {detail}, so it was kept"
        return f"routed to {chosen.urn} because it {detail}"


def _intersect(existing: Any, incoming: Any) -> Any:
    """Narrow a requirement rather than replace it.

    Two policies each restricting where data may go must both be honoured. If
    their allowed sets are disjoint, nothing can satisfy both -- represented as an
    empty set, which no model matches, producing a denial rather than a silent
    pick of one policy's answer over the other's.
    """
    if existing is None:
        return incoming
    left = set(existing if isinstance(existing, (list, tuple, set)) else [existing])
    right = set(incoming if isinstance(incoming, (list, tuple, set)) else [incoming])
    return sorted(left & right)
