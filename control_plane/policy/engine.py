"""Evaluating an access request against a policy set.

The engine answers three things at once, and the third is what makes it useful
in an audit: what the decision was, what duties come with it, and *why*. A
decision without a trace is an assertion; a decision with one is evidence.

Evaluation is pure. It touches no database, performs no I/O, and depends on no
clock, so a decision can be replayed months later against the same policy version
and produce byte-identical output. Everything the engine needs arrives in the
:class:`~control_plane.policy.model.AccessRequest`.
"""

from __future__ import annotations

from collections.abc import Container, Iterable, Mapping, Sequence
from dataclasses import dataclass, field
from typing import Any

from control_plane.policy.model import (
    AccessRequest,
    CombiningAlgorithm,
    Effect,
    Obligation,
    Policy,
)
from control_plane.policy.operators import MISSING, PolicyError, apply_operator, resolve_path

__all__ = ["EFFECT_RANK", "ConditionTrace", "Decision", "PolicyEngine", "PolicyTrace"]

#: Precedence used to break ties between equal-priority matches.
EFFECT_RANK: dict[Effect, int] = {
    Effect.ALLOW: 0,
    Effect.REQUIRE_APPROVAL: 1,
    Effect.DENY: 2,
}

#: Trace values are truncated: a trace is written to an audit log, and resource
#: attributes can carry more than anyone wants durably stored.
MAX_TRACE_VALUE_CHARS = 200


def _summarise(value: Any) -> Any:
    """A compact, log-safe rendering of a value that appeared in a condition."""
    if value is MISSING:
        return None
    if isinstance(value, (list, tuple, set, frozenset)):
        items = [_summarise(v) for v in list(value)[:12]]
        if len(value) > 12:
            items.append(f"... +{len(value) - 12} more")
        return items
    if isinstance(value, str) and len(value) > MAX_TRACE_VALUE_CHARS:
        return value[:MAX_TRACE_VALUE_CHARS] + "..."
    if isinstance(value, (str, int, float, bool)) or value is None:
        return value
    return f"<{type(value).__name__}>"


@dataclass(frozen=True, slots=True)
class ConditionTrace:
    """One selector/operator test and its outcome."""

    selector: str
    operator: str
    operand: Any
    observed: Any
    passed: bool

    def describe(self) -> str:
        verb = "matched" if self.passed else "did not match"
        return (
            f"{self.selector} {self.operator} {self.operand!r} {verb} (observed {self.observed!r})"
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "selector": self.selector,
            "operator": self.operator,
            "operand": _summarise(self.operand),
            "observed": self.observed,
            "passed": self.passed,
            "description": self.describe(),
        }


@dataclass(frozen=True, slots=True)
class PolicyTrace:
    """Why one policy did or did not apply."""

    key: str
    name: str
    effect: Effect
    priority: int
    matched: bool
    reason: str
    conditions: tuple[ConditionTrace, ...] = ()
    error: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "key": self.key,
            "name": self.name,
            "effect": str(self.effect),
            "priority": self.priority,
            "matched": self.matched,
            "reason": self.reason,
            "conditions": [c.to_dict() for c in self.conditions],
            "error": self.error,
        }


@dataclass(frozen=True, slots=True)
class Decision:
    """The engine's answer."""

    effect: Effect
    reason: str
    obligations: tuple[Obligation, ...] = ()
    matched_policies: tuple[str, ...] = ()
    determining_policy: str | None = None
    algorithm: CombiningAlgorithm = CombiningAlgorithm.DENY_OVERRIDES
    policies_evaluated: int = 0
    trace: tuple[PolicyTrace, ...] = ()
    errors: tuple[str, ...] = ()

    @property
    def allowed(self) -> bool:
        return self.effect is Effect.ALLOW

    @property
    def redaction_obligations(self) -> tuple[Obligation, ...]:
        return tuple(o for o in self.obligations if o.type == "redact")

    def to_dict(self, *, include_trace: bool = True) -> dict[str, Any]:
        payload: dict[str, Any] = {
            "effect": str(self.effect),
            "reason": self.reason,
            "obligations": [o.to_dict() for o in self.obligations],
            "matched_policies": list(self.matched_policies),
            "determining_policy": self.determining_policy,
            "algorithm": str(self.algorithm),
            "policies_evaluated": self.policies_evaluated,
        }
        if self.errors:
            payload["errors"] = list(self.errors)
        if include_trace:
            payload["trace"] = [t.to_dict() for t in self.trace]
        return payload


@dataclass
class _NodeResult:
    passed: bool
    conditions: list[ConditionTrace] = field(default_factory=list)
    #: The first failing condition, which is the useful half of "why not".
    failure: ConditionTrace | None = None


class PolicyEngine:
    """A compiled, reusable view over a set of policies.

    Construction sorts and validates once; :meth:`evaluate` is then a pure
    function of the request. Instances are immutable and safe to share across
    concurrent requests.
    """

    __slots__ = ("_algorithm", "_default_effect", "_load_errors", "_policies")

    def __init__(
        self,
        policies: Iterable[Policy],
        *,
        algorithm: CombiningAlgorithm = CombiningAlgorithm.DENY_OVERRIDES,
        default_effect: Effect = Effect.DENY,
        load_errors: Sequence[str] = (),
    ) -> None:
        enabled = [p for p in policies if p.enabled]
        # Highest priority first; stable on key so ordering is reproducible.
        self._policies: tuple[Policy, ...] = tuple(
            sorted(enabled, key=lambda p: (-p.priority, p.key))
        )
        self._algorithm = algorithm
        self._default_effect = default_effect
        # Policies that failed to load are carried into every decision this
        # engine makes. A control that silently fails to load is worse than one
        # that fails loudly: the system looks compliant and is not.
        self._load_errors = tuple(load_errors)

    @property
    def load_errors(self) -> tuple[str, ...]:
        return self._load_errors

    @property
    def policies(self) -> tuple[Policy, ...]:
        return self._policies

    @property
    def algorithm(self) -> CombiningAlgorithm:
        return self._algorithm

    def __len__(self) -> int:
        return len(self._policies)

    # --- match-tree evaluation -------------------------------------------- #

    def _eval_conditions(
        self, conditions: Mapping[str, Any], root: Mapping[str, Any], explain: bool
    ) -> _NodeResult:
        result = _NodeResult(passed=True)
        for selector, condition in conditions.items():
            observed = resolve_path(root, selector)
            for operator, operand in condition.items():
                passed = apply_operator(operator, observed, operand)
                trace = ConditionTrace(
                    selector=selector,
                    operator=operator,
                    operand=operand,
                    observed=_summarise(observed),
                    passed=passed,
                )
                if explain:
                    result.conditions.append(trace)
                if not passed:
                    result.passed = False
                    if result.failure is None:
                        result.failure = trace
                    if not explain:
                        return result
        return result

    def _eval_node(
        self, node: Mapping[str, Any], root: Mapping[str, Any], explain: bool
    ) -> _NodeResult:
        if "conditions" in node:
            return self._eval_conditions(node["conditions"], root, explain)

        if "all" in node:
            combined = _NodeResult(passed=True)
            for child in node["all"]:
                child_result = self._eval_node(child, root, explain)
                combined.conditions.extend(child_result.conditions)
                if not child_result.passed:
                    combined.passed = False
                    if combined.failure is None:
                        combined.failure = child_result.failure
                    if not explain:
                        return combined
            return combined

        if "any" in node:
            children = node["any"]
            combined = _NodeResult(passed=not children)
            for child in children:
                child_result = self._eval_node(child, root, explain)
                combined.conditions.extend(child_result.conditions)
                if child_result.passed:
                    combined.passed = True
                    combined.failure = None
                    if not explain:
                        return combined
                elif combined.failure is None:
                    combined.failure = child_result.failure
            if combined.passed:
                combined.failure = None
            return combined

        if "not" in node:
            inner = self._eval_node(node["not"], root, explain)
            negated = _NodeResult(passed=not inner.passed, conditions=inner.conditions)
            if not negated.passed:
                negated.failure = ConditionTrace(
                    selector="not",
                    operator="not",
                    operand=None,
                    observed=None,
                    passed=False,
                )
            return negated

        # An empty node matches everything: a policy with no conditions is a
        # blanket rule, which is a legitimate thing to author deliberately.
        return _NodeResult(passed=True)

    # --- evaluation -------------------------------------------------------- #

    def evaluate(self, request: AccessRequest, *, explain: bool = True) -> Decision:
        """Decide ``request`` against this policy set."""
        root = request.selector_root()
        traces: list[PolicyTrace] = []
        matched: list[Policy] = []
        errors: list[str] = list(self._load_errors)

        for policy in self._policies:
            try:
                node_result = self._eval_node(policy.match, root, explain)
            except PolicyError as exc:
                # A broken policy must not silently vanish from the decision.
                # It is recorded as an error and, under fail-closed combining,
                # is surfaced to the caller.
                message = f"policy {policy.key!r} failed to evaluate: {exc}"
                errors.append(message)
                traces.append(
                    PolicyTrace(
                        key=policy.key,
                        name=policy.name,
                        effect=policy.effect,
                        priority=policy.priority,
                        matched=False,
                        reason="evaluation error",
                        error=str(exc),
                    )
                )
                continue

            if node_result.passed:
                matched.append(policy)
                reason = "all conditions matched"
            elif node_result.failure is not None:
                reason = node_result.failure.describe()
            else:
                reason = "did not match"

            if explain or node_result.passed:
                traces.append(
                    PolicyTrace(
                        key=policy.key,
                        name=policy.name,
                        effect=policy.effect,
                        priority=policy.priority,
                        matched=node_result.passed,
                        reason=reason,
                        conditions=tuple(node_result.conditions),
                    )
                )

        effect, determining = self._combine(matched)
        obligations = self._collect_obligations(matched, effect)
        reason = self._describe(effect, determining, matched, errors)

        return Decision(
            effect=effect,
            reason=reason,
            obligations=obligations,
            matched_policies=tuple(p.key for p in matched),
            determining_policy=determining.key if determining else None,
            algorithm=self._algorithm,
            policies_evaluated=len(self._policies),
            trace=tuple(traces),
            errors=tuple(errors),
        )

    def _combine(self, matched: Sequence[Policy]) -> tuple[Effect, Policy | None]:
        if not matched:
            return self._default_effect, None

        def strongest(effect: Effect) -> Policy | None:
            candidates = [p for p in matched if p.effect is effect]
            if not candidates:
                return None
            return max(candidates, key=lambda p: (p.priority, p.key))

        match self._algorithm:
            case CombiningAlgorithm.DENY_OVERRIDES:
                order = (Effect.DENY, Effect.REQUIRE_APPROVAL, Effect.ALLOW)
            case CombiningAlgorithm.PERMIT_OVERRIDES:
                order = (Effect.ALLOW, Effect.REQUIRE_APPROVAL, Effect.DENY)
            case CombiningAlgorithm.PRIORITY_ORDERED:
                # Highest priority wins outright; a tie falls back to the safest
                # effect present at that priority.
                winner = max(matched, key=lambda p: (p.priority, EFFECT_RANK[p.effect], p.key))
                return winner.effect, winner
            case _:  # pragma: no cover - exhaustive over the enum
                order = (Effect.DENY, Effect.REQUIRE_APPROVAL, Effect.ALLOW)

        for effect in order:
            found = strongest(effect)
            if found is not None:
                return effect, found
        return self._default_effect, None  # pragma: no cover - unreachable

    @staticmethod
    def _union_obligations(policies: Iterable[Policy]) -> tuple[Obligation, ...]:
        """Deduplicated obligations from a set of policies, strongest first."""
        collected: list[Obligation] = []
        seen: set[str] = set()
        for policy in sorted(policies, key=lambda p: (-p.priority, p.key)):
            for obligation in policy.obligations:
                fingerprint = repr(sorted(obligation.to_dict().items(), key=lambda kv: kv[0]))
                if fingerprint in seen:
                    continue
                seen.add(fingerprint)
                collected.append(obligation)
        return tuple(collected)

    @classmethod
    def _collect_obligations(
        cls, matched: Sequence[Policy], effect: Effect
    ) -> tuple[Obligation, ...]:
        """Union the obligations of every matched policy sharing the winning effect.

        Union, not override: obligations only ever add constraints, so combining
        them can make a decision stricter but never looser.
        """
        if effect is Effect.DENY:
            return ()
        return cls._union_obligations(p for p in matched if p.effect is effect)

    def obligations_for(
        self, policy_keys: Iterable[str], effects: Container[Effect]
    ) -> tuple[Obligation, ...]:
        """Obligations from the named policies whose effect is in ``effects``.

        Used when a decision changes effect after evaluation -- specifically when
        a human approval turns ``require_approval`` into ``allow``. The duties an
        ``allow`` policy would have imposed have to come with it, or redeeming an
        approval would become a way to shed the redaction that policy required.
        """
        wanted = set(policy_keys)
        return self._union_obligations(
            policy for policy in self._policies if policy.key in wanted and policy.effect in effects
        )

    def _describe(
        self,
        effect: Effect,
        determining: Policy | None,
        matched: Sequence[Policy],
        errors: Sequence[str],
    ) -> str:
        if determining is None:
            base = f"no policy matched; applied the default effect '{self._default_effect}'"
        else:
            base = (
                f"'{determining.name}' ({determining.key}, priority {determining.priority}) "
                f"produced '{effect}' under {self._algorithm}"
            )
            others = [p.key for p in matched if p.key != determining.key]
            if others:
                base += f"; also matched: {', '.join(sorted(others))}"
        if errors:
            base += f"; {len(errors)} policy/policies failed to evaluate"
        return base
