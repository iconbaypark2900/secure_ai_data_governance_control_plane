"""The condition operators a policy may use.

A condition is a mapping of operator name to operand, evaluated against one value
pulled out of the access request. Every operator here is total: given any value
and any operand it returns a boolean or raises :class:`PolicyError`, never a
surprise. That matters because an operator that throws at decision time is an
outage, and an operator that silently returns False is a security hole.

Set-membership operators use *prefix-aware* matching on dotted keys, so a policy
that names ``pii`` matches a resource classified ``pii.email``. For values with no
dots -- action names, principal types, identifiers -- this collapses to plain
equality, so the behaviour is only ever visible where a hierarchy exists.
"""

from __future__ import annotations

import fnmatch
import re
from collections.abc import Callable, Iterable
from typing import Any

__all__ = ["OPERATORS", "PolicyError", "apply_operator", "known_operators", "validate_condition"]

#: Longest regex a policy may contain. Policy authors are trusted, but a bounded
#: pattern still limits the blast radius of a careless one.
MAX_REGEX_LENGTH = 512


class PolicyError(ValueError):
    """A policy document is malformed or uses an operator incorrectly."""


#: Sentinel distinguishing "the selector resolved to nothing" from "it resolved to None".
class _Missing:
    __slots__ = ()

    def __repr__(self) -> str:  # pragma: no cover - debug aid
        return "<missing>"

    def __bool__(self) -> bool:
        return False


MISSING = _Missing()


def _as_sequence(operand: Any, operator: str) -> tuple[Any, ...]:
    if isinstance(operand, (list, tuple, set, frozenset)):
        return tuple(operand)
    if isinstance(operand, (str, bytes)) or not isinstance(operand, Iterable):
        return (operand,)
    return tuple(operand)  # pragma: no cover - exotic iterables


def _values_of(value: Any) -> tuple[Any, ...]:
    """Normalise the left-hand side to a tuple, so scalars and lists share a path."""
    if value is MISSING:
        return ()
    if isinstance(value, (list, tuple, set, frozenset)):
        return tuple(value)
    return (value,)


def _token_matches(value: Any, pattern: Any) -> bool:
    """Equality, extended so a dotted ancestor matches its descendants."""
    if value == pattern:
        return True
    if isinstance(value, str) and isinstance(pattern, str):
        return value.startswith(f"{pattern}.")
    return False


def _numeric(value: Any, operator: str) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise PolicyError(f"operator {operator!r} needs a number, got {type(value).__name__}")
    return float(value)


def _compile(pattern: Any, operator: str) -> re.Pattern[str]:
    if not isinstance(pattern, str):
        raise PolicyError(f"operator {operator!r} needs a string pattern")
    if len(pattern) > MAX_REGEX_LENGTH:
        raise PolicyError(f"operator {operator!r} pattern exceeds {MAX_REGEX_LENGTH} characters")
    try:
        return re.compile(pattern)
    except re.error as exc:
        raise PolicyError(f"invalid regex in {operator!r}: {exc}") from exc


# --------------------------------------------------------------------------- #
# Operator implementations
# --------------------------------------------------------------------------- #


def op_eq(value: Any, operand: Any) -> bool:
    return value is not MISSING and value == operand


def op_neq(value: Any, operand: Any) -> bool:
    return value is MISSING or value != operand


def op_in(value: Any, operand: Any) -> bool:
    """True if the value -- or any element of a list value -- is in the operand set."""
    candidates = _as_sequence(operand, "in")
    return any(
        _token_matches(item, candidate) for item in _values_of(value) for candidate in candidates
    )


def op_not_in(value: Any, operand: Any) -> bool:
    return not op_in(value, operand)


def op_any_of(value: Any, operand: Any) -> bool:
    """True if the value set intersects the operand set. Alias of ``in`` for lists."""
    return op_in(value, operand)


def op_all_of(value: Any, operand: Any) -> bool:
    """True if every operand element is covered by some element of the value set."""
    items = _values_of(value)
    if not items:
        return False
    return all(
        any(_token_matches(item, candidate) for item in items)
        for candidate in _as_sequence(operand, "all_of")
    )


def op_none_of(value: Any, operand: Any) -> bool:
    return not op_in(value, operand)


def op_glob(value: Any, operand: Any) -> bool:
    patterns = _as_sequence(operand, "glob")
    return any(
        isinstance(item, str) and isinstance(p, str) and fnmatch.fnmatchcase(item, p)
        for item in _values_of(value)
        for p in patterns
    )


def op_not_glob(value: Any, operand: Any) -> bool:
    return not op_glob(value, operand)


def op_regex(value: Any, operand: Any) -> bool:
    pattern = _compile(operand, "regex")
    return any(
        isinstance(item, str) and pattern.search(item) is not None for item in _values_of(value)
    )


def op_exists(value: Any, operand: Any) -> bool:
    present = value is not MISSING and value is not None
    if not isinstance(operand, bool):
        raise PolicyError("operator 'exists' needs a boolean operand")
    return present is operand


def op_contains(value: Any, operand: Any) -> bool:
    needles = _as_sequence(operand, "contains")
    return any(
        isinstance(item, str) and isinstance(n, str) and n in item
        for item in _values_of(value)
        for n in needles
    )


def op_startswith(value: Any, operand: Any) -> bool:
    prefixes = tuple(p for p in _as_sequence(operand, "startswith") if isinstance(p, str))
    return (
        any(isinstance(item, str) and item.startswith(prefixes) for item in _values_of(value))
        if prefixes
        else False
    )


def op_endswith(value: Any, operand: Any) -> bool:
    suffixes = tuple(s for s in _as_sequence(operand, "endswith") if isinstance(s, str))
    return (
        any(isinstance(item, str) and item.endswith(suffixes) for item in _values_of(value))
        if suffixes
        else False
    )


def _compare(value: Any, operand: Any, operator: str, test: Callable[[float, float], bool]) -> bool:
    if value is MISSING:
        return False
    threshold = _numeric(operand, operator)
    for item in _values_of(value):
        try:
            if test(_numeric(item, operator), threshold):
                return True
        except PolicyError:
            continue
    return False


def op_gt(value: Any, operand: Any) -> bool:
    return _compare(value, operand, "gt", lambda a, b: a > b)


def op_gte(value: Any, operand: Any) -> bool:
    return _compare(value, operand, "gte", lambda a, b: a >= b)


def op_lt(value: Any, operand: Any) -> bool:
    return _compare(value, operand, "lt", lambda a, b: a < b)


def op_lte(value: Any, operand: Any) -> bool:
    return _compare(value, operand, "lte", lambda a, b: a <= b)


def op_count_gte(value: Any, operand: Any) -> bool:
    return len(_values_of(value)) >= _numeric(operand, "count_gte")


def op_count_lte(value: Any, operand: Any) -> bool:
    return len(_values_of(value)) <= _numeric(operand, "count_lte")


def op_empty(value: Any, operand: Any) -> bool:
    if not isinstance(operand, bool):
        raise PolicyError("operator 'empty' needs a boolean operand")
    return (len(_values_of(value)) == 0) is operand


OPERATORS: dict[str, Callable[[Any, Any], bool]] = {
    "eq": op_eq,
    "neq": op_neq,
    "in": op_in,
    "not_in": op_not_in,
    "any_of": op_any_of,
    "all_of": op_all_of,
    "none_of": op_none_of,
    "glob": op_glob,
    "not_glob": op_not_glob,
    "regex": op_regex,
    "exists": op_exists,
    "contains": op_contains,
    "startswith": op_startswith,
    "endswith": op_endswith,
    "gt": op_gt,
    "gte": op_gte,
    "lt": op_lt,
    "lte": op_lte,
    "count_gte": op_count_gte,
    "count_lte": op_count_lte,
    "empty": op_empty,
}


def known_operators() -> tuple[str, ...]:
    return tuple(sorted(OPERATORS))


def apply_operator(operator: str, value: Any, operand: Any) -> bool:
    """Evaluate one operator, raising :class:`PolicyError` for an unknown name."""
    try:
        func = OPERATORS[operator]
    except KeyError:
        raise PolicyError(
            f"unknown operator {operator!r}; known operators: {', '.join(known_operators())}"
        ) from None
    return func(value, operand)


def validate_condition(condition: Any, *, where: str = "condition") -> None:
    """Check a condition mapping at authoring time rather than at decision time."""
    if not isinstance(condition, dict) or not condition:
        raise PolicyError(f"{where} must be a non-empty object of operator -> operand")
    for operator, operand in condition.items():
        if operator not in OPERATORS:
            raise PolicyError(
                f"{where} uses unknown operator {operator!r}; "
                f"known operators: {', '.join(known_operators())}"
            )
        if operator in {"regex"}:
            _compile(operand, operator)
        if operator in {"exists", "empty"} and not isinstance(operand, bool):
            raise PolicyError(f"{where}.{operator} needs a boolean operand")
        if operator in {"gt", "gte", "lt", "lte", "count_gte", "count_lte"}:
            _numeric(operand, operator)


def resolve_path(root: Any, path: str) -> Any:
    """Walk a dotted path, returning :data:`MISSING` if any segment is absent.

    Supports mappings, objects with attributes, and integer indices into lists,
    which is enough to address anything an access request can contain.
    """
    current: Any = root
    for segment in path.split("."):
        if current is MISSING or current is None:
            return MISSING
        if isinstance(current, dict):
            if segment not in current:
                return MISSING
            current = current[segment]
        elif isinstance(current, (list, tuple)):
            if not segment.lstrip("-").isdigit():
                return MISSING
            index = int(segment)
            if not -len(current) <= index < len(current):
                return MISSING
            current = current[index]
        elif hasattr(current, segment):
            current = getattr(current, segment)
        else:
            return MISSING
    return current
