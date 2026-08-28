"""What an obligation may say, and who is expected to act on it.

The rule these tests exist to hold: an obligation type that nothing implements
must not be accepted. It validates at authoring time, reaches the enforcement
point as a duty nobody can discharge, and turns a policy written in good faith
into a way to deny your own traffic.
"""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from control_plane.pdp import SELF_EXECUTABLE
from control_plane.policy.model import (
    CONTROL_PLANE_OBLIGATIONS,
    KNOWN_OBLIGATIONS,
    OBLIGATION_SPECS,
    Executor,
    Obligation,
    Policy,
)


class TestTheSupportedSet:
    def test_every_type_names_who_executes_it(self) -> None:
        assert set(OBLIGATION_SPECS) == set(KNOWN_OBLIGATIONS)
        assert all(isinstance(s.executor, Executor) for s in OBLIGATION_SPECS.values())

    def test_the_control_plane_set_is_derived_not_duplicated(self) -> None:
        """Two copies would drift, and the drift means a duty going unenforced."""
        assert SELF_EXECUTABLE is CONTROL_PLANE_OBLIGATIONS
        assert {"redact", "annotate", "log", "ttl"} == CONTROL_PLANE_OBLIGATIONS

    def test_the_enforcement_point_set_is_what_the_reference_pep_implements(self) -> None:
        import sys
        from pathlib import Path

        sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
        from pep.reverse_proxy.obligations import SATISFIABLE

        assert KNOWN_OBLIGATIONS - CONTROL_PLANE_OBLIGATIONS == SATISFIABLE

    @pytest.mark.parametrize("removed", ["notify", "route"])
    def test_types_nothing_implements_were_removed(self, removed: str) -> None:
        assert removed not in KNOWN_OBLIGATIONS


class TestValidation:
    def test_an_unknown_type_is_rejected_at_authoring_time(self) -> None:
        with pytest.raises(ValidationError, match="unknown obligation type"):
            Obligation.model_validate({"type": "frobnicate"})

    def test_the_error_lists_what_is_supported(self) -> None:
        with pytest.raises(ValidationError, match="watermark"):
            Obligation.model_validate({"type": "nope"})

    @pytest.mark.parametrize(
        ("document", "message"),
        [
            ({"type": "redact"}, "at least one of"),
            ({"type": "redact", "labels": ["pii.aura"]}, "unknown labels"),
            ({"type": "redact", "labels": ["pii"], "strategy": "vanish"}, "unknown redaction"),
            ({"type": "limit"}, "at least one of"),
            ({"type": "limit", "max_rows": -1}, "non-negative"),
            ({"type": "watermark"}, "at least one of"),
            ({"type": "require_purpose"}, "at least one of"),
            ({"type": "require_purpose", "purposes": "support"}, "as a list"),
            ({"type": "require_purpose", "purposes": []}, "permits nothing"),
            ({"type": "ttl"}, "at least one of"),
            ({"type": "ttl", "seconds": 0}, "positive integer"),
            ({"type": "ttl", "seconds": "an hour"}, "positive integer"),
        ],
    )
    def test_malformed_obligations_are_rejected(self, document, message) -> None:
        with pytest.raises(ValidationError, match=message):
            Obligation.model_validate(document)

    @pytest.mark.parametrize(
        "document",
        [
            {"type": "redact", "labels": ["pii"], "strategy": "mask"},
            {"type": "redact", "labels": "*"},
            {"type": "limit", "max_tokens": 500},
            {"type": "watermark", "text": "internal use only"},
            {"type": "require_purpose", "purposes": ["support"]},
            {"type": "ttl", "seconds": 3600},
            {"type": "log", "level": "notice"},
            {"type": "annotate", "note": "reviewed"},
        ],
    )
    def test_well_formed_obligations_are_accepted(self, document) -> None:
        assert Obligation.model_validate(document).type == document["type"]

    def test_a_policy_carrying_a_removed_type_no_longer_parses(self) -> None:
        """Cutting one is a breaking change, and it should break loudly."""
        with pytest.raises(ValidationError, match="unknown obligation type"):
            Policy(
                key="p",
                name="p",
                effect="allow",
                match={},
                obligations=[{"type": "notify", "channel": "slack"}],
            )


class TestExecutorRouting:
    def test_control_plane_obligations_are_marked_as_such(self) -> None:
        assert Obligation.model_validate(
            {"type": "redact", "labels": ["pii"]}
        ).executed_by_control_plane

    def test_enforcement_point_obligations_are_not(self) -> None:
        assert not Obligation.model_validate(
            {"type": "watermark", "text": "x"}
        ).executed_by_control_plane

    def test_the_schema_advertises_only_what_exists(self) -> None:
        """GET /v1/policies/schema serves this set, so it must not overpromise."""
        assert "notify" not in KNOWN_OBLIGATIONS
        assert "route" not in KNOWN_OBLIGATIONS
        assert set(OBLIGATION_SPECS) == KNOWN_OBLIGATIONS
