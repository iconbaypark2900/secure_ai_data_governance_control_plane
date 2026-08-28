"""The obligations the reference enforcement point discharges."""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from pep.reverse_proxy.obligations import (
    SATISFIABLE,
    apply_request_obligations,
    apply_response_obligations,
    check_purpose,
    obligations_of,
    token_cap,
)


def completion(*contents: str) -> dict:
    return {
        "choices": [
            {"index": i, "message": {"role": "assistant", "content": c}}
            for i, c in enumerate(contents)
        ]
    }


class TestRequirePurpose:
    def test_a_permitted_purpose_passes(self) -> None:
        obligations = [{"type": "require_purpose", "purposes": ["support", "billing"]}]
        assert check_purpose(obligations, "support") is None

    def test_a_purpose_outside_the_list_is_refused(self) -> None:
        obligations = [{"type": "require_purpose", "purposes": ["support"]}]
        assert "not among the purposes" in check_purpose(obligations, "training")

    def test_two_obligations_intersect_rather_than_race(self) -> None:
        """Each narrowing must hold; satisfying one is not satisfying both."""
        obligations = [
            {"type": "require_purpose", "purposes": ["support", "billing"]},
            {"type": "require_purpose", "purposes": ["billing", "audit"]},
        ]
        assert check_purpose(obligations, "billing") is None
        assert check_purpose(obligations, "support") is not None

    def test_no_obligation_permits_anything(self) -> None:
        assert check_purpose([{"type": "watermark", "text": "x"}], "whatever") is None


class TestLimit:
    def test_the_tightest_token_cap_wins(self) -> None:
        assert (
            token_cap([{"type": "limit", "max_tokens": 900}, {"type": "limit", "max_tokens": 300}])
            == 300
        )

    def test_a_cap_lowers_but_never_raises_what_was_asked_for(self) -> None:
        obligations = [{"type": "limit", "max_tokens": 500}]
        capped, notes = apply_request_obligations({"max_tokens": 4000}, obligations)
        assert capped["max_tokens"] == 500
        assert notes

        already_lower, notes = apply_request_obligations({"max_tokens": 100}, obligations)
        assert already_lower["max_tokens"] == 100
        assert notes == []

    def test_a_cap_applies_when_the_caller_asked_for_nothing(self) -> None:
        capped, _ = apply_request_obligations({}, [{"type": "limit", "max_tokens": 250}])
        assert capped["max_tokens"] == 250

    def test_max_results_drops_extra_choices(self) -> None:
        out, applied = apply_response_obligations(
            completion("a", "b", "c"), [{"type": "limit", "max_results": 1}]
        )
        assert len(out["choices"]) == 1
        assert applied.dropped_choices == 2

    def test_max_bytes_truncates_and_says_so(self) -> None:
        out, applied = apply_response_obligations(
            completion("x" * 500), [{"type": "limit", "max_bytes": 50}]
        )
        content = out["choices"][0]["message"]["content"]
        assert content.startswith("x" * 50)
        assert "truncated by data governance policy" in content
        assert applied.truncated_bytes == 450

    def test_truncation_cuts_on_a_character_boundary(self) -> None:
        """A response sliced mid-codepoint is not smaller, it is broken."""
        out, _ = apply_response_obligations(
            completion("é" * 100), [{"type": "limit", "max_bytes": 15}]
        )
        content = out["choices"][0]["message"]["content"]
        assert content.startswith("é")
        content.encode("utf-8")  # would raise if the string were malformed

    def test_content_under_the_cap_is_untouched(self) -> None:
        out, applied = apply_response_obligations(
            completion("short"), [{"type": "limit", "max_bytes": 1000}]
        )
        assert out["choices"][0]["message"]["content"] == "short"
        assert applied.truncated_bytes is None


class TestWatermark:
    def test_the_marking_is_appended(self) -> None:
        out, applied = apply_response_obligations(
            completion("the answer"), [{"type": "watermark", "text": "INTERNAL USE ONLY"}]
        )
        assert out["choices"][0]["message"]["content"].endswith("INTERNAL USE ONLY")
        assert applied.watermarked is True

    def test_every_choice_is_marked(self) -> None:
        out, _ = apply_response_obligations(
            completion("a", "b"), [{"type": "watermark", "text": "MARK"}]
        )
        assert all(c["message"]["content"].endswith("MARK") for c in out["choices"])

    def test_an_empty_marking_is_ignored(self) -> None:
        out, applied = apply_response_obligations(
            completion("a"), [{"type": "watermark", "text": "   "}]
        )
        assert applied.watermarked is False
        assert out["choices"][0]["message"]["content"] == "a"


class TestCombination:
    def test_caps_apply_before_marking(self) -> None:
        """Truncating after watermarking would cut the marking off."""
        out, applied = apply_response_obligations(
            completion("x" * 500),
            [{"type": "limit", "max_bytes": 20}, {"type": "watermark", "text": "MARK"}],
        )
        content = out["choices"][0]["message"]["content"]
        assert content.endswith("MARK")
        assert applied.truncated_bytes == 480

    def test_nothing_to_do_leaves_the_response_alone(self) -> None:
        original = completion("untouched")
        out, applied = apply_response_obligations(original, [])
        assert out["choices"][0]["message"]["content"] == "untouched"
        assert applied.changed is False


class TestDeclaration:
    def test_the_proxy_declares_exactly_what_it_implements(self) -> None:
        assert {"limit", "watermark", "require_purpose"} == SATISFIABLE

    def test_obligations_of_filters_by_type(self) -> None:
        obligations = [{"type": "limit", "max_rows": 1}, {"type": "watermark", "text": "x"}]
        assert len(obligations_of(obligations, "limit")) == 1
        assert obligations_of(obligations, "notify") == []
