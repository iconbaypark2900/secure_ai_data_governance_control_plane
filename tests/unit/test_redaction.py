"""Redaction strategies and their guarantees."""

from __future__ import annotations

import pytest

from control_plane.classification.scanner import scan_structured, scan_text
from control_plane.redaction.transforms import (
    InMemoryTokenVault,
    RedactionRule,
    Redactor,
    Strategy,
)

TEXT = "Mail jane.doe@acme.com, card 4111 1111 1111 1111, ssn 536-90-4432"


def redact(*rules: RedactionRule, text: str = TEXT, **kwargs):
    result = scan_text(text)
    return Redactor(rules=rules, key=b"test-key", **kwargs).apply_to_text(text, result.findings)


class TestStrategies:
    def test_mask_removes_the_value_entirely(self) -> None:
        out = redact(RedactionRule(("pii.email",), Strategy.MASK))
        assert "jane.doe@acme.com" not in out.payload
        assert "[REDACTED:pii.email]" in out.payload

    def test_partial_keeps_a_recognisable_suffix(self) -> None:
        out = redact(RedactionRule(("pci.card_number",), Strategy.PARTIAL, keep_last=4))
        assert "**** **** **** 1111" in out.payload

    def test_hash_is_deterministic_and_irreversible(self) -> None:
        first = redact(RedactionRule(("pii.email",), Strategy.HASH))
        second = redact(RedactionRule(("pii.email",), Strategy.HASH))
        assert first.payload == second.payload
        assert "jane.doe" not in first.payload

    def test_hash_differs_under_a_different_key(self) -> None:
        findings = scan_text(TEXT).findings
        rules = (RedactionRule(("pii.email",), Strategy.HASH),)
        a = Redactor(rules=rules, key=b"key-a").apply_to_text(TEXT, findings)
        b = Redactor(rules=rules, key=b"key-b").apply_to_text(TEXT, findings)
        assert a.payload != b.payload

    def test_tokenize_round_trips_through_the_vault(self) -> None:
        vault = InMemoryTokenVault(b"vault-key")
        out = redact(RedactionRule(("pii.email",), Strategy.TOKENIZE), vault=vault)
        token = next(a.replacement for a in out.applied)
        assert vault.detokenize(token) == "jane.doe@acme.com"

    def test_tokenize_without_a_vault_degrades_to_a_hash(self) -> None:
        """It must not silently emit a token nobody can reverse."""
        out = redact(RedactionRule(("pii.email",), Strategy.TOKENIZE))
        assert out.applied[0].replacement.startswith("<pii.email:")

    def test_drop_removes_the_span(self) -> None:
        out = redact(RedactionRule(("pii.email",), Strategy.DROP))
        assert "Mail , card" in out.payload

    def test_synthetic_preserves_shape(self) -> None:
        out = redact(RedactionRule(("pii.email",), Strategy.SYNTHETIC))
        assert "@example.invalid" in out.payload
        assert "jane.doe@acme.com" not in out.payload


class TestRuleSelection:
    def test_first_matching_rule_wins(self) -> None:
        out = redact(
            RedactionRule(("pii.email",), Strategy.DROP),
            RedactionRule(("pii",), Strategy.MASK),
        )
        assert out.applied[0].strategy is Strategy.DROP

    def test_parent_label_covers_children(self) -> None:
        out = redact(RedactionRule(("pii",), Strategy.MASK))
        assert {a.label for a in out.applied} == {"pii.email", "pii.ssn"}

    def test_wildcard_covers_everything(self) -> None:
        out = redact(RedactionRule(("*",), Strategy.MASK))
        assert len(out.applied) == 3

    def test_uncovered_findings_are_reported_not_silently_kept(self) -> None:
        out = redact(RedactionRule(("secret",), Strategy.MASK))
        assert out.applied == ()
        assert {f.label for f in out.unhandled} == {"pii.email", "pci.card_number", "pii.ssn"}


class TestOffsets:
    def test_multiple_replacements_do_not_corrupt_each_other(self) -> None:
        """Replacements are applied right-to-left so earlier offsets stay valid."""
        out = redact(RedactionRule(("*",), Strategy.MASK))
        assert "acme.com" not in out.payload
        assert "4111" not in out.payload
        assert "536-90-4432" not in out.payload
        assert out.payload.startswith("Mail ")

    def test_applied_list_is_in_document_order(self) -> None:
        out = redact(RedactionRule(("*",), Strategy.MASK))
        starts = [a.start for a in out.applied]
        assert starts == sorted(starts)


class TestStructured:
    def test_rewrites_only_the_matching_leaf(self) -> None:
        payload = {"user": {"email": "a.b@example.com", "role": "admin"}, "count": 3}
        findings = scan_structured(payload).findings
        out = Redactor(
            rules=(RedactionRule(("pii",), Strategy.MASK),), key=b"k"
        ).apply_to_structured(payload, findings)
        assert out.payload["user"]["email"] == "[REDACTED:pii.email]"
        assert out.payload["user"]["role"] == "admin"
        assert out.payload["count"] == 3

    def test_handles_lists(self) -> None:
        payload = {"emails": ["a@x.com", "b@y.com"]}
        findings = scan_structured(payload).findings
        out = Redactor(
            rules=(RedactionRule(("pii",), Strategy.MASK),), key=b"k"
        ).apply_to_structured(payload, findings)
        assert out.payload["emails"] == ["[REDACTED:pii.email]"] * 2


class TestObligationParsing:
    def test_builds_rules_from_policy_obligations(self) -> None:
        redactor = Redactor.from_obligations(
            [{"type": "redact", "labels": ["pii"], "strategy": "partial", "keep_last": 2}],
            key=b"k",
        )
        rule = redactor.rule_for("pii.email")
        assert rule is not None
        assert rule.strategy is Strategy.PARTIAL
        assert rule.keep_last == 2

    def test_ignores_non_redaction_obligations(self) -> None:
        redactor = Redactor.from_obligations([{"type": "notify", "channel": "slack"}], key=b"k")
        assert redactor.rules == ()

    def test_rejects_an_unknown_strategy(self) -> None:
        with pytest.raises(ValueError, match="obliterate"):
            Redactor.from_obligations(
                [{"type": "redact", "labels": ["pii"], "strategy": "obliterate"}]
            )
