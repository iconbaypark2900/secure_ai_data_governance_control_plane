"""Policy parsing, matching, and combining."""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from control_plane.policy.engine import PolicyEngine
from control_plane.policy.model import (
    AccessRequest,
    CombiningAlgorithm,
    Effect,
    Policy,
    Principal,
    Resource,
)


def make_request(**overrides) -> AccessRequest:
    base = {
        "principal": Principal(id="agent:rag", type="agent", attributes={"trust_tier": "low"}),
        "action": "read",
        "resource": Resource(urn="qdrant://kb_docs", classifications=["pii.email"]),
        "context": {"destination": "internal"},
    }
    base.update(overrides)
    return AccessRequest(**base)


ALLOW_READ = Policy(
    key="allow-agent-read",
    name="Agents may read the knowledge base",
    effect=Effect.ALLOW,
    priority=100,
    match={"all": [{"principal.type": "agent"}, {"action": ["read", "embed"]}]},
    obligations=[{"type": "redact", "labels": ["pii"], "strategy": "mask"}],
)

DENY_EXTERNAL = Policy(
    key="deny-external-pii",
    name="No PII to external destinations",
    effect=Effect.DENY,
    priority=900,
    match={
        "all": [
            {"resource.classifications": {"any_of": ["pii", "phi"]}},
            {"context.destination": "external"},
        ]
    },
)


class TestMatching:
    def test_scalar_sugar_becomes_eq(self) -> None:
        policy = Policy(key="p", name="p", effect="allow", match={"action": "read"})
        assert policy.match == {"conditions": {"action": {"eq": "read"}}}

    def test_list_sugar_becomes_in(self) -> None:
        policy = Policy(key="p", name="p", effect="allow", match={"action": ["read", "list"]})
        assert policy.match == {"conditions": {"action": {"in": ["read", "list"]}}}

    def test_labels_match_hierarchically(self) -> None:
        """A policy naming 'pii' covers 'pii.email' without enumerating children."""
        policy = Policy(
            key="p",
            name="p",
            effect="deny",
            match={"resource.classifications": {"any_of": ["pii"]}},
        )
        engine = PolicyEngine([policy])
        assert engine.evaluate(make_request()).effect is Effect.DENY

    def test_any_combinator(self) -> None:
        policy = Policy(
            key="p",
            name="p",
            effect="allow",
            match={"any": [{"action": "write"}, {"action": "read"}]},
        )
        assert PolicyEngine([policy]).evaluate(make_request()).effect is Effect.ALLOW

    def test_not_combinator(self) -> None:
        policy = Policy(
            key="p",
            name="p",
            effect="allow",
            match={"not": {"context.destination": "external"}},
        )
        assert PolicyEngine([policy]).evaluate(make_request()).effect is Effect.ALLOW

    def test_nested_combinators(self) -> None:
        policy = Policy(
            key="p",
            name="p",
            effect="deny",
            match={
                "all": [
                    {"any": [{"principal.type": "agent"}, {"principal.type": "service"}]},
                    {"not": {"context.purpose": "break_glass"}},
                ]
            },
        )
        assert PolicyEngine([policy]).evaluate(make_request()).effect is Effect.DENY

    def test_attributes_are_reachable_two_ways(self) -> None:
        """Both principal.trust_tier and principal.attributes.trust_tier resolve."""
        for selector in ("principal.trust_tier", "principal.attributes.trust_tier"):
            policy = Policy(key="p", name="p", effect="allow", match={selector: {"in": ["low"]}})
            assert PolicyEngine([policy]).evaluate(make_request()).effect is Effect.ALLOW

    def test_glob_on_urn(self) -> None:
        policy = Policy(
            key="p",
            name="p",
            effect="allow",
            match={"resource.urn": {"glob": "qdrant://*"}},
        )
        assert PolicyEngine([policy]).evaluate(make_request()).effect is Effect.ALLOW

    def test_empty_match_is_a_blanket_rule(self) -> None:
        policy = Policy(key="p", name="p", effect="deny", match={})
        assert PolicyEngine([policy]).evaluate(make_request()).effect is Effect.DENY

    def test_missing_selector_does_not_match(self) -> None:
        policy = Policy(
            key="p",
            name="p",
            effect="allow",
            match={"context.nonexistent": {"eq": "anything"}},
        )
        assert PolicyEngine([policy]).evaluate(make_request()).effect is Effect.DENY


class TestCombining:
    def test_deny_overrides_regardless_of_priority(self) -> None:
        low_priority_deny = DENY_EXTERNAL.model_copy(update={"priority": 1})
        engine = PolicyEngine([ALLOW_READ, low_priority_deny])
        decision = engine.evaluate(make_request(context={"destination": "external"}))
        assert decision.effect is Effect.DENY
        assert decision.determining_policy == "deny-external-pii"

    def test_priority_ordered_allows_a_break_glass_exception(self) -> None:
        break_glass = Policy(
            key="break-glass",
            name="Break glass",
            effect=Effect.ALLOW,
            priority=1000,
            match={"context.purpose": "break_glass"},
        )
        engine = PolicyEngine(
            [DENY_EXTERNAL, break_glass],
            algorithm=CombiningAlgorithm.PRIORITY_ORDERED,
        )
        decision = engine.evaluate(
            make_request(context={"destination": "external", "purpose": "break_glass"})
        )
        assert decision.effect is Effect.ALLOW
        assert decision.determining_policy == "break-glass"

    def test_default_effect_applies_when_nothing_matches(self) -> None:
        engine = PolicyEngine([], default_effect=Effect.DENY)
        decision = engine.evaluate(make_request())
        assert decision.effect is Effect.DENY
        assert "no policy matched" in decision.reason

    def test_disabled_policies_are_not_loaded(self) -> None:
        engine = PolicyEngine([ALLOW_READ.model_copy(update={"enabled": False})])
        assert len(engine) == 0

    def test_obligations_union_across_matching_allows(self) -> None:
        second = Policy(
            key="also-redact-secrets",
            name="Redact secrets",
            effect=Effect.ALLOW,
            priority=50,
            match={"principal.type": "agent"},
            obligations=[{"type": "redact", "labels": ["secret"], "strategy": "drop"}],
        )
        decision = PolicyEngine([ALLOW_READ, second]).evaluate(make_request())
        assert decision.effect is Effect.ALLOW
        assert len(decision.obligations) == 2

    def test_identical_obligations_are_deduplicated(self) -> None:
        twin = ALLOW_READ.model_copy(update={"key": "allow-agent-read-2", "priority": 50})
        decision = PolicyEngine([ALLOW_READ, twin]).evaluate(make_request())
        assert len(decision.obligations) == 1

    def test_deny_carries_no_obligations(self) -> None:
        decision = PolicyEngine([ALLOW_READ, DENY_EXTERNAL]).evaluate(
            make_request(context={"destination": "external"})
        )
        assert decision.effect is Effect.DENY
        assert decision.obligations == ()


class TestExplainability:
    def test_trace_names_the_failing_condition(self) -> None:
        decision = PolicyEngine([DENY_EXTERNAL]).evaluate(make_request(), explain=True)
        trace = next(t for t in decision.trace if t.key == "deny-external-pii")
        assert trace.matched is False
        assert "context.destination" in trace.reason

    def test_matched_policies_are_traced_even_without_explain(self) -> None:
        decision = PolicyEngine([ALLOW_READ]).evaluate(make_request(), explain=False)
        assert [t.key for t in decision.trace] == ["allow-agent-read"]

    def test_trace_truncates_long_values(self) -> None:
        request = make_request(context={"note": "x" * 5000})
        policy = Policy(
            key="p", name="p", effect="allow", match={"context.note": {"contains": "x"}}
        )
        decision = PolicyEngine([policy]).evaluate(request, explain=True)
        observed = decision.trace[0].conditions[0].observed
        assert len(str(observed)) < 300


class TestValidation:
    def test_unknown_operator_is_rejected_at_authoring_time(self) -> None:
        with pytest.raises(ValidationError, match="unknown operator"):
            Policy(key="p", name="p", effect="allow", match={"action": {"sorta_like": "read"}})

    def test_unknown_selector_root_is_rejected(self) -> None:
        with pytest.raises(ValidationError, match="must start with one of"):
            Policy(key="p", name="p", effect="allow", match={"whatever.field": "x"})

    def test_mixing_combinators_and_selectors_is_rejected(self) -> None:
        with pytest.raises(ValidationError, match="mixes combinators"):
            Policy(
                key="p",
                name="p",
                effect="allow",
                match={"all": [{"action": "read"}], "principal.type": "agent"},
            )

    def test_deny_with_obligations_is_rejected(self) -> None:
        with pytest.raises(ValidationError, match="cannot carry obligations"):
            Policy(
                key="p",
                name="p",
                effect="deny",
                match={},
                obligations=[{"type": "redact", "labels": ["pii"]}],
            )

    def test_redact_obligation_requires_known_labels(self) -> None:
        with pytest.raises(ValidationError, match="unknown labels"):
            Policy(
                key="p",
                name="p",
                effect="allow",
                match={},
                obligations=[{"type": "redact", "labels": ["pii.telepathy"]}],
            )

    def test_unknown_redaction_strategy_is_rejected(self) -> None:
        with pytest.raises(ValidationError, match="unknown redaction strategy"):
            Policy(
                key="p",
                name="p",
                effect="allow",
                match={},
                obligations=[{"type": "redact", "labels": ["pii"], "strategy": "obliterate"}],
            )

    def test_bad_regex_is_caught_at_authoring_time(self) -> None:
        with pytest.raises(ValidationError, match="invalid regex"):
            Policy(key="p", name="p", effect="allow", match={"action": {"regex": "([a-z"}})

    def test_unknown_classification_on_a_request_is_rejected(self) -> None:
        with pytest.raises(ValidationError, match="unknown classification"):
            Resource(urn="x://y", classifications=["not.a.label"])


class TestLabelSelectors:
    """The three label selectors mean different things and must stay distinct."""

    @staticmethod
    def _request(resource_labels: list[str], payload_labels: list[str]) -> AccessRequest:
        return AccessRequest(
            principal=Principal(id="agent:x", type="agent"),
            action="read",
            resource=Resource(urn="pg://t", classifications=resource_labels),
            findings=payload_labels,
        )

    @staticmethod
    def _matched(policy: Policy, request: AccessRequest) -> bool:
        """Whether the policy itself applied.

        Checked instead of the resulting effect: with deny-by-default, "denied"
        and "no rule matched" look identical from the outside, and here the
        distinction is the whole point.
        """
        return policy.key in PolicyEngine([policy]).evaluate(request).matched_policies

    def test_resource_classifications_exclude_payload_findings(self) -> None:
        """A credential pasted into a prompt must not reclassify the store."""
        policy = Policy(
            key="store-rule",
            name="Store rule",
            effect="deny",
            match={"resource.classifications": {"any_of": ["secret"]}},
        )
        request = self._request(resource_labels=[], payload_labels=["secret.aws_access_key"])
        assert self._matched(policy, request) is False

    def test_findings_exclude_catalog_labels(self) -> None:
        """A rule about content must not fire on a catalog label alone."""
        policy = Policy(
            key="content-rule",
            name="Content rule",
            effect="deny",
            match={"findings": {"any_of": ["pii.ssn"]}},
        )
        request = self._request(resource_labels=["pii.ssn"], payload_labels=[])
        assert self._matched(policy, request) is False

    def test_findings_fire_on_payload_content(self) -> None:
        policy = Policy(
            key="content-rule",
            name="Content rule",
            effect="deny",
            match={"findings": {"any_of": ["secret"]}},
        )
        request = self._request(resource_labels=[], payload_labels=["secret.aws_access_key"])
        assert self._matched(policy, request) is True

    def test_the_union_selector_covers_both(self) -> None:
        policy = Policy(
            key="either",
            name="Either",
            effect="deny",
            match={"classifications": {"any_of": ["pii.ssn"]}},
        )
        assert self._matched(policy, self._request(["pii.ssn"], [])) is True
        assert self._matched(policy, self._request([], ["pii.ssn"])) is True
        assert self._matched(policy, self._request([], [])) is False

    def test_empty_operator_detects_clean_payloads(self) -> None:
        policy = Policy(
            key="clean-only",
            name="Clean only",
            effect="allow",
            match={"findings": {"empty": True}},
        )
        assert self._matched(policy, self._request([], [])) is True
        assert self._matched(policy, self._request([], ["pii.email"])) is False
