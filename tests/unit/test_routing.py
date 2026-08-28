"""Choosing where a permitted request may go.

Routing is the "yes, but" at the infrastructure layer: without it, a policy's
only answer to sensitive-data-meets-wrong-model is refusal, and a control people
route around is worse than no control.
"""

from __future__ import annotations

import pytest

from control_plane.routing import ModelCandidate, ModelRouter, RoutingUnsatisfiable

US_SAAS = ModelCandidate(
    "model://openai/gpt-4o",
    "gpt-4o",
    {"region": "us", "hosting": "saas", "aliases": ["fast-llm"], "routing_priority": 5},
)
EU_ONPREM = ModelCandidate(
    "model://internal/llama-3-70b",
    "llama-3-70b",
    {"region": "eu", "hosting": "on_prem", "aliases": ["eu-only-llm"], "routing_priority": 10},
)
EU_VPC = ModelCandidate(
    "model://azure/gpt-4o-eu",
    "gpt-4o-eu",
    {"region": "eu", "hosting": "vpc", "aliases": ["eu-only-llm"], "routing_priority": 20},
)
RETIRED = ModelCandidate(
    "model://legacy/ancient", "ancient", {"region": "eu", "routing_enabled": False}
)
UNDECLARED = ModelCandidate("model://mystery/unknown", "unknown", {})


@pytest.fixture
def router() -> ModelRouter:
    return ModelRouter([US_SAAS, EU_ONPREM, EU_VPC, RETIRED, UNDECLARED])


def route(**fields) -> list[dict]:
    return [{"type": "route", **fields}]


class TestNoOpinion:
    def test_no_route_obligation_means_no_routing(self, router) -> None:
        assert router.resolve([{"type": "redact", "labels": ["pii"]}]) is None

    def test_no_obligations_at_all(self, router) -> None:
        assert router.resolve([]) is None


class TestConstraints:
    def test_it_redirects_away_from_a_disallowed_region(self, router) -> None:
        decision = router.resolve(route(require={"region": "eu"}), original="model://openai/gpt-4o")
        assert decision.target in {EU_ONPREM.urn, EU_VPC.urn}
        assert decision.redirected is True

    def test_it_prefers_the_lower_routing_priority(self, router) -> None:
        decision = router.resolve(route(require={"region": "eu"}))
        assert decision.target == EU_ONPREM.urn

    def test_it_keeps_a_model_that_already_qualifies(self, router) -> None:
        """A route obligation is a constraint, not an instruction to move."""
        decision = router.resolve(
            route(require={"region": "eu"}), original="model://azure/gpt-4o-eu"
        )
        assert decision.target == EU_VPC.urn
        assert decision.redirected is False
        assert "kept" in decision.reason

    def test_several_attributes_must_all_hold(self, router) -> None:
        decision = router.resolve(route(require={"region": "eu", "hosting": "vpc"}))
        assert decision.target == EU_VPC.urn

    def test_a_list_of_acceptable_values(self, router) -> None:
        decision = router.resolve(route(require={"hosting": ["on_prem", "vpc"]}))
        assert decision.target == EU_ONPREM.urn

    def test_a_model_that_declares_nothing_never_qualifies(self, router) -> None:
        """Silence about where a model runs is not a claim that it runs anywhere."""
        decision = router.resolve(route(require={"region": "eu"}))
        assert UNDECLARED.urn in decision.rejected
        assert "declares no 'region'" in decision.rejected[UNDECLARED.urn]

    def test_a_disabled_model_is_never_chosen(self, router) -> None:
        decision = router.resolve(route(require={"region": "eu", "hosting": "on_prem"}))
        assert decision.target != RETIRED.urn
        assert "disabled" in decision.rejected[RETIRED.urn]


class TestNamedTargets:
    def test_a_logical_name_resolves_through_an_alias(self, router) -> None:
        decision = router.resolve(route(to="eu-only-llm"))
        assert decision.target == EU_ONPREM.urn
        assert decision.requested == "eu-only-llm"

    def test_a_urn_works_as_a_name(self, router) -> None:
        assert router.resolve(route(to="model://azure/gpt-4o-eu")).target == EU_VPC.urn

    def test_a_name_and_a_constraint_together(self, router) -> None:
        decision = router.resolve(route(to="eu-only-llm", require={"hosting": "vpc"}))
        assert decision.target == EU_VPC.urn

    def test_an_unknown_name_satisfies_nothing(self, router) -> None:
        decision = router.resolve(route(to="does-not-exist"))
        assert decision.satisfied is False
        assert "does-not-exist" in decision.reason


class TestSeveralPolicies:
    def test_requirements_intersect_rather_than_race(self, router) -> None:
        """Two policies each narrowing where data may go must both hold."""
        decision = router.resolve(
            [
                {"type": "route", "require": {"region": ["eu", "us"]}},
                {"type": "route", "require": {"region": "eu", "hosting": "on_prem"}},
            ]
        )
        assert decision.target == EU_ONPREM.urn

    def test_disjoint_requirements_satisfy_nothing(self, router) -> None:
        decision = router.resolve(
            [
                {"type": "route", "require": {"region": "eu"}},
                {"type": "route", "require": {"region": "us"}},
            ]
        )
        assert decision.satisfied is False

    def test_conflicting_named_targets_are_an_error(self, router) -> None:
        """Silently preferring one policy's answer would be the worse failure."""
        with pytest.raises(RoutingUnsatisfiable, match="different routing targets"):
            router.resolve(
                [
                    {"type": "route", "to": "eu-only-llm"},
                    {"type": "route", "to": "fast-llm"},
                ]
            )


class TestExplainability:
    def test_it_says_why_each_candidate_lost(self, router) -> None:
        """'Why did my request go there?' is asked far more than it is answerable."""
        decision = router.resolve(route(require={"region": "eu"}))
        assert set(decision.considered) == {
            US_SAAS.urn,
            EU_ONPREM.urn,
            EU_VPC.urn,
            RETIRED.urn,
            UNDECLARED.urn,
        }
        assert "region is 'us'" in decision.rejected[US_SAAS.urn]

    def test_an_unsatisfiable_route_explains_itself(self, router) -> None:
        decision = router.resolve(route(require={"region": "apac"}))
        assert decision.satisfied is False
        assert "no registered model satisfies" in decision.reason
        assert len(decision.rejected) == 5

    def test_the_decision_serialises(self, router) -> None:
        body = router.resolve(route(require={"region": "eu"})).to_dict()
        assert body["target"] == EU_ONPREM.urn
        assert body["redirected"] is True


class TestEmptyRegistry:
    def test_routing_with_nothing_registered_fails_closed(self) -> None:
        decision = ModelRouter([]).resolve(route(require={"region": "eu"}))
        assert decision.satisfied is False
        assert decision.considered == ()
