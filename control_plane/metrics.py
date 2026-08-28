"""Prometheus metrics.

``prometheus-client`` was a declared dependency with no uses and no endpoint --
a promise in the manifest that nothing behind it kept. This is the other half.

Label cardinality is deliberately bounded. ``effect`` has three values and
``label`` is drawn from a fixed 33-entry taxonomy, so a scrape cannot grow
without bound however much traffic arrives. Notably absent is a per-policy
label: policy keys are operator-defined, and a metric whose cardinality is
controlled by whoever writes policies is a way to run a monitoring system out of
memory. Per-policy counts are available from ``/v1/decisions/stats``, which is
paginated and authenticated.

Nothing here is on the decision path in any meaningful sense -- counter
increments are cheap -- but the module degrades to no-ops rather than raising if
metrics are disabled, so instrumentation calls never need guarding at the call
site.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from typing import Any

from prometheus_client import CollectorRegistry, Counter, Gauge, Histogram, generate_latest
from prometheus_client.core import CollectorRegistry as _Registry

__all__ = ["CONTENT_TYPE", "Metrics", "get_metrics", "reset_metrics"]

CONTENT_TYPE = "text/plain; version=0.0.4; charset=utf-8"

#: Buckets chosen around the observed shape of a decision: a few milliseconds
#: when the policy set is cached, tens when it is not, and a long tail worth
#: seeing rather than lumping into +Inf.
DURATION_BUCKETS = (0.001, 0.0025, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5)


class Metrics:
    """The metric family, bound to one registry."""

    def __init__(self, registry: _Registry | None = None) -> None:
        self.registry = registry or CollectorRegistry()

        self.decisions = Counter(
            "control_plane_decisions_total",
            "Decisions made, by effect.",
            ["effect"],
            registry=self.registry,
        )
        self.duration = Histogram(
            "control_plane_decision_duration_seconds",
            "End-to-end decision latency, including classification and persistence.",
            buckets=DURATION_BUCKETS,
            registry=self.registry,
        )
        self.findings = Counter(
            "control_plane_findings_total",
            "Sensitive values detected in payloads, by label.",
            ["label"],
            registry=self.registry,
        )
        self.redactions = Counter(
            "control_plane_redactions_total",
            "Values rewritten before delivery, by strategy.",
            ["strategy"],
            registry=self.registry,
        )
        self.policy_errors = Gauge(
            "control_plane_policy_load_errors",
            "Stored policies that failed to load. Any non-zero value means a "
            "control is silently absent.",
            registry=self.registry,
        )
        self.policies_loaded = Gauge(
            "control_plane_policies_loaded",
            "Enabled policies in the compiled engine.",
            registry=self.registry,
        )

    def observe_decision(
        self,
        *,
        effect: str,
        duration_seconds: float,
        finding_labels: Iterable[str] = (),
        redactions: Iterable[Mapping[str, Any]] = (),
    ) -> None:
        """Record one decision."""
        self.decisions.labels(effect=effect).inc()
        self.duration.observe(max(0.0, duration_seconds))
        for label in finding_labels:
            self.findings.labels(label=label).inc()
        for redaction in redactions:
            self.redactions.labels(strategy=str(redaction.get("strategy", "unknown"))).inc()

    def observe_policy_set(self, *, loaded: int, errors: int) -> None:
        self.policies_loaded.set(loaded)
        self.policy_errors.set(errors)

    def render(self) -> bytes:
        return generate_latest(self.registry)


_metrics: Metrics | None = None


def get_metrics() -> Metrics:
    """The process-wide metric family."""
    global _metrics
    if _metrics is None:
        _metrics = Metrics()
    return _metrics


def reset_metrics() -> None:
    """Drop the registry. For tests, which must not accumulate across cases."""
    global _metrics
    _metrics = None
