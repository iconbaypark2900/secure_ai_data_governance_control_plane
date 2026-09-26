"""Performance utilities for secure_ai_data_governance_control_plane.

This module provides:
- Adapter-level caching (memoize decisions, classifications, redactions)
- Batch processing for multiple decisions
- Timeout enforcement for all adapters
- Budget-aware early termination
- Performance metrics tracking (time per call, memory usage)
"""
from __future__ import annotations

import functools
import hashlib
import json
import os
import resource
import signal
import time
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Any, Callable


# --------------------------------------------------------------------------- #
# Performance metrics                                                         #
# --------------------------------------------------------------------------- #
@dataclass
class CallMetrics:
    """Metrics for a single adapter call."""
    service: str = ""
    call_id: str = ""
    start_time: float = 0.0
    end_time: float = 0.0
    duration_ms: float = 0.0
    memory_mb: float = 0.0
    budget_tier: int = 0
    budget_spent: float = 0.0
    success: bool = True
    error: str = ""


@dataclass
class PerformanceReport:
    """Aggregated performance report for a run."""
    total_calls: int = 0
    total_duration_ms: float = 0.0
    max_duration_ms: float = 0.0
    total_memory_mb: float = 0.0
    calls_by_service: dict[str, int] = field(default_factory=lambda: defaultdict(int))
    calls_by_tier: dict[int, int] = field(default_factory=lambda: defaultdict(int))
    errors: list[dict[str, Any]] = field(default_factory=list)
    top_slow_calls: list[dict[str, Any]] = field(default_factory=list)

    @property
    def avg_duration_ms(self) -> float:
        if self.total_calls == 0:
            return 0.0
        return self.total_duration_ms / self.total_calls

    @property
    def avg_memory_mb(self) -> float:
        if self.total_calls == 0:
            return 0.0
        return self.total_memory_mb / self.total_calls

    def add_call(self, metrics: CallMetrics):
        self.total_calls += 1
        self.total_duration_ms += metrics.duration_ms
        self.total_memory_mb += metrics.memory_mb
        self.calls_by_service[metrics.service] += 1
        self.calls_by_tier[metrics.budget_tier] += 1

        if metrics.duration_ms > self.max_duration_ms:
            self.max_duration_ms = metrics.duration_ms

        if not metrics.success:
            self.errors.append({
                "service": metrics.service,
                "error": metrics.error,
                "duration_ms": metrics.duration_ms,
            })

    def summary(self) -> dict[str, Any]:
        avg_duration = self.total_duration_ms / self.total_calls if self.total_calls > 0 else 0
        avg_memory = self.total_memory_mb / self.total_calls if self.total_calls > 0 else 0
        return {
            "total_calls": self.total_calls,
            "total_duration_ms": round(self.total_duration_ms, 2),
            "avg_duration_ms": round(avg_duration, 2),
            "max_duration_ms": round(self.max_duration_ms, 2),
            "total_memory_mb": round(self.total_memory_mb, 2),
            "avg_memory_mb": round(avg_memory, 2),
            "calls_by_service": dict(self.calls_by_service),
            "calls_by_tier": dict(self.calls_by_tier),
            "errors": self.errors,
        }


# Global performance tracker
_perf_report: PerformanceReport | None = None


def get_perf_report() -> PerformanceReport:
    global _perf_report
    if _perf_report is None:
        _perf_report = PerformanceReport()
    return _perf_report


def reset_perf_report():
    global _perf_report
    _perf_report = None


# --------------------------------------------------------------------------- #
# Caching                                                                     #
# --------------------------------------------------------------------------- #
class AdapterCache:
    """LRU cache for adapter operations (decisions, classifications, redactions).

    Keys are computed from the input data. Values are the adapter's output.
    """

    def __init__(self, max_size: int = 1000):
        self.max_size = max_size
        self._cache: dict[str, Any] = {}
        self._order: list[str] = []

    def _make_key(self, *args: Any, **kwargs: Any) -> str:
        key_data = json.dumps({"args": args, "kwargs": kwargs}, sort_keys=True, default=str)
        return hashlib.sha256(key_data.encode()).hexdigest()[:32]

    def get(self, *args: Any, **kwargs: Any) -> Any | None:
        key = self._make_key(*args, **kwargs)
        if key in self._cache:
            self._order.remove(key)
            self._order.append(key)
            return self._cache[key]
        return None

    def put(self, *args: Any, value: Any, **kwargs: Any):
        key = self._make_key(*args, **kwargs)
        if key in self._cache:
            self._order.remove(key)
        else:
            if len(self._cache) >= self.max_size:
                lru_key = self._order.pop(0)
                del self._cache[lru_key]
        self._cache[key] = value
        self._order.append(key)

    def clear(self):
        self._cache.clear()
        self._order.clear()

    def __len__(self) -> int:
        return len(self._cache)


# Global adapter caches
_adapter_caches: dict[str, AdapterCache] = {}


def get_adapter_cache(adapter_name: str, max_size: int = 1000) -> AdapterCache:
    if adapter_name not in _adapter_caches:
        _adapter_caches[adapter_name] = AdapterCache(max_size)
    return _adapter_caches[adapter_name]


def clear_adapter_caches():
    for cache in _adapter_caches.values():
        cache.clear()


# --------------------------------------------------------------------------- #
# Batch processing                                                            #
# --------------------------------------------------------------------------- #
def batch_items(items: list[Any], batch_size: int = 10) -> list[list[Any]]:
    """Split a list of items into batches."""
    return [items[i:i + batch_size] for i in range(0, len(items), batch_size)]


def process_batch(
    batch: list[Any],
    process_fn: Callable[[Any], Any],
    **kwargs: Any,
) -> list[Any]:
    """Process a batch of items."""
    return [process_fn(c, **kwargs) for c in batch]


# --------------------------------------------------------------------------- #
# Timeout enforcement                                                         #
# --------------------------------------------------------------------------- #
def enforce_timeout(timeout: float | None = None) -> Callable:
    """Decorator to enforce a timeout on a function call.

    Args:
        timeout: Timeout in seconds (None = no timeout).

    Returns:
        Decorator function.
    """
    def decorator(func: Callable) -> Callable:
        if timeout is None or timeout <= 0:
            return func

        def _handler(signum, frame):
            raise TimeoutError(f"Function {func.__name__} exceeded timeout of {timeout}s")

        @functools.wraps(func)
        def wrapper(*args, **kwargs):
            prev_handler = signal.getsignal(signal.SIGALRM)
            try:
                signal.signal(signal.SIGALRM, _handler)
                signal.alarm(int(timeout))
                try:
                    return func(*args, **kwargs)
                finally:
                    signal.alarm(0)
            except TimeoutError:
                raise
            except Exception:
                raise
            finally:
                signal.signal(signal.SIGALRM, prev_handler)

        return wrapper

    return decorator


# --------------------------------------------------------------------------- #
# Budget-aware early termination                                              #
# --------------------------------------------------------------------------- #
def should_terminate(
    budget_remaining: float | None,
    estimated_cost: float,
) -> bool:
    """Check if we should terminate early due to budget exhaustion.

    Args:
        budget_remaining: Remaining budget (None = unlimited).
        estimated_cost: Estimated cost for the next call.

    Returns:
        True if we should terminate early.
    """
    if budget_remaining is None:
        return False
    return budget_remaining < estimated_cost


# --------------------------------------------------------------------------- #
# Performance tracking context manager                                        #
# --------------------------------------------------------------------------- #
class PerformanceTracker:
    """Context manager for tracking adapter call performance."""

    def __init__(self, service: str, call_id: str = ""):
        self.service = service
        self.call_id = call_id or f"call-{time.time_ns()}"
        self.metrics = CallMetrics(
            service=service,
            call_id=self.call_id,
            start_time=time.time(),
        )

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.metrics.end_time = time.time()
        self.metrics.duration_ms = (self.metrics.end_time - self.metrics.start_time) * 1000

        try:
            usage = resource.getrusage(resource.RUSAGE_SELF)
            self.metrics.memory_mb = usage.ru_maxrss / 1024
        except Exception:
            self.metrics.memory_mb = 0.0

        if exc_type is not None:
            self.metrics.success = False
            self.metrics.error = f"{exc_type.__name__}: {exc_val}"

        get_perf_report().add_call(self.metrics)
        return False


def track_performance(service: str, call_id: str = "") -> PerformanceTracker:
    return PerformanceTracker(service=service, call_id=call_id)
