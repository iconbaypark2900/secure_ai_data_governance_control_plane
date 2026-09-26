"""Managed agents adapter layer for secure_ai_data_governance_control_plane.

Wraps key components (PDP, Scanner, Redactor, AuditService, CatalogService,
PolicyStore) with:
- Top-N gate (5 calls max per instance)
- Timeout enforcement (120s default)
- LRU caching (AdapterCache)
- Budget-aware early termination
- Performance tracking
"""
from __future__ import annotations

import asyncio
import time
from collections.abc import AsyncIterator
from dataclasses import dataclass, field
from typing import Any

from control_plane.perf import (
    AdapterCache,
    CallMetrics,
    PerformanceReport,
    enforce_timeout,
    get_adapter_cache,
    get_perf_report,
    track_performance,
)

__all__ = [
    "TopNGate",
    "AdapterTimeout",
    "AdapterCacheMixin",
    "BudgetAwareAdapter",
    "PDPAdapter",
    "ScannerAdapter",
    "RedactorAdapter",
    "AuditServiceAdapter",
    "CatalogServiceAdapter",
    "PolicyStoreAdapter",
]


# --------------------------------------------------------------------------- #
# Top-N gate                                                                  #
# --------------------------------------------------------------------------- #
class TopNGate:
    """Limits the number of calls a component can make.

    After N calls, the gate is closed and subsequent calls are rejected
    with a `GateClosedError`.
    """

    def __init__(self, max_calls: int = 5):
        self.max_calls = max_calls
        self._calls = 0
        self._closed = False

    def acquire(self) -> bool:
        if self._closed:
            return False
        if self._calls >= self.max_calls:
            self._closed = True
            return False
        self._calls += 1
        return True

    @property
    def calls(self) -> int:
        return self._calls

    @property
    def closed(self) -> bool:
        return self._closed

    def reset(self):
        self._calls = 0
        self._closed = False


class GateClosedError(RuntimeError):
    """Raised when the Top-N gate is closed."""


# --------------------------------------------------------------------------- #
# Adapter timeout                                                             #
# --------------------------------------------------------------------------- #
class AdapterTimeout(Exception):
    """Raised when an adapter call exceeds the timeout."""


# --------------------------------------------------------------------------- #
# Adapter cache mixin                                                         #
# --------------------------------------------------------------------------- #
class AdapterCacheMixin:
    """Mixin that adds LRU caching to an adapter."""

    def __init__(self, cache_name: str, max_size: int = 1000):
        self._cache = get_adapter_cache(cache_name, max_size)

    def _cache_get(self, *args: Any, **kwargs: Any) -> Any | None:
        return self._cache.get(*args, **kwargs)

    def _cache_put(self, *args: Any, value: Any, **kwargs: Any):
        self._cache.put(*args, value=value, **kwargs)

    def _cache_key(self, *args: Any, **kwargs: Any) -> str:
        return self._cache._make_key(*args, **kwargs)


# --------------------------------------------------------------------------- #
# Budget-aware adapter                                                        #
# --------------------------------------------------------------------------- #
class BudgetAwareAdapter:
    """Adapter that respects budget constraints.

    Tracks cumulative cost and stops when the budget is exhausted.
    """

    def __init__(self, budget_limit: float | None = None):
        self.budget_limit = budget_limit
        self._spent: float = 0.0

    @property
    def spent(self) -> float:
        return self._spent

    @property
    def remaining(self) -> float | None:
        if self.budget_limit is None:
            return None
        return max(0.0, self.budget_limit - self._spent)

    def charge(self, cost: float) -> bool:
        """Charge cost to the budget. Returns False if over budget."""
        if self.budget_limit is not None and self._spent + cost > self.budget_limit:
            return False
        self._spent += cost
        return True

    def reset(self):
        self._spent = 0.0


# --------------------------------------------------------------------------- #
# PDP Adapter                                                                   #
# --------------------------------------------------------------------------- #
class PDPAdapter(BudgetAwareAdapter):
    """Adapter wrapping the Policy Decision Point.

    Limits PDP calls to 5 per instance, enforces 120s timeout, caches
    decisions keyed on (principal, resource, action, payload_hash).
    """

    def __init__(self, pdp, budget_limit: float | None = None):
        super().__init__(budget_limit)
        self._pdp = pdp
        self._gate = TopNGate(max_calls=5)
        self._timeout = 120.0
        self._cache = AdapterCache(max_size=100)

    async def decide(self, request: Any, **kwargs: Any) -> Any:
        """Run a decision through the PDP with adapter constraints."""
        if not self._gate.acquire():
            raise GateClosedError(
                f"PDP calls exhausted (max {self._gate.max_calls}). "
                "Create a new PDPAdapter instance to reset."
            )

        if not self.charge(1.0):
            raise GateClosedError("Budget exhausted")

        cache_key = self._cache._make_key(
            principal=request.principal,
            resource=request.resource,
            action=request.action,
            payload_hash=getattr(request, "payload_hash", ""),
        )

        cached = self._cache.get(cache_key)
        if cached is not None:
            return cached

        try:
            with track_performance("pdp") as tracker:
                result = await asyncio.wait_for(
                    self._pdp.decide(request, **kwargs),
                    timeout=self._timeout,
                )
                self._cache.put(cache_key, value=result)
                return result
        except asyncio.TimeoutError:
            raise AdapterTimeout(f"PDP decision exceeded {self._timeout}s timeout")

    @property
    def calls(self) -> int:
        return self._gate.calls

    def reset(self):
        self._gate.reset()
        self._cache.clear()
        self.reset_budget()

    def reset_budget(self):
        self._spent = 0.0


# --------------------------------------------------------------------------- #
# Scanner Adapter                                                             #
# --------------------------------------------------------------------------- #
class ScannerAdapter(BudgetAwareAdapter):
    """Adapter wrapping the classification Scanner.

    Caches scan results keyed on payload hash. Limits to 5 calls per instance.
    """

    def __init__(self, scanner, budget_limit: float | None = None):
        super().__init__(budget_limit)
        self._scanner = scanner
        self._gate = TopNGate(max_calls=5)
        self._timeout = 60.0
        self._cache = AdapterCache(max_size=500)

    async def scan(self, payload: Any, **kwargs: Any) -> Any:
        """Scan a payload with adapter constraints."""
        if not self._gate.acquire():
            raise GateClosedError(
                f"Scanner calls exhausted (max {self._gate.max_calls})."
            )

        if not self.charge(0.5):
            raise GateClosedError("Budget exhausted")

        payload_hash = self._cache._make_key(payload)
        cached = self._cache.get(payload_hash)
        if cached is not None:
            return cached

        try:
            with track_performance("scanner") as tracker:
                result = await asyncio.wait_for(
                    self._scanner.scan(payload, **kwargs),
                    timeout=self._timeout,
                )
                self._cache.put(payload_hash, value=result)
                return result
        except asyncio.TimeoutError:
            raise AdapterTimeout(f"Scanner exceeded {self._timeout}s timeout")

    @property
    def calls(self) -> int:
        return self._gate.calls

    def reset(self):
        self._gate.reset()
        self._cache.clear()
        self._spent = 0.0


# --------------------------------------------------------------------------- #
# Redactor Adapter                                                            #
# --------------------------------------------------------------------------- #
class RedactorAdapter(BudgetAwareAdapter):
    """Adapter wrapping the Redactor.

    Caches redaction results keyed on (payload_hash, strategy).
    """

    def __init__(self, redactor, budget_limit: float | None = None):
        super().__init__(budget_limit)
        self._redactor = redactor
        self._gate = TopNGate(max_calls=5)
        self._timeout = 60.0
        self._cache = AdapterCache(max_size=500)

    async def redact(self, payload: Any, findings: Any, strategy: str = "mask", **kwargs: Any) -> Any:
        """Redact a payload with adapter constraints."""
        if not self._gate.acquire():
            raise GateClosedError(
                f"Redactor calls exhausted (max {self._gate.max_calls})."
            )

        if not self.charge(0.3):
            raise GateClosedError("Budget exhausted")

        cache_key = self._cache._make_key(payload, strategy)
        cached = self._cache.get(cache_key)
        if cached is not None:
            return cached

        try:
            with track_performance("redactor") as tracker:
                result = await asyncio.wait_for(
                    self._redactor.redact(payload, findings, strategy=strategy, **kwargs),
                    timeout=self._timeout,
                )
                self._cache.put(cache_key, value=result)
                return result
        except asyncio.TimeoutError:
            raise AdapterTimeout(f"Redactor exceeded {self._timeout}s timeout")

    @property
    def calls(self) -> int:
        return self._gate.calls

    def reset(self):
        self._gate.reset()
        self._cache.clear()
        self._spent = 0.0


# --------------------------------------------------------------------------- #
# Audit Service Adapter                                                       #
# --------------------------------------------------------------------------- #
class AuditServiceAdapter(BudgetAwareAdapter):
    """Adapter wrapping the AuditService.

    Enforces timeout on audit writes. No caching (audit must be persisted).
    """

    def __init__(self, audit_service, budget_limit: float | None = None):
        super().__init__(budget_limit)
        self._audit_service = audit_service
        self._timeout = 30.0

    async def append(self, event: Any, **kwargs: Any) -> Any:
        """Append an audit event with adapter constraints."""
        if not self.charge(0.1):
            raise GateClosedError("Budget exhausted")

        try:
            with track_performance("audit") as tracker:
                result = await asyncio.wait_for(
                    self._audit_service.append(event, **kwargs),
                    timeout=self._timeout,
                )
                return result
        except asyncio.TimeoutError:
            raise AdapterTimeout(f"Audit append exceeded {self._timeout}s timeout")

    def reset(self):
        self._spent = 0.0


# --------------------------------------------------------------------------- #
# Catalog Service Adapter                                                     #
# --------------------------------------------------------------------------- #
class CatalogServiceAdapter(BudgetAwareAdapter):
    """Adapter wrapping the CatalogService.

    Caches resolved assets keyed on URN.
    """

    def __init__(self, catalog_service, budget_limit: float | None = None):
        super().__init__(budget_limit)
        self._catalog = catalog_service
        self._gate = TopNGate(max_calls=5)
        self._timeout = 30.0
        self._cache = AdapterCache(max_size=1000)

    async def resolve_asset(self, urn: str, **kwargs: Any) -> Any:
        """Resolve an asset with adapter constraints."""
        if not self._gate.acquire():
            raise GateClosedError(
                f"Catalog calls exhausted (max {self._gate.max_calls})."
            )

        if not self.charge(0.2):
            raise GateClosedError("Budget exhausted")

        cached = self._cache.get(urn)
        if cached is not None:
            return cached

        try:
            with track_performance("catalog") as tracker:
                result = await asyncio.wait_for(
                    self._catalog.resolve_asset(urn, **kwargs),
                    timeout=self._timeout,
                )
                self._cache.put(urn, value=result)
                return result
        except asyncio.TimeoutError:
            raise AdapterTimeout(f"Catalog resolve exceeded {self._timeout}s timeout")

    @property
    def calls(self) -> int:
        return self._gate.calls

    def reset(self):
        self._gate.reset()
        self._cache.clear()
        self._spent = 0.0


# --------------------------------------------------------------------------- #
# Policy Store Adapter                                                        #
# --------------------------------------------------------------------------- #
class PolicyStoreAdapter(BudgetAwareAdapter):
    """Adapter wrapping the PolicyStore.

    Caches compiled engines. Enforces timeout on writes.
    """

    def __init__(self, policy_store, budget_limit: float | None = None):
        super().__init__(budget_limit)
        self._store = policy_store
        self._gate = TopNGate(max_calls=5)
        self._timeout = 30.0
        self._cache = AdapterCache(max_size=10)

    async def get_engine(self, **kwargs: Any) -> Any:
        """Get the compiled policy engine with adapter constraints."""
        if not self._gate.acquire():
            raise GateClosedError(
                f"PolicyStore calls exhausted (max {self._gate.max_calls})."
            )

        if not self.charge(0.1):
            raise GateClosedError("Budget exhausted")

        cached = self._cache.get("engine")
        if cached is not None:
            return cached

        try:
            with track_performance("policy_store") as tracker:
                result = await asyncio.wait_for(
                    self._store.get_engine(**kwargs),
                    timeout=self._timeout,
                )
                self._cache.put("engine", value=result)
                return result
        except asyncio.TimeoutError:
            raise AdapterTimeout(f"PolicyStore get_engine exceeded {self._timeout}s timeout")

    async def write_policy(self, policy: Any, **kwargs: Any) -> Any:
        """Write a policy with adapter constraints."""
        if not self._gate.acquire():
            raise GateClosedError(
                f"PolicyStore calls exhausted (max {self._gate.max_calls})."
            )

        if not self.charge(0.5):
            raise GateClosedError("Budget exhausted")

        try:
            with track_performance("policy_store_write") as tracker:
                result = await asyncio.wait_for(
                    self._store.write_policy(policy, **kwargs),
                    timeout=self._timeout,
                )
                self._cache.clear()  # Invalidate cache on write
                return result
        except asyncio.TimeoutError:
            raise AdapterTimeout(f"PolicyStore write exceeded {self._timeout}s timeout")

    @property
    def calls(self) -> int:
        return self._gate.calls

    def reset(self):
        self._gate.reset()
        self._cache.clear()
        self._spent = 0.0
