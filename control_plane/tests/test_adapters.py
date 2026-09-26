"""Tests for the managed agents adapter layer.

Verifies:
- TopNGate enforcement (5 calls max)
- Timeout enforcement
- LRU caching
- Budget-aware termination
- Performance tracking
"""
import asyncio
import time
from unittest.mock import AsyncMock, MagicMock

import pytest

from control_plane.managed_adapters import (
    AdapterCacheMixin,
    AdapterTimeout,
    BudgetAwareAdapter,
    GateClosedError,
    PDPAdapter,
    RedactorAdapter,
    ScannerAdapter,
    TopNGate,
)
from control_plane.perf import (
    AdapterCache,
    CallMetrics,
    PerformanceReport,
    batch_items,
    clear_adapter_caches,
    enforce_timeout,
    get_adapter_cache,
    get_perf_report,
    process_batch,
    reset_perf_report,
    track_performance,
)


# --------------------------------------------------------------------------- #
# TopNGate tests                                                              #
# --------------------------------------------------------------------------- #
class TestTopNGate:
    def test_acquires_up_to_limit(self):
        gate = TopNGate(max_calls=3)
        assert gate.acquire() is True
        assert gate.acquire() is True
        assert gate.acquire() is True
        assert gate.calls == 3

    def test_rejects_after_limit(self):
        gate = TopNGate(max_calls=2)
        assert gate.acquire() is True
        assert gate.acquire() is True
        assert gate.acquire() is False
        assert gate.closed is True

    def test_reset(self):
        gate = TopNGate(max_calls=2)
        gate.acquire()
        gate.acquire()
        gate.reset()
        assert gate.calls == 0
        assert gate.closed is False
        assert gate.acquire() is True


# --------------------------------------------------------------------------- #
# AdapterCache tests                                                          #
# --------------------------------------------------------------------------- #
class TestAdapterCache:
    def test_put_and_get(self):
        cache = AdapterCache(max_size=10)
        cache.put("key1", value="value1")
        assert cache.get("key1") == "value1"

    def test_miss_returns_none(self):
        cache = AdapterCache(max_size=10)
        assert cache.get("nonexistent") is None

    def test_evicts_lru(self):
        cache = AdapterCache(max_size=2)
        cache.put("a", value="a")
        cache.put("b", value="b")
        cache.put("c", value="c")  # Should evict "a"
        assert cache.get("a") is None
        assert cache.get("b") == "b"
        assert cache.get("c") == "c"

    def test_update_existing(self):
        cache = AdapterCache(max_size=10)
        cache.put("key", value="old")
        cache.put("key", value="new")
        assert cache.get("key") == "new"
        assert len(cache) == 1

    def test_clear(self):
        cache = AdapterCache(max_size=10)
        cache.put("a", value="a")
        cache.put("b", value="b")
        cache.clear()
        assert len(cache) == 0
        assert cache.get("a") is None


# --------------------------------------------------------------------------- #
# BudgetAwareAdapter tests                                                    #
# --------------------------------------------------------------------------- #
class TestBudgetAwareAdapter:
    def test_charge_within_budget(self):
        adapter = BudgetAwareAdapter(budget_limit=10.0)
        assert adapter.charge(3.0) is True
        assert adapter.spent == 3.0
        assert adapter.remaining == 7.0

    def test_charge_exceeds_budget(self):
        adapter = BudgetAwareAdapter(budget_limit=5.0)
        assert adapter.charge(3.0) is True
        assert adapter.charge(3.0) is False
        assert adapter.spent == 3.0

    def test_unlimited_budget(self):
        adapter = BudgetAwareAdapter(budget_limit=None)
        assert adapter.charge(100.0) is True
        assert adapter.remaining is None

    def test_reset(self):
        adapter = BudgetAwareAdapter(budget_limit=10.0)
        adapter.charge(5.0)
        adapter.reset()
        assert adapter.spent == 0.0
        assert adapter.remaining == 10.0


# --------------------------------------------------------------------------- #
# PDPAdapter tests                                                            #
# --------------------------------------------------------------------------- #
class TestPDPAdapter:
    @pytest.fixture
    def mock_pdp(self):
        pdp = AsyncMock()
        pdp.decide = AsyncMock(return_value={"decision": "allow"})
        return pdp

    def test_gate_limits_calls(self, mock_pdp):
        adapter = PDPAdapter(mock_pdp, budget_limit=100.0)
        request = MagicMock()
        request.principal = "user1"
        request.resource = "resource1"
        request.action = "read"
        request.payload_hash = "abc123"

        # First 5 calls should succeed
        for i in range(5):
            result = asyncio.run(adapter.decide(request))
            assert result == {"decision": "allow"}

        # 6th call should raise GateClosedError
        with pytest.raises(GateClosedError):
            asyncio.run(adapter.decide(request))

    def test_timeout_enforcement(self, mock_pdp):
        """Test that timeout is enforced (120s default).

        Note: We can't easily test actual timeout with a 120s timeout,
        so we verify the timeout attribute is set correctly.
        """
        adapter = PDPAdapter(mock_pdp, budget_limit=100.0)
        assert adapter._timeout == 120.0

    def test_caching(self, mock_pdp):
        mock_pdp.decide = AsyncMock(return_value={"decision": "allow"})
        adapter = PDPAdapter(mock_pdp, budget_limit=100.0)

        request = MagicMock()
        request.principal = "user1"
        request.resource = "resource1"
        request.action = "read"
        request.payload_hash = "abc123"

        # First call should hit the PDP
        result1 = asyncio.run(adapter.decide(request))
        assert mock_pdp.decide.call_count == 1

        # Second call with same args should use cache
        result2 = asyncio.run(adapter.decide(request))
        assert mock_pdp.decide.call_count == 1  # Still 1
        assert result1 == result2

    def test_budget_exhaustion(self, mock_pdp):
        adapter = PDPAdapter(mock_pdp, budget_limit=1.0)
        request = MagicMock()
        request.principal = "user1"
        request.resource = "resource1"
        request.action = "read"
        request.payload_hash = "abc123"

        # First call charges 1.0, exhausting budget
        asyncio.run(adapter.decide(request))
        assert adapter.spent == 1.0

        # Second call should fail due to budget
        with pytest.raises(GateClosedError, match="Budget exhausted"):
            asyncio.run(adapter.decide(request))

    def test_reset(self, mock_pdp):
        adapter = PDPAdapter(mock_pdp, budget_limit=100.0)
        request = MagicMock()
        request.principal = "user1"
        request.resource = "resource1"
        request.action = "read"
        request.payload_hash = "abc123"

        # Exhaust the gate
        for _ in range(5):
            asyncio.run(adapter.decide(request))

        # Reset
        adapter.reset()
        assert adapter.calls == 0
        assert adapter.spent == 0.0

        # Should work again
        result = asyncio.run(adapter.decide(request))
        assert result == {"decision": "allow"}


# --------------------------------------------------------------------------- #
# ScannerAdapter tests                                                        #
# --------------------------------------------------------------------------- #
class TestScannerAdapter:
    @pytest.fixture
    def mock_scanner(self):
        scanner = AsyncMock()
        scanner.scan = AsyncMock(return_value={"findings": []})
        return scanner

    def test_gate_limits_calls(self, mock_scanner):
        adapter = ScannerAdapter(mock_scanner, budget_limit=100.0)

        for i in range(5):
            result = asyncio.run(adapter.scan("test payload"))
            assert result == {"findings": []}

        with pytest.raises(GateClosedError):
            asyncio.run(adapter.scan("test payload"))

    def test_caching(self, mock_scanner):
        adapter = ScannerAdapter(mock_scanner, budget_limit=100.0)

        # First call
        result1 = asyncio.run(adapter.scan("test payload"))
        assert mock_scanner.scan.call_count == 1

        # Second call with same payload should use cache
        result2 = asyncio.run(adapter.scan("test payload"))
        assert mock_scanner.scan.call_count == 1
        assert result1 == result2


# --------------------------------------------------------------------------- #
# RedactorAdapter tests                                                       #
# --------------------------------------------------------------------------- #
class TestRedactorAdapter:
    @pytest.fixture
    def mock_redactor(self):
        redactor = AsyncMock()
        redactor.redact = AsyncMock(return_value={"redacted": "safe"})
        return redactor

    def test_gate_limits_calls(self, mock_redactor):
        adapter = RedactorAdapter(mock_redactor, budget_limit=100.0)

        for i in range(5):
            result = asyncio.run(adapter.redact("payload", "findings"))
            assert result == {"redacted": "safe"}

        with pytest.raises(GateClosedError):
            asyncio.run(adapter.redact("payload", "findings"))

    def test_caching(self, mock_redactor):
        adapter = RedactorAdapter(mock_redactor, budget_limit=100.0)

        result1 = asyncio.run(adapter.redact("payload", "findings"))
        assert mock_redactor.redact.call_count == 1

        result2 = asyncio.run(adapter.redact("payload", "findings"))
        assert mock_redactor.redact.call_count == 1
        assert result1 == result2


# --------------------------------------------------------------------------- #
# Batch processing tests                                                      #
# --------------------------------------------------------------------------- #
class TestBatchProcessing:
    def test_batch_items(self):
        items = list(range(25))
        batches = batch_items(items, batch_size=10)
        assert len(batches) == 3
        assert batches[0] == list(range(10))
        assert batches[1] == list(range(10, 20))
        assert batches[2] == list(range(20, 25))

    def test_process_batch(self):
        items = [1, 2, 3, 4, 5]
        results = process_batch(items, lambda x: x * 2)
        assert results == [2, 4, 6, 8, 10]


# --------------------------------------------------------------------------- #
# Performance tracking tests                                                  #
# --------------------------------------------------------------------------- #
class TestPerformanceTracking:
    def test_track_performance(self):
        reset_perf_report()
        with track_performance("test_service") as tracker:
            time.sleep(0.01)

        report = get_perf_report()
        assert report.total_calls == 1
        assert report.calls_by_service["test_service"] == 1
        assert tracker.metrics.duration_ms > 0

    def test_error_tracking(self):
        reset_perf_report()

        def failing_func():
            raise ValueError("test error")

        try:
            with track_performance("failing_service") as tracker:
                failing_func()
        except ValueError:
            pass

        report = get_perf_report()
        assert report.total_calls == 1
        assert len(report.errors) == 1
        assert report.errors[0]["service"] == "failing_service"
        assert "ValueError" in report.errors[0]["error"]

    def test_reset_perf_report(self):
        reset_perf_report()
        with track_performance("test"):
            pass
        assert get_perf_report().total_calls == 1

        reset_perf_report()
        assert get_perf_report().total_calls == 0


# --------------------------------------------------------------------------- #
# Global cache tests                                                          #
# --------------------------------------------------------------------------- #
class TestGlobalCache:
    def setup_method(self):
        clear_adapter_caches()

    def test_get_adapter_cache(self):
        cache1 = get_adapter_cache("test_cache", max_size=10)
        cache2 = get_adapter_cache("test_cache", max_size=10)
        assert cache1 is cache2

    def test_different_caches(self):
        cache1 = get_adapter_cache("cache_a")
        cache2 = get_adapter_cache("cache_b")
        assert cache1 is not cache2

    def test_clear_adapter_caches(self):
        cache = get_adapter_cache("test")
        cache.put("key", value="value")
        assert len(cache) == 1

        clear_adapter_caches()
        assert len(cache) == 0


# --------------------------------------------------------------------------- #
# Integration test                                                            #
# --------------------------------------------------------------------------- #
class TestIntegration:
    """End-to-end test of the adapter layer."""

    @pytest.fixture
    def mock_components(self):
        pdp = AsyncMock()
        pdp.decide = AsyncMock(return_value={"decision": "allow"})

        scanner = AsyncMock()
        scanner.scan = AsyncMock(return_value={"findings": []})

        redactor = AsyncMock()
        redactor.redact = AsyncMock(return_value={"redacted": "safe"})

        return {
            "pdp": pdp,
            "scanner": scanner,
            "redactor": redactor,
        }

    def test_full_pipeline(self, mock_components):
        """Test the full decision pipeline with adapters."""
        pdp_adapter = PDPAdapter(mock_components["pdp"], budget_limit=10.0)
        scanner_adapter = ScannerAdapter(mock_components["scanner"], budget_limit=10.0)
        redactor_adapter = RedactorAdapter(mock_components["redactor"], budget_limit=10.0)

        request = MagicMock()
        request.principal = "user1"
        request.resource = "resource1"
        request.action = "read"
        request.payload_hash = "abc123"

        # Step 1: Scan payload
        scan_result = asyncio.run(scanner_adapter.scan("sensitive data"))
        assert scan_result == {"findings": []}

        # Step 2: Make decision
        decision = asyncio.run(pdp_adapter.decide(request))
        assert decision == {"decision": "allow"}

        # Step 3: Redact if needed
        redaction = asyncio.run(redactor_adapter.redact("payload", "findings"))
        assert redaction == {"redacted": "safe"}

        # Verify all adapters tracked calls
        assert scanner_adapter.calls == 1
        assert pdp_adapter.calls == 1
        assert redactor_adapter.calls == 1
