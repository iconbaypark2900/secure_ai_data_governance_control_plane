"""The enforcement-point client.

Three behaviours here are not conveniences but requirements of being an
enforcement point, and they are the reason to use this client rather than
calling the API directly:

*Fail closed.* If the control plane cannot be reached, the client denies. An
enforcement point that lets traffic through when its authority is unavailable
provides no control at all -- it provides the appearance of one, which is worse.

*Obligations are binding.* A decision carrying an obligation the caller has not
declared it can satisfy is treated as a deny by :meth:`Decision.enforce`. "Allow,
but redact the SSNs" must never degrade into "allow".

*Metadata-only caching.* Decisions with a payload are never cached, because the
payload is part of what was decided. Only payload-free decisions -- the pure
authorisation question -- are eligible.
"""

from __future__ import annotations

import json
import time
from collections.abc import AsyncIterator, Iterable, Mapping
from contextlib import asynccontextmanager
from dataclasses import dataclass, field
from typing import Any, Literal, Self

import httpx

__all__ = [
    "ApprovalTimeout",
    "AsyncControlPlaneClient",
    "ControlPlaneClient",
    "ControlPlaneError",
    "ControlPlaneUnavailable",
    "Decision",
    "DecisionDenied",
    "ObligationUnsatisfied",
    "Outcome",
]

#: Approval states from which nothing further will change on its own.
TERMINAL_APPROVAL_STATES = frozenset({"granted", "denied", "expired"})

DEFAULT_TIMEOUT = 5.0
DEFAULT_RETRIES = 2
#: Obligations this client can satisfy on the caller's behalf, because the
#: control plane already applied them to the returned payload.
SATISFIED_BY_CONTROL_PLANE = frozenset({"redact", "annotate", "log", "ttl"})


class Outcome:
    """What actually happened to a decision."""

    ENFORCED = "enforced"
    REFUSED = "refused"
    PARTIAL = "partial"


class ControlPlaneError(Exception):
    """Base class for every error this client raises."""


class ControlPlaneUnavailable(ControlPlaneError):
    """The control plane could not be reached or did not answer in time."""


class DecisionDenied(ControlPlaneError):
    """The requested action was refused."""

    def __init__(self, decision: Decision) -> None:
        self.decision = decision
        super().__init__(f"denied: {decision.reason}")


class ApprovalTimeout(ControlPlaneError):
    """A parked decision was not resolved within the time allowed."""

    def __init__(self, approval_id: str, waited: float) -> None:
        self.approval_id = approval_id
        self.waited = waited
        super().__init__(f"approval {approval_id} was still unresolved after {waited:.0f}s")


class ObligationUnsatisfied(ControlPlaneError):
    """An allow arrived with a duty this enforcement point cannot carry out."""

    def __init__(self, decision: Decision, obligations: list[str]) -> None:
        self.decision = decision
        self.obligations = obligations
        super().__init__(
            "the decision allows the action only subject to obligations this "
            f"enforcement point cannot satisfy: {', '.join(obligations)}"
        )


@dataclass(frozen=True, slots=True)
class Decision:
    """A decision as seen by the enforcement point."""

    effect: Literal["allow", "deny", "require_approval"]
    reason: str = ""
    decision_id: str | None = None
    payload: Any = None
    obligations: tuple[dict[str, Any], ...] = ()
    classifications: tuple[str, ...] = ()
    redactions: tuple[dict[str, Any], ...] = ()
    matched_policies: tuple[str, ...] = ()
    determining_policy: str | None = None
    unsupported_obligations: tuple[str, ...] = ()
    approval: dict[str, Any] | None = None
    latency_ms: float = 0.0
    raw: dict[str, Any] = field(default_factory=dict, repr=False)

    @property
    def allowed(self) -> bool:
        return self.effect == "allow"

    @property
    def needs_approval(self) -> bool:
        return self.effect == "require_approval"

    @property
    def approval_id(self) -> str | None:
        """The approval to wait on, when this decision was parked for a human."""
        return (self.approval or {}).get("id")

    @property
    def approval_redeemed(self) -> bool:
        return bool(self.raw.get("approval_redeemed"))

    @property
    def approval_error(self) -> str | None:
        """Why a presented approval did not apply, if one was presented."""
        error = self.raw.get("approval_error")
        return str(error) if error else None

    @property
    def redacted(self) -> bool:
        return bool(self.redactions)

    @classmethod
    def from_response(cls, body: Mapping[str, Any]) -> Decision:
        return cls(
            effect=body.get("effect", "deny"),
            reason=body.get("reason", ""),
            decision_id=body.get("decision_id"),
            payload=body.get("payload"),
            obligations=tuple(body.get("obligations") or ()),
            classifications=tuple(body.get("classifications") or ()),
            redactions=tuple(body.get("redactions") or ()),
            matched_policies=tuple(body.get("matched_policies") or ()),
            determining_policy=body.get("determining_policy"),
            unsupported_obligations=tuple(body.get("unsupported_obligations") or ()),
            approval=body.get("approval"),
            latency_ms=float(body.get("latency_ms") or 0.0),
            raw=dict(body),
        )

    @classmethod
    def denial(cls, reason: str) -> Decision:
        return cls(effect="deny", reason=reason)

    def obligation_types(self) -> list[str]:
        return sorted({str(o.get("type")) for o in self.obligations if o.get("type")})

    def outstanding(self, can_satisfy: Iterable[str] = ()) -> list[str]:
        """Obligation types nobody in this exchange is going to carry out."""
        satisfiable = SATISFIED_BY_CONTROL_PLANE | {str(item) for item in can_satisfy}
        return sorted(t for t in self.obligation_types() if t not in satisfiable)

    def enforce(self, *, can_satisfy: Iterable[str] = ()) -> Any:
        """Return the payload, or raise if the action must not proceed.

        ``can_satisfy`` names obligation types this enforcement point implements
        itself. Anything the control plane did not already apply, and that is not
        named here, turns the allow into a refusal.

        Pure: it decides, it does not report. Use the client's ``enforce`` to
        have the outcome reported as well, which is what makes the control
        plane's record match what happened.
        """
        if not self.allowed:
            raise DecisionDenied(self)
        outstanding = self.outstanding(can_satisfy)
        if outstanding:
            raise ObligationUnsatisfied(self, outstanding)
        return self.payload


class _DecisionCache:
    """A tiny TTL cache for payload-free decisions."""

    __slots__ = ("_entries", "_max", "_ttl")

    def __init__(self, ttl: float, max_entries: int) -> None:
        self._entries: dict[str, tuple[float, Decision]] = {}
        self._ttl = ttl
        self._max = max_entries

    def get(self, key: str) -> Decision | None:
        entry = self._entries.get(key)
        if entry is None:
            return None
        expires_at, decision = entry
        if time.monotonic() >= expires_at:
            self._entries.pop(key, None)
            return None
        return decision

    def set(self, key: str, decision: Decision) -> None:
        if self._ttl <= 0:
            return
        if len(self._entries) >= self._max:
            # Cheap eviction: drop the oldest insertion. A decision cache is a
            # latency optimisation, not a correctness mechanism, so an
            # approximate policy is fine.
            self._entries.pop(next(iter(self._entries)), None)
        self._entries[key] = (time.monotonic() + self._ttl, decision)

    def clear(self) -> None:
        self._entries.clear()


def _cache_key(body: Mapping[str, Any]) -> str:
    """A key that distinguishes questions the policy engine distinguishes.

    Context and classifications are JSON-encoded rather than stringified. The
    obvious ``f"{k}={v}"`` form conflates values the server does not: it made
    ``{"external": True}`` and ``{"external": "True"}`` the same key, and a
    policy matching a boolean does not match the string. The second caller then
    received the first one's decision -- a cache answering a different question,
    which is a correctness bug whatever the cache is nominally for. Found while
    porting this function to TypeScript, by asking what the two would disagree
    about.
    """
    principal = body.get("principal", {})
    resource = body.get("resource", {})
    return "|".join(
        [
            str(principal.get("id")),
            str(principal.get("type")),
            str(body.get("action")),
            str(resource.get("urn")),
            _canonical(sorted(str(c) for c in resource.get("classifications", []))),
            _canonical(body.get("context", {})),
        ]
    )


def _canonical(value: Any) -> str:
    """A stable, type-preserving rendering. Falls back rather than raising."""
    try:
        return json.dumps(value, sort_keys=True, separators=(",", ":"), default=repr)
    except (TypeError, ValueError):
        return repr(value)


def _build_body(
    *,
    principal_id: str,
    action: str,
    principal_type: str,
    principal_attributes: Mapping[str, Any] | None,
    resource_urn: str | None,
    resource_kind: str | None,
    classifications: Iterable[str] | None,
    resource_attributes: Mapping[str, Any] | None,
    context: Mapping[str, Any] | None,
    payload: Any,
    correlation_id: str | None,
    approval_id: str | None,
    explain: bool,
    apply_obligations: bool,
    persist: bool,
) -> dict[str, Any]:
    body: dict[str, Any] = {
        "principal": {
            "id": principal_id,
            "type": principal_type,
            "attributes": dict(principal_attributes or {}),
        },
        "action": action,
        "resource": {
            "urn": resource_urn,
            "kind": resource_kind,
            "classifications": list(classifications or []),
            "attributes": dict(resource_attributes or {}),
        },
        "context": dict(context or {}),
        "options": {
            "explain": explain,
            "apply_obligations": apply_obligations,
            "persist": persist,
        },
    }
    if payload is not None:
        body["payload"] = payload
    if correlation_id:
        body["correlation_id"] = correlation_id
    if approval_id:
        body["approval_id"] = str(approval_id)
    return body


class _ClientBase:
    """Shared configuration and response handling."""

    def __init__(
        self,
        base_url: str,
        api_key: str | None = None,
        *,
        timeout: float = DEFAULT_TIMEOUT,
        retries: int = DEFAULT_RETRIES,
        fail_closed: bool = True,
        cache_ttl: float = 5.0,
        cache_max_entries: int = 1024,
        default_principal_type: str = "service",
    ) -> None:
        self.base_url = base_url.rstrip("/")
        self.api_key = api_key
        self.timeout = timeout
        self.retries = max(0, retries)
        self.fail_closed = fail_closed
        self.default_principal_type = default_principal_type
        self._cache = _DecisionCache(cache_ttl, cache_max_entries)

    @property
    def _headers(self) -> dict[str, str]:
        headers = {"Content-Type": "application/json"}
        if self.api_key:
            headers["X-API-Key"] = self.api_key
        return headers

    def _handle(self, response: httpx.Response) -> Decision:
        if response.status_code == 200:
            return Decision.from_response(response.json())
        if response.status_code in (401, 403):
            # An authorisation failure against the control plane is itself a
            # denial, not a reason to proceed unchecked.
            return Decision.denial(
                f"the control plane rejected this enforcement point "
                f"({response.status_code}): {_detail(response)}"
            )
        raise ControlPlaneError(
            f"control plane returned {response.status_code}: {_detail(response)}"
        )

    def _on_unreachable(self, error: Exception) -> Decision:
        if self.fail_closed:
            return Decision.denial(
                f"the control plane is unreachable and this enforcement point fails closed: {error}"
            )
        raise ControlPlaneUnavailable(str(error)) from error

    def clear_cache(self) -> None:
        self._cache.clear()


def _detail(response: httpx.Response) -> str:
    try:
        return str(response.json().get("detail", response.text))[:500]
    except Exception:
        return response.text[:500]


class AsyncControlPlaneClient(_ClientBase):
    """Async client. Use this inside an async enforcement point."""

    def __init__(self, *args: Any, client: httpx.AsyncClient | None = None, **kwargs: Any):
        super().__init__(*args, **kwargs)
        self._client = client
        self._owns_client = client is None

    async def __aenter__(self) -> Self:
        return self

    async def __aexit__(self, *_exc: object) -> None:
        await self.aclose()

    async def aclose(self) -> None:
        if self._client is not None and self._owns_client:
            await self._client.aclose()
            self._client = None

    def _http(self) -> httpx.AsyncClient:
        if self._client is None:
            self._client = httpx.AsyncClient(base_url=self.base_url, timeout=self.timeout)
        return self._client

    async def decide(
        self,
        *,
        principal_id: str,
        action: str,
        principal_type: str | None = None,
        principal_attributes: Mapping[str, Any] | None = None,
        resource_urn: str | None = None,
        resource_kind: str | None = None,
        classifications: Iterable[str] | None = None,
        resource_attributes: Mapping[str, Any] | None = None,
        context: Mapping[str, Any] | None = None,
        payload: Any = None,
        correlation_id: str | None = None,
        approval_id: str | None = None,
        explain: bool = False,
        apply_obligations: bool = True,
        persist: bool = True,
        use_cache: bool = True,
    ) -> Decision:
        """Ask whether an action is permitted.

        ``persist=False`` evaluates without writing a decision record. It is for
        asking a question, not for taking an action: an enforcement point that
        acts on the answer must record it, because a decision that was enforced
        and not recorded is precisely the gap this system exists to close. The
        legitimate use is advisory -- deciding what to *offer* someone, where
        nothing is carried out and the real decision happens later.
        """
        body = _build_body(
            principal_id=principal_id,
            action=action,
            principal_type=principal_type or self.default_principal_type,
            principal_attributes=principal_attributes,
            resource_urn=resource_urn,
            resource_kind=resource_kind,
            classifications=classifications,
            resource_attributes=resource_attributes,
            context=context,
            payload=payload,
            correlation_id=correlation_id,
            approval_id=approval_id,
            explain=explain,
            apply_obligations=apply_obligations,
            persist=persist,
        )

        # A decision about content depends on that content, and an approval
        # redemption is a state change that must happen exactly once. Only the
        # pure authorisation question is cacheable.
        cacheable = use_cache and payload is None and not explain and approval_id is None
        key = _cache_key(body) if cacheable else ""
        if cacheable:
            cached = self._cache.get(key)
            if cached is not None:
                return cached

        last_error: Exception | None = None
        for attempt in range(self.retries + 1):
            try:
                response = await self._http().post("/v1/decide", json=body, headers=self._headers)
                decision = self._handle(response)
                if cacheable:
                    self._cache.set(key, decision)
                return decision
            except (httpx.TimeoutException, httpx.TransportError) as exc:
                last_error = exc
                if attempt < self.retries:
                    # Linear backoff: the control plane is on the request path,
                    # so a long exponential wait costs more than failing fast.
                    await _async_sleep(0.05 * (attempt + 1))
        return self._on_unreachable(last_error or RuntimeError("unreachable"))

    async def classify(self, payload: Any, *, min_confidence: float = 0.0) -> dict[str, Any]:
        """Classify content without asking an authorisation question."""
        response = await self._http().post(
            "/v1/classify",
            json={"payload": payload, "min_confidence": min_confidence},
            headers=self._headers,
        )
        response.raise_for_status()
        return dict(response.json())

    async def report_outcome(
        self,
        decision: Decision,
        outcome: str,
        *,
        reason: str = "",
        discharged: Iterable[str] = (),
        undischarged: Iterable[str] = (),
    ) -> bool:
        """Tell the control plane what actually happened.

        Never raises. By the time this is called the action has already been
        taken or refused, and failing the caller over a bookkeeping round trip
        would turn a reporting problem into an outage. An outcome that does not
        arrive shows up server-side as *unreported*, which is the detection path
        -- silence is treated as "nothing is known", not as "it went fine".
        """
        if not decision.decision_id:
            return False
        try:
            response = await self._http().post(
                f"/v1/decisions/{decision.decision_id}/outcome",
                json={
                    "outcome": outcome,
                    "reason": reason,
                    "discharged": sorted(set(discharged)),
                    "undischarged": sorted(set(undischarged)),
                },
                headers=self._headers,
            )
            return response.status_code < 300
        except (httpx.TimeoutException, httpx.TransportError):
            return False

    @asynccontextmanager
    async def enforcing(
        self, decision: Decision, *, can_satisfy: Iterable[str] = ()
    ) -> AsyncIterator[Any]:
        """Act on a decision, and report the outcome when the work is done.

        The right shape whenever anything happens *after* the obligation check --
        a backend call, a downstream hop, a second decision. Reporting at the
        moment the obligations merely check out is premature: the action has not
        happened yet, and if a later step fails the record ends up saying
        "enforced" behind something that never took place. That is exactly the
        failure this reporting exists to prevent::

            async with client.enforcing(decision, can_satisfy={"watermark"}) as payload:
                await send_upstream(payload)
            # reported enforced here, or refused if the block raised

        An exception escaping the block is reported as a refusal, because from
        the control plane's side that is what it is: permitted, and it did not
        happen. So is an obligation this point cannot discharge, which is the
        same refusal arriving earlier -- reporting one and not the other left
        the decision *unreported*, and a duty nobody could carry out is exactly
        what an operator is scanning that list for.

        A denial is not reported: nothing was permitted, so there is no action
        to account for, and the record already says it was refused.
        """
        try:
            payload = decision.enforce(can_satisfy=can_satisfy)
        except ObligationUnsatisfied as exc:
            await self.report_outcome(
                decision,
                Outcome.REFUSED,
                reason=str(exc),
                discharged=[t for t in decision.obligation_types() if t not in exc.obligations],
                undischarged=exc.obligations,
            )
            raise
        try:
            yield payload
        except Exception as exc:
            await self.report_outcome(
                decision,
                Outcome.REFUSED,
                reason=str(exc) or exc.__class__.__name__,
                discharged=[],
                undischarged=decision.obligation_types(),
            )
            raise
        await self.report_outcome(
            decision, Outcome.ENFORCED, discharged=decision.obligation_types()
        )

    async def enforce(self, decision: Decision, *, can_satisfy: Iterable[str] = ()) -> Any:
        """Act on a decision and report it enforced, in one call.

        Correct only when acting on the decision is the *last* thing that
        happens. If anything can still fail afterwards, use :meth:`enforcing`:
        this reports success as soon as the obligations check out, and a later
        failure would leave a record saying "enforced" behind an action that
        never took place.
        """
        try:
            payload = decision.enforce(can_satisfy=can_satisfy)
        except ObligationUnsatisfied as exc:
            await self.report_outcome(
                decision,
                Outcome.REFUSED,
                reason=str(exc),
                discharged=[t for t in decision.obligation_types() if t not in exc.obligations],
                undischarged=exc.obligations,
            )
            raise
        except DecisionDenied:
            # Nothing to report: the record already says it was refused, and the
            # enforcement point never had an action to take.
            raise
        await self.report_outcome(
            decision, Outcome.ENFORCED, discharged=decision.obligation_types()
        )
        return payload

    async def report_partial(
        self, decision: Decision, *, undischarged: Iterable[str], reason: str
    ) -> bool:
        """Report that the action happened but a duty went undischarged.

        The honest outcome when an enforcement point proceeds anyway. Reporting
        ``enforced`` here would hide the very thing worth knowing.
        """
        missing = sorted(set(undischarged))
        return await self.report_outcome(
            decision,
            Outcome.PARTIAL,
            reason=reason,
            discharged=[t for t in decision.obligation_types() if t not in missing],
            undischarged=missing,
        )

    async def get_approval(self, approval_id: str) -> dict[str, Any]:
        """Read the current state of a parked decision."""
        response = await self._http().get(f"/v1/approvals/{approval_id}", headers=self._headers)
        response.raise_for_status()
        return dict(response.json())

    async def await_approval(
        self,
        approval_id: str,
        *,
        # ASYNC109: this is a polling budget, not a cancellation scope. It has to
        # raise a domain error the caller can act on -- "nobody approved this" --
        # rather than CancelledError, and it mirrors the sync client's signature.
        # A caller who wants cancellation can still wrap the call in asyncio.timeout.
        timeout: float = 300.0,  # noqa: ASYNC109
        poll_interval: float = 2.0,
    ) -> dict[str, Any]:
        """Poll until a human resolves the request, then return it.

        Polls the approvals endpoint rather than re-sending the decision: that
        is a cheap read, and it does not evaluate policy, write a decision
        record, and seal an audit entry every couple of seconds.

        Returns on any terminal state -- granted, denied, or expired -- so the
        caller decides what to do about a refusal. Raises
        :class:`ApprovalTimeout` if nobody has acted in time.
        """
        deadline = time.monotonic() + timeout
        while True:
            approval = await self.get_approval(approval_id)
            if str(approval.get("status")) in TERMINAL_APPROVAL_STATES:
                return approval
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise ApprovalTimeout(approval_id, timeout)
            await _async_sleep(min(poll_interval, remaining))

    async def health(self) -> bool:
        try:
            response = await self._http().get("/v1/health", timeout=self.timeout)
            return response.status_code == 200
        except (httpx.TimeoutException, httpx.TransportError):
            return False


class ControlPlaneClient(_ClientBase):
    """Blocking client, for enforcement points that are not async."""

    def __init__(self, *args: Any, client: httpx.Client | None = None, **kwargs: Any):
        super().__init__(*args, **kwargs)
        self._client = client
        self._owns_client = client is None

    def __enter__(self) -> Self:
        return self

    def __exit__(self, *_exc: object) -> None:
        self.close()

    def close(self) -> None:
        if self._client is not None and self._owns_client:
            self._client.close()
            self._client = None

    def _http(self) -> httpx.Client:
        if self._client is None:
            self._client = httpx.Client(base_url=self.base_url, timeout=self.timeout)
        return self._client

    def decide(
        self,
        *,
        principal_id: str,
        action: str,
        principal_type: str | None = None,
        principal_attributes: Mapping[str, Any] | None = None,
        resource_urn: str | None = None,
        resource_kind: str | None = None,
        classifications: Iterable[str] | None = None,
        resource_attributes: Mapping[str, Any] | None = None,
        context: Mapping[str, Any] | None = None,
        payload: Any = None,
        correlation_id: str | None = None,
        approval_id: str | None = None,
        explain: bool = False,
        apply_obligations: bool = True,
        persist: bool = True,
        use_cache: bool = True,
    ) -> Decision:
        body = _build_body(
            principal_id=principal_id,
            action=action,
            principal_type=principal_type or self.default_principal_type,
            principal_attributes=principal_attributes,
            resource_urn=resource_urn,
            resource_kind=resource_kind,
            classifications=classifications,
            resource_attributes=resource_attributes,
            context=context,
            payload=payload,
            correlation_id=correlation_id,
            approval_id=approval_id,
            explain=explain,
            apply_obligations=apply_obligations,
            persist=persist,
        )
        # Never cache an approval redemption: it is spent exactly once.
        cacheable = use_cache and payload is None and not explain and approval_id is None
        key = _cache_key(body) if cacheable else ""
        if cacheable:
            cached = self._cache.get(key)
            if cached is not None:
                return cached

        last_error: Exception | None = None
        for attempt in range(self.retries + 1):
            try:
                response = self._http().post("/v1/decide", json=body, headers=self._headers)
                decision = self._handle(response)
                if cacheable:
                    self._cache.set(key, decision)
                return decision
            except (httpx.TimeoutException, httpx.TransportError) as exc:
                last_error = exc
                if attempt < self.retries:
                    time.sleep(0.05 * (attempt + 1))
        return self._on_unreachable(last_error or RuntimeError("unreachable"))

    def classify(self, payload: Any, *, min_confidence: float = 0.0) -> dict[str, Any]:
        response = self._http().post(
            "/v1/classify",
            json={"payload": payload, "min_confidence": min_confidence},
            headers=self._headers,
        )
        response.raise_for_status()
        return dict(response.json())

    def get_approval(self, approval_id: str) -> dict[str, Any]:
        """Read the current state of a parked decision."""
        response = self._http().get(f"/v1/approvals/{approval_id}", headers=self._headers)
        response.raise_for_status()
        return dict(response.json())

    def await_approval(
        self,
        approval_id: str,
        *,
        timeout: float = 300.0,
        poll_interval: float = 2.0,
    ) -> dict[str, Any]:
        """Block until a human resolves the request. See the async client."""
        deadline = time.monotonic() + timeout
        while True:
            approval = self.get_approval(approval_id)
            if str(approval.get("status")) in TERMINAL_APPROVAL_STATES:
                return approval
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise ApprovalTimeout(approval_id, timeout)
            time.sleep(min(poll_interval, remaining))

    def health(self) -> bool:
        try:
            return self._http().get("/v1/health", timeout=self.timeout).status_code == 200
        except (httpx.TimeoutException, httpx.TransportError):
            return False


async def _async_sleep(seconds: float) -> None:
    import asyncio

    await asyncio.sleep(seconds)
