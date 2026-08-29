"""A governing reverse proxy for OpenAI-compatible chat completions.

This is the reference enforcement point: the smallest thing that demonstrates
what a PEP actually has to do. Point an existing client at it instead of at the
model provider and every prompt is governed, with no change to the client.

    client ──> this proxy ──> control plane  (may I? what must I strip?)
                   │
                   └────────> model provider (with the sanitised prompt)
                   │
                   ◄──────── response
                   │
                   └────────> control plane  (may this go back to the caller?)

Both directions are governed, which matters more than it first appears: a model
that was given clean input can still emit a training-data memorisation, a
credential a tool handed it, or a row it inferred from context. Governing only
the inbound half protects the provider, not the user.

Run it against a real provider, or with ``PEP_UPSTREAM_MODE=echo`` for a
self-contained demo that needs no API key.
"""

from __future__ import annotations

import asyncio
import os
import sys
import time
import uuid
from collections.abc import AsyncIterator, Sequence
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Any

import httpx
from fastapi import FastAPI, Header, HTTPException, Request
from fastapi.responses import JSONResponse, StreamingResponse

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "sdk" / "python"))

from control_plane_sdk import (
    AsyncControlPlaneClient,
    Decision,
    ObligationUnsatisfied,
)

from pep.reverse_proxy.obligations import (
    RESPONSE_SATISFIABLE,
    SATISFIABLE,
    Backend,
    apply_request_obligations,
    apply_response_obligations,
    check_purpose,
    load_backends,
    routed_target,
)
from pep.reverse_proxy.streaming import (
    DEFAULT_GOVERN_EVERY,
    DEFAULT_WINDOW_CHARS,
    DONE,
    StreamGovernor,
    govern_stream,
    rebuild_delta,
    sse,
)

CONTROL_PLANE_URL = os.getenv("PEP_CONTROL_PLANE_URL", "http://localhost:8000")
CONTROL_PLANE_KEY = os.getenv("PEP_CONTROL_PLANE_KEY", "")
UPSTREAM_URL = os.getenv("PEP_UPSTREAM_URL", "https://api.openai.com")
UPSTREAM_KEY = os.getenv("PEP_UPSTREAM_KEY", "")
#: "proxy" forwards to UPSTREAM_URL; "echo" answers locally so the demo needs no
#: provider account and no egress.
UPSTREAM_MODE = os.getenv("PEP_UPSTREAM_MODE", "echo").lower()
#: Whether the model is operated by a third party. Policies match on this to
#: distinguish "our GPU" from "someone else's".
DESTINATION = os.getenv("PEP_DESTINATION", "external")
DEFAULT_PRINCIPAL = os.getenv("PEP_DEFAULT_PRINCIPAL", "service:llm_gateway")

#: How a streamed response is governed.
#:   "window"  emit tokens a fixed distance behind production, so nothing goes out
#:             until everything it could be part of has been seen. Streams, with a
#:             blind spot for values longer than the window.
#:   "buffer"  collect the whole answer, govern it, then emit. No blind spot, and
#:             no incremental delivery -- time-to-first-token becomes
#:             time-to-last-token.
STREAM_MODE = os.getenv("PEP_STREAM_MODE", "window").lower()
STREAM_WINDOW_CHARS = int(os.getenv("PEP_STREAM_WINDOW_CHARS", DEFAULT_WINDOW_CHARS))
STREAM_GOVERN_EVERY = int(os.getenv("PEP_STREAM_GOVERN_EVERY", DEFAULT_GOVERN_EVERY))

#: Model URN -> endpoint, for requests the control plane routes. Keyed by the URN
#: it resolves to, so both sides agree on identity without the control plane ever
#: holding a credential.
#:
#:   {"model://internal/llama-3-70b": {"base_url": "http://llama:8000",
#:                                     "model": "llama-3-70b",
#:                                     "api_key": "..."}}
MODEL_BACKENDS = load_backends(os.getenv("PEP_MODEL_BACKENDS", ""))

#: Where a request goes when no policy routed it.
DEFAULT_BACKEND = Backend(base_url=UPSTREAM_URL, api_key=UPSTREAM_KEY)

_control_plane: AsyncControlPlaneClient | None = None
_upstream: httpx.AsyncClient | None = None


@asynccontextmanager
async def lifespan(_app: FastAPI) -> AsyncIterator[None]:
    global _control_plane, _upstream
    _control_plane = AsyncControlPlaneClient(
        CONTROL_PLANE_URL,
        CONTROL_PLANE_KEY or None,
        timeout=float(os.getenv("PEP_TIMEOUT", "5")),
        # The whole point of an enforcement point: if it cannot reach its
        # authority, it does not guess.
        fail_closed=os.getenv("PEP_FAIL_CLOSED", "true").lower() != "false",
    )
    # No base_url: the endpoint is chosen per request, because a policy may
    # route this one somewhere other than the default.
    _upstream = httpx.AsyncClient(timeout=120.0)
    yield
    await _control_plane.aclose()
    await _upstream.aclose()


app = FastAPI(
    title="Governing LLM proxy",
    description=__doc__,
    version="0.1.0",
    lifespan=lifespan,
)


def _messages_text(messages: list[dict[str, Any]]) -> str:
    """Flatten a chat array into the text the classifier should see."""
    parts: list[str] = []
    for message in messages:
        content = message.get("content")
        if isinstance(content, str):
            parts.append(content)
        elif isinstance(content, list):
            # The multimodal content array form: only text parts are scanned.
            parts.extend(
                str(block.get("text", ""))
                for block in content
                if isinstance(block, dict) and block.get("type") == "text"
            )
    return "\n\n".join(part for part in parts if part)


def _replace_messages_text(messages: list[dict[str, Any]], governed: str) -> list[dict[str, Any]]:
    """Put the sanitised text back, preserving the original message structure.

    The control plane returns one governed string for the whole conversation, so
    it is split back along the same boundaries it was joined on. Splitting on the
    join separator is exact as long as redaction does not introduce one, which is
    why the separator is a blank line rather than a single newline.
    """
    chunks = governed.split("\n\n")
    rebuilt: list[dict[str, Any]] = []
    index = 0
    for message in messages:
        content = message.get("content")
        if isinstance(content, str) and content:
            rebuilt.append({**message, "content": chunks[index] if index < len(chunks) else ""})
            index += 1
        else:
            rebuilt.append(dict(message))
    return rebuilt


class _Refused(Exception):
    """This proxy will not proceed, for a reason worth reporting.

    Raised rather than returned so the outcome reporting happens in one place:
    a refusal that returns early is a refusal somebody has to remember to
    report, and that is how a record ends up saying "allow" behind an action
    that never took place.
    """

    def __init__(self, reason: str, undischarged: list[str]) -> None:
        self.reason = reason
        self.undischarged = undischarged
        super().__init__(reason)


def _select_backend(obligations: list[dict[str, Any]]) -> tuple[Backend, str | None]:
    """The endpoint to use, or a refusal reason.

    A target this proxy has no configuration for is a duty it cannot discharge,
    so it refuses rather than quietly falling back to the default -- falling back
    would send the data to exactly the model the policy steered it away from.
    """
    target = routed_target(obligations)
    if target is None:
        return DEFAULT_BACKEND, None
    backend = MODEL_BACKENDS.get(target)
    if backend is None:
        return DEFAULT_BACKEND, (
            f"policy routed this request to {target}, which this enforcement "
            f"point has no backend configured for; add it to PEP_MODEL_BACKENDS"
        )
    return backend, None


def _denied(decision: Decision, direction: str) -> JSONResponse:
    """An OpenAI-shaped error, so existing clients render it sensibly."""
    return JSONResponse(
        status_code=403,
        content={
            "error": {
                "message": (
                    f"Blocked by data governance policy on the {direction} path: {decision.reason}"
                ),
                "type": "data_governance_denied",
                "code": "policy_denied",
                "decision_id": decision.decision_id,
                "policy": decision.determining_policy,
                "classifications": list(decision.classifications),
            }
        },
    )


@app.post("/v1/chat/completions")
async def chat_completions(
    request: Request,
    x_principal_id: str | None = Header(default=None),
    x_principal_type: str | None = Header(default=None),
    x_purpose: str | None = Header(default=None),
) -> Any:
    """Govern a chat completion in both directions."""
    assert _control_plane is not None and _upstream is not None

    body = await request.json()
    messages = body.get("messages") or []
    if not isinstance(messages, list):
        raise HTTPException(status_code=400, detail="'messages' must be a list")

    model = str(body.get("model", "unknown"))
    principal = x_principal_id or DEFAULT_PRINCIPAL
    correlation_id = request.headers.get("x-request-id") or str(uuid.uuid4())
    context = {
        "destination": DESTINATION,
        "model": model,
        "purpose": x_purpose or "chat",
        "channel": "chat_completions",
    }

    # --- inbound: may this prompt reach the model, and in what form? -------- #
    prompt = _messages_text(messages)
    inbound = await _control_plane.decide(
        principal_id=principal,
        principal_type=x_principal_type or "service",
        action="infer",
        resource_urn=f"model://{model}",
        resource_kind="model",
        context=context,
        payload=prompt,
        correlation_id=correlation_id,
    )
    if not inbound.allowed:
        return _denied(inbound, "inbound")
    # Everything that can still refuse happens before anything is reported.
    # Declaring what this proxy can discharge is not a formality: a duty not
    # named here turns the allow into a refusal, which is the correct outcome
    # for one nobody is going to carry out.
    try:
        governed_prompt = inbound.enforce(can_satisfy=SATISFIABLE)

        purpose_error = check_purpose(inbound.obligations, str(context["purpose"]))
        if purpose_error is not None:
            raise _Refused(purpose_error, ["require_purpose"])

        upstream_body = dict(body)
        if governed_prompt is not None and governed_prompt != prompt:
            upstream_body["messages"] = _replace_messages_text(messages, governed_prompt)
        upstream_body, request_notes = apply_request_obligations(
            upstream_body, list(inbound.obligations)
        )

        backend, backend_error = _select_backend(list(inbound.obligations))
        if backend_error is not None:
            raise _Refused(backend_error, ["route"])
    except ObligationUnsatisfied as exc:
        await _control_plane.report_outcome(
            inbound, "refused", reason=str(exc), undischarged=exc.obligations
        )
        return _denied(Decision.denial(str(exc)), "inbound")
    except _Refused as exc:
        await _control_plane.report_outcome(
            inbound, "refused", reason=exc.reason, undischarged=exc.undischarged
        )
        return _denied(Decision.denial(exc.reason), "inbound")
    if backend.model:
        # The logical model the caller named is not necessarily what the chosen
        # backend calls itself.
        upstream_body["model"] = backend.model
    if routed_target(list(inbound.obligations)):
        request_notes.append(f"routed to {routed_target(list(inbound.obligations))}")

    if bool(body.get("stream")):
        return StreamingResponse(
            _stream(
                upstream_body,
                backend=backend,
                model=model,
                principal=principal,
                principal_type=x_principal_type or "service",
                context=context,
                correlation_id=correlation_id,
                inbound=inbound,
            ),
            media_type="text/event-stream",
            headers={"Cache-Control": "no-store", "X-Accel-Buffering": "no"},
        )

    # --- call the model ---------------------------------------------------- #
    #
    # Inside `enforcing`, so the inbound decision is reported enforced once the
    # request has actually gone upstream -- and reported refused if it did not.
    # Reporting when the obligations merely checked out would leave a record
    # saying "enforced" behind a call that never happened.
    started = time.perf_counter()
    async with _control_plane.enforcing(inbound, can_satisfy=SATISFIABLE):
        if UPSTREAM_MODE == "echo":
            completion = _echo_completion(upstream_body, model)
        else:
            upstream_response = await _upstream.post(
                f"{backend.base_url}/v1/chat/completions",
                json=upstream_body,
                headers=backend.headers(),
            )
            upstream_response.raise_for_status()
            completion = upstream_response.json()
    upstream_ms = round((time.perf_counter() - started) * 1000, 2)

    # --- outbound: may this answer reach the caller? ------------------------ #
    answer = _completion_text(completion)
    outbound = await _control_plane.decide(
        principal_id=principal,
        principal_type=x_principal_type or "service",
        action="return",
        resource_urn=f"model://{model}",
        resource_kind="model",
        context={**context, "direction": "outbound"},
        payload=answer,
        correlation_id=correlation_id,
    )
    if not outbound.allowed:
        return _denied(outbound, "outbound")
    try:
        governed_answer = await _control_plane.enforce(outbound, can_satisfy=RESPONSE_SATISFIABLE)
    except ObligationUnsatisfied as exc:
        return _denied(Decision.denial(str(exc)), "outbound")
    if governed_answer is not None and governed_answer != answer:
        completion = _replace_completion_text(completion, governed_answer)

    # Caps and markings come from both directions, deduplicated: a watermark
    # attached to the inbound policy describes this exchange just as much as one
    # attached to the outbound policy, and it should mark the answer once.
    completion, applied = apply_response_obligations(
        completion, _merge_obligations(inbound.obligations, outbound.obligations)
    )

    completion.setdefault("x_governance", {}).update(
        {
            "inbound_decision_id": inbound.decision_id,
            "outbound_decision_id": outbound.decision_id,
            "inbound_redactions": len(inbound.redactions),
            "outbound_redactions": len(outbound.redactions),
            "classifications": sorted(set(inbound.classifications) | set(outbound.classifications)),
            # What was done, not just what was decided. An obligation carried out
            # silently is indistinguishable from one that was skipped.
            "obligations_applied": [*request_notes, *applied.notes],
            "routed_to": routed_target(list(inbound.obligations)),
            "upstream_ms": upstream_ms,
        }
    )
    return completion


def _merge_obligations(*groups: Sequence[dict[str, Any]]) -> list[dict[str, Any]]:
    """Union obligations from several decisions, dropping exact duplicates."""
    merged: list[dict[str, Any]] = []
    seen: set[str] = set()
    for group in groups:
        for obligation in group:
            fingerprint = repr(sorted(obligation.items(), key=lambda kv: kv[0]))
            if fingerprint in seen:
                continue
            seen.add(fingerprint)
            merged.append(dict(obligation))
    return merged


async def _stream(
    upstream_body: dict[str, Any],
    *,
    backend: Backend,
    model: str,
    principal: str,
    principal_type: str,
    context: dict[str, Any],
    correlation_id: str,
    inbound: Decision,
) -> AsyncIterator[bytes]:
    """Govern a streamed completion on its way back.

    The outbound decision is asked repeatedly, over a growing prefix of the
    answer, because a value is only recognisable once all of it has arrived. The
    governor decides what that makes safe to release.
    """
    assert _control_plane is not None and _upstream is not None

    async def govern(span: str) -> tuple[str, str | None]:
        decision = await _control_plane.decide(
            principal_id=principal,
            principal_type=principal_type,
            action="return",
            resource_urn=f"model://{model}",
            resource_kind="model",
            context={**context, "direction": "outbound", "channel": "stream"},
            payload=span,
            correlation_id=correlation_id,
        )
        if not decision.allowed:
            return span, decision.reason
        try:
            governed = await _control_plane.enforce(decision, can_satisfy=RESPONSE_SATISFIABLE)
        except ObligationUnsatisfied as exc:
            return span, str(exc)
        return (governed if isinstance(governed, str) else span), None

    governor = StreamGovernor(
        govern,
        window_chars=STREAM_WINDOW_CHARS,
        govern_every=STREAM_GOVERN_EVERY,
    )

    def refusal_event(reason: str) -> dict[str, Any]:
        # An error the client can actually see. Ending the stream silently would
        # look like a truncated answer rather than a refusal.
        return {
            "error": {
                "message": f"Blocked by data governance policy on the outbound path: {reason}",
                "type": "data_governance_denied",
                "code": "policy_denied",
            }
        }

    # A streamed answer is not finished when the handler returns -- it is
    # finished when the last frame goes out. So the outcome is reported from
    # here rather than around the handler, where it would land while the stream
    # was still running.
    refused: str | None = None
    try:
        if STREAM_MODE == "buffer":
            async for frame in _stream_buffered(upstream_body, governor, refusal_event):
                yield frame
        else:
            async with _upstream_frames(upstream_body, model, backend) as frames:
                async for frame in govern_stream(frames, governor, on_refusal=refusal_event):
                    yield frame
        refused = governor.refused_reason
    except httpx.HTTPError as exc:
        refused = f"the model provider could not be reached: {exc}"
        yield sse(refusal_event(refused))
        yield sse(DONE)

    if refused is None:
        await _control_plane.report_outcome(
            inbound, "enforced", discharged=inbound.obligation_types()
        )
    else:
        await _control_plane.report_outcome(
            inbound,
            "refused",
            reason=refused,
            undischarged=inbound.obligation_types(),
        )


@asynccontextmanager
async def _upstream_frames(
    body: dict[str, Any], model: str, backend: Backend
) -> AsyncIterator[AsyncIterator[bytes]]:
    """Raw SSE bytes from wherever the answer comes from.

    One shape for both sources, so the governing loop never branches on which
    upstream it is talking to.
    """
    if UPSTREAM_MODE == "echo":
        async with _echo_stream(body, model) as frames:
            yield frames
        return

    async with _upstream.stream(
        "POST",
        f"{backend.base_url}/v1/chat/completions",
        json=body,
        headers={**backend.headers(), "Accept": "text/event-stream"},
    ) as response:
        response.raise_for_status()
        yield response.aiter_bytes()


async def _stream_buffered(
    upstream_body: dict[str, Any],
    governor: StreamGovernor,
    refusal_event: Any,
) -> AsyncIterator[bytes]:
    """Collect the whole answer, govern it, then emit. No blind spot."""
    completion = _echo_completion(upstream_body, str(upstream_body.get("model", "unknown")))
    if UPSTREAM_MODE != "echo":
        response = await _upstream.post(
            "/v1/chat/completions",
            json={**upstream_body, "stream": False},
            headers={"Authorization": f"Bearer {UPSTREAM_KEY}"},
        )
        response.raise_for_status()
        completion = response.json()

    text = _completion_text(completion)
    await governor.feed(text)
    final = await governor.finish()
    if final is None:
        yield sse(DONE)
        return
    if final.is_refusal:
        yield sse(refusal_event(final.refusal or ""))
    elif final.text:
        yield sse(rebuild_delta({"choices": [{"index": 0, "delta": {}}]}, final.text))
    yield sse(DONE)


@asynccontextmanager
async def _echo_stream(body: dict[str, Any], model: str) -> AsyncIterator[AsyncIterator[bytes]]:
    """A local stand-in that streams, so the demo exercises the real path."""
    text = _messages_text(body.get("messages") or [])
    answer = f"[echo upstream] the model received:\n\n{text}"

    async def frames() -> AsyncIterator[bytes]:
        for index in range(0, len(answer), 24):
            yield sse(
                {
                    "id": "chatcmpl-echo",
                    "model": model,
                    "choices": [{"index": 0, "delta": {"content": answer[index : index + 24]}}],
                }
            )
            await asyncio.sleep(0)
        yield sse(DONE)

    yield frames()


def _completion_text(completion: dict[str, Any]) -> str:
    choices = completion.get("choices") or []
    return "\n\n".join(
        str((choice.get("message") or {}).get("content") or "") for choice in choices
    )


def _replace_completion_text(completion: dict[str, Any], governed: str) -> dict[str, Any]:
    chunks = governed.split("\n\n")
    updated = dict(completion)
    choices = []
    for index, choice in enumerate(updated.get("choices") or []):
        message = dict(choice.get("message") or {})
        message["content"] = chunks[index] if index < len(chunks) else ""
        choices.append({**choice, "message": message})
    updated["choices"] = choices
    return updated


def _echo_completion(body: dict[str, Any], model: str) -> dict[str, Any]:
    """A local stand-in for a provider, so the demo runs with no credentials.

    It echoes the governed prompt back, which makes the redactions visible in the
    response -- exactly what you want to see when demonstrating the proxy.
    """
    text = _messages_text(body.get("messages") or [])
    return {
        "id": f"chatcmpl-echo-{uuid.uuid4().hex[:12]}",
        "object": "chat.completion",
        "model": model,
        "choices": [
            {
                "index": 0,
                "message": {
                    "role": "assistant",
                    "content": f"[echo upstream] the model received:\n\n{text}",
                },
                "finish_reason": "stop",
            }
        ],
        "usage": {"prompt_tokens": len(text) // 4, "completion_tokens": 0},
    }


@app.get("/health")
async def health() -> dict[str, Any]:
    """Report whether the control plane is reachable.

    A proxy whose control plane is down is not healthy, even though it is
    running: every request it serves will be denied.
    """
    reachable = await _control_plane.health() if _control_plane else False
    return {
        "status": "ok" if reachable else "degraded",
        "control_plane": CONTROL_PLANE_URL,
        "control_plane_reachable": reachable,
        "upstream_mode": UPSTREAM_MODE,
        "destination": DESTINATION,
    }
