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
from fastapi.responses import JSONResponse

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "sdk" / "python"))

from control_plane_sdk import (
    AsyncControlPlaneClient,
    Decision,
    ObligationUnsatisfied,
)

from pep.reverse_proxy.obligations import (
    SATISFIABLE,
    apply_request_obligations,
    apply_response_obligations,
    check_purpose,
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
    _upstream = httpx.AsyncClient(base_url=UPSTREAM_URL, timeout=120.0)
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
    try:
        # Declaring what this proxy can discharge is not a formality: anything
        # not named here turns the allow into a refusal, which is the correct
        # outcome for a duty nobody is going to carry out.
        governed_prompt = inbound.enforce(can_satisfy=SATISFIABLE)
    except ObligationUnsatisfied as exc:
        return _denied(Decision.denial(str(exc)), "inbound")

    purpose_error = check_purpose(inbound.obligations, str(context["purpose"]))
    if purpose_error is not None:
        return _denied(Decision.denial(purpose_error), "inbound")

    upstream_body = dict(body)
    if governed_prompt is not None and governed_prompt != prompt:
        upstream_body["messages"] = _replace_messages_text(messages, governed_prompt)
    upstream_body, request_notes = apply_request_obligations(
        upstream_body, list(inbound.obligations)
    )

    # --- call the model ---------------------------------------------------- #
    started = time.perf_counter()
    if UPSTREAM_MODE == "echo":
        completion = _echo_completion(upstream_body, model)
    else:
        upstream_response = await _upstream.post(
            "/v1/chat/completions",
            json=upstream_body,
            headers={
                "Authorization": f"Bearer {UPSTREAM_KEY}",
                "Content-Type": "application/json",
            },
        )
        if upstream_response.status_code >= 400:
            return JSONResponse(
                status_code=upstream_response.status_code, content=upstream_response.json()
            )
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
        governed_answer = outbound.enforce(can_satisfy=SATISFIABLE)
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
