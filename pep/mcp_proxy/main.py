"""A governing proxy for the Model Context Protocol.

The second reference enforcement point. Where the reverse proxy governs what an
agent says to a model, this governs what an agent *does* -- the tools it calls,
the arguments it sends them, and the data those tools hand back.

    agent ──> this proxy ──> control plane  (may this agent call this tool
                  │                          with these arguments?)
                  │
                  └───────> MCP server (with sanitised arguments)
                  │
                  ◄──────── result
                  │
                  └───────> control plane  (may this result reach the agent?)

Both directions, for the reason the MCP adapter gives: arguments carry data *to*
a tool, so an agent pasting a customer record into a web search has exfiltrated
it, and results carry data *back*, so a file read returns whatever the file held.
A proxy that governed only the call would let the second half through untouched.

There is a third thing this can do that a chat proxy cannot. Tool listings flow
through the same endpoint, so a tool the agent may not call need not be
advertised to it at all. Filtering the listing is not a substitute for governing
the call -- an agent can name a tool it was never shown -- but not offering a
capability is a great deal cheaper than refusing it afterwards.

Everything this does not understand is forwarded unchanged. It is a proxy for a
protocol it does not own, and the first duty is to not corrupt it.

    PEP_MCP_UPSTREAM=http://127.0.0.1:3001/mcp \\
    PEP_MCP_UPSTREAM_AUTH="Bearer ..." \\
    uvicorn pep.mcp_proxy.main:app --port 8170
"""

from __future__ import annotations

import json
import os
import sys
from collections.abc import Mapping
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Any

import httpx
from fastapi import FastAPI, Request, Response
from fastapi.responses import JSONResponse

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "sdk" / "python"))

from control_plane_sdk import (
    AsyncControlPlaneClient,
    Decision,
    ObligationUnsatisfied,
    Outcome,
)

from control_plane.adapters.mcp_gateway import ToolCall, declared_action, infer_action
from pep.mcp_proxy.framing import (
    INTERNAL_ERROR,
    POLICY_DENIED,
    SSEEvent,
    encode_sse,
    is_notification,
    iter_sse,
    rpc_error,
    rpc_id,
    rpc_method,
)

UPSTREAM = os.environ.get("PEP_MCP_UPSTREAM", "http://127.0.0.1:3001/mcp")
UPSTREAM_AUTH = os.environ.get("PEP_MCP_UPSTREAM_AUTH", "")
CONTROL_PLANE = os.environ.get("PEP_CONTROL_PLANE", "http://127.0.0.1:8000")
CONTROL_PLANE_KEY = os.environ.get("PEP_CONTROL_PLANE_KEY", "")
SERVER_NAME = os.environ.get("PEP_MCP_SERVER_NAME", "mcphub")
DEFAULT_AGENT = os.environ.get("PEP_MCP_DEFAULT_AGENT", "mcp-agent")
TIMEOUT = float(os.environ.get("PEP_MCP_TIMEOUT", "120"))

#: Headers that belong to this hop and must not be relayed. Content-Length is
#: recomputed by httpx; forwarding the client's would describe the wrong body
#: whenever arguments are redacted.
_HOP_BY_HOP = frozenset(
    {"host", "content-length", "connection", "keep-alive", "transfer-encoding", "accept-encoding"}
)

#: Methods that carry no governable payload. Forwarded without a decision --
#: the handshake has to work before anything can be governed, and asking the
#: control plane about a ping is noise in the audit log.
_TRANSPARENT = frozenset(
    {"initialize", "ping", "completion/complete", "logging/setLevel", "resources/templates/list"}
)


class _Refused(Exception):
    """This proxy will not carry out the call, whatever the control plane said.

    Kept distinct from a denial so the outcome reported is "refused" rather than
    a silent success: an enforcement point that cannot do what it was permitted
    to do is exactly the case the outcome record exists to surface.
    """

    def __init__(self, message: str, *, decision: Decision | None = None) -> None:
        super().__init__(message)
        self.decision = decision


@asynccontextmanager
async def lifespan(app: FastAPI):
    app.state.upstream = httpx.AsyncClient(timeout=TIMEOUT)
    app.state.cp = AsyncControlPlaneClient(CONTROL_PLANE, api_key=CONTROL_PLANE_KEY or None)
    try:
        yield
    finally:
        await app.state.upstream.aclose()
        await app.state.cp.aclose()


app = FastAPI(title="MCP governing proxy", lifespan=lifespan)


def _forward_headers(request: Request) -> dict[str, str]:
    headers = {k: v for k, v in request.headers.items() if k.lower() not in _HOP_BY_HOP}
    if UPSTREAM_AUTH:
        headers["authorization"] = UPSTREAM_AUTH
    return headers


def _return_headers(response: httpx.Response) -> dict[str, str]:
    """Relay the session id and content type; drop this hop's framing headers."""
    out = {}
    for name in ("mcp-session-id", "mcp-protocol-version"):
        if name in response.headers:
            out[name] = response.headers[name]
    return out


def _agent_of(request: Request) -> tuple[str, str]:
    return (
        request.headers.get("x-principal-id") or DEFAULT_AGENT,
        request.headers.get("x-principal-type") or "agent",
    )


def _decode(body: bytes, content_type: str) -> Any:
    """Read a JSON-RPC message out of a body that may be JSON or SSE."""
    text = body.decode("utf-8", errors="replace")
    if "text/event-stream" in content_type:
        events = list(iter_sse(text))
        return [e.json() for e in events]
    try:
        return json.loads(text)
    except ValueError:
        return None


def _content_text(result: Any) -> str:
    """The text a tool result carries, for classification.

    An MCP result is a list of typed content blocks. Only text blocks hold
    anything a classifier can read; an image is passed through untouched rather
    than being pretended about.
    """
    if not isinstance(result, Mapping):
        return ""
    blocks = result.get("content")
    if not isinstance(blocks, list):
        return ""
    parts = [
        str(b.get("text", "")) for b in blocks if isinstance(b, Mapping) and b.get("type") == "text"
    ]
    return "\n".join(p for p in parts if p)


def _rewrite_content(result: Any, replacement: str) -> Any:
    """Put governed text back into the block structure it came from.

    The blocks are rewritten in place rather than replaced with one big block:
    a client that indexes into content[] should still find what it expects, and
    the non-text blocks are none of our business.
    """
    if not isinstance(result, Mapping):
        return result
    blocks = result.get("content")
    if not isinstance(blocks, list):
        return result
    pieces = replacement.split("\n")
    out, i = [], 0
    for block in blocks:
        if isinstance(block, Mapping) and block.get("type") == "text":
            text = pieces[i] if i < len(pieces) else ""
            i += 1
            out.append({**block, "text": text})
        else:
            out.append(block)
    # Anything left over -- redaction that grew the line count -- is appended so
    # nothing is silently dropped.
    if i < len(pieces):
        tail = "\n".join(pieces[i:])
        if tail:
            out.append({"type": "text", "text": tail})
    return {**result, "content": out}


async def _post_upstream(request: Request, body: bytes) -> httpx.Response:
    client: httpx.AsyncClient = request.app.state.upstream
    return await client.post(UPSTREAM, content=body, headers=_forward_headers(request))


def _passthrough(upstream: httpx.Response) -> Response:
    return Response(
        content=upstream.content,
        status_code=upstream.status_code,
        media_type=upstream.headers.get("content-type"),
        headers=_return_headers(upstream),
    )


def _as_wire(upstream: httpx.Response, message: Any) -> Response:
    """Render a rewritten message in whichever framing the upstream used."""
    content_type = upstream.headers.get("content-type", "application/json")
    if "text/event-stream" in content_type:
        body = encode_sse(SSEEvent(data=json.dumps(message)))
        return Response(
            content=body,
            status_code=upstream.status_code,
            media_type="text/event-stream",
            headers=_return_headers(upstream),
        )
    return JSONResponse(
        content=message, status_code=upstream.status_code, headers=_return_headers(upstream)
    )


def _deny_response(request_id: Any, decision: Decision, reason: str) -> Response:
    """A refusal the agent's own runtime will understand.

    A JSON-RPC error, not an HTTP error: an HTTP 403 kills the session, while an
    error carrying the request's id is a normal, recoverable answer to one call.
    The decision id travels with it so the refusal is traceable to the record
    that caused it.
    """
    return JSONResponse(
        content=rpc_error(
            request_id,
            POLICY_DENIED,
            reason,
            {"decision_id": decision.decision_id} if decision.decision_id else None,
        )
    )


@app.get("/healthz")
async def healthz() -> dict[str, str]:
    return {"status": "ok"}


@app.post("/mcp")
async def mcp(request: Request) -> Response:
    body = await request.body()
    try:
        message = json.loads(body.decode("utf-8"))
    except (ValueError, UnicodeDecodeError):
        # Not something we can read. The upstream is entitled to its own opinion.
        return _passthrough(await _post_upstream(request, body))

    method = rpc_method(message)
    if method is None or is_notification(message) or method in _TRANSPARENT:
        return _passthrough(await _post_upstream(request, body))
    if method == "tools/list":
        return await _governed_listing(request, body, message)
    if method == "tools/call":
        return await _governed_call(request, body, message)
    return _passthrough(await _post_upstream(request, body))


@app.get("/mcp")
async def mcp_stream(request: Request) -> Response:
    """The server-to-client channel. Nothing here originates from the agent."""
    client: httpx.AsyncClient = request.app.state.upstream
    upstream = await client.get(UPSTREAM, headers=_forward_headers(request))
    return _passthrough(upstream)


@app.delete("/mcp")
async def mcp_end(request: Request) -> Response:
    client: httpx.AsyncClient = request.app.state.upstream
    upstream = await client.delete(UPSTREAM, headers=_forward_headers(request))
    return _passthrough(upstream)


async def _governed_listing(request: Request, body: bytes, message: Any) -> Response:
    """Forward the listing, then remove tools this agent may not call.

    Asked with persist=False, which is the important part. Filtering a listing
    is advisory: nothing is carried out, no data moves, and the real enforcement
    happens at the call, which an agent can make for a tool it was never shown.
    Recording these as decisions looked right and was not -- against a gateway
    fronting 118 tools, one tools/list wrote 360 records with no outcome on any
    of them, twenty times the volume of the calls themselves. That buries the
    "unreported" filter, which exists to make an enforcement point that stopped
    reporting visible, under advisory questions that never had an outcome to
    report. Better a quiet audit log that means something.

    apply_obligations=False for the same reason: there is nothing to discharge.
    """
    upstream = await _post_upstream(request, body)
    if upstream.status_code >= 400:
        return _passthrough(upstream)
    decoded = _decode(upstream.content, upstream.headers.get("content-type", ""))
    messages = decoded if isinstance(decoded, list) else [decoded]
    reply = next((m for m in messages if rpc_id(m) == rpc_id(message)), None)
    if not isinstance(reply, Mapping) or "result" not in reply:
        return _passthrough(upstream)
    tools = reply["result"].get("tools")
    if not isinstance(tools, list):
        return _passthrough(upstream)

    agent, agent_type = _agent_of(request)
    cp: AsyncControlPlaneClient = request.app.state.cp
    allowed = []
    for tool in tools:
        name = str(tool.get("name", ""))
        if not name:
            continue
        action = infer_action(name, declared_action(tool.get("annotations") or {}))
        decision = await cp.decide(
            principal_id=agent,
            principal_type=agent_type,
            action=action,
            resource_urn=f"mcp://{SERVER_NAME}/{name}",
            resource_kind="tool",
            context={"channel": "mcp", "direction": "list", "server": SERVER_NAME},
            apply_obligations=False,
            persist=False,
        )
        if decision.allowed:
            allowed.append(tool)
    filtered = {**reply, "result": {**reply["result"], "tools": allowed}}
    return _as_wire(upstream, filtered)


async def _governed_call(request: Request, body: bytes, message: Any) -> Response:
    agent, agent_type = _agent_of(request)
    cp: AsyncControlPlaneClient = request.app.state.cp
    params = message.get("params") or {}
    name = str(params.get("name", ""))
    arguments = params.get("arguments")
    if not isinstance(arguments, Mapping):
        arguments = {}
    call = ToolCall(
        server=SERVER_NAME,
        tool=name,
        agent_id=agent,
        arguments=arguments,
        conversation_id=request.headers.get("mcp-session-id"),
    )

    inbound = await cp.decide(
        principal_id=agent,
        principal_type=agent_type,
        action=call.action,
        resource_urn=call.urn,
        resource_kind="tool",
        context={
            "channel": "mcp",
            "direction": "invoke",
            "server": SERVER_NAME,
            "tool": name,
        },
        payload=dict(arguments),
        correlation_id=call.conversation_id,
    )
    if not inbound.allowed:
        return _deny_response(rpc_id(message), inbound, inbound.reason or "denied by policy")

    try:
        async with cp.enforcing(inbound) as governed_arguments:
            forwarded = dict(message)
            forwarded["params"] = {**params, "arguments": governed_arguments}
            upstream = await _post_upstream(request, json.dumps(forwarded).encode())
            if upstream.status_code >= 400:
                raise _Refused(f"upstream returned {upstream.status_code}", decision=inbound)
    except ObligationUnsatisfied as exc:
        # An allow this proxy cannot honour is a refusal, not a pass. Reported
        # by `enforcing` on the way out, and the tool was never called.
        return _deny_response(rpc_id(message), inbound, str(exc))
    except _Refused as refused:
        return JSONResponse(
            content=rpc_error(rpc_id(message), INTERNAL_ERROR, str(refused)), status_code=200
        )

    decoded = _decode(upstream.content, upstream.headers.get("content-type", ""))
    messages = decoded if isinstance(decoded, list) else [decoded]
    reply = next((m for m in messages if rpc_id(m) == rpc_id(message)), None)
    if not isinstance(reply, Mapping) or "result" not in reply:
        # An error, or something we do not recognise. The call happened; there is
        # nothing of the tool's to govern on the way back.
        return _passthrough(upstream)

    text = _content_text(reply["result"])
    if not text:
        return _passthrough(upstream)

    outbound = await cp.decide(
        principal_id=agent,
        principal_type=agent_type,
        action="return",
        resource_urn=call.urn,
        resource_kind="tool",
        context={
            "channel": "mcp",
            "direction": "result",
            "server": SERVER_NAME,
            "tool": name,
        },
        payload=text,
        correlation_id=call.conversation_id,
    )
    if not outbound.allowed:
        # The call already happened. Withholding the result is still worth doing
        # -- it is the difference between the agent having the data and not --
        # but it cannot undo the side effect, and saying so is not optional.
        #
        # An agent runtime that reads this as "the call failed" may retry, and
        # for a tool with a side effect that means doing it twice. So the error
        # states plainly that the tool ran, and the denial is reported as
        # enforced rather than refused: the duty this proxy was given -- keep
        # the data from the agent -- was carried out in full.
        await cp.report_outcome(
            outbound,
            Outcome.ENFORCED,
            reason="result withheld from the agent; the call itself had already run",
        )
        return _deny_response(
            rpc_id(message),
            outbound,
            f"the tool ran, but its result is withheld: "
            f"{outbound.reason or 'denied by policy'}. Do not retry; "
            f"the call has already taken effect.",
        )

    try:
        async with cp.enforcing(outbound) as governed_text:
            if governed_text == text:
                return _passthrough(upstream)
            rewritten = {**reply, "result": _rewrite_content(reply["result"], str(governed_text))}
    except ObligationUnsatisfied as exc:
        # The call has already run. An obligation on the result that this proxy
        # cannot discharge means the result must not be handed over -- failing
        # open here would deliver exactly the data the obligation was protecting.
        return _deny_response(
            rpc_id(message),
            outbound,
            f"the tool ran, but its result cannot be delivered: {exc}. "
            f"Do not retry; the call has already taken effect.",
        )
    return _as_wire(upstream, rewritten)
