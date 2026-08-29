"""A minimal MCP server, for testing a proxy that sits in front of one.

Speaks enough of streamable HTTP to exercise the governing proxy: initialize
with a session id, tools/list, tools/call, and notifications. It answers in SSE
because that is what the real gateway does, and framing is the part most likely
to break.

Deliberately not a mock of the proxy's own view of the world -- it is a server,
and the proxy has to talk to it the way it would talk to any other.
"""

from __future__ import annotations

import json
import uuid
from typing import Any

from fastapi import FastAPI, Request, Response
from fastapi.responses import JSONResponse

#: One tool per shape the proxy has to handle: a read whose result is clean, a
#: read whose result is not, a declared-destructive write, and one with no
#: annotations at all.
TOOLS: list[dict[str, Any]] = [
    {
        "name": "read_notes",
        "description": "Read a note.",
        "annotations": {"readOnlyHint": True, "openWorldHint": False},
        "inputSchema": {"type": "object", "properties": {"id": {"type": "string"}}},
    },
    {
        "name": "read_patient_file",
        "description": "Read a patient record.",
        "annotations": {"readOnlyHint": True, "openWorldHint": False},
        "inputSchema": {"type": "object", "properties": {"id": {"type": "string"}}},
    },
    {
        "name": "delete_record",
        "description": "Delete a record.",
        "annotations": {"readOnlyHint": False, "destructiveHint": True},
        "inputSchema": {"type": "object", "properties": {"id": {"type": "string"}}},
    },
    {
        "name": "frobnicate",
        "description": "Unannotated, so the proxy must guess conservatively.",
        "inputSchema": {"type": "object", "properties": {}},
    },
]

RESULTS: dict[str, list[dict[str, Any]]] = {
    "read_notes": [{"type": "text", "text": "Quarterly revenue was up."}],
    "read_patient_file": [
        {"type": "text", "text": "Maria Alvarez, SSN 501-72-9384, mrn 4419772."},
        {"type": "image", "data": "aGVsbG8=", "mimeType": "image/png"},
        {"type": "text", "text": "Contact maria.alvarez@clinic.example."},
    ],
    "delete_record": [{"type": "text", "text": "deleted"}],
    "frobnicate": [{"type": "text", "text": "frobnicated"}],
}

app = FastAPI()
#: Every call that reached this server, so a test can assert a denied call never
#: arrived -- the difference between refusing an action and merely hiding it.
app.state.calls = []


def _sse(message: Any) -> Response:
    body = f"event: message\ndata: {json.dumps(message)}\n\n"
    return Response(content=body, media_type="text/event-stream")


@app.post("/mcp")
async def mcp(request: Request) -> Response:
    raw = await request.body()
    try:
        message = json.loads(raw)
    except (ValueError, UnicodeDecodeError):
        # What a real server does with a body it cannot read: a parse error, not
        # a crash. The proxy is entitled to forward anything.
        return JSONResponse(
            {"jsonrpc": "2.0", "id": None, "error": {"code": -32700, "message": "parse error"}},
            status_code=400,
        )
    if not isinstance(message, dict):
        return JSONResponse(
            {"jsonrpc": "2.0", "id": None, "error": {"code": -32600, "message": "invalid"}},
            status_code=400,
        )
    method = message.get("method")
    mid = message.get("id")

    if mid is None:
        return Response(status_code=202)

    if method == "initialize":
        response = _sse(
            {
                "jsonrpc": "2.0",
                "id": mid,
                "result": {
                    "protocolVersion": "2025-06-18",
                    "capabilities": {"tools": {"listChanged": True}},
                    "serverInfo": {"name": "fake-mcp", "version": "1.0.0"},
                },
            }
        )
        response.headers["Mcp-Session-Id"] = str(uuid.uuid4())
        return response

    if method == "tools/list":
        return _sse({"jsonrpc": "2.0", "id": mid, "result": {"tools": TOOLS}})

    if method == "tools/call":
        params = message.get("params") or {}
        name = params.get("name", "")
        app.state.calls.append({"tool": name, "arguments": params.get("arguments")})
        if name not in RESULTS:
            return _sse(
                {"jsonrpc": "2.0", "id": mid, "error": {"code": -32602, "message": "no such tool"}}
            )
        return _sse(
            {"jsonrpc": "2.0", "id": mid, "result": {"content": RESULTS[name], "isError": False}}
        )

    return JSONResponse({"jsonrpc": "2.0", "id": mid, "error": {"code": -32601, "message": method}})


@app.get("/healthz")
async def healthz() -> dict[str, str]:
    return {"status": "ok"}
