"""MCP adapter: governing an agent's tools.

A Model Context Protocol server publishes tools; an agent calls them. Between
those two facts is the question this adapter puts to the control plane: may
*this* agent call *this* tool with *these* arguments right now?

The mapping is the whole trick, and it is small:

    tool                 -> resource  ``mcp://<server>/<tool>``
    the agent            -> principal
    the tool's operation -> action    read | write | execute | delete
    the arguments        -> payload   (classified, and possibly redacted)
    the result           -> payload   (classified again on the way back)

Both directions matter. Arguments carry data *to* a tool -- an agent that pastes
a customer record into a web-search query has exfiltrated it. Results carry data
*back* -- a file read returns whatever the file held, which the agent's own
prompt never disclosed.

Read-only: it decides, it does not proxy. Wiring it into a specific gateway is a
few lines at that gateway's call site, and is deliberately left there rather than
guessed at here.
"""

from __future__ import annotations

import re
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import Any

from control_plane.adapters.base import DiscoveredAsset

__all__ = ["MCPAdapter", "ToolCall", "infer_action"]

#: Tool-name prefixes that reliably indicate what a tool does. Matched longest
#: first, so ``list_`` does not shadow ``list_and_delete_``.
ACTION_PREFIXES: tuple[tuple[str, str], ...] = (
    ("delete", "delete"),
    ("remove", "delete"),
    ("drop", "delete"),
    ("truncate", "delete"),
    ("create", "write"),
    ("update", "write"),
    ("insert", "write"),
    ("write", "write"),
    ("append", "write"),
    ("edit", "write"),
    ("patch", "write"),
    ("upload", "write"),
    ("send", "write"),
    ("post", "write"),
    ("publish", "write"),
    ("execute", "execute"),
    ("run", "execute"),
    ("exec", "execute"),
    ("shell", "execute"),
    ("eval", "execute"),
    ("call", "execute"),
    ("invoke", "execute"),
    ("read", "read"),
    ("get", "read"),
    ("list", "read"),
    ("search", "read"),
    ("query", "read"),
    ("fetch", "read"),
    ("find", "read"),
    ("describe", "read"),
)

_WORD = re.compile(r"[a-z]+")


def infer_action(tool_name: str, declared: str | None = None) -> str:
    """Map a tool name to a governed action.

    A declared annotation from the server wins when present. Otherwise the name
    is the only signal available, and the default is ``execute`` -- the most
    restrictive reading, because a tool whose effects are unknown should not be
    treated as a read.
    """
    if declared:
        normalised = declared.strip().lower()
        if normalised in {"read", "write", "execute", "delete"}:
            return normalised

    words = _WORD.findall(tool_name.lower())
    for prefix, action in ACTION_PREFIXES:
        if any(word.startswith(prefix) for word in words):
            return action
    return "execute"


@dataclass(frozen=True, slots=True)
class ToolCall:
    """One tool invocation, in the form the control plane understands."""

    server: str
    tool: str
    agent_id: str
    arguments: Mapping[str, Any]
    declared_action: str | None = None
    conversation_id: str | None = None

    @property
    def urn(self) -> str:
        return f"mcp://{self.server}/{self.tool}"

    @property
    def action(self) -> str:
        return infer_action(self.tool, self.declared_action)

    def decide_request(self, *, direction: str = "invoke") -> dict[str, Any]:
        """The ``POST /v1/decide`` body for this call."""
        return {
            "principal": {"id": self.agent_id, "type": "agent"},
            "action": self.action,
            "resource": {"urn": self.urn, "kind": "tool"},
            "context": {
                "channel": "mcp",
                "server": self.server,
                "tool": self.tool,
                "direction": direction,
                "conversation_id": self.conversation_id,
            },
            # Arguments are the data leaving the agent. Classifying them is the
            # point: this is where an agent hands a customer record to a tool.
            "payload": dict(self.arguments),
            "correlation_id": self.conversation_id,
        }

    def result_request(self, result: Any) -> dict[str, Any]:
        """The decide body for what a tool returned.

        A separate question from whether the call was permitted. A file read may
        be allowed and its contents still not fit to reach the model.
        """
        return {
            "principal": {"id": self.agent_id, "type": "agent"},
            "action": "return",
            "resource": {"urn": self.urn, "kind": "tool"},
            "context": {
                "channel": "mcp",
                "server": self.server,
                "tool": self.tool,
                "direction": "result",
                "conversation_id": self.conversation_id,
            },
            "payload": result,
            "correlation_id": self.conversation_id,
        }


class MCPAdapter:
    """Turns an MCP server's tool listing into governable catalog assets."""

    name = "mcp"

    def __init__(self, server: str) -> None:
        self.server = server

    def urn_for(self, tool: str) -> str:
        return f"mcp://{self.server}/{tool}"

    def discover_from_listing(self, tools: Sequence[Mapping[str, Any]]) -> list[DiscoveredAsset]:
        """Convert an MCP ``tools/list`` response into catalog assets.

        Takes the listing rather than fetching it, so this works against any
        transport -- stdio, SSE, a gateway's REST shim -- without this module
        needing to know which.
        """
        discovered: list[DiscoveredAsset] = []
        for entry in tools:
            name = str(entry.get("name", "")).strip()
            if not name:
                continue
            annotations = entry.get("annotations") or {}
            declared = annotations.get("action") or (
                "read" if annotations.get("readOnlyHint") else None
            )
            action = infer_action(name, declared)
            discovered.append(
                DiscoveredAsset(
                    urn=self.urn_for(name),
                    name=name,
                    kind="tool",
                    description=str(entry.get("description", "")),
                    attributes={
                        "server": self.server,
                        "action": action,
                        "destructive": action in {"write", "delete", "execute"},
                        "parameters": sorted(
                            (entry.get("inputSchema") or {}).get("properties", {}).keys()
                        ),
                    },
                )
            )
        return discovered
