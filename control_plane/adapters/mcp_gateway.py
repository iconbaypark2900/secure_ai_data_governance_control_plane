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

__all__ = ["MCPAdapter", "ToolCall", "declared_action", "infer_action"]

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


def declared_action(annotations: Mapping[str, Any]) -> str | None:
    """What the server itself says a tool does, or None if it did not say.

    MCP defines four optional annotation hints. Only ``readOnlyHint`` was read
    before, which meant a tool the server explicitly flagged ``destructiveHint``
    fell through to guessing from its name -- and on a real gateway that
    misclassified six of the nine declared-destructive tools, ``git_reset`` and
    ``move_file`` among them.

    Two ordering decisions:

    A contradictory pair (read-only *and* destructive) resolves to the
    restrictive reading. Nothing sane emits that, but a governance layer should
    not need the server to be sane.

    ``readOnlyHint: false`` yields "write" rather than falling through to the
    name. The name is a weaker signal than an explicit declaration, and letting
    it win produced the inversion worth avoiding most: ``arxiv-get_paper_latex``
    is declared not-read-only, yet "get" would have classified it as a read.

    Absence is not read as destruction. The spec's prose says ``destructiveHint``
    defaults to true, but the SDK schema applies no default and real servers
    plainly do not set it deliberately: honouring that default would have marked
    five obviously non-destructive arxiv tools as deletions, and a ``delete``
    label that is usually wrong is one operators learn to ignore. The raw hint is
    stored alongside, so a stricter reading stays available to policy.
    """
    #: Not part of MCP. A local escape hatch for operators who post-process a
    #: listing to correct a server that annotates badly; no real server emits it.
    override = annotations.get("action")
    if override:
        return str(override)
    read_only = annotations.get("readOnlyHint")
    if annotations.get("destructiveHint") is True:
        return "delete"
    if read_only is True:
        return "read"
    if read_only is False:
        return "write"
    return None


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
            declared = declared_action(annotations)
            action = infer_action(name, declared)
            destructive_hint = annotations.get("destructiveHint")
            schema = entry.get("inputSchema") or {}
            properties = schema.get("properties") or {}
            discovered.append(
                DiscoveredAsset(
                    urn=self.urn_for(name),
                    name=name,
                    kind="tool",
                    description=str(entry.get("description", "")),
                    attributes={
                        "server": self.server,
                        "action": action,
                        # Whether the server told us or we guessed from the name.
                        # The spec calls annotations hints and warns that clients
                        # "should never make tool use decisions based on
                        # ToolAnnotations received from untrusted servers", so a
                        # server's self-description is recorded as an assertion,
                        # not laundered into a fact. A policy that cares can
                        # require action_source == "declared", or refuse to treat
                        # an unannotated tool as safe.
                        "action_source": "declared" if declared else "inferred",
                        "destructive": (
                            bool(destructive_hint)
                            if destructive_hint is not None
                            else action in {"write", "delete", "execute"}
                        ),
                        "read_only": annotations.get("readOnlyHint"),
                        # A tool that reaches outside the boundary is an egress
                        # path whether or not it is destructive: the arguments
                        # go somewhere we do not control.
                        "open_world": annotations.get("openWorldHint"),
                        "idempotent": annotations.get("idempotentHint"),
                        # 38 of 118 tools on a real gateway declared nothing at
                        # all. Being able to find those is the point of storing it.
                        "annotated": bool(annotations),
                        "parameters": sorted(str(k) for k in properties),
                    },
                )
            )
        return discovered
