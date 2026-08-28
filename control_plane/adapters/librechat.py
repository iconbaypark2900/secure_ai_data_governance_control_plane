"""LibreChat adapter.

LibreChat is a chat front end: users hold conversations with models, upload
files, and build retrieval collections from them. Three things there are worth
governing, and each maps onto something the control plane already understands:

    a user or an agent      -> principal
    an uploaded file or a
    vector store built
    from it                 -> data asset
    a message heading to
    a model provider        -> an ``infer`` decision with destination=external

The uploaded-file case is the one that motivates this. A file a user drops into
a conversation has no owner, no classification, and no retention policy, and it
is about to be embedded and retained. Registering it as an asset at upload time
is what makes it governable at all.

This module maps identifiers and builds request bodies. It does not reach into
LibreChat's database: that schema is not ours, and coupling to it would break on
their next migration. The integration point is LibreChat's own hook or a proxy
in front of it.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import Any

from control_plane.adapters.base import DiscoveredAsset

__all__ = ["ChatTurn", "LibreChatAdapter"]

#: Providers whose models run outside the organisation's boundary. Policies key
#: on the resulting ``destination`` to separate "our GPU" from "someone else's".
EXTERNAL_ENDPOINTS = frozenset(
    {"openai", "anthropic", "google", "azureopenai", "bedrock", "vertexai", "groq", "mistral"}
)


@dataclass(frozen=True, slots=True)
class ChatTurn:
    """One message on its way to a model."""

    user_id: str
    conversation_id: str
    endpoint: str
    model: str
    text: str
    #: File ids attached to this turn, already registered as assets.
    attachments: tuple[str, ...] = ()
    agent_id: str | None = None

    @property
    def principal_id(self) -> str:
        """An agent acts on its own behalf; otherwise the user does."""
        return f"agent:{self.agent_id}" if self.agent_id else f"user:{self.user_id}"

    @property
    def principal_type(self) -> str:
        return "agent" if self.agent_id else "user"

    @property
    def destination(self) -> str:
        return "external" if self.endpoint.lower() in EXTERNAL_ENDPOINTS else "internal"

    def decide_request(self) -> dict[str, Any]:
        """The decide body for sending this turn to the model."""
        return {
            "principal": {"id": self.principal_id, "type": self.principal_type},
            "action": "infer",
            "resource": {
                "urn": f"model://{self.endpoint}/{self.model}",
                "kind": "model",
                "attributes": {"attachments": list(self.attachments)},
            },
            "context": {
                "channel": "librechat",
                "destination": self.destination,
                "endpoint": self.endpoint,
                "model": self.model,
                "conversation_id": self.conversation_id,
            },
            "payload": self.text,
            "correlation_id": self.conversation_id,
        }


class LibreChatAdapter:
    """Maps LibreChat entities onto control-plane identifiers."""

    name = "librechat"

    def __init__(self, instance: str = "librechat") -> None:
        self.instance = instance

    def file_urn(self, file_id: str) -> str:
        return f"librechat://{self.instance}/files/{file_id}"

    def vector_store_urn(self, store_id: str) -> str:
        return f"librechat://{self.instance}/vector_stores/{store_id}"

    def model_urn(self, endpoint: str, model: str) -> str:
        return f"model://{endpoint}/{model}"

    def principal_for_user(self, user_id: str) -> str:
        return f"user:{user_id}"

    def principal_for_agent(self, agent_id: str) -> str:
        return f"agent:{agent_id}"

    def asset_for_upload(
        self,
        file_id: str,
        *,
        filename: str,
        uploaded_by: str,
        content_type: str = "",
        size_bytes: int = 0,
        conversation_id: str | None = None,
    ) -> DiscoveredAsset:
        """Register an uploaded file so it becomes a governable asset.

        Called at upload time. A file that is embedded before it is registered
        is retained under no policy at all, and the retrieval collection built
        from it inherits that absence.
        """
        return DiscoveredAsset(
            urn=self.file_urn(file_id),
            name=filename,
            kind="file",
            owner=uploaded_by,
            description=f"Uploaded to LibreChat by {uploaded_by}.",
            attributes={
                "content_type": content_type,
                "size_bytes": size_bytes,
                "conversation_id": conversation_id,
                "instance": self.instance,
                # Nothing has looked at it yet. A policy can key on this to
                # refuse retrieval until it has been classified.
                "classified": False,
            },
        )

    def assets_for_agents(self, agents: Sequence[Mapping[str, Any]]) -> list[DiscoveredAsset]:
        """Turn a LibreChat agent listing into catalog assets.

        Agents are governable in two ways at once: as principals that make
        requests, and as assets, because an agent's system prompt and attached
        files are themselves data somebody owns.
        """
        discovered: list[DiscoveredAsset] = []
        for agent in agents:
            agent_id = str(agent.get("id") or agent.get("_id") or "").strip()
            if not agent_id:
                continue
            discovered.append(
                DiscoveredAsset(
                    urn=f"librechat://{self.instance}/agents/{agent_id}",
                    name=str(agent.get("name", agent_id)),
                    kind="agent",
                    owner=str(agent.get("author", "")),
                    description=str(agent.get("description", "")),
                    attributes={
                        "provider": agent.get("provider"),
                        "model": agent.get("model"),
                        "tools": list(agent.get("tools") or []),
                        "instance": self.instance,
                    },
                )
            )
        return discovered
