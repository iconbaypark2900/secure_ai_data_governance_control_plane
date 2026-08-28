"""Adapters connecting the control plane to systems that hold data.

Each adapter discovers assets and samples content. None of them enforce:
enforcement belongs on the data path, at the enforcement point.
"""

from control_plane.adapters.base import (
    Adapter,
    AdapterError,
    AdapterUnavailable,
    DiscoveredAsset,
    Sample,
)
from control_plane.adapters.librechat import ChatTurn, LibreChatAdapter
from control_plane.adapters.mcp_gateway import MCPAdapter, ToolCall, infer_action
from control_plane.adapters.postgres import PostgresAdapter
from control_plane.adapters.qdrant import QdrantAdapter
from control_plane.adapters.registry import (
    DISCOVERABLE_ADAPTERS,
    MAPPING_ADAPTERS,
    SourceConfig,
    SourceConfigError,
    SourceRegistry,
    UnknownSource,
)

__all__ = [
    "DISCOVERABLE_ADAPTERS",
    "MAPPING_ADAPTERS",
    "Adapter",
    "AdapterError",
    "AdapterUnavailable",
    "ChatTurn",
    "DiscoveredAsset",
    "LibreChatAdapter",
    "MCPAdapter",
    "PostgresAdapter",
    "QdrantAdapter",
    "Sample",
    "SourceConfig",
    "SourceConfigError",
    "SourceRegistry",
    "ToolCall",
    "UnknownSource",
    "infer_action",
]
