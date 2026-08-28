"""Client library for the Secure AI Data Governance Control Plane.

An enforcement point is whatever sits on the data path -- a retrieval pipeline,
a model proxy, an agent's tool dispatcher. Its job is small: ask before acting,
and honour the answer.

    from control_plane_sdk import ControlPlaneClient, DecisionDenied

    client = ControlPlaneClient(base_url="http://localhost:8000", api_key=KEY)

    decision = await client.decide(
        principal_id="agent:support_bot",
        principal_type="agent",
        action="read",
        resource_urn="qdrant://kb_docs",
        payload=retrieved_chunk,
    )
    if not decision.allowed:
        raise DecisionDenied(decision)
    safe_chunk = decision.payload   # obligations already applied
"""

from control_plane_sdk.client import (
    AsyncControlPlaneClient,
    ControlPlaneClient,
    ControlPlaneError,
    ControlPlaneUnavailable,
    Decision,
    DecisionDenied,
    ObligationUnsatisfied,
)

__all__ = [
    "AsyncControlPlaneClient",
    "ControlPlaneClient",
    "ControlPlaneError",
    "ControlPlaneUnavailable",
    "Decision",
    "DecisionDenied",
    "ObligationUnsatisfied",
]

__version__ = "0.1.0"
