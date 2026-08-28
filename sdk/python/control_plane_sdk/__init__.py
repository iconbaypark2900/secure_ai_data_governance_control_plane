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
    safe_chunk = await client.enforce(decision)   # acts, and reports what it did

When a policy parks the request for a human, wait and re-send it unchanged:

    if decision.needs_approval:
        await client.await_approval(decision.approval_id, timeout=600)
        decision = await client.decide(..., approval_id=decision.approval_id)
"""

from control_plane_sdk.client import (
    ApprovalTimeout,
    AsyncControlPlaneClient,
    ControlPlaneClient,
    ControlPlaneError,
    ControlPlaneUnavailable,
    Decision,
    DecisionDenied,
    ObligationUnsatisfied,
    Outcome,
)

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

__version__ = "0.1.0"
