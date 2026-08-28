"""SQLAlchemy models.

Importing this package registers every table on :class:`Base.metadata`, which is
what Alembic autogeneration and the test-database fixture rely on.
"""

from control_plane.models.audit import AuditRecordRow
from control_plane.models.auth import ApiKey
from control_plane.models.base import Base, TimestampMixin, UUIDPrimaryKey, utcnow
from control_plane.models.catalog import AssetClassification, DataAsset, Principal
from control_plane.models.decision import ApprovalRequest, DecisionRecord
from control_plane.models.policy import PolicyRecord, PolicyVersion

__all__ = [
    "ApiKey",
    "ApprovalRequest",
    "AssetClassification",
    "AuditRecordRow",
    "Base",
    "DataAsset",
    "DecisionRecord",
    "PolicyRecord",
    "PolicyVersion",
    "Principal",
    "TimestampMixin",
    "UUIDPrimaryKey",
    "utcnow",
]
