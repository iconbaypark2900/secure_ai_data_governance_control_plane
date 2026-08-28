"""Version 1 of the HTTP API."""

from fastapi import APIRouter

from control_plane.api.v1 import admin, approvals, audit, catalog, decisions, policies

router = APIRouter()
router.include_router(decisions.router)
router.include_router(policies.router)
router.include_router(catalog.router)
router.include_router(audit.router)
router.include_router(approvals.router)
router.include_router(admin.router)

__all__ = ["router"]
