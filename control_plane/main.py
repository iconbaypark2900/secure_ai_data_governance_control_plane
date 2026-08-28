"""The FastAPI application.

Assembles the routers, installs middleware, and performs the small amount of
startup work the service needs: configure logging, verify the database answers,
and mint the bootstrap credential if one was configured.
"""

from __future__ import annotations

import time
import uuid
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Any

import structlog
from fastapi import FastAPI, Request, Response
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from sqlalchemy import select, text

from control_plane.api.v1 import router as v1_router
from control_plane.auth.keys import Scope, hash_key, split_key
from control_plane.config import Settings, get_settings
from control_plane.db import dispose_engine, get_sessionmaker
from control_plane.logging import configure_logging
from control_plane.models.auth import ApiKey
from control_plane.policy.operators import PolicyError
from control_plane.policy.store import PolicyStore

log = structlog.get_logger(__name__)

DESCRIPTION = """
A policy decision point and data governance control plane for AI systems.

Enforcement points -- a proxy in front of a model, a retrieval pipeline, an agent
runtime -- ask `POST /v1/decide` whether an action on data is permitted. The
control plane resolves what the data is, evaluates the policy set, returns an
effect and its obligations, and seals the whole thing into a tamper-evident
audit chain.

**Start here:** `POST /v1/decide` is the only endpoint an enforcement point needs.
`GET /v1/policies/schema` describes the policy language. `GET /v1/audit/verify`
proves the log has not been altered.
"""


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncIterator[None]:
    settings: Settings = get_settings()
    configure_logging(settings)
    log.info(
        "starting",
        service=settings.app_name,
        environment=str(settings.environment),
        default_effect=settings.default_effect,
        fail_closed=settings.fail_closed,
    )

    try:
        factory = get_sessionmaker()
        async with factory() as session:
            await session.execute(text("SELECT 1"))
            await _ensure_bootstrap_key(session, settings)
            await _warn_about_unusable_policies(session, settings)
            await session.commit()
    except Exception as exc:
        # Not fatal: the readiness probe reports the database as unavailable and
        # the orchestrator holds traffic back. Crashing here would turn a slow
        # database into a crash loop.
        log.error("startup_database_check_failed", error=str(exc))

    yield

    await dispose_engine()
    log.info("stopped")


async def _ensure_bootstrap_key(session: Any, settings: Settings) -> None:
    """Install the configured bootstrap admin key if it is not already present.

    Solves the first-run problem -- every endpoint needs a key, and keys are
    issued through an endpoint. Configuring ``CP_BOOTSTRAP_ADMIN_KEY`` creates
    exactly one admin credential; leaving it unset skips this entirely.
    """
    secret = settings.bootstrap_admin_key.get_secret_value()
    if not secret:
        return
    parts = split_key(secret)
    if parts is None:
        log.error(
            "bootstrap_key_malformed",
            hint="CP_BOOTSTRAP_ADMIN_KEY must look like cpk_<prefix>_<secret>",
        )
        return
    prefix, _ = parts
    existing = (
        await session.execute(select(ApiKey).where(ApiKey.prefix == prefix))
    ).scalar_one_or_none()
    if existing is not None:
        return
    session.add(
        ApiKey(
            name="bootstrap-admin",
            description="Created at startup from CP_BOOTSTRAP_ADMIN_KEY.",
            prefix=prefix,
            key_hash=hash_key(secret),
            scopes=[Scope.ADMIN],
            created_by="bootstrap",
        )
    )
    log.warning(
        "bootstrap_admin_key_created",
        prefix=prefix,
        hint="Issue scoped keys and revoke this one.",
    )


async def _warn_about_unusable_policies(session: Any, settings: Settings) -> None:
    """Say at boot if a stored policy asks for something this process cannot do.

    A policy requiring the ``tokenize`` strategy on a deployment with no
    tokenisation key will deny every request it matches. That is the correct
    behaviour and a miserable way to discover a missing environment variable --
    so it is stated once, loudly, at startup rather than only in the reason
    string of each denial.
    """
    if settings.tokenization_enabled:
        return
    try:
        policies, _ = await PolicyStore(session).load_policies_with_errors(enabled_only=True)
    except Exception as exc:
        log.debug("policy_precheck_skipped", error=str(exc))
        return

    affected = sorted(
        policy.key
        for policy in policies
        for obligation in policy.redaction_obligations
        if str(obligation.to_dict().get("strategy", "")).lower() == "tokenize"
    )
    if affected:
        log.error(
            "tokenization_key_missing",
            policies=affected,
            impact="every request these policies match will be denied",
            hint="set CP_TOKENIZATION_KEY, or change the redaction strategy",
        )


def create_app(settings: Settings | None = None) -> FastAPI:
    """Build the application."""
    settings = settings or get_settings()

    app = FastAPI(
        title="Secure AI Data Governance Control Plane",
        description=DESCRIPTION,
        version="0.1.0",
        lifespan=lifespan,
        docs_url="/docs" if settings.docs_enabled else None,
        redoc_url="/redoc" if settings.docs_enabled else None,
        openapi_url="/openapi.json" if settings.docs_enabled else None,
    )

    if settings.cors_origins:
        app.add_middleware(
            CORSMiddleware,
            allow_origins=settings.cors_origins,
            allow_credentials=True,
            allow_methods=["GET", "POST", "PUT", "DELETE", "OPTIONS"],
            allow_headers=["Authorization", "Content-Type", "X-API-Key"],
        )

    @app.middleware("http")
    async def request_context(request: Request, call_next: Any) -> Response:
        """Attach a request id, time the request, and keep both in every log line."""
        request_id = request.headers.get("x-request-id") or str(uuid.uuid4())
        structlog.contextvars.bind_contextvars(
            request_id=request_id, path=request.url.path, method=request.method
        )
        started = time.perf_counter()
        try:
            response = await call_next(request)
        finally:
            structlog.contextvars.unbind_contextvars("request_id", "path", "method")
        duration_ms = round((time.perf_counter() - started) * 1000, 3)
        response.headers["x-request-id"] = request_id
        response.headers["x-response-time-ms"] = str(duration_ms)
        return response

    @app.exception_handler(PolicyError)
    async def policy_error_handler(_request: Request, exc: PolicyError) -> JSONResponse:
        """A malformed policy is the author's error, not a server fault."""
        return JSONResponse(status_code=422, content={"detail": str(exc)})

    @app.get("/", include_in_schema=False)
    async def root() -> dict[str, Any]:
        return {
            "service": settings.app_name,
            "version": "0.1.0",
            "docs": "/docs" if settings.docs_enabled else None,
            "console": "/console",
            "decide": f"{settings.api_prefix}/decide",
            "health": f"{settings.api_prefix}/health",
        }

    app.include_router(v1_router, prefix=settings.api_prefix)
    _mount_console(app)
    return app


def _mount_console(app: FastAPI) -> None:
    """Serve the built admin UI at /console, if it has been built.

    Optional on purpose. The API is the product and must run without a UI
    present -- in a container that only built the backend, or in a deployment
    that serves the console from a CDN. Mounting is skipped rather than fatal
    when ``ui/dist`` is absent.
    """
    dist = Path(__file__).resolve().parent.parent / "ui" / "dist"
    if not (dist / "index.html").exists():
        log.info("console_not_mounted", reason="ui/dist not built", path=str(dist))
        return

    assets = dist / "assets"
    if assets.is_dir():
        app.mount("/console/assets", StaticFiles(directory=assets), name="console-assets")

    index = (dist / "index.html").read_text(encoding="utf-8")
    # Vite emits absolute /assets/... URLs; the console lives under /console.
    index = index.replace('"/assets/', '"/console/assets/')

    @app.get("/console", include_in_schema=False)
    @app.get("/console/{path:path}", include_in_schema=False)
    async def console(path: str = "") -> HTMLResponse:
        # A single-page app: every path under /console returns the same
        # document and the client router takes it from there.
        return HTMLResponse(index)

    log.info("console_mounted", path="/console")


app = create_app()
