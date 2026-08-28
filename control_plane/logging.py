"""Structured logging.

JSON in deployment so records are queryable, human-readable in a terminal.
Either way the same processors run, so a field present locally is present in
production.
"""

from __future__ import annotations

import logging
import sys
from typing import Any

import structlog

from control_plane.config import Settings

#: Keys whose values are never logged, wherever they appear in an event dict.
REDACT_KEYS = frozenset(
    {"password", "api_key", "apikey", "authorization", "token", "secret", "key", "payload"}
)


def _scrub(_logger: Any, _method: str, event: dict[str, Any]) -> dict[str, Any]:
    """Drop credential-shaped fields before a record is emitted.

    Log statements are written by people in a hurry. This makes the careless
    ``log.info("decision", **request_body)`` safe by default rather than a leak.
    """
    for key in list(event):
        if key.lower() in REDACT_KEYS and event[key] is not None:
            event[key] = "[redacted]"
    return event


def configure_logging(settings: Settings) -> None:
    """Install the logging configuration for this process."""
    level = getattr(logging, settings.log_level.upper(), logging.INFO)
    logging.basicConfig(format="%(message)s", stream=sys.stdout, level=level)

    processors: list[Any] = [
        structlog.contextvars.merge_contextvars,
        structlog.processors.add_log_level,
        structlog.processors.TimeStamper(fmt="iso", utc=True),
        _scrub,
        structlog.processors.StackInfoRenderer(),
        structlog.processors.format_exc_info,
    ]
    processors.append(
        structlog.processors.JSONRenderer()
        if settings.log_json
        else structlog.dev.ConsoleRenderer(colors=True)
    )

    structlog.configure(
        processors=processors,
        wrapper_class=structlog.make_filtering_bound_logger(level),
        logger_factory=structlog.PrintLoggerFactory(),
        cache_logger_on_first_use=True,
    )
