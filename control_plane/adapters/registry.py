"""Named, pre-configured data sources.

Discovery needs credentials for the system being catalogued. Those must not
travel in an API request body, so they are configured once, server-side, and
everything else refers to a source by name:

    cpctl catalog discover warehouse
    POST /v1/catalog/sources/warehouse/discover

Secrets are interpolated from the environment rather than written in the file,
so the configuration is safe to commit and the credentials live wherever the
deployment already keeps them::

    sources:
      - name: warehouse
        adapter: postgres
        dsn: ${WAREHOUSE_DSN}
        exclude: ["pg://audit.*", "pg://pg_*.*"]

Not every adapter is a *source*. ``postgres`` and ``qdrant`` enumerate and
sample, so they can be discovered from. ``mcp`` and ``librechat`` map identifiers
and build request bodies -- there is nothing to enumerate without a live client
session -- so naming one here is an error with an explanation rather than a
silent no-op.
"""

from __future__ import annotations

import os
import re
from pathlib import Path
from typing import Any, Literal

import yaml
from pydantic import BaseModel, ConfigDict, Field, field_validator

from control_plane.adapters.base import Adapter
from control_plane.adapters.postgres import PostgresAdapter
from control_plane.adapters.qdrant import QdrantAdapter

__all__ = [
    "DISCOVERABLE_ADAPTERS",
    "MAPPING_ADAPTERS",
    "SourceConfig",
    "SourceConfigError",
    "SourceRegistry",
    "UnknownSource",
]

#: Adapters that can enumerate and sample, and so can back a source.
DISCOVERABLE_ADAPTERS: frozenset[str] = frozenset({"postgres", "qdrant"})

#: Adapters that map identifiers and build request bodies. Useful, not sources.
MAPPING_ADAPTERS: frozenset[str] = frozenset({"mcp", "librechat"})

_PLACEHOLDER = re.compile(r"\$\{([A-Za-z_][A-Za-z0-9_]*)(?::-([^}]*))?\}")


class SourceConfigError(ValueError):
    """The sources file is malformed, or names something that cannot be a source."""


class UnknownSource(LookupError):
    """No source is configured under that name."""


def interpolate(value: Any) -> Any:
    """Expand ``${VAR}`` and ``${VAR:-default}`` from the environment.

    An unset variable with no default expands to an empty string rather than
    raising, so a partially configured file still loads and the failure surfaces
    where it is actionable -- at connection time, naming the source.
    """
    if isinstance(value, str):
        return _PLACEHOLDER.sub(lambda m: os.environ.get(m.group(1), m.group(2) or ""), value)
    if isinstance(value, dict):
        return {key: interpolate(item) for key, item in value.items()}
    if isinstance(value, list):
        return [interpolate(item) for item in value]
    return value


class SourceConfig(BaseModel):
    """One configured system to catalogue."""

    model_config = ConfigDict(extra="forbid")

    name: str = Field(min_length=1, max_length=64, pattern=r"^[a-z0-9][a-z0-9._\-]*$")
    adapter: Literal["postgres", "qdrant", "mcp", "librechat"]
    description: str = ""
    enabled: bool = True

    # --- connection ---------------------------------------------------------- #
    dsn: str | None = Field(default=None, description="postgres only")
    base_url: str | None = Field(default=None, description="qdrant only")
    api_key: str | None = Field(default=None, description="qdrant only")
    timeout: float = 10.0

    # --- discovery defaults -------------------------------------------------- #
    owner: str = Field(
        default="",
        description="Applied to every asset this source registers, so ownership "
        "is set at discovery rather than backfilled later.",
    )
    include: list[str] = Field(default_factory=list, description="URN globs to keep.")
    exclude: list[str] = Field(
        default_factory=list,
        description="URN globs to skip. Exclusion wins, and it is the right place "
        "to keep sampling away from an audit table or anything under legal hold.",
    )
    scan: bool = Field(
        default=False,
        description="Sample and classify by default. Off unless chosen: sampling "
        "reads real records.",
    )
    max_assets: int = Field(default=500, ge=1, le=50_000)
    sample_limit: int = Field(default=100, ge=1, le=10_000)
    min_confidence: float = Field(default=0.6, ge=0.0, le=1.0)

    @field_validator("adapter")
    @classmethod
    def _must_be_discoverable(cls, value: str) -> str:
        if value in MAPPING_ADAPTERS:
            raise ValueError(
                f"{value!r} is a mapping adapter, not a discoverable source: it "
                f"translates identifiers and builds decision requests, and has "
                f"nothing to enumerate without a live client session. Configurable "
                f"sources are: {', '.join(sorted(DISCOVERABLE_ADAPTERS))}"
            )
        return value

    #: The field each adapter cannot connect without.
    _REQUIRED_FIELD = {"postgres": "dsn", "qdrant": "base_url"}

    @property
    def configured(self) -> bool:
        """Whether this source has the connection details it needs.

        Checked here rather than at load time on purpose. Connection details
        come from the environment, and a file listing four sources should still
        load -- and still be listable -- when only two of their variables happen
        to be set in the shell you are standing in. The failure belongs at the
        moment someone tries to use the unconfigured one, where it can name what
        is missing.
        """
        field_name = self._REQUIRED_FIELD.get(self.adapter)
        return bool(field_name and getattr(self, field_name, None))

    @property
    def target(self) -> str:
        """Where this source points, safe to display."""
        if not self.configured:
            return "[not configured]"
        return "[configured]" if self.dsn else (self.base_url or "")

    def build(self) -> Adapter:
        """Instantiate the adapter this source describes."""
        if not self.configured:
            field_name = self._REQUIRED_FIELD.get(self.adapter, "connection details")
            raise SourceConfigError(
                f"source {self.name!r} has no {field_name}: the value is empty, "
                f"which usually means the environment variable it interpolates "
                f"from is unset in this process"
            )
        if self.adapter == "postgres":
            return PostgresAdapter(dsn=self.dsn)
        if self.adapter == "qdrant":
            return QdrantAdapter(
                base_url=self.base_url or "",
                api_key=self.api_key or None,
                timeout=self.timeout,
            )
        raise SourceConfigError(f"cannot build an adapter for {self.adapter!r}")

    def redacted(self) -> dict[str, Any]:
        """A view safe to return over the API or print to a terminal."""
        payload = self.model_dump(mode="json")
        for key in ("dsn", "api_key"):
            if payload.get(key):
                payload[key] = "[configured]"
        payload["target"] = self.target
        payload["configured"] = self.configured
        return payload


class SourceRegistry:
    """The configured sources, loaded from a file."""

    def __init__(self, sources: dict[str, SourceConfig] | None = None) -> None:
        self._sources: dict[str, SourceConfig] = dict(sources or {})

    def __len__(self) -> int:
        return len(self._sources)

    def __contains__(self, name: object) -> bool:
        return str(name) in self._sources

    @classmethod
    def from_file(cls, path: str | Path) -> SourceRegistry:
        """Load and validate a sources file.

        A missing file is an empty registry, not an error: running without
        configured sources is the normal state for a fresh deployment, and for
        anyone driving discovery from the CLI with explicit connection details.
        """
        target = Path(path)
        if not target.exists():
            return cls()
        try:
            document = yaml.safe_load(target.read_text()) or {}
        except yaml.YAMLError as exc:
            raise SourceConfigError(f"{target} is not valid YAML: {exc}") from exc
        return cls.from_document(document, origin=str(target))

    @classmethod
    def from_document(cls, document: Any, *, origin: str = "<memory>") -> SourceRegistry:
        if document is None:
            return cls()
        if isinstance(document, dict):
            # Either a wrapped document or an empty one. An empty file is a
            # deployment with no sources yet, which is not a misconfiguration.
            entries = document.get("sources") or []
        elif isinstance(document, list):
            entries = document
        else:
            raise SourceConfigError(
                f"{origin}: expected a list of sources, or an object with a "
                f"'sources' key; got {type(document).__name__}"
            )
        if not isinstance(entries, list):
            raise SourceConfigError(f"{origin}: 'sources' must be a list")

        sources: dict[str, SourceConfig] = {}
        for index, entry in enumerate(entries):
            try:
                config = SourceConfig.model_validate(interpolate(entry))
            except Exception as exc:
                raise SourceConfigError(f"{origin}: sources[{index}] is invalid: {exc}") from exc
            if config.name in sources:
                raise SourceConfigError(f"{origin}: duplicate source name {config.name!r}")
            sources[config.name] = config
        return cls(sources)

    def names(self, *, enabled_only: bool = False) -> list[str]:
        return sorted(
            name for name, config in self._sources.items() if config.enabled or not enabled_only
        )

    def all(self) -> list[SourceConfig]:
        return [self._sources[name] for name in self.names()]

    def get(self, name: str) -> SourceConfig:
        try:
            config = self._sources[name]
        except KeyError:
            known = ", ".join(self.names()) or "none are configured"
            raise UnknownSource(f"no source named {name!r}; known sources: {known}") from None
        return config
