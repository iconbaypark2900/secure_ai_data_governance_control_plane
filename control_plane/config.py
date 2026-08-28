"""Runtime configuration.

Every value is settable through the environment with a ``CP_`` prefix, so the
same image runs in a test harness, in docker compose, and in a cluster without a
code change. Defaults are chosen to be safe rather than convenient: the policy
engine denies by default, and secrets have no usable default at all.
"""

from __future__ import annotations

import secrets
from enum import StrEnum
from functools import lru_cache
from typing import Any

from pydantic import Field, SecretStr, field_validator, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Environment(StrEnum):
    LOCAL = "local"
    TEST = "test"
    STAGING = "staging"
    PRODUCTION = "production"


class Settings(BaseSettings):
    """Process-wide settings, loaded once and cached."""

    model_config = SettingsConfigDict(
        env_prefix="CP_",
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
        case_sensitive=False,
    )

    # --- Service identity -------------------------------------------------- #
    app_name: str = "secure-ai-data-governance-control-plane"
    environment: Environment = Environment.LOCAL
    debug: bool = False
    log_level: str = "INFO"
    log_json: bool = True

    # --- Storage ----------------------------------------------------------- #
    database_url: str = Field(
        default="postgresql+asyncpg://control_plane:control_plane@localhost:5432/control_plane",
        description="SQLAlchemy async DSN. Use sqlite+aiosqlite:// for tests.",
    )
    db_pool_size: int = 10
    db_max_overflow: int = 20
    db_echo: bool = False

    # --- Policy decisions -------------------------------------------------- #
    default_effect: str = Field(
        default="deny",
        description="Effect when no policy matches. Deny-by-default is the secure "
        "posture; set to 'allow' only for a permissive observation rollout.",
    )
    policy_cache_ttl_seconds: int = Field(
        default=30,
        description="How long the compiled policy set is cached in-process. "
        "Bounds how long another process's policy edit stays invisible; writes "
        "through this process invalidate it immediately.",
    )
    max_scan_chars: int = Field(
        default=1_000_000,
        description="Ceiling on how much of a payload is classified. A larger "
        "payload is scanned up to this point and reported as truncated, so a "
        "clean result is never mistaken for a complete one.",
    )
    #: Fail closed if the policy engine errors. Turning this off trades safety for uptime.
    fail_closed: bool = True

    # --- Data sources -------------------------------------------------------- #
    sources_file: str = Field(
        default="sources.yaml",
        description="Named systems the catalog can discover from. Absent is fine: "
        "a deployment with no configured sources is the normal starting state.",
    )

    # --- Cryptographic material -------------------------------------------- #
    redaction_hmac_key: SecretStr = Field(
        default=SecretStr(""),
        description="Key for deterministic pseudonymisation. Rotating it breaks "
        "the ability to join previously hashed values.",
    )
    audit_hmac_key: SecretStr = Field(
        default=SecretStr(""),
        description="Key sealing the audit hash chain. Without it the chain proves "
        "only ordering, not authenticity.",
    )
    tokenization_key: SecretStr = Field(
        default=SecretStr(""),
        description="Key for reversible tokenisation. The token is the ciphertext, "
        "so this key is the entire security boundary: losing it makes every "
        "existing token permanently irreversible. Required only if a policy "
        "actually uses the 'tokenize' strategy.",
    )
    tokenization_previous_keys: str = Field(
        default="",
        description="Comma-separated keys retired by rotation, newest first. Used "
        "for reading old tokens only; new ones are always minted with the current "
        "key. Without these, rotating breaks every token issued before it.",
    )

    # --- API surface ------------------------------------------------------- #
    api_prefix: str = "/v1"
    cors_origins: list[str] = Field(default_factory=lambda: ["http://localhost:5173"])
    docs_enabled: bool = True
    metrics_enabled: bool = Field(
        default=True,
        description="Serve Prometheus metrics at /metrics. Unauthenticated by "
        "convention, so restrict it at the network layer rather than exposing "
        "the port publicly.",
    )
    #: When set, unauthenticated requests are accepted. Local development only.
    auth_disabled: bool = False
    bootstrap_admin_key: SecretStr = Field(default=SecretStr(""))

    @field_validator("default_effect")
    @classmethod
    def _validate_default_effect(cls, value: str) -> str:
        allowed = {"allow", "deny"}
        normalised = value.strip().lower()
        if normalised not in allowed:
            raise ValueError(f"default_effect must be one of {sorted(allowed)}")
        return normalised

    @field_validator("cors_origins", mode="before")
    @classmethod
    def _split_origins(cls, value: Any) -> Any:
        if isinstance(value, str):
            return [item.strip() for item in value.split(",") if item.strip()]
        return value

    @model_validator(mode="after")
    def _enforce_production_hygiene(self) -> Settings:
        """Refuse to start a production process that is missing its secrets.

        A control plane that silently generates an ephemeral audit key would
        produce a hash chain that verifies today and fails after any restart.
        Better to fail loudly at boot.
        """
        if self.environment is Environment.PRODUCTION:
            missing = [
                name
                for name in ("redaction_hmac_key", "audit_hmac_key")
                if not getattr(self, name).get_secret_value()
            ]
            if missing:
                raise ValueError(
                    "these settings must be set in production: "
                    + ", ".join(f"CP_{m.upper()}" for m in missing)
                )
            if self.auth_disabled:
                raise ValueError("CP_AUTH_DISABLED cannot be true in production")
            if self.debug:
                raise ValueError("CP_DEBUG cannot be true in production")
        return self

    @property
    def is_production(self) -> bool:
        return self.environment is Environment.PRODUCTION

    def redaction_key_bytes(self) -> bytes:
        """The pseudonymisation key, with a dev fallback outside production."""
        return self._key_bytes("redaction_hmac_key")

    @property
    def tokenization_enabled(self) -> bool:
        """Whether reversible tokenisation is configured.

        Unlike the other keys this one has no development fallback. An ephemeral
        tokenisation key would mint tokens that stop reversing at the next
        restart, which is worse than refusing: the failure would show up later,
        somewhere else, as data that cannot be recovered.
        """
        return bool(self.tokenization_key.get_secret_value())

    def tokenization_key_bytes(self) -> bytes:
        return self.tokenization_key.get_secret_value().encode("utf-8")

    def tokenization_previous_key_bytes(self) -> tuple[bytes, ...]:
        return tuple(
            part.strip().encode("utf-8")
            for part in self.tokenization_previous_keys.split(",")
            if part.strip()
        )

    def audit_key_bytes(self) -> bytes:
        """The audit-chain key, with a dev fallback outside production."""
        return self._key_bytes("audit_hmac_key")

    def _key_bytes(self, name: str) -> bytes:
        raw: SecretStr = getattr(self, name)
        value = raw.get_secret_value()
        if value:
            return value.encode("utf-8")
        # Non-production only; _enforce_production_hygiene has already run.
        return _ephemeral_key(name)


_EPHEMERAL: dict[str, bytes] = {}


def _ephemeral_key(name: str) -> bytes:
    """A stable-per-process stand-in so local development needs no setup."""
    if name not in _EPHEMERAL:
        _EPHEMERAL[name] = secrets.token_bytes(32)
    return _EPHEMERAL[name]


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    """The cached process settings."""
    return Settings()


def reset_settings_cache() -> None:
    """Drop the cache so tests can rebuild settings from a patched environment."""
    get_settings.cache_clear()
    _EPHEMERAL.clear()
