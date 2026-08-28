"""Issuing and verifying API keys.

A key looks like ``cpk_3f8a91c2_<32 random chars>``. The middle segment is a
non-secret prefix stored in the clear and indexed, so authenticating a request
is one row lookup rather than an Argon2 verification against every key in the
table. The trailing secret is never stored -- only its Argon2id hash.

Argon2id rather than SHA-256: API keys are high-entropy, so a fast hash would be
defensible, but keys get pasted into ``.env`` files and reused, and the cost of
being wrong about that is unbounded. The verification cost is paid once per
request and is small next to a policy evaluation.
"""

from __future__ import annotations

import hmac
import secrets
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any

from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerificationError, VerifyMismatchError

__all__ = [
    "KEY_PREFIX",
    "IssuedKey",
    "Scope",
    "generate_key",
    "hash_key",
    "normalise_scopes",
    "scope_satisfies",
    "split_key",
    "verify_key",
]

KEY_PREFIX = "cpk"
_PREFIX_BYTES = 4
_SECRET_BYTES = 24

# Tuned for an interactive request path: strong enough to matter, fast enough
# that authentication is not the slowest part of a decision.
_hasher = PasswordHasher(time_cost=2, memory_cost=64 * 1024, parallelism=2, hash_len=32)


class Scope:
    """The permissions a key can carry.

    Deliberately coarse. Fine-grained scopes on an administrative API tend to be
    configured once, wrongly, and never revisited; a small set that people
    actually reason about is worth more.
    """

    DECIDE = "decide"
    CATALOG_READ = "catalog:read"
    CATALOG_WRITE = "catalog:write"
    POLICY_READ = "policy:read"
    POLICY_WRITE = "policy:write"
    AUDIT_READ = "audit:read"
    APPROVALS = "approvals"
    #: Reverse a token back to the value it replaced. The most sensitive
    #: capability the API offers, and the reason it has its own scope: it
    #: should be grantable to an investigator without granting anything else.
    DETOKENIZE = "detokenize"
    ADMIN = "admin"

    ALL: frozenset[str] = frozenset(
        {
            DECIDE,
            CATALOG_READ,
            CATALOG_WRITE,
            POLICY_READ,
            POLICY_WRITE,
            AUDIT_READ,
            APPROVALS,
            DETOKENIZE,
            ADMIN,
        }
    )

    #: What an enforcement point needs, and nothing more.
    ENFORCEMENT_POINT: frozenset[str] = frozenset({DECIDE, CATALOG_READ})
    #: Read-only observer: dashboards, compliance reporting.
    READ_ONLY: frozenset[str] = frozenset({CATALOG_READ, POLICY_READ, AUDIT_READ})


@dataclass(frozen=True, slots=True)
class IssuedKey:
    """A freshly minted key. The plaintext exists only here, once."""

    plaintext: str
    prefix: str
    key_hash: str

    def to_dict(self) -> dict[str, Any]:
        return {"key": self.plaintext, "prefix": self.prefix}


def generate_key() -> IssuedKey:
    """Mint a new key."""
    prefix = secrets.token_hex(_PREFIX_BYTES)
    secret = secrets.token_urlsafe(_SECRET_BYTES)
    plaintext = f"{KEY_PREFIX}_{prefix}_{secret}"
    return IssuedKey(plaintext=plaintext, prefix=prefix, key_hash=hash_key(plaintext))


def hash_key(plaintext: str) -> str:
    return _hasher.hash(plaintext)


def verify_key(plaintext: str, key_hash: str) -> bool:
    """Check a presented key against a stored hash, without leaking why it failed."""
    try:
        return _hasher.verify(key_hash, plaintext)
    except (VerifyMismatchError, VerificationError, InvalidHashError):
        return False


def split_key(plaintext: str) -> tuple[str, str] | None:
    """Extract ``(prefix, secret)``, or None if the key is not well-formed."""
    parts = plaintext.strip().split("_", 2)
    if len(parts) != 3:
        return None
    scheme, prefix, secret = parts
    if not hmac.compare_digest(scheme, KEY_PREFIX) or not prefix or not secret:
        return None
    return prefix, secret


def normalise_scopes(scopes: Any) -> list[str]:
    """Validate and de-duplicate a scope list."""
    if isinstance(scopes, str):
        scopes = [scopes]
    cleaned = {str(scope).strip().lower() for scope in (scopes or []) if str(scope).strip()}
    unknown = cleaned - Scope.ALL
    if unknown:
        raise ValueError(
            f"unknown scopes: {', '.join(sorted(unknown))}; "
            f"known scopes: {', '.join(sorted(Scope.ALL))}"
        )
    return sorted(cleaned)


def scope_satisfies(held: set[str] | frozenset[str], required: str) -> bool:
    """True if the key's scopes cover ``required``.

    ``admin`` implies everything, and a write scope implies the matching read
    scope -- nobody sensibly grants ``policy:write`` while withholding
    ``policy:read``.
    """
    if Scope.ADMIN in held or required in held:
        return True
    implied = {
        Scope.CATALOG_READ: Scope.CATALOG_WRITE,
        Scope.POLICY_READ: Scope.POLICY_WRITE,
    }.get(required)
    return implied is not None and implied in held


def is_expired(expires_at: datetime | None, now: datetime | None = None) -> bool:
    if expires_at is None:
        return False
    reference = now or datetime.now(UTC)
    if expires_at.tzinfo is None:
        expires_at = expires_at.replace(tzinfo=UTC)
    return expires_at <= reference
