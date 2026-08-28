"""Issuing and verifying API keys.

A key looks like ``cpk_3f8a91c2_<32 random chars>``. The middle segment is a
non-secret prefix stored in the clear and indexed, so authenticating a request
is one row lookup rather than a hash comparison against every key in the table.
The trailing secret is never stored -- only a keyed digest of it.

**On the choice of hash.** This used to be Argon2id, on the reasoning that keys
get pasted into ``.env`` files and a slow hash is the conservative choice. That
reasoning was wrong, and measurably so: Argon2id at these parameters costs about
82 ms, which is roughly fourteen times what classifying an 8 KB payload costs and
which dominated every authenticated request.

A slow hash exists to make *guessing* expensive, and guessing is only a threat
when the secret might be guessable. These secrets are not: ``token_urlsafe(24)``
is 192 bits from the OS entropy pool, so an attacker who has the stored digest
and infinite time still cannot brute-force it, whatever the hash costs. Paying
82 ms per request to defend against an attack the key length already prevents is
not conservatism, it is a throughput ceiling bought for nothing.

So: HMAC-SHA256 under a server-side pepper, compared in constant time. Argon2id
digests already in the database still verify, and are transparently re-hashed on
first use, so no key has to be reissued.
"""

from __future__ import annotations

import hashlib
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

#: Digests produced by the current scheme carry this marker, so a stored digest
#: is self-describing and the legacy path can be recognised without a schema
#: column recording which algorithm made it.
HMAC_SCHEME = "hmac-sha256"

#: Retained only to verify -- and then replace -- digests written by the previous
#: scheme. Nothing new is hashed with it.
_legacy_hasher = PasswordHasher(time_cost=2, memory_cost=64 * 1024, parallelism=2, hash_len=32)


def _pepper() -> bytes:
    """The server-side key mixed into every digest.

    Optional, and the system is secure without it: 192 bits of secret means the
    digest is not brute-forceable regardless. Setting one adds a second thing an
    attacker needs -- a database dump alone stops being enough to check guesses
    offline -- for no runtime cost.
    """
    from control_plane.config import get_settings

    configured = get_settings().api_key_pepper.get_secret_value()
    return configured.encode("utf-8") if configured else b"control-plane/api-key/v1"


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
    """The storable digest of a key."""
    digest = hmac.new(_pepper(), plaintext.encode("utf-8"), hashlib.sha256).hexdigest()
    return f"{HMAC_SCHEME}${digest}"


def verify_key(plaintext: str, key_hash: str) -> bool:
    """Check a presented key against a stored digest, in constant time.

    Accepts both schemes. Whether a digest matches must not be inferable from how
    long the check took, which is why the comparison is ``compare_digest`` rather
    than ``==``.
    """
    if key_hash.startswith(f"{HMAC_SCHEME}$"):
        expected = hmac.new(_pepper(), plaintext.encode("utf-8"), hashlib.sha256).hexdigest()
        return hmac.compare_digest(key_hash.split("$", 1)[1], expected)
    try:
        return _legacy_hasher.verify(key_hash, plaintext)
    except (VerifyMismatchError, VerificationError, InvalidHashError):
        return False


def needs_rehash(key_hash: str) -> bool:
    """Whether a stored digest was written by the superseded scheme."""
    return not key_hash.startswith(f"{HMAC_SCHEME}$")


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
