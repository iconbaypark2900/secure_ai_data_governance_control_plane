"""Reversible tokenisation without a store of sensitive values.

The obvious way to make tokenisation reversible is a vault: a table mapping each
token to the value it replaced. That table would be the single largest
concentration of sensitive data in the deployment, sitting inside the component
introduced to reduce exactly that -- and it would contradict the rule that the
control plane never persists payload content (`ADR 0006`).

So there is no table. **The token is the ciphertext.** Reversing one requires the
key, which lives in the process environment rather than the database, and there
is nothing to steal from a database dump.

The construction is deterministic authenticated encryption, in the SIV style:

    K_prf, K_enc = HKDF(key, info="control-plane/tokenization/v1")
    nonce        = HMAC-SHA256(K_prf, label || 0x00 || value)[:12]
    ciphertext   = AES-256-GCM(K_enc, nonce, value)
    token        = "tok_" + base64url(version || nonce || ciphertext)

Deriving the nonce as a keyed function of the value is what makes it
deterministic: the same value under the same label always produces the same
token, so tokenised columns still join and a customer stays recognisable across a
conversation. That determinism leaks equality -- two identical tokens mean two
identical inputs -- which is precisely the property being bought, and exactly the
same leak the `hash` strategy already has.

Two consequences worth knowing before choosing this strategy:

*Tokens are longer than what they replace.* This is not format-preserving
encryption; a tokenised email does not look like an email and will not fit a
column sized for one.

*The key is the whole security boundary.* Losing it makes every existing token
permanently irreversible. Rotating it makes new tokens differ from old ones for
the same input, which breaks joins across the rotation -- so
``CP_TOKENIZATION_PREVIOUS_KEYS`` exists to keep old tokens readable.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
from collections.abc import Sequence
from dataclasses import dataclass, field
from typing import Any

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

__all__ = [
    "TOKEN_PREFIX",
    "DeterministicTokenizer",
    "TokenizationUnavailable",
    "looks_like_token",
]

TOKEN_PREFIX = "tok_"  # noqa: S105 - a token's visible prefix, not a secret

#: Bumped only if the construction changes. Old tokens keep decrypting because
#: the byte travels inside the token itself.
SCHEME_VERSION = 1

NONCE_BYTES = 12
KEY_BYTES = 32
HKDF_INFO = b"control-plane/tokenization/v1"

#: A token for a megabyte of text is not a token. Detectors match bounded spans,
#: so anything past this is a bug upstream rather than a value to encrypt.
MAX_VALUE_BYTES = 4096


class TokenizationUnavailable(RuntimeError):
    """Tokenisation was requested and cannot be performed.

    Raised rather than quietly substituting a hash. A policy that asked for a
    reversible token and received an irreversible digest has been silently
    downgraded, and nobody finds out until someone needs to reverse one.
    """


def _subkeys(key: bytes) -> tuple[bytes, bytes]:
    """Split one configured key into a PRF key and an encryption key.

    Domain separation: the value that derives the nonce must not be the value
    that encrypts, or the nonce derivation leaks into the cipher's key schedule.
    """
    material = HKDF(
        algorithm=hashes.SHA256(), length=KEY_BYTES * 2, salt=None, info=HKDF_INFO
    ).derive(key)
    return material[:KEY_BYTES], material[KEY_BYTES:]


def looks_like_token(value: str) -> bool:
    """Whether a string has the shape this module produces."""
    return value.startswith(TOKEN_PREFIX) and len(value) > len(TOKEN_PREFIX) + 16


def _b64encode(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")


def _b64decode(value: str) -> bytes:
    padded = value + "=" * (-len(value) % 4)
    return base64.urlsafe_b64decode(padded.encode("ascii"))


@dataclass
class DeterministicTokenizer:
    """Turns a value into a reversible token, and back.

    Satisfies the :class:`~control_plane.redaction.transforms.TokenVault`
    protocol, so it drops into the redactor wherever a vault would go. Unlike a
    vault it stores nothing, which is the point.
    """

    key: bytes
    #: Keys retired by rotation. Used for decryption only, newest first, so
    #: tokens minted before a rotation stay readable.
    previous_keys: Sequence[bytes] = ()

    _prf: bytes = field(init=False, repr=False)
    _enc: bytes = field(init=False, repr=False)
    _retired: tuple[tuple[bytes, bytes], ...] = field(init=False, repr=False)

    def __post_init__(self) -> None:
        if not self.key:
            raise TokenizationUnavailable(
                "no tokenization key is configured; set CP_TOKENIZATION_KEY"
            )
        self._prf, self._enc = _subkeys(self.key)
        self._retired = tuple(_subkeys(old) for old in self.previous_keys if old)

    def tokenize(self, label: str, value: str) -> str:
        """A stable, reversible surrogate for ``value``."""
        raw = value.encode("utf-8")
        if len(raw) > MAX_VALUE_BYTES:
            raise TokenizationUnavailable(
                f"value is {len(raw)} bytes, over the {MAX_VALUE_BYTES}-byte tokenisation limit"
            )
        context = label.encode("utf-8") + b"\x00" + raw
        nonce = hmac.new(self._prf, context, hashlib.sha256).digest()[:NONCE_BYTES]
        ciphertext = AESGCM(self._enc).encrypt(nonce, raw, None)
        return TOKEN_PREFIX + _b64encode(bytes([SCHEME_VERSION]) + nonce + ciphertext)

    def detokenize(self, token: str) -> str | None:
        """The original value, or None if this token is not ours to read.

        Returns None rather than raising for every failure mode -- malformed,
        wrong key, tampered -- because the caller of a re-identification API
        should not learn which of those it was.
        """
        if not token.startswith(TOKEN_PREFIX):
            return None
        try:
            blob = _b64decode(token[len(TOKEN_PREFIX) :])
        except (ValueError, TypeError):
            return None
        if len(blob) < 1 + NONCE_BYTES + 16 or blob[0] != SCHEME_VERSION:
            return None

        nonce = blob[1 : 1 + NONCE_BYTES]
        ciphertext = blob[1 + NONCE_BYTES :]
        for _, enc in ((self._prf, self._enc), *self._retired):
            try:
                return AESGCM(enc).decrypt(nonce, ciphertext, None).decode("utf-8")
            except (InvalidTag, UnicodeDecodeError):
                continue
        return None

    @classmethod
    def from_settings(cls, settings: Any) -> DeterministicTokenizer | None:
        """Build from configuration, or None when no key is set.

        Deliberately without a development fallback, unlike the audit and
        redaction keys. An ephemeral tokenisation key would mint tokens that stop
        reversing at the next restart -- a failure that surfaces later, somewhere
        else, as data nobody can recover. Refusing to tokenise at all is the
        kinder error.
        """
        if not settings.tokenization_enabled:
            return None
        return cls(
            key=settings.tokenization_key_bytes(),
            previous_keys=settings.tokenization_previous_key_bytes(),
        )

    def verify(self, label: str, value: str, token: str) -> bool:
        """Whether ``token`` is the one this tokeniser would mint for ``value``.

        Lets a caller confirm a suspected match without the reverse direction --
        useful for "is this the customer in that incident?" when the answer
        should not involve handing anyone a plaintext.
        """
        try:
            return hmac.compare_digest(self.tokenize(label, value), token)
        except TokenizationUnavailable:
            return False
