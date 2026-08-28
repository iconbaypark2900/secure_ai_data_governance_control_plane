"""How API keys are stored and checked.

The scheme changed from Argon2id to a keyed HMAC. These tests hold both halves:
that the new scheme is correct, and that digests written by the old one still
work and are upgraded rather than stranded.
"""

from __future__ import annotations

import time

import pytest
from argon2 import PasswordHasher

from control_plane.auth.keys import (
    HMAC_SCHEME,
    generate_key,
    hash_key,
    needs_rehash,
    split_key,
    verify_key,
)


@pytest.fixture
def issued():
    return generate_key()


class TestTheCurrentScheme:
    def test_a_key_verifies_against_its_own_digest(self, issued) -> None:
        assert verify_key(issued.plaintext, issued.key_hash) is True

    def test_a_different_key_does_not(self, issued) -> None:
        assert verify_key(generate_key().plaintext, issued.key_hash) is False

    def test_the_digest_is_self_describing(self, issued) -> None:
        """A stored digest says which scheme made it, so no schema column has to."""
        assert issued.key_hash.startswith(f"{HMAC_SCHEME}$")
        assert needs_rehash(issued.key_hash) is False

    def test_the_digest_does_not_contain_the_key(self, issued) -> None:
        _, secret = split_key(issued.plaintext)
        assert secret not in issued.key_hash

    def test_hashing_is_deterministic(self, issued) -> None:
        assert hash_key(issued.plaintext) == hash_key(issued.plaintext)

    def test_keys_carry_enough_entropy_to_make_a_fast_hash_safe(self) -> None:
        """The premise of the whole change.

        A slow hash defends against guessing. These secrets cannot be guessed:
        token_urlsafe(24) is 192 bits, so the digest is not brute-forceable
        however fast the hash is.
        """
        secrets_seen = {split_key(generate_key().plaintext)[1] for _ in range(200)}
        assert len(secrets_seen) == 200
        assert all(len(s) >= 32 for s in secrets_seen)


class TestTheSupersededScheme:
    @pytest.fixture
    def legacy_digest(self, issued) -> str:
        return PasswordHasher(time_cost=2, memory_cost=64 * 1024, parallelism=2, hash_len=32).hash(
            issued.plaintext
        )

    def test_an_old_digest_still_verifies(self, issued, legacy_digest) -> None:
        """Nobody should have to reissue a key because the scheme improved."""
        assert verify_key(issued.plaintext, legacy_digest) is True

    def test_an_old_digest_still_rejects_the_wrong_key(self, legacy_digest) -> None:
        assert verify_key(generate_key().plaintext, legacy_digest) is False

    def test_an_old_digest_is_flagged_for_upgrade(self, legacy_digest) -> None:
        assert needs_rehash(legacy_digest) is True

    def test_a_malformed_digest_is_rejected_rather_than_raising(self, issued) -> None:
        for garbage in ("", "not-a-digest", "$argon2id$broken", "hmac-sha256$"):
            assert verify_key(issued.plaintext, garbage) is False


class TestCost:
    def test_verification_is_no_longer_the_dominant_request_cost(self, issued) -> None:
        """The defect this change fixed.

        Argon2id at the previous parameters cost ~82 ms, about fourteen times
        what classifying an 8 KB payload costs, on every authenticated request.
        A generous ceiling here still fails loudly if a slow hash returns.
        """
        iterations = 500
        start = time.perf_counter()
        for _ in range(iterations):
            verify_key(issued.plaintext, issued.key_hash)
        per_call_ms = (time.perf_counter() - start) / iterations * 1000
        assert per_call_ms < 1.0, f"verification took {per_call_ms:.2f} ms per call"


class TestPepper:
    def test_a_pepper_changes_the_digest(self, monkeypatch) -> None:
        from control_plane.config import reset_settings_cache

        issued = generate_key()
        monkeypatch.setenv("CP_API_KEY_PEPPER", "a-server-side-secret")
        reset_settings_cache()
        peppered = hash_key(issued.plaintext)
        monkeypatch.delenv("CP_API_KEY_PEPPER")
        reset_settings_cache()
        assert peppered != hash_key(issued.plaintext)

    def test_the_wrong_pepper_fails_to_verify(self, monkeypatch) -> None:
        """Which is why changing it invalidates every issued key."""
        from control_plane.config import reset_settings_cache

        monkeypatch.setenv("CP_API_KEY_PEPPER", "pepper-a")
        reset_settings_cache()
        issued = generate_key()
        monkeypatch.setenv("CP_API_KEY_PEPPER", "pepper-b")
        reset_settings_cache()
        assert verify_key(issued.plaintext, issued.key_hash) is False
