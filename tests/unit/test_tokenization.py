"""Reversible tokenisation.

The token is the ciphertext, so these tests are the specification of a
cryptographic construction rather than of a lookup table. What matters is that
it is deterministic (or joins break), label-bound (or a token moves between
fields), reversible only with the key (or the point is lost), and that a token
never contains what it replaced.
"""

from __future__ import annotations

import pytest

from control_plane.config import Settings
from control_plane.redaction.tokenization import (
    MAX_VALUE_BYTES,
    DeterministicTokenizer,
    TokenizationUnavailable,
    looks_like_token,
)

KEY = b"k" * 32
OTHER_KEY = b"z" * 32
EMAIL = "jane.doe@acme.com"


@pytest.fixture
def tokenizer() -> DeterministicTokenizer:
    return DeterministicTokenizer(key=KEY)


class TestDeterminism:
    def test_the_same_value_always_gives_the_same_token(self, tokenizer) -> None:
        """Without this, tokenised columns stop joining."""
        assert tokenizer.tokenize("pii.email", EMAIL) == tokenizer.tokenize("pii.email", EMAIL)

    def test_a_fresh_tokenizer_with_the_same_key_agrees(self) -> None:
        """Tokens have to survive a restart, or they are not identifiers."""
        first = DeterministicTokenizer(key=KEY).tokenize("pii.email", EMAIL)
        second = DeterministicTokenizer(key=KEY).tokenize("pii.email", EMAIL)
        assert first == second

    def test_different_values_give_different_tokens(self, tokenizer) -> None:
        assert tokenizer.tokenize("pii.email", EMAIL) != tokenizer.tokenize(
            "pii.email", "other@acme.com"
        )

    def test_the_same_value_under_a_different_label_differs(self, tokenizer) -> None:
        """A token minted for one field should not silently mean another."""
        assert tokenizer.tokenize("pii.email", EMAIL) != tokenizer.tokenize("pii.ssn", EMAIL)

    def test_a_different_key_gives_a_different_token(self) -> None:
        assert DeterministicTokenizer(key=KEY).tokenize(
            "pii.email", EMAIL
        ) != DeterministicTokenizer(key=OTHER_KEY).tokenize("pii.email", EMAIL)


class TestReversal:
    def test_a_token_round_trips(self, tokenizer) -> None:
        assert tokenizer.detokenize(tokenizer.tokenize("pii.email", EMAIL)) == EMAIL

    def test_unicode_survives(self, tokenizer) -> None:
        value = "Ada Lovelace — café, 東京"
        assert tokenizer.detokenize(tokenizer.tokenize("pii.name", value)) == value

    def test_the_wrong_key_recovers_nothing(self, tokenizer) -> None:
        token = tokenizer.tokenize("pii.email", EMAIL)
        assert DeterministicTokenizer(key=OTHER_KEY).detokenize(token) is None

    def test_a_tampered_token_is_rejected(self, tokenizer) -> None:
        """AES-GCM authenticates; a flipped character does not decrypt to garbage."""
        token = tokenizer.tokenize("pii.email", EMAIL)
        assert tokenizer.detokenize(token[:-4] + "AAAA") is None

    def test_a_truncated_token_is_rejected(self, tokenizer) -> None:
        token = tokenizer.tokenize("pii.email", EMAIL)
        assert tokenizer.detokenize(token[:20]) is None

    @pytest.mark.parametrize("value", ["", "not a token", "tok_", "tok_!!!!not-base64!!!!", EMAIL])
    def test_things_that_are_not_tokens_recover_nothing(self, tokenizer, value) -> None:
        assert tokenizer.detokenize(value) is None


class TestDisclosure:
    def test_a_token_does_not_contain_the_value(self, tokenizer) -> None:
        token = tokenizer.tokenize("pii.email", EMAIL)
        assert EMAIL not in token
        assert "jane" not in token
        assert "acme" not in token

    def test_a_token_is_recognisable_as_one(self, tokenizer) -> None:
        assert looks_like_token(tokenizer.tokenize("pii.email", EMAIL))
        assert not looks_like_token(EMAIL)
        assert not looks_like_token("tok_short")


class TestVerification:
    def test_a_correct_guess_is_confirmed(self, tokenizer) -> None:
        token = tokenizer.tokenize("pii.email", EMAIL)
        assert tokenizer.verify("pii.email", EMAIL, token) is True

    def test_a_wrong_guess_is_refuted(self, tokenizer) -> None:
        token = tokenizer.tokenize("pii.email", EMAIL)
        assert tokenizer.verify("pii.email", "someone@else.com", token) is False

    def test_the_label_is_part_of_the_claim(self, tokenizer) -> None:
        token = tokenizer.tokenize("pii.email", EMAIL)
        assert tokenizer.verify("pii.ssn", EMAIL, token) is False


class TestRotation:
    def test_a_retired_key_still_reads_its_tokens(self) -> None:
        """Rotating without this makes every existing token unreadable."""
        old_token = DeterministicTokenizer(key=KEY).tokenize("pii.email", EMAIL)
        rotated = DeterministicTokenizer(key=OTHER_KEY, previous_keys=[KEY])
        assert rotated.detokenize(old_token) == EMAIL

    def test_new_tokens_use_the_current_key(self) -> None:
        rotated = DeterministicTokenizer(key=OTHER_KEY, previous_keys=[KEY])
        assert rotated.tokenize("pii.email", EMAIL) == DeterministicTokenizer(
            key=OTHER_KEY
        ).tokenize("pii.email", EMAIL)

    def test_rotation_changes_the_token_for_the_same_value(self) -> None:
        """The cost of rotating: joins do not survive across the boundary."""
        before = DeterministicTokenizer(key=KEY).tokenize("pii.email", EMAIL)
        after = DeterministicTokenizer(key=OTHER_KEY, previous_keys=[KEY]).tokenize(
            "pii.email", EMAIL
        )
        assert before != after


class TestRefusals:
    def test_no_key_is_a_refusal_not_a_default(self) -> None:
        with pytest.raises(TokenizationUnavailable, match="CP_TOKENIZATION_KEY"):
            DeterministicTokenizer(key=b"")

    def test_an_oversized_value_is_refused(self, tokenizer) -> None:
        with pytest.raises(TokenizationUnavailable, match="tokenisation limit"):
            tokenizer.tokenize("pii.name", "x" * (MAX_VALUE_BYTES + 1))

    def test_a_value_at_the_limit_is_accepted(self, tokenizer) -> None:
        value = "x" * MAX_VALUE_BYTES
        assert tokenizer.detokenize(tokenizer.tokenize("pii.name", value)) == value


class TestSettingsFactory:
    def test_absent_configuration_yields_no_tokenizer(self) -> None:
        assert DeterministicTokenizer.from_settings(Settings()) is None

    def test_a_configured_key_yields_one(self) -> None:
        settings = Settings(tokenization_key="k" * 32)
        tokenizer = DeterministicTokenizer.from_settings(settings)
        assert tokenizer is not None
        assert tokenizer.detokenize(tokenizer.tokenize("pii.email", EMAIL)) == EMAIL

    def test_previous_keys_are_parsed(self) -> None:
        settings = Settings(tokenization_key="new" * 11, tokenization_previous_keys="old-a, old-b")
        tokenizer = DeterministicTokenizer.from_settings(settings)
        assert tokenizer is not None
        legacy = DeterministicTokenizer(key=b"old-a").tokenize("pii.email", EMAIL)
        assert tokenizer.detokenize(legacy) == EMAIL
