"""Detector and scanner behaviour."""

from __future__ import annotations

import pytest

from control_plane.classification import taxonomy
from control_plane.classification.detectors import (
    high_entropy,
    luhn,
    valid_card_number,
    valid_iban,
    valid_npi,
    valid_ssn,
)
from control_plane.classification.scanner import Scanner, mask_preview, scan_structured, scan_text


class TestValidators:
    @pytest.mark.parametrize(
        ("pan", "expected"),
        [
            ("4111111111111111", True),  # Visa test number
            ("4111 1111 1111 1111", True),
            ("5555555555554444", True),  # Mastercard
            ("378282246310005", True),  # Amex
            ("6011111111111117", True),  # Discover
            ("4111111111111112", False),  # fails Luhn
            ("1234567812345678", False),  # no known brand prefix
            ("1111111111111111", False),  # single repeated digit
        ],
    )
    def test_card_numbers(self, pan: str, expected: bool) -> None:
        assert valid_card_number(pan) is expected

    @pytest.mark.parametrize(
        ("ssn", "expected"),
        [
            ("536-90-4432", True),
            ("536904432", True),
            ("000-12-3456", False),  # reserved area
            ("666-12-3456", False),  # reserved area
            ("900-12-3456", False),  # 9xx is an ITIN range
            ("536-00-4432", False),  # reserved group
            ("536-90-0000", False),  # reserved serial
            ("123-45-6789", False),  # documentation placeholder
        ],
    )
    def test_ssns(self, ssn: str, expected: bool) -> None:
        assert valid_ssn(ssn) is expected

    def test_iban_mod97(self) -> None:
        assert valid_iban("DE89 3704 0044 0532 0130 00") is True
        assert valid_iban("DE89 3704 0044 0532 0130 01") is False

    def test_npi_uses_the_issuer_prefix(self) -> None:
        assert valid_npi("1234567893") is True
        assert valid_npi("1234567890") is False

    def test_luhn_rejects_short_input(self) -> None:
        assert luhn("18") is False

    def test_entropy_rejects_placeholders(self) -> None:
        assert high_entropy("your_api_key_here") is False
        assert high_entropy("aaaaaaaaaaaaaaaaaaaa") is False
        assert high_entropy("xK9m2Qp7Lz4Rw8Tn6Yb3") is True


class TestScanning:
    def test_finds_common_pii(self) -> None:
        result = scan_text("Reach Jane at jane.doe@acme.com or (415) 555-0142. SSN 536-90-4432.")
        assert result.labels == {"pii.email", "pii.phone", "pii.ssn"}
        assert result.max_severity is taxonomy.Severity.CRITICAL

    def test_specific_detector_beats_generic_on_overlap(self) -> None:
        """sk-ant-... matches both the Anthropic and the generic sk- pattern."""
        result = scan_text("key sk-ant-api03-AbCdEfGh1234567890XyZq")
        assert [f.label for f in result.findings] == ["secret.anthropic_key"]

    def test_field_name_supplies_context(self) -> None:
        """Nine bare digits are only an SSN because of the field they sit in."""
        assert scan_text("536904432").labels == set()
        result = scan_structured({"ssn": "536904432"})
        assert result.labels == {"pii.ssn"}
        assert result.findings[0].path == "/ssn"

    def test_json_pointer_paths(self) -> None:
        result = scan_structured({"users": [{"email": "a.b@example.com"}]})
        assert result.findings[0].path == "/users/0/email"

    def test_context_required_detectors_stay_quiet(self) -> None:
        """A bare date is not a date of birth."""
        assert scan_text("The release shipped 2024-03-15.").labels == set()
        assert "pii.dob" in scan_text("Patient DOB 2024-03-15").labels

    def test_findings_never_expose_the_value(self) -> None:
        result = scan_text("card 4111 1111 1111 1111")
        serialised = result.findings[0].redacted_dict()
        assert "4111 1111 1111 1111" not in str(serialised)
        assert serialised["preview"].count("*") > 4

    def test_truncates_oversized_input(self) -> None:
        scanner = Scanner(max_chars=100)
        result = scanner.scan_text("x" * 500)
        assert result.truncated is True
        assert result.scanned_chars == 100

    def test_for_labels_narrows_the_detector_set(self) -> None:
        scanner = Scanner.for_labels(["secret"])
        result = scanner.scan_text("mail a@b.com and key ghp_" + "a" * 36)
        assert result.labels == {"secret.github_token"}

    def test_min_confidence_filters(self) -> None:
        noisy = Scanner(min_confidence=0.95)
        result = noisy.scan_text("server at 10.1.2.3")
        assert result.labels == set()


class TestPreview:
    @pytest.mark.parametrize(
        ("value", "expected"),
        [
            ("abc", "***"),
            ("jane@acme.com", "j***@acme.com"),
            ("1234567890", "1********0"),
        ],
    )
    def test_masking(self, value: str, expected: str) -> None:
        assert mask_preview(value) == expected


class TestTaxonomy:
    def test_prefix_expansion(self) -> None:
        assert "pii.email" in taxonomy.expand("pii")
        assert taxonomy.expand("pii.email") == {"pii.email"}

    def test_covers_is_hierarchical(self) -> None:
        assert taxonomy.covers("pii", "pii.email") is True
        assert taxonomy.covers("pii.email", "pii") is False

    def test_unknown_label_raises_with_guidance(self) -> None:
        with pytest.raises(KeyError, match="known labels"):
            taxonomy.get("pii.telepathy")
