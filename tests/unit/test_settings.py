"""Configuration.

One of these tests exists because the shipped ``.env.example`` broke the
application on a first run: ``CP_CORS_ORIGINS=http://localhost:5173`` is not
JSON, and pydantic-settings decodes list-typed fields in the source layer before
any validator sees them. Every documented command after ``make secrets`` failed.

It was only found by walking the documented path from a clean clone, which is
the case no unit test had been covering.
"""

from __future__ import annotations

import pathlib

import pytest

from control_plane.config import Environment, Settings

ROOT = pathlib.Path(__file__).resolve().parents[2]
ENV_EXAMPLE = ROOT / ".env.example"


def settings_from(tmp_path: pathlib.Path, body: str) -> Settings:
    env = tmp_path / ".env"
    env.write_text(body)
    return Settings(_env_file=str(env))


class TestTheShippedTemplate:
    def test_env_example_actually_loads(self, tmp_path) -> None:
        """The file `make secrets` copies must produce a usable configuration.

        Anything else means a first run fails on the template we handed people.
        """
        body = ENV_EXAMPLE.read_text()
        settings = settings_from(tmp_path, body)
        assert settings.default_effect == "deny"
        assert settings.fail_closed is True

    #: CP_-prefixed names in the template that the application deliberately does
    #: not read. Each is consumed by docker compose, and each is labelled as such
    #: in the file -- otherwise someone sets it, nothing moves, and they are left
    #: wondering which layer ignored them.
    COMPOSE_ONLY = {"cp_port"}

    def test_every_documented_setting_is_a_real_one(self) -> None:
        """A template naming a setting the code ignores is a lie in a comment."""
        documented = {
            line.split("=", 1)[0].strip().lower()
            for line in ENV_EXAMPLE.read_text().splitlines()
            if line.strip() and not line.startswith("#") and "=" in line
        }
        known = {f"cp_{name}" for name in Settings.model_fields}
        # Names without the CP_ prefix belong to the proxy or to compose.
        unknown = {n for n in documented if n.startswith("cp_")} - known - self.COMPOSE_ONLY
        assert not unknown, f"documented but unknown to Settings: {sorted(unknown)}"


class TestCorsOrigins:
    """The field that broke, in every form it plausibly arrives in."""

    @pytest.mark.parametrize(
        ("raw", "expected"),
        [
            ("http://localhost:5173", ["http://localhost:5173"]),
            ("http://a.test,http://b.test", ["http://a.test", "http://b.test"]),
            ("http://a.test, http://b.test", ["http://a.test", "http://b.test"]),
            ('["http://a.test","http://b.test"]', ["http://a.test", "http://b.test"]),
            ("", []),
        ],
    )
    def test_it_parses(self, tmp_path, raw: str, expected: list[str]) -> None:
        assert settings_from(tmp_path, f"CP_CORS_ORIGINS={raw}\n").cors_origins == expected

    def test_a_python_caller_may_pass_a_list(self) -> None:
        assert Settings(cors_origins=["http://x.test"]).cors_origins == ["http://x.test"]

    def test_the_default_stands_when_unset(self, tmp_path) -> None:
        assert settings_from(tmp_path, "CP_LOG_LEVEL=INFO\n").cors_origins == [
            "http://localhost:5173"
        ]


class TestProductionHygiene:
    """Settings read the ambient environment whatever ``_env_file`` says, so
    these clear it first -- otherwise the result depends on the shell."""

    @pytest.fixture(autouse=True)
    def _no_ambient_secrets(self, monkeypatch) -> None:
        for name in ("CP_AUDIT_HMAC_KEY", "CP_REDACTION_HMAC_KEY", "CP_ENVIRONMENT"):
            monkeypatch.delenv(name, raising=False)

    def test_production_demands_its_secrets(self) -> None:
        with pytest.raises(ValueError, match="CP_AUDIT_HMAC_KEY"):
            Settings(environment=Environment.PRODUCTION, _env_file=None)

    def test_production_refuses_disabled_auth(self) -> None:
        with pytest.raises(ValueError, match="AUTH_DISABLED"):
            Settings(
                environment=Environment.PRODUCTION,
                audit_hmac_key="a",
                redaction_hmac_key="r",
                auth_disabled=True,
                _env_file=None,
            )

    def test_production_refuses_debug(self) -> None:
        with pytest.raises(ValueError, match="DEBUG"):
            Settings(
                environment=Environment.PRODUCTION,
                audit_hmac_key="a",
                redaction_hmac_key="r",
                debug=True,
                _env_file=None,
            )

    def test_a_valid_production_configuration_starts(self) -> None:
        settings = Settings(
            environment=Environment.PRODUCTION,
            audit_hmac_key="a",
            redaction_hmac_key="r",
            _env_file=None,
        )
        assert settings.is_production is True


class TestDefaultsAreTheSafeOnes:
    @pytest.fixture(autouse=True)
    def _no_ambient_overrides(self, monkeypatch) -> None:
        for name in list(Settings.model_fields):
            monkeypatch.delenv(f"CP_{name.upper()}", raising=False)

    def test_nothing_is_permitted_implicitly(self) -> None:
        assert Settings(_env_file=None).default_effect == "deny"

    def test_an_internal_error_denies(self) -> None:
        assert Settings(_env_file=None).fail_closed is True

    def test_authentication_is_on(self) -> None:
        assert Settings(_env_file=None).auth_disabled is False

    def test_tokenisation_is_off_until_configured(self) -> None:
        """No development fallback: an ephemeral key would mint tokens that stop
        reversing at the next restart."""
        assert Settings(_env_file=None).tokenization_enabled is False

    def test_the_audit_log_is_one_chain_until_asked_otherwise(self) -> None:
        assert Settings(_env_file=None).audit_partitions == 1

    def test_the_scan_ceiling_is_sized_against_wall_clock(self) -> None:
        """64 KiB is about 40 ms of CPU; the old 1,000,000 was 600 ms."""
        assert Settings(_env_file=None).max_scan_chars == 65_536

    def test_an_unknown_default_effect_is_rejected(self) -> None:
        with pytest.raises(ValueError, match="default_effect"):
            Settings(default_effect="maybe", _env_file=None)
