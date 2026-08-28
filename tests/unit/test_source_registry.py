"""Named source configuration."""

from __future__ import annotations

import pytest

from control_plane.adapters.registry import (
    SourceConfig,
    SourceConfigError,
    SourceRegistry,
    UnknownSource,
    interpolate,
)

WAREHOUSE = {
    "name": "warehouse",
    "adapter": "postgres",
    "dsn": "postgresql+asyncpg://u:p@db/warehouse",
    "exclude": ["pg://audit.*"],
    "owner": "data-platform",
}


class TestInterpolation:
    def test_a_placeholder_reads_the_environment(self, monkeypatch) -> None:
        monkeypatch.setenv("CP_TEST_DSN", "postgresql://real")
        assert interpolate("${CP_TEST_DSN}") == "postgresql://real"

    def test_a_default_is_used_when_unset(self, monkeypatch) -> None:
        monkeypatch.delenv("CP_TEST_ABSENT", raising=False)
        assert interpolate("${CP_TEST_ABSENT:-http://localhost:6333}") == "http://localhost:6333"

    def test_an_unset_variable_with_no_default_is_empty(self, monkeypatch) -> None:
        """The file still loads; the failure surfaces at connection time."""
        monkeypatch.delenv("CP_TEST_ABSENT", raising=False)
        assert interpolate("${CP_TEST_ABSENT}") == ""

    def test_it_reaches_into_nested_structures(self, monkeypatch) -> None:
        monkeypatch.setenv("CP_TEST_KEY", "shh")
        assert interpolate({"a": ["${CP_TEST_KEY}"]}) == {"a": ["shh"]}

    def test_plain_values_pass_through(self) -> None:
        assert interpolate({"n": 5, "b": True, "s": "plain"}) == {"n": 5, "b": True, "s": "plain"}


class TestConfiguration:
    def test_a_source_without_its_credential_still_loads(self) -> None:
        """A file listing four sources must load when only two vars are set.

        Connection details come from the environment, so an empty one is a fact
        about this process rather than a broken file. It has to stay listable.
        """
        config = SourceConfig(name="w", adapter="postgres")
        assert config.configured is False
        assert config.target == "[not configured]"

    def test_using_an_unconfigured_source_fails_where_it_is_actionable(self) -> None:
        config = SourceConfig(name="w", adapter="postgres")
        with pytest.raises(SourceConfigError, match="environment variable"):
            config.build()

    def test_a_qdrant_source_needs_a_base_url_to_build(self) -> None:
        config = SourceConfig(name="v", adapter="qdrant")
        assert config.configured is False
        with pytest.raises(SourceConfigError, match="no base_url"):
            config.build()

    def test_a_configured_source_builds(self) -> None:
        config = SourceConfig(name="v", adapter="qdrant", base_url="http://q:6333")
        assert config.configured is True
        assert config.target == "http://q:6333"

    def test_a_mapping_adapter_is_refused_with_an_explanation(self) -> None:
        """Naming one is a mistake worth explaining rather than silently ignoring."""
        with pytest.raises(ValueError, match="mapping adapter, not a discoverable source"):
            SourceConfig(name="tools", adapter="mcp")

    def test_credentials_are_redacted_for_display(self) -> None:
        config = SourceConfig.model_validate(WAREHOUSE)
        assert config.redacted()["dsn"] == "[configured]"
        assert "u:p@db" not in str(config.redacted())

    def test_a_source_with_no_credential_is_not_marked_configured(self) -> None:
        config = SourceConfig(name="v", adapter="qdrant", base_url="http://x:6333")
        assert config.redacted()["api_key"] is None

    def test_sampling_is_off_unless_chosen(self) -> None:
        """Sampling reads real records; it should be a decision, not a default."""
        assert SourceConfig.model_validate(WAREHOUSE).scan is False


class TestRegistry:
    def test_loads_a_document(self) -> None:
        registry = SourceRegistry.from_document({"sources": [WAREHOUSE]})
        assert registry.names() == ["warehouse"]
        assert "warehouse" in registry

    def test_a_bare_list_is_accepted(self) -> None:
        assert SourceRegistry.from_document([WAREHOUSE]).names() == ["warehouse"]

    def test_an_empty_document_is_an_empty_registry(self) -> None:
        assert len(SourceRegistry.from_document({})) == 0

    def test_a_missing_file_is_not_an_error(self, tmp_path) -> None:
        """Running with no configured sources is the normal starting state."""
        assert len(SourceRegistry.from_file(tmp_path / "absent.yaml")) == 0

    def test_a_file_round_trips(self, tmp_path) -> None:
        import yaml

        path = tmp_path / "sources.yaml"
        path.write_text(yaml.safe_dump({"sources": [WAREHOUSE]}))
        assert SourceRegistry.from_file(path).get("warehouse").owner == "data-platform"

    def test_duplicate_names_are_refused(self) -> None:
        with pytest.raises(SourceConfigError, match="duplicate source name"):
            SourceRegistry.from_document({"sources": [WAREHOUSE, WAREHOUSE]})

    def test_an_invalid_entry_names_its_index(self) -> None:
        with pytest.raises(SourceConfigError, match=r"sources\[1\]"):
            SourceRegistry.from_document({"sources": [WAREHOUSE, {"name": "x"}]})

    def test_malformed_yaml_is_reported(self, tmp_path) -> None:
        path = tmp_path / "sources.yaml"
        path.write_text("sources: [{name: x\n")
        with pytest.raises(SourceConfigError, match="not valid YAML"):
            SourceRegistry.from_file(path)

    def test_an_unknown_name_lists_what_is_known(self) -> None:
        registry = SourceRegistry.from_document({"sources": [WAREHOUSE]})
        with pytest.raises(UnknownSource, match="known sources: warehouse"):
            registry.get("nope")

    def test_disabled_sources_can_be_filtered(self) -> None:
        registry = SourceRegistry.from_document(
            {"sources": [WAREHOUSE, {**WAREHOUSE, "name": "old", "enabled": False}]}
        )
        assert registry.names() == ["old", "warehouse"]
        assert registry.names(enabled_only=True) == ["warehouse"]

    def test_it_builds_the_right_adapter(self) -> None:
        from control_plane.adapters.postgres import PostgresAdapter

        adapter = SourceRegistry.from_document({"sources": [WAREHOUSE]}).get("warehouse").build()
        assert isinstance(adapter, PostgresAdapter)
