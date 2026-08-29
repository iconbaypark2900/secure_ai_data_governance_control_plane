"""Mapping a real MCP tool listing onto governed actions.

tests/fixtures/mcp_tools_list.json is a subset of an actual ``tools/list``
response from a gateway fronting the filesystem, git, memory, arxiv, fetch,
context7 and github servers -- recorded, not invented. It is trimmed (verbose
per-property schemas and output schemas removed) but the names, descriptions and
annotations are verbatim, because the annotations are the thing under test and
they are the one part that cannot be guessed correctly.

The listing of 118 tools it came from showed the adapter reading one of MCP's
four annotation hints and ignoring the rest.
"""

from __future__ import annotations

import json
import pathlib

import pytest

from control_plane.adapters.mcp_gateway import MCPAdapter, declared_action, infer_action

LISTING = json.loads(
    (pathlib.Path(__file__).parent.parent / "fixtures" / "mcp_tools_list.json").read_text()
)


@pytest.fixture(scope="module")
def assets() -> dict[str, dict]:
    found = MCPAdapter("mcphub").discover_from_listing(LISTING)
    return {a.name: a.attributes for a in found}


class TestDeclaredActionUsesEveryHint:
    def test_a_destructive_tool_is_a_delete(self) -> None:
        """The defect this file exists for.

        Only readOnlyHint was read, so a tool the server explicitly flagged
        destructive fell through to guessing from its name. On the real listing
        that misclassified six of nine declared-destructive tools.
        """
        assert declared_action({"readOnlyHint": False, "destructiveHint": True}) == "delete"

    def test_read_only_is_a_read(self) -> None:
        assert declared_action({"readOnlyHint": True}) == "read"

    def test_explicitly_not_read_only_is_at_least_a_write(self) -> None:
        """Never a read: the server said so, and the name is the weaker signal."""
        assert declared_action({"readOnlyHint": False}) == "write"
        assert declared_action({"readOnlyHint": False, "destructiveHint": False}) == "write"

    def test_a_contradictory_pair_resolves_restrictively(self) -> None:
        """Nothing sane emits this; a governance layer should not require sanity."""
        assert declared_action({"readOnlyHint": True, "destructiveHint": True}) == "delete"

    def test_silence_is_silence(self) -> None:
        assert declared_action({}) is None
        assert declared_action({"openWorldHint": True}) is None

    def test_absence_of_a_destructive_hint_is_not_read_as_destruction(self) -> None:
        """The spec's prose defaults destructiveHint to true. We do not.

        The SDK schema applies no default, and on a real gateway five plainly
        non-destructive arxiv tools omitted it. A delete label that is usually
        wrong is one operators learn to ignore, so the raw hint is stored
        instead and a stricter reading is left available to policy.
        """
        assert declared_action({"readOnlyHint": False}) != "delete"


class TestAgainstTheRecordedListing:
    def test_declared_destructive_tools_map_to_delete(self, assets) -> None:
        for name in ("filesystem-write_file", "git-git_reset", "memory-delete_entities"):
            assert assets[name]["action"] == "delete", name
            assert assets[name]["destructive"] is True

    def test_a_declaration_beats_a_misleading_name(self, assets) -> None:
        """'get_paper_latex' reads like a read. The server says it is not."""
        assert assets["arxiv-get_paper_latex"]["read_only"] is False
        assert assets["arxiv-get_paper_latex"]["action"] == "write"

    def test_a_declaration_rescues_a_name_we_cannot_parse(self, assets) -> None:
        """'git_status' is unrecognised, so inference alone would say execute."""
        assert infer_action("git-git_status") == "execute"
        assert assets["git-git_status"]["action"] == "read"

    def test_the_servers_word_on_not_being_destructive_is_honoured(self, assets) -> None:
        """It was previously overridden: destructive was just action != read."""
        assert assets["git-git_status"]["destructive"] is False
        assert assets["context7-resolve-library-id"]["destructive"] is False

    def test_an_unannotated_tool_is_still_treated_conservatively(self, assets) -> None:
        assert assets["github-create_or_update_file"]["annotated"] is False
        assert assets["github-create_or_update_file"]["action_source"] == "inferred"
        assert assets["github-create_or_update_file"]["action"] == "write"

    def test_provenance_of_the_verdict_is_recorded(self, assets) -> None:
        """A hint is an assertion by the system being governed, not a finding.

        The MCP SDK's own note: clients "should never make tool use decisions
        based on ToolAnnotations received from untrusted servers." The adapter
        cannot verify them, so it records who said what and lets policy decide
        how much that is worth.
        """
        assert assets["filesystem-read_file"]["action_source"] == "declared"
        assert assets["fetch-fetch"]["action_source"] == "inferred"

    def test_reaching_outside_the_boundary_is_recorded(self, assets) -> None:
        """Egress is a governance fact independent of destructiveness."""
        assert assets["arxiv-search_papers"]["open_world"] is True
        assert assets["filesystem-read_file"]["open_world"] is False

    def test_parameters_are_captured_for_every_tool(self, assets) -> None:
        assert "path" in assets["filesystem-read_file"]["parameters"]
        assert all(isinstance(a["parameters"], list) for a in assets.values())


class TestMalformedListings:
    """A gateway is a system we do not control; it can send anything."""

    def test_a_tool_without_a_name_is_skipped(self) -> None:
        found = MCPAdapter("s").discover_from_listing([{"description": "no name"}])
        assert found == []

    def test_a_null_properties_block_does_not_crash(self) -> None:
        """inputSchema.properties is optional in the schema, so it can be absent."""
        found = MCPAdapter("s").discover_from_listing(
            [{"name": "t", "inputSchema": {"type": "object", "properties": None}}]
        )
        assert found[0].attributes["parameters"] == []

    def test_annotations_of_the_wrong_type_do_not_crash(self) -> None:
        found = MCPAdapter("s").discover_from_listing([{"name": "t", "annotations": None}])
        assert found[0].attributes["annotated"] is False
