"""Adapter mapping logic. No live services required."""

from __future__ import annotations

import pytest

from control_plane.adapters import ChatTurn, LibreChatAdapter, MCPAdapter, ToolCall, infer_action
from control_plane.adapters.postgres import _suggest_labels


class _Column:
    def __init__(self, name: str, comment: str = "") -> None:
        self.column_name = name
        self.column_comment = comment


class TestActionInference:
    @pytest.mark.parametrize(
        ("tool", "expected"),
        [
            ("read_file", "read"),
            ("list_directory", "read"),
            ("search_web", "read"),
            ("write_file", "write"),
            ("send_email", "write"),
            ("delete_record", "delete"),
            ("drop_table", "delete"),
            ("run_shell", "execute"),
            ("execute_query", "execute"),
        ],
    )
    def test_names_map_to_actions(self, tool: str, expected: str) -> None:
        assert infer_action(tool) == expected

    def test_an_unrecognised_tool_defaults_to_execute(self) -> None:
        """The most restrictive reading, not the most convenient one."""
        assert infer_action("frobnicate_widget") == "execute"

    def test_a_declared_annotation_wins(self) -> None:
        assert infer_action("delete_everything", declared="read") == "read"

    def test_a_nonsense_annotation_is_ignored(self) -> None:
        assert infer_action("read_file", declared="whatever") == "read"


class TestMCPMapping:
    def test_a_tool_call_becomes_a_decide_request(self) -> None:
        call = ToolCall(
            server="filesystem",
            tool="read_file",
            agent_id="agent:coder",
            arguments={"path": "/etc/passwd"},
            conversation_id="conv-1",
        )
        body = call.decide_request()
        assert body["resource"]["urn"] == "mcp://filesystem/read_file"
        assert body["action"] == "read"
        assert body["payload"] == {"path": "/etc/passwd"}
        assert body["correlation_id"] == "conv-1"

    def test_arguments_are_the_payload_so_they_get_classified(self) -> None:
        """An agent pasting a customer record into a search query is exfiltration."""
        call = ToolCall(
            server="web",
            tool="search",
            agent_id="agent:x",
            arguments={"query": "who is jane.doe@acme.com, ssn 536-90-4432"},
        )
        assert "536-90-4432" in str(call.decide_request()["payload"])

    def test_results_are_a_separate_question(self) -> None:
        call = ToolCall(server="fs", tool="read_file", agent_id="agent:x", arguments={})
        result = call.result_request("contents with jane@acme.com")
        assert result["action"] == "return"
        assert result["context"]["direction"] == "result"

    def test_a_tool_listing_becomes_catalog_assets(self) -> None:
        assets = MCPAdapter("filesystem").discover_from_listing(
            [
                {
                    "name": "read_file",
                    "description": "Read a file",
                    "inputSchema": {"properties": {"path": {}}},
                    "annotations": {"readOnlyHint": True},
                },
                {"name": "delete_file", "description": "Delete a file"},
            ]
        )
        assert [a.urn for a in assets] == [
            "mcp://filesystem/read_file",
            "mcp://filesystem/delete_file",
        ]
        assert assets[0].attributes["destructive"] is False
        assert assets[1].attributes["destructive"] is True
        assert assets[0].attributes["parameters"] == ["path"]

    def test_unnamed_tools_are_skipped(self) -> None:
        assert MCPAdapter("s").discover_from_listing([{"description": "no name"}]) == []


class TestLibreChatMapping:
    def test_an_external_endpoint_is_marked_external(self) -> None:
        turn = ChatTurn(
            user_id="u1",
            conversation_id="c1",
            endpoint="anthropic",
            model="claude-opus-5",
            text="hello",
        )
        assert turn.destination == "external"
        assert turn.decide_request()["context"]["destination"] == "external"

    def test_a_self_hosted_endpoint_is_internal(self) -> None:
        turn = ChatTurn(
            user_id="u1", conversation_id="c1", endpoint="ollama", model="llama3", text="hi"
        )
        assert turn.destination == "internal"

    def test_an_agent_acts_on_its_own_behalf(self) -> None:
        turn = ChatTurn(
            user_id="u1",
            conversation_id="c1",
            endpoint="openai",
            model="gpt-4",
            text="hi",
            agent_id="researcher",
        )
        assert turn.principal_id == "agent:researcher"
        assert turn.principal_type == "agent"

    def test_a_plain_user_turn_is_attributed_to_the_user(self) -> None:
        turn = ChatTurn(
            user_id="u1", conversation_id="c1", endpoint="openai", model="gpt-4", text="hi"
        )
        assert turn.principal_id == "user:u1"

    def test_an_upload_becomes_an_unclassified_asset(self) -> None:
        asset = LibreChatAdapter("main").asset_for_upload(
            "f-99", filename="patients.csv", uploaded_by="user:nurse", size_bytes=2048
        )
        assert asset.urn == "librechat://main/files/f-99"
        assert asset.owner == "user:nurse"
        assert asset.attributes["classified"] is False

    def test_agents_become_assets_too(self) -> None:
        assets = LibreChatAdapter().assets_for_agents(
            [{"id": "a1", "name": "Researcher", "provider": "openai", "tools": ["web"]}]
        )
        assert assets[0].kind == "agent"
        assert assets[0].attributes["tools"] == ["web"]


class TestColumnHints:
    def test_exact_and_substring_names_are_recognised(self) -> None:
        labels = _suggest_labels(
            [_Column("ssn"), _Column("customer_email"), _Column("id"), _Column("created_at")]
        )
        assert set(labels) == {"pii.ssn", "pii.email"}

    def test_a_documented_label_in_a_comment_is_honoured(self) -> None:
        """A team that already documented the sensitivity should not redo it."""
        labels = _suggest_labels([_Column("notes", "may contain pii.dob")])
        assert labels == ("pii.dob",)

    def test_nothing_is_suggested_for_ordinary_columns(self) -> None:
        assert _suggest_labels([_Column("id"), _Column("quantity")]) == ()
