"""The HTTP surface, exercised through a real ASGI client."""

from __future__ import annotations

import pytest

DENY_SECRETS = {
    "policy": {
        "key": "deny-secrets",
        "name": "Credentials never leave the control plane",
        "effect": "deny",
        "priority": 950,
        "match": {"findings": {"any_of": ["secret"]}},
    },
    "change_note": "initial control",
}

ALLOW_AGENTS = {
    "policy": {
        "key": "allow-agents",
        "name": "Agents may read with PII masked",
        "effect": "allow",
        "priority": 100,
        "match": {"all": [{"principal.type": "agent"}, {"action": ["read", "embed"]}]},
        "obligations": [{"type": "redact", "labels": ["pii"], "strategy": "mask"}],
    },
    "change_note": "initial control",
}


@pytest.fixture
async def seeded(client):
    """A client with a minimal working policy set."""
    for policy in (DENY_SECRETS, ALLOW_AGENTS):
        response = await client.post("/v1/policies", json=policy)
        assert response.status_code == 201, response.text
    return client


def decide_body(**overrides) -> dict:
    body = {
        "principal": {"id": "agent:bot", "type": "agent"},
        "action": "read",
        "resource": {"urn": "qdrant://kb"},
    }
    body.update(overrides)
    return body


class TestServiceEndpoints:
    async def test_root_advertises_the_decision_endpoint(self, client) -> None:
        body = (await client.get("/")).json()
        assert body["decide"] == "/v1/decide"

    async def test_health_and_readiness(self, client) -> None:
        assert (await client.get("/v1/health")).json()["status"] == "ok"
        ready = (await client.get("/v1/ready")).json()
        assert ready["database"] == "ok"
        assert ready["default_effect"] == "deny"

    async def test_openapi_is_served(self, client) -> None:
        spec = (await client.get("/openapi.json")).json()
        assert "/v1/decide" in spec["paths"]

    async def test_request_id_is_echoed(self, client) -> None:
        response = await client.get("/v1/health", headers={"x-request-id": "abc-123"})
        assert response.headers["x-request-id"] == "abc-123"
        assert "x-response-time-ms" in response.headers


class TestPolicyAdministration:
    async def test_create_read_update_version(self, client) -> None:
        created = await client.post("/v1/policies", json=ALLOW_AGENTS)
        assert created.status_code == 201
        assert created.json()["version"] == 1

        updated = await client.put(
            "/v1/policies/allow-agents",
            json={
                "policy": {**ALLOW_AGENTS["policy"], "priority": 150},
                "change_note": "raised priority above the export rule",
            },
        )
        assert updated.json()["version"] == 2
        assert updated.json()["priority"] == 150

        versions = (await client.get("/v1/policies/allow-agents/versions")).json()
        assert [v["version"] for v in versions] == [2, 1]
        assert versions[0]["change_note"] == "raised priority above the export rule"

    async def test_duplicate_key_conflicts(self, client) -> None:
        await client.post("/v1/policies", json=ALLOW_AGENTS)
        assert (await client.post("/v1/policies", json=ALLOW_AGENTS)).status_code == 409

    async def test_invalid_policy_is_rejected_with_a_reason(self, client) -> None:
        response = await client.post(
            "/v1/policies",
            json={
                "policy": {
                    "key": "bad",
                    "name": "Bad",
                    "effect": "allow",
                    "match": {"nonsense.field": "x"},
                }
            },
        )
        assert response.status_code == 422
        assert "must start with one of" in response.json()["detail"]

    async def test_disable_then_enable(self, client) -> None:
        await client.post("/v1/policies", json=ALLOW_AGENTS)
        disabled = await client.post("/v1/policies/allow-agents/enabled?enabled=false")
        assert disabled.json()["enabled"] is False
        enabled = await client.post("/v1/policies/allow-agents/enabled?enabled=true")
        assert enabled.json()["enabled"] is True

    async def test_delete(self, client) -> None:
        await client.post("/v1/policies", json=ALLOW_AGENTS)
        assert (await client.delete("/v1/policies/allow-agents")).status_code == 204
        assert (await client.get("/v1/policies/allow-agents")).status_code == 404

    async def test_sync_reports_what_changed(self, client) -> None:
        first = await client.post(
            "/v1/policies/sync",
            json={"policies": [ALLOW_AGENTS["policy"], DENY_SECRETS["policy"]]},
        )
        assert first.json()["created"] == ["allow-agents", "deny-secrets"]

        second = await client.post(
            "/v1/policies/sync",
            json={"policies": [ALLOW_AGENTS["policy"], DENY_SECRETS["policy"]]},
        )
        assert second.json()["unchanged"] == ["allow-agents", "deny-secrets"]
        assert second.json()["updated"] == []

    async def test_sync_prunes_only_when_asked(self, client) -> None:
        await client.post(
            "/v1/policies/sync",
            json={"policies": [ALLOW_AGENTS["policy"], DENY_SECRETS["policy"]]},
        )
        kept = await client.post("/v1/policies/sync", json={"policies": [ALLOW_AGENTS["policy"]]})
        assert kept.json()["removed"] == []

        pruned = await client.post(
            "/v1/policies/sync", json={"policies": [ALLOW_AGENTS["policy"]], "prune": True}
        )
        assert pruned.json()["removed"] == ["deny-secrets"]

    async def test_schema_describes_the_language(self, client) -> None:
        schema = (await client.get("/v1/policies/schema")).json()
        assert "any_of" in schema["operators"]
        assert "resource" in schema["selectors"]
        assert {"allow", "deny", "require_approval"} == set(schema["effects"])
        assert any(label["key"] == "pii.ssn" for label in schema["labels"])


class TestCatalog:
    async def test_register_classify_and_resolve(self, client) -> None:
        await client.post(
            "/v1/assets",
            json={"urn": "pg://public.customers", "name": "Customers", "owner": "data-team"},
        )
        await client.post(
            "/v1/assets/classifications?urn=pg://public.customers",
            json={"label": "pii.ssn", "source": "manual"},
        )
        resolved = (await client.get("/v1/assets/resolve?urn=pg://public.customers")).json()
        assert resolved["classifications"] == ["pii.ssn"]
        assert "GLBA" in resolved["regulations"]

    async def test_pattern_registration_covers_unregistered_assets(self, client) -> None:
        await client.post("/v1/assets", json={"urn": "pg://clinical.*"})
        await client.post(
            "/v1/assets/classifications?urn=pg://clinical.*",
            json={"label": "phi.mrn", "source": "manual"},
        )
        resolved = (await client.get("/v1/assets/resolve?urn=pg://clinical.encounters")).json()
        assert resolved["classifications"] == ["phi.mrn"]
        assert resolved["matched_patterns"] == ["pg://clinical.*"]
        assert resolved["registered"] is True

    async def test_scan_infers_labels_and_stores_only_previews(self, client) -> None:
        response = await client.post(
            "/v1/assets/scan",
            json={
                "urn": "pg://public.orders",
                "sample": {"email": "jane@acme.com", "card": "4111 1111 1111 1111"},
            },
        )
        body = response.json()
        assert set(body["labels_applied"]) == {"pii.email", "pci.card_number"}

        detail = (await client.get("/v1/assets/detail?urn=pg://public.orders")).json()
        evidence = str(detail["classifications"])
        assert "jane@acme.com" not in evidence
        assert "4111 1111 1111 1111" not in evidence

    async def test_unknown_label_is_rejected(self, client) -> None:
        await client.post("/v1/assets", json={"urn": "x://y"})
        response = await client.post(
            "/v1/assets/classifications?urn=x://y", json={"label": "pii.aura"}
        )
        assert response.status_code == 422

    async def test_principal_attributes_round_trip(self, client) -> None:
        await client.post(
            "/v1/principals",
            json={
                "external_id": "agent:bot",
                "type": "agent",
                "attributes": {"trust_tier": "low"},
            },
        )
        body = (await client.get("/v1/principals/detail?external_id=agent:bot")).json()
        assert body["attributes"]["trust_tier"] == "low"

    async def test_filter_assets_by_label(self, client) -> None:
        await client.post("/v1/assets", json={"urn": "pg://a"})
        await client.post("/v1/assets", json={"urn": "pg://b"})
        await client.post("/v1/assets/classifications?urn=pg://a", json={"label": "phi.mrn"})
        found = (await client.get("/v1/assets?label=phi")).json()
        assert [a["urn"] for a in found] == ["pg://a"]


class TestDecisionEndpoint:
    async def test_allow_with_redaction(self, seeded) -> None:
        response = await seeded.post(
            "/v1/decide", json=decide_body(payload="write to jane.doe@acme.com")
        )
        body = response.json()
        assert body["effect"] == "allow"
        assert "jane.doe@acme.com" not in body["payload"]
        assert body["redactions"][0]["label"] == "pii.email"

    async def test_deny_withholds_the_payload(self, seeded) -> None:
        body = (await seeded.post("/v1/decide", json=decide_body(payload="ghp_" + "a" * 36))).json()
        assert body["effect"] == "deny"
        assert body["payload"] is None

    async def test_explain_returns_the_trace(self, seeded) -> None:
        body = (await seeded.post("/v1/decide", json=decide_body(options={"explain": True}))).json()
        assert body["explain"]["trace"]

    async def test_classify_endpoint_reports_without_deciding(self, client) -> None:
        body = (
            await client.post(
                "/v1/classify", json={"payload": "ssn 536-90-4432 and card 4111111111111111"}
            )
        ).json()
        assert set(body["labels"]) == {"pii.ssn", "pci.card_number"}
        assert body["max_severity"] == "critical"
        assert "536-90-4432" not in str(body)

    async def test_decisions_are_listed_and_retrievable(self, seeded) -> None:
        created = (await seeded.post("/v1/decide", json=decide_body())).json()
        listing = (await seeded.get("/v1/decisions")).json()
        assert listing["total"] == 1

        detail = (await seeded.get(f"/v1/decisions/{created['decision_id']}")).json()
        assert detail["effect"] == "allow"

    async def test_decision_stats_aggregate(self, seeded) -> None:
        await seeded.post("/v1/decide", json=decide_body())
        await seeded.post("/v1/decide", json=decide_body(payload="ghp_" + "a" * 36))
        stats = (await seeded.get("/v1/decisions/stats")).json()
        assert stats["by_effect"] == {"allow": 1, "deny": 1}


class TestSimulation:
    async def test_simulation_shows_the_effect_of_a_change(self, seeded) -> None:
        stricter = {
            "key": "deny-all-email",
            "name": "Block anything containing an email address",
            "effect": "deny",
            "priority": 990,
            "match": {"findings": {"any_of": ["pii.email"]}},
        }
        body = (
            await seeded.post(
                "/v1/simulate",
                json={
                    "request": decide_body(payload="mail jane.doe@acme.com"),
                    "additional_policies": [stricter],
                },
            )
        ).json()
        assert body["decision"]["effect"] == "deny"
        assert body["baseline"]["effect"] == "allow"
        assert body["changed"] is True

    async def test_simulation_persists_nothing(self, seeded) -> None:
        await seeded.post(
            "/v1/simulate", json={"request": decide_body(), "additional_policies": []}
        )
        assert (await seeded.get("/v1/decisions")).json()["total"] == 0

    async def test_invalid_candidate_policies_are_rejected(self, seeded) -> None:
        response = await seeded.post(
            "/v1/simulate",
            json={"request": decide_body(), "policies": [{"key": "x"}]},
        )
        assert response.status_code == 422


class TestAuditEndpoint:
    async def test_administrative_changes_are_audited(self, client) -> None:
        await client.post("/v1/policies", json=ALLOW_AGENTS)
        events = (await client.get("/v1/audit")).json()
        assert events["items"][0]["event"] == "policy.created"
        assert events["items"][0]["subject"] == "allow-agents"

    async def test_chain_verifies(self, seeded) -> None:
        await seeded.post("/v1/decide", json=decide_body())
        result = (await seeded.get("/v1/audit/verify")).json()
        assert result["valid"] is True
        assert result["checked"] >= 3

    async def test_events_can_be_filtered(self, seeded) -> None:
        await seeded.post("/v1/decide", json=decide_body())
        filtered = (await seeded.get("/v1/audit?event=decision")).json()
        assert all(item["event"] == "decision" for item in filtered["items"])


class TestApprovals:
    @pytest.fixture
    async def parked(self, client):
        await client.post(
            "/v1/policies",
            json={
                "policy": {
                    "key": "approve-exports",
                    "name": "Exports need a human",
                    "effect": "require_approval",
                    "priority": 500,
                    "match": {"action": "export"},
                }
            },
        )
        response = await client.post("/v1/decide", json=decide_body(action="export"))
        return client, response.json()

    async def test_decision_is_parked(self, parked) -> None:
        _, decision = parked
        assert decision["effect"] == "require_approval"
        assert decision["approval"]["status"] == "pending"

    async def test_queue_lists_it_with_context(self, parked) -> None:
        client, _ = parked
        queue = (await client.get("/v1/approvals")).json()
        assert len(queue) == 1
        assert queue[0]["decision"]["action"] == "export"

    async def test_granting_records_who_decided(self, parked) -> None:
        client, decision = parked
        approval_id = decision["approval"]["id"]
        granted = (
            await client.post(
                f"/v1/approvals/{approval_id}/decide?grant=true",
                json={"note": "ticket DATA-1183"},
            )
        ).json()
        assert granted["status"] == "granted"
        assert granted["decision_note"] == "ticket DATA-1183"

    async def test_cannot_resolve_twice(self, parked) -> None:
        client, decision = parked
        approval_id = decision["approval"]["id"]
        await client.post(f"/v1/approvals/{approval_id}/decide?grant=true", json={"note": ""})
        again = await client.post(
            f"/v1/approvals/{approval_id}/decide?grant=false", json={"note": ""}
        )
        assert again.status_code == 409


class TestApprovalRedemptionOverHttp:
    """The loop a reviewer will actually walk through by hand."""

    @pytest.fixture
    async def parked(self, client):
        await client.post(
            "/v1/policies",
            json={
                "policy": {
                    "key": "approve-exports",
                    "name": "Exports need a human",
                    "effect": "require_approval",
                    "priority": 500,
                    "match": {"action": "export"},
                }
            },
        )
        response = await client.post("/v1/decide", json=decide_body(action="export"))
        return client, response.json()

    async def test_the_whole_loop(self, parked) -> None:
        client, decision = parked
        assert decision["effect"] == "require_approval"
        approval_id = decision["approval"]["id"]

        # Nothing to redeem yet.
        pending = await client.post(
            "/v1/decide", json=decide_body(action="export", approval_id=approval_id)
        )
        assert pending.json()["effect"] == "require_approval"
        assert "awaiting a decision" in pending.json()["approval_error"]

        # A human grants it.
        granted = await client.post(
            f"/v1/approvals/{approval_id}/decide?grant=true", json={"note": "DATA-1183"}
        )
        assert granted.json()["status"] == "granted"

        # The same request now succeeds.
        redeemed = await client.post(
            "/v1/decide", json=decide_body(action="export", approval_id=approval_id)
        )
        body = redeemed.json()
        assert body["effect"] == "allow"
        assert body["approval_redeemed"] is True
        assert body["approval"]["decision_note"] == "DATA-1183"

        # And only once.
        again = await client.post(
            "/v1/decide", json=decide_body(action="export", approval_id=approval_id)
        )
        assert again.json()["effect"] == "require_approval"
        assert "already redeemed" in again.json()["approval_error"]

    async def test_polling_endpoint_reports_redeemability(self, parked) -> None:
        client, decision = parked
        approval_id = decision["approval"]["id"]

        before = (await client.get(f"/v1/approvals/{approval_id}")).json()
        assert before["status"] == "pending"
        assert before["redeemable"] is False

        await client.post(f"/v1/approvals/{approval_id}/decide?grant=true", json={"note": ""})
        after = (await client.get(f"/v1/approvals/{approval_id}")).json()
        assert after["redeemable"] is True
        assert after["decision"]["action"] == "export"

        await client.post("/v1/decide", json=decide_body(action="export", approval_id=approval_id))
        spent = (await client.get(f"/v1/approvals/{approval_id}")).json()
        assert spent["redeemable"] is False
        assert spent["redeemed_at"] is not None
        assert spent["redeemed_decision_id"] is not None

    async def test_an_approval_does_not_transfer_to_another_request(self, parked) -> None:
        client, decision = parked
        approval_id = decision["approval"]["id"]
        await client.post(f"/v1/approvals/{approval_id}/decide?grant=true", json={"note": ""})

        elsewhere = await client.post(
            "/v1/decide",
            json=decide_body(
                action="export", resource={"urn": "pg://somewhere.else"}, approval_id=approval_id
            ),
        )
        assert elsewhere.json()["effect"] == "require_approval"
        assert "different request" in elsewhere.json()["approval_error"]

    async def test_an_unknown_approval_is_a_404_on_the_polling_endpoint(self, client) -> None:
        import uuid

        response = await client.get(f"/v1/approvals/{uuid.uuid4()}")
        assert response.status_code == 404

    async def test_redemption_is_visible_in_the_audit_chain(self, parked) -> None:
        client, decision = parked
        approval_id = decision["approval"]["id"]
        await client.post(f"/v1/approvals/{approval_id}/decide?grant=true", json={"note": ""})
        await client.post("/v1/decide", json=decide_body(action="export", approval_id=approval_id))

        events = (await client.get("/v1/audit")).json()
        kinds = {item["event"] for item in events["items"]}
        assert {"approval.requested", "approval.granted", "approval.redeemed"} <= kinds
        assert (await client.get("/v1/audit/verify")).json()["valid"] is True


class TestDiscoverySources:
    """The HTTP surface for discovery. Credentials stay server-side."""

    @staticmethod
    def _configure(monkeypatch, tmp_path, document) -> None:
        import yaml

        from control_plane.config import reset_settings_cache

        path = tmp_path / "sources.yaml"
        path.write_text(yaml.safe_dump(document))
        monkeypatch.setenv("CP_SOURCES_FILE", str(path))
        reset_settings_cache()

    async def test_no_sources_configured_is_an_empty_list(self, client, monkeypatch) -> None:
        from control_plane.config import reset_settings_cache

        monkeypatch.setenv("CP_SOURCES_FILE", "/nonexistent/sources.yaml")
        reset_settings_cache()
        assert (await client.get("/v1/catalog/sources")).json() == []

    async def test_sources_are_listed_without_their_credentials(
        self, client, monkeypatch, tmp_path
    ) -> None:
        self._configure(
            monkeypatch,
            tmp_path,
            {
                "sources": [
                    {
                        "name": "warehouse",
                        "adapter": "postgres",
                        "dsn": "postgresql+asyncpg://user:hunter2@db/warehouse",
                        "owner": "data-platform",
                        "exclude": ["pg://audit.*"],
                    }
                ]
            },
        )
        body = (await client.get("/v1/catalog/sources")).json()
        assert body[0]["name"] == "warehouse"
        assert body[0]["target"] == "[configured]"
        assert body[0]["exclude"] == ["pg://audit.*"]
        assert "hunter2" not in str(body)

    async def test_an_unset_variable_leaves_a_source_listable(
        self, client, monkeypatch, tmp_path
    ) -> None:
        """One missing credential must not make the whole file unreadable."""
        monkeypatch.delenv("CP_TEST_MISSING_DSN", raising=False)
        self._configure(
            monkeypatch,
            tmp_path,
            {
                "sources": [
                    {"name": "a", "adapter": "postgres", "dsn": "${CP_TEST_MISSING_DSN}"},
                    {"name": "b", "adapter": "qdrant", "base_url": "http://q:6333"},
                ]
            },
        )
        body = (await client.get("/v1/catalog/sources")).json()
        assert [s["name"] for s in body] == ["a", "b"]
        assert body[0]["target"] == "[not configured]"

    async def test_an_unknown_source_is_a_404(self, client, monkeypatch, tmp_path) -> None:
        self._configure(monkeypatch, tmp_path, {"sources": []})
        response = await client.post("/v1/catalog/sources/nope/discover", json={})
        assert response.status_code == 404
        assert "no source named" in response.json()["detail"]

    async def test_a_disabled_source_is_refused(self, client, monkeypatch, tmp_path) -> None:
        self._configure(
            monkeypatch,
            tmp_path,
            {
                "sources": [
                    {
                        "name": "legacy",
                        "adapter": "postgres",
                        "dsn": "postgresql+asyncpg://u:p@db/x",
                        "enabled": False,
                    }
                ]
            },
        )
        response = await client.post("/v1/catalog/sources/legacy/discover", json={})
        assert response.status_code == 409
        assert "disabled" in response.json()["detail"]

    async def test_an_unconfigured_source_says_what_is_missing(
        self, client, monkeypatch, tmp_path
    ) -> None:
        monkeypatch.delenv("CP_TEST_MISSING_DSN", raising=False)
        self._configure(
            monkeypatch,
            tmp_path,
            {"sources": [{"name": "a", "adapter": "postgres", "dsn": "${CP_TEST_MISSING_DSN}"}]},
        )
        response = await client.post("/v1/catalog/sources/a/discover", json={})
        assert response.status_code == 409
        assert "environment variable" in response.json()["detail"]

    async def test_an_unreachable_source_reports_in_the_body_not_a_500(
        self, client, monkeypatch, tmp_path
    ) -> None:
        """A source being down is a result to report, not a server fault."""
        self._configure(
            monkeypatch,
            tmp_path,
            {
                "sources": [
                    {
                        "name": "down",
                        "adapter": "qdrant",
                        "base_url": "http://127.0.0.1:1",
                        "timeout": 0.2,
                    }
                ]
            },
        )
        response = await client.post("/v1/catalog/sources/down/discover", json={})
        assert response.status_code == 200
        body = response.json()
        assert body["discovered"] == 0
        assert body["errors"]

    async def test_a_mapping_adapter_cannot_be_configured_as_a_source(
        self, client, monkeypatch, tmp_path
    ) -> None:
        self._configure(monkeypatch, tmp_path, {"sources": [{"name": "t", "adapter": "mcp"}]})
        response = await client.get("/v1/catalog/sources")
        assert response.status_code == 500
        assert "mapping adapter" in response.json()["detail"]
