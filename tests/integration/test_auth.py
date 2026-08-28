"""Authentication and scope enforcement."""

from __future__ import annotations

from control_plane.auth.keys import Scope


class TestAuthentication:
    async def test_no_key_is_rejected(self, authed_client) -> None:
        client, _, _ = authed_client
        response = await client.get("/v1/policies")
        assert response.status_code == 401
        assert response.headers["www-authenticate"] == "Bearer"

    async def test_bearer_scheme_works(self, authed_client) -> None:
        client, admin, _ = authed_client
        response = await client.get("/v1/policies", headers={"Authorization": f"Bearer {admin}"})
        assert response.status_code == 200

    async def test_api_key_header_works(self, authed_client) -> None:
        client, admin, _ = authed_client
        assert (await client.get("/v1/policies", headers={"X-API-Key": admin})).status_code == 200

    async def test_a_wrong_key_is_rejected(self, authed_client) -> None:
        client, _, _ = authed_client
        response = await client.get(
            "/v1/policies", headers={"X-API-Key": "cpk_deadbeef_notarealsecret"}
        )
        assert response.status_code == 401

    async def test_a_malformed_key_is_rejected(self, authed_client) -> None:
        client, _, _ = authed_client
        assert (
            await client.get("/v1/policies", headers={"X-API-Key": "garbage"})
        ).status_code == 401

    async def test_failures_do_not_reveal_which_part_was_wrong(self, authed_client) -> None:
        """A probe must not learn that a prefix exists but the secret is wrong."""
        client, admin, _ = authed_client
        prefix = admin.split("_")[1]
        unknown = await client.get(
            "/v1/policies", headers={"X-API-Key": "cpk_00000000_wrongsecret"}
        )
        known_prefix = await client.get(
            "/v1/policies", headers={"X-API-Key": f"cpk_{prefix}_wrongsecret"}
        )
        assert unknown.status_code == known_prefix.status_code == 401
        assert unknown.json() == known_prefix.json()

    async def test_health_needs_no_credential(self, authed_client) -> None:
        client, _, _ = authed_client
        assert (await client.get("/v1/health")).status_code == 200


class TestScopes:
    async def test_a_scope_gates_its_endpoint(self, authed_client) -> None:
        client, _, issue = authed_client
        decide_only = await issue([Scope.DECIDE])
        response = await client.get("/v1/policies", headers={"X-API-Key": decide_only})
        assert response.status_code == 403
        assert "policy:read" in response.json()["detail"]

    async def test_write_implies_read(self, authed_client) -> None:
        client, _, issue = authed_client
        writer = await issue([Scope.POLICY_WRITE])
        assert (await client.get("/v1/policies", headers={"X-API-Key": writer})).status_code == 200

    async def test_read_does_not_imply_write(self, authed_client) -> None:
        client, _, issue = authed_client
        reader = await issue([Scope.POLICY_READ])
        response = await client.post(
            "/v1/policies",
            headers={"X-API-Key": reader},
            json={"policy": {"key": "x", "name": "X", "effect": "allow", "match": {}}},
        )
        assert response.status_code == 403

    async def test_admin_implies_everything(self, authed_client) -> None:
        client, admin, _ = authed_client
        for path in ("/v1/policies", "/v1/assets", "/v1/audit", "/v1/keys"):
            response = await client.get(path, headers={"X-API-Key": admin})
            assert response.status_code == 200, path


class TestPrincipalBinding:
    async def test_a_bound_key_cannot_speak_for_another_principal(self, authed_client) -> None:
        """A stolen agent key must not be usable to impersonate a privileged one."""
        client, _, issue = authed_client
        bound = await issue([Scope.DECIDE], allowed_principals=["agent:support_bot"])

        allowed = await client.post(
            "/v1/decide",
            headers={"X-API-Key": bound},
            json={
                "principal": {"id": "agent:support_bot", "type": "agent"},
                "action": "read",
                "resource": {"urn": "qdrant://kb"},
            },
        )
        assert allowed.status_code == 200

        forbidden = await client.post(
            "/v1/decide",
            headers={"X-API-Key": bound},
            json={
                "principal": {"id": "user:cfo", "type": "user"},
                "action": "read",
                "resource": {"urn": "qdrant://kb"},
            },
        )
        assert forbidden.status_code == 403

    async def test_a_wildcard_binding_covers_a_family(self, authed_client) -> None:
        client, _, issue = authed_client
        bound = await issue([Scope.DECIDE], allowed_principals=["agent:*"])
        response = await client.post(
            "/v1/decide",
            headers={"X-API-Key": bound},
            json={
                "principal": {"id": "agent:anything", "type": "agent"},
                "action": "read",
                "resource": {"urn": "qdrant://kb"},
            },
        )
        assert response.status_code == 200

    async def test_an_unbound_key_may_act_for_anyone(self, authed_client) -> None:
        client, _, issue = authed_client
        gateway = await issue([Scope.DECIDE])
        response = await client.post(
            "/v1/decide",
            headers={"X-API-Key": gateway},
            json={
                "principal": {"id": "user:anyone", "type": "user"},
                "action": "read",
                "resource": {"urn": "qdrant://kb"},
            },
        )
        assert response.status_code == 200


class TestKeyLifecycle:
    async def test_issue_returns_the_secret_exactly_once(self, authed_client) -> None:
        client, admin, _ = authed_client
        created = await client.post(
            "/v1/keys",
            headers={"X-API-Key": admin},
            json={"name": "pipeline", "scopes": ["decide"]},
        )
        body = created.json()
        assert body["key"].startswith("cpk_")

        listed = (await client.get("/v1/keys", headers={"X-API-Key": admin})).json()
        assert all("key" not in item for item in listed)
        assert not any(body["key"] in str(item) for item in listed)

    async def test_revocation_takes_effect_immediately(self, authed_client) -> None:
        client, admin, _ = authed_client
        created = (
            await client.post(
                "/v1/keys",
                headers={"X-API-Key": admin},
                json={"name": "temp", "scopes": ["policy:read"]},
            )
        ).json()
        assert (
            await client.get("/v1/policies", headers={"X-API-Key": created["key"]})
        ).status_code == 200

        await client.delete(f"/v1/keys/{created['prefix']}", headers={"X-API-Key": admin})
        assert (
            await client.get("/v1/policies", headers={"X-API-Key": created["key"]})
        ).status_code == 401

    async def test_unknown_scopes_are_rejected(self, authed_client) -> None:
        client, admin, _ = authed_client
        response = await client.post(
            "/v1/keys",
            headers={"X-API-Key": admin},
            json={"name": "bad", "scopes": ["become:root"]},
        )
        assert response.status_code == 422
        assert "unknown scopes" in response.json()["detail"]

    async def test_key_issuance_is_audited(self, authed_client) -> None:
        client, admin, _ = authed_client
        await client.post(
            "/v1/keys",
            headers={"X-API-Key": admin},
            json={"name": "audited", "scopes": ["decide"]},
        )
        events = (await client.get("/v1/audit", headers={"X-API-Key": admin})).json()
        issued = [e for e in events["items"] if e["event"] == "apikey.issued"]
        assert issued and issued[0]["payload"]["name"] == "audited"
        assert not any("cpk_" in str(e["payload"]) for e in events["items"])


class TestDigestUpgrade:
    async def test_a_legacy_digest_is_replaced_on_first_use(self, authed_client) -> None:
        """Verify, then upgrade, so nobody reissues a key over a scheme change."""
        from argon2 import PasswordHasher
        from sqlalchemy import select

        from control_plane.auth.keys import HMAC_SCHEME, generate_key
        from control_plane.models.auth import ApiKey

        client, _admin, _issue = authed_client
        issued = generate_key()

        # Plant a key hashed the old way, as an upgrade would find it.
        from control_plane.db import get_sessionmaker

        factory = get_sessionmaker()
        async with factory() as session:
            session.add(
                ApiKey(
                    name="legacy",
                    prefix=issued.prefix,
                    key_hash=PasswordHasher(
                        time_cost=2, memory_cost=64 * 1024, parallelism=2, hash_len=32
                    ).hash(issued.plaintext),
                    scopes=["policy:read"],
                )
            )
            await session.commit()

        assert (
            await client.get("/v1/policies", headers={"X-API-Key": issued.plaintext})
        ).status_code == 200

        async with factory() as session:
            stored = (
                await session.execute(select(ApiKey).where(ApiKey.prefix == issued.prefix))
            ).scalar_one()
            assert stored.key_hash.startswith(f"{HMAC_SCHEME}$")

        assert (
            await client.get("/v1/policies", headers={"X-API-Key": issued.plaintext})
        ).status_code == 200
