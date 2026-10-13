"""Tests for the API client using respx to mock httpx."""

from __future__ import annotations

import pytest
import respx
from httpx import Response

from defined_mcp.client import DefinedApiError, DefinedClient
from defined_mcp.models import (
    FirewallRule,
    HostCreate,
    HostUpdate,
    PortRange,
    RoleCreate,
    RoleUpdate,
    RouteCreate,
    TagCreate,
)
from defined_mcp.settings import Settings
from tests.conftest import (
    PAGINATION_METADATA,
    SAMPLE_AUDIT_LOG,
    SAMPLE_HOST,
    SAMPLE_NETWORK,
    SAMPLE_ROLE,
    SAMPLE_ROLE_LIST_ITEM,
    SAMPLE_ROLE_NULL_TAGS,
    SAMPLE_ROUTE,
    SAMPLE_ROUTE_LIST_ITEM,
    SAMPLE_TAG,
)


@pytest.fixture
def client(settings_env: None) -> DefinedClient:
    return DefinedClient(Settings())


class TestAuth:
    @respx.mock
    async def test_auth_header(self, client: DefinedClient) -> None:
        route = respx.get("https://api.defined.net/v1/networks").mock(
            return_value=Response(200, json={"data": [], "metadata": {}})
        )
        await client.list_networks()
        assert route.called
        request = route.calls[0].request
        assert request.headers["authorization"] == "Bearer dnkey-test-key-12345"


class TestErrorHandling:
    @respx.mock
    async def test_api_error_raised(self, client: DefinedClient) -> None:
        respx.get("https://api.defined.net/v1/hosts/bad-id").mock(
            return_value=Response(
                404,
                json={"errors": [{"code": "ERR_NOT_FOUND", "message": "not found", "path": None}]},
            )
        )
        with pytest.raises(DefinedApiError) as exc_info:
            await client.get_host("bad-id")
        assert exc_info.value.status_code == 404
        assert "not found" in str(exc_info.value)

    @respx.mock
    async def test_api_error_non_json(self, client: DefinedClient) -> None:
        respx.get("https://api.defined.net/v1/hosts/bad").mock(
            return_value=Response(500, text="Internal Server Error")
        )
        with pytest.raises(DefinedApiError) as exc_info:
            await client.get_host("bad")
        assert exc_info.value.status_code == 500


class TestHosts:
    @respx.mock
    async def test_list_hosts(self, client: DefinedClient) -> None:
        respx.get("https://api.defined.net/v1/hosts").mock(
            return_value=Response(
                200,
                json={"data": [SAMPLE_HOST], "metadata": PAGINATION_METADATA},
            )
        )
        resp = await client.list_hosts()
        assert len(resp.data) == 1
        assert resp.data[0].name == "test-host"
        assert resp.metadata.has_next_page is True

    @respx.mock
    async def test_list_hosts_with_filters(self, client: DefinedClient) -> None:
        route = respx.get("https://api.defined.net/v1/hosts").mock(
            return_value=Response(200, json={"data": [], "metadata": {}})
        )
        await client.list_hosts(role_id="role-X", is_blocked=True, page_size=10)
        params = dict(route.calls[0].request.url.params)
        assert params["filter.roleID"] == "role-X"
        assert params["filter.isBlocked"] == "true"
        assert params["pageSize"] == "10"

    @respx.mock
    async def test_get_host(self, client: DefinedClient) -> None:
        host_id = SAMPLE_HOST["id"]
        respx.get(f"https://api.defined.net/v1/hosts/{host_id}").mock(
            return_value=Response(200, json={"data": SAMPLE_HOST, "metadata": {}})
        )
        host = await client.get_host(host_id)
        assert host.name == "test-host"
        assert host.ip_address == "100.100.0.10"

    @respx.mock
    async def test_create_host(self, client: DefinedClient) -> None:
        route = respx.post("https://api.defined.net/v1/hosts").mock(
            return_value=Response(200, json={"data": SAMPLE_HOST, "metadata": {}})
        )
        data = HostCreate(name="test-host", network_id="network-123")
        await client.create_host(data)
        body = route.calls[0].request.content
        import json

        payload = json.loads(body)
        assert payload["name"] == "test-host"
        assert payload["networkID"] == "network-123"

    @respx.mock
    async def test_update_host_uses_v2(self, client: DefinedClient) -> None:
        host_id = SAMPLE_HOST["id"]
        route = respx.put(f"https://api.defined.net/v2/hosts/{host_id}").mock(
            return_value=Response(200, json={"data": SAMPLE_HOST, "metadata": {}})
        )
        data = HostUpdate(name="updated", tags=["env:staging"])
        await client.update_host(host_id, data)
        assert route.called
        import json

        payload = json.loads(route.calls[0].request.content)
        assert payload["name"] == "updated"
        assert payload["tags"] == ["env:staging"]

    @respx.mock
    async def test_delete_host(self, client: DefinedClient) -> None:
        host_id = SAMPLE_HOST["id"]
        route = respx.delete(f"https://api.defined.net/v1/hosts/{host_id}").mock(
            return_value=Response(200, json={"data": {}, "metadata": {}})
        )
        await client.delete_host(host_id)
        assert route.called

    @respx.mock
    async def test_block_host(self, client: DefinedClient) -> None:
        host_id = SAMPLE_HOST["id"]
        blocked_host = {**SAMPLE_HOST, "isBlocked": True}
        respx.post(f"https://api.defined.net/v1/hosts/{host_id}/block").mock(
            return_value=Response(200, json={"data": {"host": blocked_host}, "metadata": {}})
        )
        host = await client.block_host(host_id)
        assert host.is_blocked is True

    @respx.mock
    async def test_enrollment_code(self, client: DefinedClient) -> None:
        host_id = SAMPLE_HOST["id"]
        respx.post(f"https://api.defined.net/v1/hosts/{host_id}/enrollment-code").mock(
            return_value=Response(
                200,
                json={
                    "data": {"code": "abc123", "lifetimeSeconds": 86400},
                    "metadata": {},
                },
            )
        )
        result = await client.create_enrollment_code(host_id)
        assert result["code"] == "abc123"

    @respx.mock
    async def test_host_and_enrollment_code(self, client: DefinedClient) -> None:
        respx.post("https://api.defined.net/v1/host-and-enrollment-code").mock(
            return_value=Response(
                200,
                json={
                    "data": {
                        "host": SAMPLE_HOST,
                        "enrollmentCode": {
                            "code": "xyz789",
                            "lifetimeSeconds": 86400,
                        },
                    },
                    "metadata": {},
                },
            )
        )
        data = HostCreate(name="new-host", network_id="net-1")
        result = await client.create_host_and_enrollment_code(data)
        assert result["host"]["name"] == "test-host"
        assert result["enrollmentCode"]["code"] == "xyz789"


class TestRoles:
    @respx.mock
    async def test_list_roles(self, client: DefinedClient) -> None:
        respx.get("https://api.defined.net/v1/roles").mock(
            return_value=Response(
                200,
                json={"data": [SAMPLE_ROLE_LIST_ITEM], "metadata": PAGINATION_METADATA},
            )
        )
        resp = await client.list_roles()
        assert len(resp.data) == 1
        assert resp.data[0].firewall_rules_count == 2
        assert resp.data[0].host_count == 3

    @respx.mock
    async def test_get_role_with_null_allowed_tags(self, client: DefinedClient) -> None:
        role_id = SAMPLE_ROLE_NULL_TAGS["id"]
        respx.get(f"https://api.defined.net/v1/roles/{role_id}").mock(
            return_value=Response(200, json={"data": SAMPLE_ROLE_NULL_TAGS, "metadata": {}})
        )
        role = await client.get_role(role_id)
        assert role.firewall_rules[0].allowed_tags is None
        assert role.firewall_rules[1].allowed_tags == ["ssh:allow"]

    @respx.mock
    async def test_create_role(self, client: DefinedClient) -> None:
        route = respx.post("https://api.defined.net/v1/roles").mock(
            return_value=Response(200, json={"data": SAMPLE_ROLE, "metadata": {}})
        )
        data = RoleCreate(
            name="web",
            firewall_rules=[
                FirewallRule(
                    protocol="TCP",
                    port_range=PortRange(from_port=443, to_port=443),
                    allowed_tags=["env:prod"],
                )
            ],
        )
        await client.create_role(data)
        import json

        payload = json.loads(route.calls[0].request.content)
        rule = payload["firewallRules"][0]
        assert rule["portRange"] == {"from": 443, "to": 443}
        assert rule["allowedTags"] == ["env:prod"]

    @respx.mock
    async def test_update_role_preserves_firewall_rules(self, client: DefinedClient) -> None:
        role_id = SAMPLE_ROLE["id"]
        route = respx.put(f"https://api.defined.net/v1/roles/{role_id}").mock(
            return_value=Response(200, json={"data": SAMPLE_ROLE, "metadata": {}})
        )
        data = RoleUpdate(
            description="updated",
            firewall_rules=[
                FirewallRule(
                    protocol="TCP",
                    description="SSH",
                    port_range=PortRange(from_port=22, to_port=22),
                    allowed_role_id="role-X",
                    allowed_tags=["env:prod"],
                )
            ],
        )
        await client.update_role(role_id, data)
        import json

        payload = json.loads(route.calls[0].request.content)
        rule = payload["firewallRules"][0]
        assert rule["portRange"] == {"from": 22, "to": 22}
        assert rule["allowedRoleID"] == "role-X"
        assert rule["allowedTags"] == ["env:prod"]
        assert rule["description"] == "SSH"


class TestTags:
    @respx.mock
    async def test_list_tags_uses_v2(self, client: DefinedClient) -> None:
        route = respx.get("https://api.defined.net/v2/tags").mock(
            return_value=Response(
                200,
                json={"data": [SAMPLE_TAG], "metadata": PAGINATION_METADATA},
            )
        )
        resp = await client.list_tags()
        assert route.called
        assert len(resp.data) == 1

    @respx.mock
    async def test_get_tag_uses_v1(self, client: DefinedClient) -> None:
        route = respx.get("https://api.defined.net/v1/tags/env:prod").mock(
            return_value=Response(200, json={"data": SAMPLE_TAG, "metadata": {}})
        )
        tag = await client.get_tag("env:prod")
        assert route.called
        assert tag.name == "env:prod"

    @respx.mock
    async def test_create_tag(self, client: DefinedClient) -> None:
        respx.post("https://api.defined.net/v1/tags").mock(
            return_value=Response(200, json={"data": SAMPLE_TAG, "metadata": {}})
        )
        data = TagCreate(name="env:prod", description="Production")
        tag = await client.create_tag(data)
        assert tag.name == "env:prod"


class TestNetworks:
    @respx.mock
    async def test_list_networks(self, client: DefinedClient) -> None:
        respx.get("https://api.defined.net/v1/networks").mock(
            return_value=Response(
                200,
                json={
                    "data": [SAMPLE_NETWORK],
                    "metadata": PAGINATION_METADATA,
                },
            )
        )
        resp = await client.list_networks()
        assert len(resp.data) == 1
        assert resp.data[0].cidr == "100.100.0.0/22"


class TestRoutes:
    @respx.mock
    async def test_list_routes(self, client: DefinedClient) -> None:
        respx.get("https://api.defined.net/v1/routes").mock(
            return_value=Response(
                200,
                json={
                    "data": [SAMPLE_ROUTE_LIST_ITEM],
                    "metadata": PAGINATION_METADATA,
                },
            )
        )
        resp = await client.list_routes()
        assert len(resp.data) == 1
        assert resp.data[0].firewall_rules_count == 1

    @respx.mock
    async def test_get_route(self, client: DefinedClient) -> None:
        route_id = SAMPLE_ROUTE["id"]
        respx.get(f"https://api.defined.net/v1/routes/{route_id}").mock(
            return_value=Response(200, json={"data": SAMPLE_ROUTE, "metadata": {}})
        )
        route = await client.get_route(route_id)
        assert len(route.firewall_rules) == 1
        assert route.firewall_rules[0].local_cidr == "192.168.14.56/32"

    @respx.mock
    async def test_create_route(self, client: DefinedClient) -> None:
        respx.post("https://api.defined.net/v1/routes").mock(
            return_value=Response(200, json={"data": SAMPLE_ROUTE, "metadata": {}})
        )
        data = RouteCreate(name="test-route")
        route = await client.create_route(data)
        assert route.name == "test-route"


class TestAuditLogs:
    @respx.mock
    async def test_list_audit_logs(self, client: DefinedClient) -> None:
        respx.get("https://api.defined.net/v1/audit-logs").mock(
            return_value=Response(
                200,
                json={
                    "data": [SAMPLE_AUDIT_LOG],
                    "metadata": PAGINATION_METADATA,
                },
            )
        )
        resp = await client.list_audit_logs()
        assert len(resp.data) == 1
        assert resp.data[0].event.type == "CREATED"

    @respx.mock
    async def test_audit_log_filters(self, client: DefinedClient) -> None:
        route = respx.get("https://api.defined.net/v1/audit-logs").mock(
            return_value=Response(200, json={"data": [], "metadata": {}})
        )
        await client.list_audit_logs(target_id="role-X", target_type="role")
        params = dict(route.calls[0].request.url.params)
        assert params["filter.targetID"] == "role-X"
        assert params["filter.targetType"] == "role"


class TestDownloads:
    @respx.mock
    async def test_list_downloads(self, client: DefinedClient) -> None:
        respx.get("https://api.defined.net/v1/downloads").mock(
            return_value=Response(
                200,
                json={
                    "data": {
                        "dnclient": {},
                        "mobile": {"android": "https://play.google.com"},
                        "container": {},
                        "versionInfo": {},
                    }
                },
            )
        )
        dl = await client.list_downloads()
        assert dl.mobile["android"] == "https://play.google.com"


class TestPagination:
    @respx.mock
    async def test_cursor_forwarded(self, client: DefinedClient) -> None:
        route = respx.get("https://api.defined.net/v1/roles").mock(
            return_value=Response(200, json={"data": [], "metadata": {}})
        )
        await client.list_roles(cursor="abc123", page_size=50)
        params = dict(route.calls[0].request.url.params)
        assert params["cursor"] == "abc123"
        assert params["pageSize"] == "50"

    @respx.mock
    async def test_include_counts(self, client: DefinedClient) -> None:
        route = respx.get("https://api.defined.net/v1/roles").mock(
            return_value=Response(200, json={"data": [], "metadata": {}})
        )
        await client.list_roles(include_counts=True)
        params = dict(route.calls[0].request.url.params)
        assert params["includeCounts"] == "true"
