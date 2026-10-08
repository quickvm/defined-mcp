"""Tests for MCP server tool registration and behavior."""

from __future__ import annotations

import json
from typing import TYPE_CHECKING, Any
from unittest.mock import AsyncMock, patch

import respx
from httpx import Response

from defined_mcp.client import DefinedClient
from defined_mcp.models import (
    FirewallRule,
    Host,
    PaginationMetadata,
    PortRange,
    Role,
    Tag,
)
from defined_mcp.server import mcp
from defined_mcp.settings import Settings
from tests.conftest import (
    SAMPLE_HOST,
    SAMPLE_ROLE,
    SAMPLE_ROLE_NULL_TAGS,
    SAMPLE_TAG,
)

if TYPE_CHECKING:
    import pytest


def _mock_list_response(data: list[Any]) -> Any:
    from defined_mcp.client import ListResponse

    return ListResponse(data=data, metadata=PaginationMetadata())


class TestToolRegistration:
    async def test_all_tools_registered(self) -> None:
        tools = await mcp.list_tools()
        tool_names = {t.name for t in tools}
        expected = {
            "list_hosts",
            "get_host",
            "create_host",
            "update_host",
            "delete_host",
            "block_host",
            "unblock_host",
            "create_enrollment_code",
            "create_host_and_enrollment_code",
            "list_roles",
            "get_role",
            "create_role",
            "update_role",
            "delete_role",
            "list_tags",
            "get_tag",
            "create_tag",
            "update_tag",
            "delete_tag",
            "list_networks",
            "get_network",
            "create_network",
            "update_network",
            "list_routes",
            "get_route",
            "create_route",
            "update_route",
            "delete_route",
            "list_audit_logs",
            "list_downloads",
            "add_firewall_rule",
            "remove_firewall_rule",
            "add_host_tag",
            "remove_host_tag",
            "add_tag_config_override",
            "remove_tag_config_override",
            "add_route_firewall_rule",
            "remove_route_firewall_rule",
        }
        assert expected.issubset(tool_names), f"Missing: {expected - tool_names}"


class TestReadOnlyTools:
    @patch("defined_mcp.server._get_client")
    async def test_list_hosts(self, mock_client_fn: Any) -> None:
        mock_client = AsyncMock()
        mock_client.list_hosts.return_value = _mock_list_response([Host.model_validate(SAMPLE_HOST)])
        mock_client_fn.return_value = mock_client

        from defined_mcp.server import list_hosts

        result = await list_hosts()
        assert len(result["data"]) == 1
        assert result["data"][0]["name"] == "test-host"

    @patch("defined_mcp.server._get_client")
    async def test_get_role(self, mock_client_fn: Any) -> None:
        mock_client = AsyncMock()
        mock_client.get_role.return_value = Role.model_validate(SAMPLE_ROLE)
        mock_client_fn.return_value = mock_client

        from defined_mcp.server import get_role

        result = await get_role("role-123")
        assert result["name"] == "test-role"
        assert len(result["firewallRules"]) == 2
        assert result["firewallRules"][0]["portRange"] == {"from": 22, "to": 22}


class TestMutatingTools:
    @patch("defined_mcp.server._get_client")
    async def test_create_role_with_firewall_rules(self, mock_client_fn: Any) -> None:
        mock_client = AsyncMock()
        mock_client.create_role.return_value = Role.model_validate(SAMPLE_ROLE)
        mock_client_fn.return_value = mock_client

        from defined_mcp.server import create_role

        # _parse_json accepts both str and list at runtime
        await create_role(
            name="web",
            firewall_rules=[  # ty: ignore[invalid-argument-type]
                {
                    "protocol": "TCP",
                    "portRange": {"from": 443, "to": 443},
                    "allowedTags": ["env:prod"],
                }
            ],
        )
        call_args = mock_client.create_role.call_args[0][0]
        assert call_args.firewall_rules[0].port_range is not None
        assert call_args.firewall_rules[0].port_range.from_port == 443
        assert call_args.firewall_rules[0].allowed_tags == ["env:prod"]

    @patch("defined_mcp.server._get_client")
    async def test_update_role_preserves_all_fields(self, mock_client_fn: Any) -> None:
        mock_client = AsyncMock()
        mock_client.update_role.return_value = Role.model_validate(SAMPLE_ROLE)
        mock_client_fn.return_value = mock_client

        from defined_mcp.server import update_role

        await update_role(
            role_id="role-123",
            description="updated",
            firewall_rules=[  # ty: ignore[invalid-argument-type]
                {
                    "protocol": "TCP",
                    "description": "SSH",
                    "allowedRoleID": "role-X",
                    "allowedTags": ["env:prod", "tier:web"],
                    "portRange": {"from": 22, "to": 22},
                }
            ],
        )
        call_args = mock_client.update_role.call_args
        role_id = call_args[0][0]
        data = call_args[0][1]
        assert role_id == "role-123"
        rule = data.firewall_rules[0]
        assert rule.port_range is not None
        assert rule.port_range.from_port == 22
        assert rule.allowed_role_id == "role-X"
        assert rule.allowed_tags == ["env:prod", "tier:web"]

    @patch("defined_mcp.server._get_client")
    async def test_delete_host(self, mock_client_fn: Any) -> None:
        mock_client = AsyncMock()
        mock_client_fn.return_value = mock_client

        from defined_mcp.server import delete_host

        result = await delete_host("host-123")
        assert result["status"] == "deleted"
        mock_client.delete_host.assert_called_once_with("host-123")


class TestFirewallRoundTrip:
    @patch("defined_mcp.server._get_client")
    async def test_firewall_rule_round_trip(self, mock_client_fn: Any) -> None:
        """Verify that creating a role with portRange/allowedTags and reading
        it back preserves all fields — the bug that broke the old MCP server.
        """
        mock_client = AsyncMock()
        mock_client.create_role.return_value = Role.model_validate(SAMPLE_ROLE)
        mock_client.get_role.return_value = Role.model_validate(SAMPLE_ROLE)
        mock_client_fn.return_value = mock_client

        from defined_mcp.server import create_role, get_role

        created = await create_role(
            name="test-role",
            firewall_rules=[  # ty: ignore[invalid-argument-type]
                {
                    "protocol": "TCP",
                    "description": "allow SSH",
                    "allowedRoleID": "role-AAAABBBBCCCCDDDDEEEEFFFFF2",
                    "allowedTags": ["env:prod", "tier:web"],
                    "portRange": {"from": 22, "to": 22},
                }
            ],
        )

        fetched = await get_role("role-123")

        assert created["firewallRules"][0]["portRange"] == {"from": 22, "to": 22}
        assert fetched["firewallRules"][0]["portRange"] == {"from": 22, "to": 22}
        assert fetched["firewallRules"][0]["allowedTags"] == [
            "env:prod",
            "tier:web",
        ]
        assert fetched["firewallRules"][0]["allowedRoleID"] == "role-AAAABBBBCCCCDDDDEEEEFFFFF2"


class TestAtomicFirewallRules:
    @patch("defined_mcp.server._get_client")
    async def test_add_firewall_rule(self, mock_client_fn: Any) -> None:
        role_with_one_rule = Role(
            id="role-1",
            name="test",
            description="",
            firewall_rules=[
                FirewallRule(protocol="ICMP", description="ping"),
            ],
            created_at="2025-01-01T00:00:00Z",
            modified_at="2025-01-01T00:00:00Z",
        )
        role_with_two_rules = Role(
            id="role-1",
            name="test",
            description="",
            firewall_rules=[
                FirewallRule(protocol="ICMP", description="ping"),
                FirewallRule(
                    protocol="TCP",
                    description="SSH",
                    port_range=PortRange(from_port=22, to_port=22),
                ),
            ],
            created_at="2025-01-01T00:00:00Z",
            modified_at="2025-01-01T00:00:00Z",
        )
        mock_client = AsyncMock()
        mock_client.get_role.return_value = role_with_one_rule
        mock_client.update_role.return_value = role_with_two_rules
        mock_client_fn.return_value = mock_client

        from defined_mcp.server import add_firewall_rule

        await add_firewall_rule(role_id="role-1", protocol="TCP", description="SSH", port_from=22, port_to=22)
        update_data = mock_client.update_role.call_args[0][1]
        assert len(update_data.firewall_rules) == 2
        assert update_data.firewall_rules[1].protocol == "TCP"
        assert update_data.firewall_rules[1].port_range is not None
        assert update_data.firewall_rules[1].port_range.from_port == 22

    @respx.mock
    async def test_add_firewall_rule_keeps_null_allowed_tags(
        self, settings_env: None, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        role_id = SAMPLE_ROLE_NULL_TAGS["id"]
        url = f"https://api.defined.net/v1/roles/{role_id}"
        body = {"data": SAMPLE_ROLE_NULL_TAGS, "metadata": {}}
        respx.get(url).mock(return_value=Response(200, json=body))
        put = respx.put(url).mock(return_value=Response(200, json=body))
        client = DefinedClient(Settings())
        monkeypatch.setattr("defined_mcp.server._get_client", lambda: client)

        from defined_mcp.server import add_firewall_rule

        await add_firewall_rule(
            role_id=role_id, protocol="TCP", port_from=17323, port_to=17323, allowed_tags='["agent-vault:allow"]'
        )
        rules = json.loads(put.calls[0].request.content)["firewallRules"]
        assert rules[:2] == SAMPLE_ROLE_NULL_TAGS["firewallRules"]
        assert rules[2]["allowedTags"] == ["agent-vault:allow"]
        assert rules[2]["portRange"] == {"from": 17323, "to": 17323}

    @patch("defined_mcp.server._get_client")
    async def test_remove_firewall_rule(self, mock_client_fn: Any) -> None:
        role_with_two = Role(
            id="role-1",
            name="test",
            description="",
            firewall_rules=[
                FirewallRule(protocol="ICMP", description="ping"),
                FirewallRule(protocol="TCP", description="SSH"),
            ],
            created_at="2025-01-01T00:00:00Z",
            modified_at="2025-01-01T00:00:00Z",
        )
        role_with_one = Role(
            id="role-1",
            name="test",
            description="",
            firewall_rules=[
                FirewallRule(protocol="TCP", description="SSH"),
            ],
            created_at="2025-01-01T00:00:00Z",
            modified_at="2025-01-01T00:00:00Z",
        )
        mock_client = AsyncMock()
        mock_client.get_role.return_value = role_with_two
        mock_client.update_role.return_value = role_with_one
        mock_client_fn.return_value = mock_client

        from defined_mcp.server import remove_firewall_rule

        await remove_firewall_rule(role_id="role-1", rule_index=0)
        update_data = mock_client.update_role.call_args[0][1]
        assert len(update_data.firewall_rules) == 1
        assert update_data.firewall_rules[0].protocol == "TCP"

    @patch("defined_mcp.server._get_client")
    async def test_remove_firewall_rule_out_of_range(self, mock_client_fn: Any) -> None:
        role = Role(
            id="role-1",
            name="test",
            description="",
            firewall_rules=[FirewallRule(protocol="ICMP")],
            created_at="2025-01-01T00:00:00Z",
            modified_at="2025-01-01T00:00:00Z",
        )
        mock_client = AsyncMock()
        mock_client.get_role.return_value = role
        mock_client_fn.return_value = mock_client

        from defined_mcp.server import remove_firewall_rule

        result = await remove_firewall_rule(role_id="role-1", rule_index=5)
        assert "error" in result
        mock_client.update_role.assert_not_called()


class TestAtomicHostTags:
    @patch("defined_mcp.server._get_client")
    async def test_add_host_tag(self, mock_client_fn: Any) -> None:
        host = Host.model_validate(SAMPLE_HOST)
        updated_host = Host.model_validate({**SAMPLE_HOST, "tags": ["env:prod", "tier:web"]})
        mock_client = AsyncMock()
        mock_client.get_host.return_value = host
        mock_client.update_host.return_value = updated_host
        mock_client_fn.return_value = mock_client

        from defined_mcp.server import add_host_tag

        await add_host_tag(host_id=SAMPLE_HOST["id"], tag="tier:web")
        update_data = mock_client.update_host.call_args[0][1]
        assert "tier:web" in update_data.tags
        assert "env:prod" in update_data.tags

    @patch("defined_mcp.server._get_client")
    async def test_add_host_tag_idempotent(self, mock_client_fn: Any) -> None:
        host = Host.model_validate(SAMPLE_HOST)
        mock_client = AsyncMock()
        mock_client.get_host.return_value = host
        mock_client.update_host.return_value = host
        mock_client_fn.return_value = mock_client

        from defined_mcp.server import add_host_tag

        await add_host_tag(host_id=SAMPLE_HOST["id"], tag="env:prod")
        update_data = mock_client.update_host.call_args[0][1]
        assert update_data.tags.count("env:prod") == 1

    @patch("defined_mcp.server._get_client")
    async def test_remove_host_tag(self, mock_client_fn: Any) -> None:
        host = Host.model_validate({**SAMPLE_HOST, "tags": ["env:prod", "tier:web"]})
        updated = Host.model_validate({**SAMPLE_HOST, "tags": ["tier:web"]})
        mock_client = AsyncMock()
        mock_client.get_host.return_value = host
        mock_client.update_host.return_value = updated
        mock_client_fn.return_value = mock_client

        from defined_mcp.server import remove_host_tag

        await remove_host_tag(host_id=SAMPLE_HOST["id"], tag="env:prod")
        update_data = mock_client.update_host.call_args[0][1]
        assert "env:prod" not in update_data.tags
        assert "tier:web" in update_data.tags


class TestAtomicTagConfigOverrides:
    @patch("defined_mcp.server._get_client")
    async def test_add_tag_config_override(self, mock_client_fn: Any) -> None:
        tag = Tag.model_validate(SAMPLE_TAG)
        updated_tag = Tag.model_validate(
            {
                **SAMPLE_TAG,
                "configOverrides": [
                    {"key": "logging.level", "value": "info"},
                    {"key": "tun.mtu", "value": "1300"},
                ],
            }
        )
        mock_client = AsyncMock()
        mock_client.get_tag.return_value = tag
        mock_client.update_tag.return_value = updated_tag
        mock_client_fn.return_value = mock_client

        from defined_mcp.server import add_tag_config_override

        await add_tag_config_override(tag="env:prod", key="tun.mtu", value="1300")
        update_data = mock_client.update_tag.call_args[0][1]
        keys = [o.key for o in update_data.config_overrides]
        assert "tun.mtu" in keys
        assert "logging.level" in keys

    @patch("defined_mcp.server._get_client")
    async def test_add_tag_config_override_replaces_existing(self, mock_client_fn: Any) -> None:
        tag = Tag.model_validate(SAMPLE_TAG)
        mock_client = AsyncMock()
        mock_client.get_tag.return_value = tag
        mock_client.update_tag.return_value = tag
        mock_client_fn.return_value = mock_client

        from defined_mcp.server import add_tag_config_override

        await add_tag_config_override(tag="env:prod", key="logging.level", value="debug")
        update_data = mock_client.update_tag.call_args[0][1]
        level_overrides = [o for o in update_data.config_overrides if o.key == "logging.level"]
        assert len(level_overrides) == 1
        assert level_overrides[0].value == "debug"

    @patch("defined_mcp.server._get_client")
    async def test_remove_tag_config_override(self, mock_client_fn: Any) -> None:
        tag = Tag.model_validate(SAMPLE_TAG)
        mock_client = AsyncMock()
        mock_client.get_tag.return_value = tag
        mock_client.update_tag.return_value = Tag.model_validate({**SAMPLE_TAG, "configOverrides": []})
        mock_client_fn.return_value = mock_client

        from defined_mcp.server import remove_tag_config_override

        await remove_tag_config_override(tag="env:prod", key="logging.level")
        update_data = mock_client.update_tag.call_args[0][1]
        assert len(update_data.config_overrides) == 0
