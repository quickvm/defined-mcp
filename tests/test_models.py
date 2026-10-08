"""Tests for Pydantic models."""

from __future__ import annotations

from defined_mcp.models import (
    AuditLog,
    FirewallRule,
    Host,
    HostCreate,
    Network,
    PaginationMetadata,
    PortRange,
    Role,
    RoleCreate,
    RoleUpdate,
    Route,
    RouteListItem,
    Tag,
)
from tests.conftest import (
    SAMPLE_AUDIT_LOG,
    SAMPLE_HOST,
    SAMPLE_NETWORK,
    SAMPLE_ROLE,
    SAMPLE_ROLE_NULL_TAGS,
    SAMPLE_ROUTE,
    SAMPLE_ROUTE_LIST_ITEM,
    SAMPLE_TAG,
)


class TestPortRange:
    def test_parse_from_api(self) -> None:
        pr = PortRange.model_validate({"from": 22, "to": 22})
        assert pr.from_port == 22
        assert pr.to_port == 22

    def test_serialize_to_api(self) -> None:
        pr = PortRange(from_port=80, to_port=443)
        data = pr.model_dump(by_alias=True)
        assert data == {"from": 80, "to": 443}

    def test_round_trip(self) -> None:
        original = {"from": 8080, "to": 8090}
        pr = PortRange.model_validate(original)
        assert pr.model_dump(by_alias=True) == original


class TestFirewallRule:
    def test_parse_full_rule(self) -> None:
        rule_data = SAMPLE_ROLE["firewallRules"][0]
        rule = FirewallRule.model_validate(rule_data)
        assert rule.protocol == "TCP"
        assert rule.description == "allow SSH"
        assert rule.allowed_role_id == "role-AAAABBBBCCCCDDDDEEEEFFFFF2"
        assert rule.allowed_tags == ["env:prod", "tier:web"]
        assert rule.port_range is not None
        assert rule.port_range.from_port == 22
        assert rule.port_range.to_port == 22

    def test_parse_minimal_rule(self) -> None:
        rule = FirewallRule.model_validate({"protocol": "ANY"})
        assert rule.protocol == "ANY"
        assert rule.allowed_role_id is None
        assert rule.allowed_tags == []
        assert rule.port_range is None

    def test_serialize_preserves_all_fields(self) -> None:
        rule_data = SAMPLE_ROLE["firewallRules"][0]
        rule = FirewallRule.model_validate(rule_data)
        serialized = rule.model_dump(by_alias=True)
        assert serialized["portRange"] == {"from": 22, "to": 22}
        assert serialized["allowedRoleID"] == "role-AAAABBBBCCCCDDDDEEEEFFFFF2"
        assert serialized["allowedTags"] == ["env:prod", "tier:web"]

    def test_null_port_range_serialized(self) -> None:
        rule_data = SAMPLE_ROLE["firewallRules"][1]
        rule = FirewallRule.model_validate(rule_data)
        serialized = rule.model_dump(by_alias=True)
        assert serialized["portRange"] is None
        assert serialized["allowedRoleID"] is None
        assert serialized["allowedTags"] == []


class TestHost:
    def test_parse_host(self) -> None:
        host = Host.model_validate(SAMPLE_HOST)
        assert host.id == "host-AAAABBBBCCCCDDDDEEEEFFFFF1"
        assert host.network_id == "network-AAAABBBBCCCCDDDDEEEEFFF1"
        assert host.role_id == "role-AAAABBBBCCCCDDDDEEEEFFFFF1"
        assert host.tags == ["env:prod"]
        assert host.metadata.platform == "dnclient"

    def test_parse_host_null_role(self) -> None:
        data = {**SAMPLE_HOST, "roleID": None}
        host = Host.model_validate(data)
        assert host.role_id is None

    def test_parse_host_null_metadata(self) -> None:
        data = {
            **SAMPLE_HOST,
            "metadata": {
                "lastSeenAt": None,
                "version": None,
                "platform": None,
                "updateAvailable": None,
            },
        }
        host = Host.model_validate(data)
        assert host.metadata.last_seen_at is None
        assert host.metadata.platform is None


class TestRole:
    def test_parse_role_with_firewall_rules(self) -> None:
        role = Role.model_validate(SAMPLE_ROLE)
        assert role.name == "test-role"
        assert len(role.firewall_rules) == 2
        assert role.firewall_rules[0].port_range is not None
        assert role.firewall_rules[0].port_range.from_port == 22

    def test_round_trip_firewall_rules(self) -> None:
        role = Role.model_validate(SAMPLE_ROLE)
        serialized = role.model_dump(mode="json", by_alias=True)
        rule0 = serialized["firewallRules"][0]
        assert rule0["portRange"] == {"from": 22, "to": 22}
        assert rule0["allowedTags"] == ["env:prod", "tier:web"]
        assert rule0["allowedRoleID"] == "role-AAAABBBBCCCCDDDDEEEEFFFFF2"

    def test_null_allowed_tags_round_trip_unchanged(self) -> None:
        role = Role.model_validate(SAMPLE_ROLE_NULL_TAGS)
        assert role.firewall_rules[0].allowed_tags is None
        serialized = role.model_dump(mode="json", by_alias=True)
        assert serialized["firewallRules"] == SAMPLE_ROLE_NULL_TAGS["firewallRules"]


class TestTag:
    def test_parse_tag(self) -> None:
        tag = Tag.model_validate(SAMPLE_TAG)
        assert tag.name == "env:prod"
        assert tag.priority == 3
        assert tag.host_count == 10
        assert len(tag.config_overrides) == 1
        assert tag.route_subscriptions == ["route-AAAABBBBCCCCDDDDEEEEFFF1"]


class TestNetwork:
    def test_parse_network(self) -> None:
        net = Network.model_validate(SAMPLE_NETWORK)
        assert net.cidr == "100.100.0.0/22"
        assert net.lighthouses_as_relays is False
        assert net.curve == "25519"


class TestRoute:
    def test_parse_route(self) -> None:
        route = Route.model_validate(SAMPLE_ROUTE)
        assert route.router_host_id == "host-AAAABBBBCCCCDDDDEEEEFFFFF1"
        assert "192.168.14.0/26" in route.routable_cidrs
        assert len(route.firewall_rules) == 1
        assert route.firewall_rules[0].local_cidr == "192.168.14.56/32"

    def test_null_allowed_tags_round_trip_unchanged(self) -> None:
        data = {**SAMPLE_ROUTE, "firewallRules": [{**SAMPLE_ROUTE["firewallRules"][0], "allowedTags": None}]}
        route = Route.model_validate(data)
        assert route.firewall_rules[0].allowed_tags is None
        assert route.model_dump(mode="json", by_alias=True)["firewallRules"] == data["firewallRules"]

    def test_parse_route_list_item(self) -> None:
        item = RouteListItem.model_validate(SAMPLE_ROUTE_LIST_ITEM)
        assert item.firewall_rules_count == 1


class TestAuditLog:
    def test_parse_audit_log(self) -> None:
        log = AuditLog.model_validate(SAMPLE_AUDIT_LOG)
        assert log.actor.type == "apiKey"
        assert log.target.type == "role"
        assert log.event.type == "CREATED"
        assert log.event.before is None
        assert log.event.after == {"name": "test-role"}


class TestPagination:
    def test_parse_pagination(self) -> None:
        meta = PaginationMetadata.model_validate(
            {
                "hasNextPage": True,
                "hasPrevPage": False,
                "nextCursor": "abc",
                "totalCount": 500,
                "page": {"count": 25, "start": 0},
            }
        )
        assert meta.has_next_page is True
        assert meta.has_prev_page is False
        assert meta.next_cursor == "abc"
        assert meta.total_count == 500
        assert meta.page is not None
        assert meta.page.count == 25

    def test_parse_empty_metadata(self) -> None:
        meta = PaginationMetadata.model_validate({})
        assert meta.has_next_page is False
        assert meta.next_cursor is None
        assert meta.total_count is None


class TestRequestModels:
    def test_host_create_serialization(self) -> None:
        data = HostCreate(
            name="new-host",
            network_id="network-123",
            role_id="role-456",
            tags=["env:dev"],
        )
        serialized = data.model_dump(by_alias=True, exclude_none=True)
        assert serialized["networkID"] == "network-123"
        assert serialized["roleID"] == "role-456"
        assert "ipAddress" not in serialized

    def test_role_create_with_firewall_rules(self) -> None:
        data = RoleCreate(
            name="web",
            firewall_rules=[
                FirewallRule(
                    protocol="TCP",
                    description="HTTPS",
                    port_range=PortRange(from_port=443, to_port=443),
                    allowed_tags=["env:prod"],
                )
            ],
        )
        serialized = data.model_dump(by_alias=True)
        rule = serialized["firewallRules"][0]
        assert rule["portRange"] == {"from": 443, "to": 443}
        assert rule["allowedTags"] == ["env:prod"]

    def test_role_update_serialization(self) -> None:
        data = RoleUpdate(
            description="updated",
            firewall_rules=[
                FirewallRule(
                    protocol="TCP",
                    port_range=PortRange(from_port=22, to_port=22),
                    allowed_role_id="role-X",
                    allowed_tags=["env:prod"],
                )
            ],
        )
        serialized = data.model_dump(by_alias=True)
        rule = serialized["firewallRules"][0]
        assert rule["portRange"] == {"from": 22, "to": 22}
        assert rule["allowedRoleID"] == "role-X"
        assert rule["allowedTags"] == ["env:prod"]
