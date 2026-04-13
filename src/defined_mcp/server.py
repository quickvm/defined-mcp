"""FastMCP server with tool definitions for the Defined Networking API."""

from __future__ import annotations

import json
from typing import Any

from fastmcp import FastMCP

from defined_mcp.client import DefinedClient
from defined_mcp.models import (
    ConfigOverride,
    FirewallRule,
    FirewallRuleWithCIDR,
    Host,
    HostCreate,
    HostUpdate,
    NetworkCreate,
    NetworkUpdate,
    PortRange,
    RoleCreate,
    RoleUpdate,
    RouteCreate,
    RouteUpdate,
    TagCreate,
    TagUpdate,
)
from defined_mcp.settings import Settings

mcp = FastMCP(
    "defined-mcp",
    instructions=("Manage Defined Networking overlay networks, hosts, roles, firewall rules, tags, and routes."),
)

_client: DefinedClient | None = None


def _get_client() -> DefinedClient:
    global _client  # noqa: PLW0603
    if _client is None:
        _client = DefinedClient(Settings())
    return _client


def _serialize(obj: Any) -> Any:
    """Serialize a Pydantic model or list response to JSON-safe dict."""
    if hasattr(obj, "model_dump"):
        return obj.model_dump(mode="json", by_alias=True)
    return obj


def _parse_json(value: str | list[Any] | dict[str, Any] | None) -> Any:
    """Accept a JSON string or already-parsed value; return parsed Python object."""
    if value is None:
        return None
    if isinstance(value, (list, dict)):
        return value
    return json.loads(value)


def _build_firewall_rules(
    rules: list[dict[str, Any]] | None,
) -> list[FirewallRule]:
    if not rules:
        return []
    result = []
    for r in rules:
        port_range = None
        if r.get("portRange"):
            port_range = PortRange.model_validate(r["portRange"])
        result.append(
            FirewallRule(
                protocol=r["protocol"],
                description=r.get("description", ""),
                allowed_role_id=r.get("allowedRoleID"),
                allowed_tags=r.get("allowedTags", []),
                port_range=port_range,
            )
        )
    return result


def _build_route_firewall_rules(
    rules: list[dict[str, Any]] | None,
) -> list[FirewallRuleWithCIDR]:
    if not rules:
        return []
    result = []
    for r in rules:
        port_range = None
        if r.get("portRange"):
            port_range = PortRange.model_validate(r["portRange"])
        result.append(
            FirewallRuleWithCIDR(
                protocol=r["protocol"],
                description=r.get("description", ""),
                local_cidr=r.get("localCIDR"),
                allowed_role_id=r.get("allowedRoleID"),
                allowed_tags=r.get("allowedTags", []),
                port_range=port_range,
            )
        )
    return result


def _build_config_overrides(
    overrides: list[dict[str, Any]] | None,
) -> list[ConfigOverride]:
    if not overrides:
        return []
    return [ConfigOverride(key=o["key"], value=o["value"]) for o in overrides]


def _list_response(resp: Any) -> dict[str, Any]:
    return {
        "data": [_serialize(item) for item in resp.data],
        "metadata": _serialize(resp.metadata),
    }


# ==================== Hosts ====================


@mcp.tool(annotations={"readOnlyHint": True})
async def list_hosts(
    cursor: str | None = None,
    page_size: int | None = None,
    include_counts: bool = False,
    role_id: str | None = None,
    is_blocked: bool | None = None,
    is_lighthouse: bool | None = None,
    is_relay: bool | None = None,
) -> dict[str, Any]:
    """List hosts with optional filters.

    Args:
        cursor: Pagination cursor from a previous response.
        page_size: Number of results per page (max 500).
        include_counts: Include total count in metadata.
        role_id: Filter by role ID, 'null' for unassigned, 'any' for assigned.
        is_blocked: Filter by blocked status.
        is_lighthouse: Filter by lighthouse status.
        is_relay: Filter by relay status.
    """
    client = _get_client()
    resp = await client.list_hosts(
        cursor=cursor,
        page_size=page_size,
        include_counts=include_counts,
        role_id=role_id,
        is_blocked=is_blocked,
        is_lighthouse=is_lighthouse,
        is_relay=is_relay,
    )
    return _list_response(resp)


@mcp.tool(annotations={"readOnlyHint": True})
async def get_host(host_id: str) -> dict[str, Any]:
    """Get a host by ID.

    Args:
        host_id: The host ID (e.g. host-XXXX).
    """
    client = _get_client()
    host = await client.get_host(host_id)
    return _serialize(host)


@mcp.tool()
async def create_host(
    name: str,
    network_id: str,
    role_id: str | None = None,
    ip_address: str | None = None,
    static_addresses: str | None = None,
    listen_port: int = 0,
    is_lighthouse: bool = False,
    is_relay: bool = False,
    tags: str | None = None,
    config_overrides: str | None = None,
) -> dict[str, Any]:
    """Create a new host, lighthouse, or relay.

    Args:
        name: Name of the host.
        network_id: ID of the network.
        role_id: ID of the role to assign.
        ip_address: Specific IP within the network CIDR. Auto-assigned if omitted.
        static_addresses: List of static address:port pairs (required for lighthouses).
        listen_port: UDP port (0 for auto, non-zero required for lighthouses/relays).
        is_lighthouse: Create as lighthouse.
        is_relay: Create as relay.
        tags: Tags in key:value format.
        config_overrides: Nebula config overrides as [{key, value}].
    """
    client = _get_client()
    data = HostCreate(
        name=name,
        network_id=network_id,
        role_id=role_id,
        ip_address=ip_address,
        static_addresses=_parse_json(static_addresses) or [],
        listen_port=listen_port,
        is_lighthouse=is_lighthouse,
        is_relay=is_relay,
        tags=_parse_json(tags) or [],
        config_overrides=_build_config_overrides(_parse_json(config_overrides)),
    )
    host = await client.create_host(data)
    return _serialize(host)


@mcp.tool(annotations={"idempotentHint": True})
async def update_host(
    host_id: str,
    name: str | None = None,
    role_id: str | None = None,
    static_addresses: str | None = None,
    listen_port: int = 0,
    tags: str | None = None,
    config_overrides: str | None = None,
) -> dict[str, Any]:
    """Update a host. This is a full replacement — include all fields you want to keep.

    Args:
        host_id: The host ID to update.
        name: Host name.
        role_id: Role ID to assign (null to unassign).
        static_addresses: Static address:port pairs.
        listen_port: UDP listen port.
        tags: Tags in key:value format. Pass [] to clear.
        config_overrides: Nebula config overrides. Pass [] to clear.
    """
    client = _get_client()
    data = HostUpdate(
        name=name,
        role_id=role_id,
        static_addresses=_parse_json(static_addresses) or [],
        listen_port=listen_port,
        tags=_parse_json(tags) or [],
        config_overrides=_build_config_overrides(_parse_json(config_overrides)),
    )
    host = await client.update_host(host_id, data)
    return _serialize(host)


@mcp.tool(annotations={"destructiveHint": True})
async def delete_host(host_id: str) -> dict[str, str]:
    """Delete a host.

    Args:
        host_id: The host ID to delete.
    """
    client = _get_client()
    await client.delete_host(host_id)
    return {"status": "deleted", "hostID": host_id}


@mcp.tool(annotations={"destructiveHint": True})
async def block_host(host_id: str) -> dict[str, Any]:
    """Block a host, preventing it from communicating on the network.

    Args:
        host_id: The host ID to block.
    """
    client = _get_client()
    host = await client.block_host(host_id)
    return _serialize(host)


@mcp.tool()
async def unblock_host(host_id: str) -> dict[str, Any]:
    """Unblock a host, allowing it to rejoin the network.

    Args:
        host_id: The host ID to unblock.
    """
    client = _get_client()
    host = await client.unblock_host(host_id)
    return _serialize(host)


@mcp.tool()
async def add_host_tag(host_id: str, tag: str) -> dict[str, Any]:
    """Add a tag to a host. Preserves existing tags.

    Args:
        host_id: The host ID.
        tag: Tag to add in key:value format (e.g. env:prod).
    """
    client = _get_client()
    host = await client.get_host(host_id)
    tags = list(host.tags)
    if tag not in tags:
        tags.append(tag)
    data = HostUpdate(
        name=host.name,
        role_id=host.role_id,
        static_addresses=list(host.static_addresses),
        listen_port=host.listen_port,
        tags=tags,
        config_overrides=list(host.config_overrides),
    )
    updated = await client.update_host(host_id, data)
    return _serialize(updated)


@mcp.tool()
async def remove_host_tag(host_id: str, tag: str) -> dict[str, Any]:
    """Remove a tag from a host. Preserves other tags.

    Args:
        host_id: The host ID.
        tag: Tag to remove in key:value format (e.g. env:prod).
    """
    client = _get_client()
    host = await client.get_host(host_id)
    tags = [t for t in host.tags if t != tag]
    data = HostUpdate(
        name=host.name,
        role_id=host.role_id,
        static_addresses=list(host.static_addresses),
        listen_port=host.listen_port,
        tags=tags,
        config_overrides=list(host.config_overrides),
    )
    updated = await client.update_host(host_id, data)
    return _serialize(updated)


@mcp.tool()
async def create_enrollment_code(host_id: str, lifetime_seconds: int | None = None) -> dict[str, Any]:
    """Create an enrollment code for a host.

    Args:
        host_id: The host ID to create an enrollment code for.
        lifetime_seconds: How long the code is valid (seconds).
    """
    client = _get_client()
    return await client.create_enrollment_code(host_id, lifetime_seconds=lifetime_seconds)


@mcp.tool()
async def create_host_and_enrollment_code(
    name: str,
    network_id: str,
    role_id: str | None = None,
    ip_address: str | None = None,
    static_addresses: str | None = None,
    listen_port: int = 0,
    is_lighthouse: bool = False,
    is_relay: bool = False,
    tags: str | None = None,
    config_overrides: str | None = None,
    lifetime_seconds: int | None = None,
) -> dict[str, Any]:
    """Create a host and enrollment code in one call.

    Args:
        name: Name of the host.
        network_id: ID of the network.
        role_id: ID of the role to assign.
        ip_address: Specific IP within the network CIDR.
        static_addresses: Static address:port pairs.
        listen_port: UDP port.
        is_lighthouse: Create as lighthouse.
        is_relay: Create as relay.
        tags: Tags in key:value format.
        config_overrides: Nebula config overrides as [{key, value}].
        lifetime_seconds: Enrollment code validity (seconds).
    """
    client = _get_client()
    data = HostCreate(
        name=name,
        network_id=network_id,
        role_id=role_id,
        ip_address=ip_address,
        static_addresses=_parse_json(static_addresses) or [],
        listen_port=listen_port,
        is_lighthouse=is_lighthouse,
        is_relay=is_relay,
        tags=_parse_json(tags) or [],
        config_overrides=_build_config_overrides(_parse_json(config_overrides)),
    )
    result = await client.create_host_and_enrollment_code(data, lifetime_seconds=lifetime_seconds)
    return {
        "host": _serialize(Host.model_validate(result["host"])),
        "enrollmentCode": result.get("enrollmentCode", {}),
    }


# ==================== Roles ====================


@mcp.tool(annotations={"readOnlyHint": True})
async def list_roles(
    cursor: str | None = None,
    page_size: int | None = None,
    include_counts: bool = False,
) -> dict[str, Any]:
    """List roles.

    Args:
        cursor: Pagination cursor.
        page_size: Results per page (max 500).
        include_counts: Include total count.
    """
    client = _get_client()
    resp = await client.list_roles(cursor=cursor, page_size=page_size, include_counts=include_counts)
    return _list_response(resp)


@mcp.tool(annotations={"readOnlyHint": True})
async def get_role(role_id: str) -> dict[str, Any]:
    """Get a role by ID, including its firewall rules.

    Args:
        role_id: The role ID (e.g. role-XXXX).
    """
    client = _get_client()
    role = await client.get_role(role_id)
    return _serialize(role)


@mcp.tool()
async def create_role(
    name: str,
    description: str = "",
    firewall_rules: str | None = None,
) -> dict[str, Any]:
    """Create a role with firewall rules.

    Args:
        name: Role name.
        description: Role description.
        firewall_rules: List of firewall rule objects with protocol, description,
            allowedRoleID, allowedTags, and portRange ({from, to}).
    """
    client = _get_client()
    data = RoleCreate(
        name=name,
        description=description,
        firewall_rules=_build_firewall_rules(_parse_json(firewall_rules)),
    )
    role = await client.create_role(data)
    return _serialize(role)


@mcp.tool(annotations={"idempotentHint": True})
async def update_role(
    role_id: str,
    description: str = "",
    firewall_rules: str | None = None,
) -> dict[str, Any]:
    """Update a role. Full replacement — include ALL firewall rules you want to keep.

    Args:
        role_id: The role ID to update.
        description: Role description.
        firewall_rules: Complete list of firewall rules. Each rule: protocol (ANY/TCP/UDP/ICMP),
            description, allowedRoleID, allowedTags (list of key:value strings),
            portRange ({from: int, to: int} or null for all ports).
    """
    client = _get_client()
    data = RoleUpdate(
        description=description,
        firewall_rules=_build_firewall_rules(_parse_json(firewall_rules)),
    )
    role = await client.update_role(role_id, data)
    return _serialize(role)


@mcp.tool(annotations={"destructiveHint": True})
async def delete_role(role_id: str) -> dict[str, str]:
    """Delete a role.

    Args:
        role_id: The role ID to delete.
    """
    client = _get_client()
    await client.delete_role(role_id)
    return {"status": "deleted", "roleID": role_id}


@mcp.tool()
async def add_firewall_rule(
    role_id: str,
    protocol: str,
    description: str = "",
    port_from: int | None = None,
    port_to: int | None = None,
    allowed_role_id: str | None = None,
    allowed_tags: str | None = None,
) -> dict[str, Any]:
    """Add a firewall rule to a role. Reads the current role, appends the rule, and saves.

    Args:
        role_id: The role ID to add a rule to.
        protocol: Protocol — ANY, TCP, UDP, or ICMP.
        description: Rule description.
        port_from: Start of port range (1-65535). Omit for all ports.
        port_to: End of port range (1-65535). Omit for all ports.
        allowed_role_id: Only allow traffic from this role ID.
        allowed_tags: Tags to allow, as JSON list of key:value strings.
    """
    client = _get_client()
    role = await client.get_role(role_id)
    port_range = None
    if port_from is not None and port_to is not None:
        port_range = PortRange(from_port=port_from, to_port=port_to)
    new_rule = FirewallRule(
        protocol=protocol,
        description=description,
        allowed_role_id=allowed_role_id,
        allowed_tags=_parse_json(allowed_tags) or [],
        port_range=port_range,
    )
    rules = list(role.firewall_rules) + [new_rule]
    data = RoleUpdate(description=role.description, firewall_rules=rules)
    updated = await client.update_role(role_id, data)
    return _serialize(updated)


@mcp.tool()
async def remove_firewall_rule(
    role_id: str,
    rule_index: int,
) -> dict[str, Any]:
    """Remove a firewall rule from a role by its index. Use get_role to see current rules.

    Args:
        role_id: The role ID to remove a rule from.
        rule_index: Zero-based index of the rule to remove.
    """
    client = _get_client()
    role = await client.get_role(role_id)
    rules = list(role.firewall_rules)
    if rule_index < 0 or rule_index >= len(rules):
        return {"error": f"rule_index {rule_index} out of range (0-{len(rules) - 1})"}
    rules.pop(rule_index)
    data = RoleUpdate(description=role.description, firewall_rules=rules)
    updated = await client.update_role(role_id, data)
    return _serialize(updated)


# ==================== Tags ====================


@mcp.tool(annotations={"readOnlyHint": True})
async def list_tags(
    cursor: str | None = None,
    page_size: int | None = None,
    include_counts: bool = False,
) -> dict[str, Any]:
    """List tags.

    Args:
        cursor: Pagination cursor.
        page_size: Results per page (max 500).
        include_counts: Include total count.
    """
    client = _get_client()
    resp = await client.list_tags(cursor=cursor, page_size=page_size, include_counts=include_counts)
    return _list_response(resp)


@mcp.tool(annotations={"readOnlyHint": True})
async def get_tag(tag: str) -> dict[str, Any]:
    """Get a tag by name.

    Args:
        tag: The tag name in key:value format (e.g. env:prod).
    """
    client = _get_client()
    t = await client.get_tag(tag)
    return _serialize(t)


@mcp.tool()
async def create_tag(
    name: str,
    description: str = "",
    config_overrides: str | None = None,
    before: str | None = None,
    after: str | None = None,
    route_subscriptions: str | None = None,
) -> dict[str, Any]:
    """Create a tag.

    Args:
        name: Tag name in key:value format.
        description: Tag description.
        config_overrides: Config overrides as [{key, value}].
        before: Insert before this tag (lower priority).
        after: Insert after this tag (higher priority).
        route_subscriptions: Route IDs to subscribe tagged hosts to.
    """
    client = _get_client()
    data = TagCreate(
        name=name,
        description=description,
        config_overrides=_build_config_overrides(_parse_json(config_overrides)),
        before=before,
        after=after,
        route_subscriptions=_parse_json(route_subscriptions) or [],
    )
    t = await client.create_tag(data)
    return _serialize(t)


@mcp.tool(annotations={"idempotentHint": True})
async def update_tag(
    tag: str,
    description: str = "",
    config_overrides: str | None = None,
    before: str | None = None,
    after: str | None = None,
    route_subscriptions: str | None = None,
) -> dict[str, Any]:
    """Update a tag. Full replacement — include all values you want to keep.

    Args:
        tag: The tag name in key:value format.
        description: Tag description.
        config_overrides: Config overrides as [{key, value}].
        before: Move before this tag.
        after: Move after this tag.
        route_subscriptions: Route IDs to subscribe tagged hosts to.
    """
    client = _get_client()
    data = TagUpdate(
        description=description,
        config_overrides=_build_config_overrides(_parse_json(config_overrides)),
        before=before,
        after=after,
        route_subscriptions=_parse_json(route_subscriptions) or [],
    )
    t = await client.update_tag(tag, data)
    return _serialize(t)


@mcp.tool(annotations={"destructiveHint": True})
async def delete_tag(tag: str) -> dict[str, str]:
    """Delete a tag.

    Args:
        tag: The tag name to delete (key:value format).
    """
    client = _get_client()
    await client.delete_tag(tag)
    return {"status": "deleted", "tag": tag}


def _coerce_value(value: str) -> str | int | float | bool:
    """Auto-detect type for config override values."""
    if value.lower() in ("true", "false"):
        return value.lower() == "true"
    try:
        return int(value)
    except ValueError:
        pass
    try:
        return float(value)
    except ValueError:
        pass
    return value


@mcp.tool()
async def add_tag_config_override(tag: str, key: str, value: str) -> dict[str, Any]:
    """Add a config override to a tag. Preserves existing overrides.

    Values are auto-coerced: "1300" becomes int 1300, "true"/"false" become
    booleans, otherwise kept as string.

    Args:
        tag: The tag name in key:value format.
        key: Config key (e.g. logging.level, tun.mtu).
        value: Config value (auto-coerced to int/float/bool when applicable).
    """
    client = _get_client()
    current = await client.get_tag(tag)
    overrides = [o for o in current.config_overrides if o.key != key]
    overrides.append(ConfigOverride(key=key, value=_coerce_value(value)))
    data = TagUpdate(
        description=current.description,
        config_overrides=overrides,
        route_subscriptions=list(current.route_subscriptions),
    )
    updated = await client.update_tag(tag, data)
    return _serialize(updated)


@mcp.tool()
async def remove_tag_config_override(tag: str, key: str) -> dict[str, Any]:
    """Remove a config override from a tag by key.

    Args:
        tag: The tag name in key:value format.
        key: Config key to remove (e.g. logging.level).
    """
    client = _get_client()
    current = await client.get_tag(tag)
    overrides = [o for o in current.config_overrides if o.key != key]
    data = TagUpdate(
        description=current.description,
        config_overrides=overrides,
        route_subscriptions=list(current.route_subscriptions),
    )
    updated = await client.update_tag(tag, data)
    return _serialize(updated)


# ==================== Networks ====================


@mcp.tool(annotations={"readOnlyHint": True})
async def list_networks(
    cursor: str | None = None,
    page_size: int | None = None,
    include_counts: bool = False,
) -> dict[str, Any]:
    """List networks.

    Args:
        cursor: Pagination cursor.
        page_size: Results per page (max 500).
        include_counts: Include total count.
    """
    client = _get_client()
    resp = await client.list_networks(cursor=cursor, page_size=page_size, include_counts=include_counts)
    return _list_response(resp)


@mcp.tool(annotations={"readOnlyHint": True})
async def get_network(network_id: str) -> dict[str, Any]:
    """Get a network by ID.

    Args:
        network_id: The network ID (e.g. network-XXXX).
    """
    client = _get_client()
    network = await client.get_network(network_id)
    return _serialize(network)


@mcp.tool()
async def create_network(
    name: str,
    cidr: str,
    description: str = "",
    lighthouses_as_relays: bool = False,
) -> dict[str, Any]:
    """Create a network.

    Args:
        name: Network name.
        cidr: Private IP range in CIDR notation (e.g. 192.168.4.0/22).
        description: Network description.
        lighthouses_as_relays: Use lighthouses as relays.
    """
    client = _get_client()
    data = NetworkCreate(
        name=name,
        description=description,
        cidr=cidr,
        lighthouses_as_relays=lighthouses_as_relays,
    )
    network = await client.create_network(data)
    return _serialize(network)


@mcp.tool(annotations={"idempotentHint": True})
async def update_network(
    network_id: str,
    name: str,
    description: str = "",
    lighthouses_as_relays: bool = False,
) -> dict[str, Any]:
    """Update a network. Full replacement.

    Args:
        network_id: The network ID.
        name: Network name.
        description: Network description.
        lighthouses_as_relays: Use lighthouses as relays.
    """
    client = _get_client()
    data = NetworkUpdate(
        name=name,
        description=description,
        lighthouses_as_relays=lighthouses_as_relays,
    )
    network = await client.update_network(network_id, data)
    return _serialize(network)


# ==================== Routes ====================


@mcp.tool(annotations={"readOnlyHint": True})
async def list_routes(
    cursor: str | None = None,
    page_size: int | None = None,
    include_counts: bool = False,
) -> dict[str, Any]:
    """List routes (summary, without full firewall rules).

    Args:
        cursor: Pagination cursor.
        page_size: Results per page (max 500).
        include_counts: Include total count.
    """
    client = _get_client()
    resp = await client.list_routes(cursor=cursor, page_size=page_size, include_counts=include_counts)
    return _list_response(resp)


@mcp.tool(annotations={"readOnlyHint": True})
async def get_route(route_id: str) -> dict[str, Any]:
    """Get a route by ID, including full firewall rules.

    Args:
        route_id: The route ID (e.g. route-XXXX).
    """
    client = _get_client()
    route = await client.get_route(route_id)
    return _serialize(route)


@mcp.tool()
async def create_route(
    name: str,
    description: str = "",
    router_host_id: str | None = None,
    routable_cidrs: str | None = None,
    firewall_rules: str | None = None,
) -> dict[str, Any]:
    """Create a route.

    Args:
        name: Route name.
        description: Route description.
        router_host_id: Host ID of the router.
        routable_cidrs: CIDRs to route, e.g. {"192.168.14.0/26": {"install": true}}.
        firewall_rules: Route firewall rules with localCIDR, protocol, portRange, etc.
    """
    client = _get_client()
    data = RouteCreate(
        name=name,
        description=description,
        router_host_id=router_host_id,
        routable_cidrs=_parse_json(routable_cidrs) or {},
        firewall_rules=_build_route_firewall_rules(_parse_json(firewall_rules)),
    )
    route = await client.create_route(data)
    return _serialize(route)


@mcp.tool(annotations={"idempotentHint": True})
async def update_route(
    route_id: str,
    name: str,
    description: str = "",
    router_host_id: str | None = None,
    routable_cidrs: str | None = None,
    firewall_rules: str | None = None,
) -> dict[str, Any]:
    """Update a route. Full replacement — include ALL fields you want to keep.

    Args:
        route_id: The route ID.
        name: Route name.
        description: Route description.
        router_host_id: Host ID of the router.
        routable_cidrs: CIDRs to route.
        firewall_rules: Complete list of route firewall rules.
    """
    client = _get_client()
    data = RouteUpdate(
        name=name,
        description=description,
        router_host_id=router_host_id,
        routable_cidrs=_parse_json(routable_cidrs) or {},
        firewall_rules=_build_route_firewall_rules(_parse_json(firewall_rules)),
    )
    route = await client.update_route(route_id, data)
    return _serialize(route)


@mcp.tool(annotations={"destructiveHint": True})
async def delete_route(route_id: str) -> dict[str, str]:
    """Delete a route.

    Args:
        route_id: The route ID to delete.
    """
    client = _get_client()
    await client.delete_route(route_id)
    return {"status": "deleted", "routeID": route_id}


@mcp.tool()
async def add_route_firewall_rule(
    route_id: str,
    protocol: str,
    description: str = "",
    local_cidr: str | None = None,
    port_from: int | None = None,
    port_to: int | None = None,
    allowed_role_id: str | None = None,
    allowed_tags: str | None = None,
) -> dict[str, Any]:
    """Add a firewall rule to a route. Reads the current route, appends the rule, and saves.

    Args:
        route_id: The route ID.
        protocol: Protocol — ANY, TCP, UDP, or ICMP.
        description: Rule description.
        local_cidr: CIDR within routableCIDRs this rule applies to. Use 0.0.0.0/0 for all.
        port_from: Start of port range (1-65535). Omit for all ports.
        port_to: End of port range (1-65535). Omit for all ports.
        allowed_role_id: Only allow traffic from this role ID.
        allowed_tags: Tags to allow, as JSON list of key:value strings.
    """
    client = _get_client()
    route = await client.get_route(route_id)
    port_range = None
    if port_from is not None and port_to is not None:
        port_range = PortRange(from_port=port_from, to_port=port_to)
    new_rule = FirewallRuleWithCIDR(
        protocol=protocol,
        description=description,
        local_cidr=local_cidr,
        allowed_role_id=allowed_role_id,
        allowed_tags=_parse_json(allowed_tags) or [],
        port_range=port_range,
    )
    rules = list(route.firewall_rules) + [new_rule]
    data = RouteUpdate(
        name=route.name,
        description=route.description,
        router_host_id=route.router_host_id,
        routable_cidrs=route.routable_cidrs,
        firewall_rules=rules,
    )
    updated = await client.update_route(route_id, data)
    return _serialize(updated)


@mcp.tool()
async def remove_route_firewall_rule(
    route_id: str,
    rule_index: int,
) -> dict[str, Any]:
    """Remove a firewall rule from a route by index. Use get_route to see current rules.

    Args:
        route_id: The route ID.
        rule_index: Zero-based index of the rule to remove.
    """
    client = _get_client()
    route = await client.get_route(route_id)
    rules = list(route.firewall_rules)
    if rule_index < 0 or rule_index >= len(rules):
        return {"error": f"rule_index {rule_index} out of range (0-{len(rules) - 1})"}
    rules.pop(rule_index)
    data = RouteUpdate(
        name=route.name,
        description=route.description,
        router_host_id=route.router_host_id,
        routable_cidrs=route.routable_cidrs,
        firewall_rules=rules,
    )
    updated = await client.update_route(route_id, data)
    return _serialize(updated)


# ==================== Audit Logs ====================


@mcp.tool(annotations={"readOnlyHint": True})
async def list_audit_logs(
    cursor: str | None = None,
    page_size: int | None = None,
    include_counts: bool = False,
    target_id: str | None = None,
    target_type: str | None = None,
) -> dict[str, Any]:
    """List audit logs with optional filters.

    Args:
        cursor: Pagination cursor.
        page_size: Results per page (max 500).
        include_counts: Include total count.
        target_id: Filter by target resource ID.
        target_type: Filter by target type (apiKey, host, network, role, user).
    """
    client = _get_client()
    resp = await client.list_audit_logs(
        cursor=cursor,
        page_size=page_size,
        include_counts=include_counts,
        target_id=target_id,
        target_type=target_type,
    )
    return _list_response(resp)


# ==================== Downloads ====================


@mcp.tool(annotations={"readOnlyHint": True})
async def list_downloads() -> dict[str, Any]:
    """List available software downloads (unauthenticated)."""
    client = _get_client()
    downloads = await client.list_downloads()
    return _serialize(downloads)
