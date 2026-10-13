"""Pydantic models for the Defined Networking API."""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel, ConfigDict, Field

# --- Shared / Nested ---


class PortRange(BaseModel):
    """Port range for firewall rules. Uses aliases because 'from' is a Python keyword."""

    model_config = ConfigDict(populate_by_name=True)

    from_port: int = Field(alias="from", ge=1, le=65535)
    to_port: int = Field(alias="to", ge=1, le=65535)


class FirewallRule(BaseModel):
    """A firewall rule on a role.

    The API returns allowedTags as null on rules without tags. None is kept as-is so that
    read-modify-write tools send existing rules back unchanged.
    """

    model_config = ConfigDict(populate_by_name=True)

    protocol: str
    description: str = ""
    allowed_role_id: str | None = Field(default=None, alias="allowedRoleID")
    allowed_tags: list[str] | None = Field(default_factory=list, alias="allowedTags")
    port_range: PortRange | None = Field(default=None, alias="portRange")


class FirewallRuleWithCIDR(BaseModel):
    """A firewall rule on a route, with localCIDR. allowedTags may be null, as on FirewallRule."""

    model_config = ConfigDict(populate_by_name=True)

    protocol: str
    description: str = ""
    local_cidr: str | None = Field(default=None, alias="localCIDR")
    allowed_role_id: str | None = Field(default=None, alias="allowedRoleID")
    allowed_tags: list[str] | None = Field(default_factory=list, alias="allowedTags")
    port_range: PortRange | None = Field(default=None, alias="portRange")


class ConfigOverride(BaseModel):
    """A nebula config override (key/value pair)."""

    key: str
    value: Any


class HostMetadata(BaseModel):
    """Host runtime metadata."""

    model_config = ConfigDict(populate_by_name=True)

    last_seen_at: str | None = Field(default=None, alias="lastSeenAt")
    version: str | None = None
    platform: str | None = None
    update_available: bool | None = Field(default=None, alias="updateAvailable")


# --- Resources ---


class Host(BaseModel):
    """A host in a Defined Networking network."""

    model_config = ConfigDict(populate_by_name=True)

    id: str
    organization_id: str = Field(alias="organizationID")
    network_id: str = Field(alias="networkID")
    role_id: str | None = Field(default=None, alias="roleID")
    name: str
    ip_address: str = Field(alias="ipAddress")
    static_addresses: list[str] = Field(default_factory=list, alias="staticAddresses")
    listen_port: int = Field(alias="listenPort")
    is_lighthouse: bool = Field(default=False, alias="isLighthouse")
    is_relay: bool = Field(default=False, alias="isRelay")
    is_blocked: bool = Field(default=False, alias="isBlocked")
    created_at: str = Field(alias="createdAt")
    modified_at: str = Field(alias="modifiedAt")
    tags: list[str] = Field(default_factory=list)
    config_overrides: list[ConfigOverride] = Field(default_factory=list, alias="configOverrides")
    metadata: HostMetadata = Field(default_factory=HostMetadata)


class RoleListItem(BaseModel):
    """A role as returned by list (no firewall rules, just counts).

    The counts have no default, so a response without them fails validation instead of reading as zero.
    """

    model_config = ConfigDict(populate_by_name=True)

    id: str
    name: str
    description: str = ""
    created_at: str = Field(alias="createdAt")
    modified_at: str = Field(alias="modifiedAt")
    firewall_rules_count: int = Field(alias="firewallRulesCount")
    host_count: int = Field(alias="hostCount")


class Role(BaseModel):
    """A role with firewall rules."""

    model_config = ConfigDict(populate_by_name=True)

    id: str
    name: str
    description: str = ""
    firewall_rules: list[FirewallRule] = Field(default_factory=list, alias="firewallRules")
    created_at: str = Field(alias="createdAt")
    modified_at: str = Field(alias="modifiedAt")


class Tag(BaseModel):
    """A tag for hosts."""

    model_config = ConfigDict(populate_by_name=True)

    name: str
    description: str = ""
    config_overrides: list[ConfigOverride] = Field(default_factory=list, alias="configOverrides")
    priority: int = 0
    host_count: int = Field(default=0, alias="hostCount")
    route_subscriptions: list[str] = Field(default_factory=list, alias="routeSubscriptions")


class Network(BaseModel):
    """A Defined Networking network."""

    model_config = ConfigDict(populate_by_name=True)

    id: str
    cidr: str
    organization_id: str = Field(alias="organizationID")
    signing_ca_id: str = Field(alias="signingCAID")
    created_at: str = Field(alias="createdAt")
    name: str
    lighthouses_as_relays: bool = Field(default=False, alias="lighthousesAsRelays")
    curve: str = "25519"


class RouteListItem(BaseModel):
    """A route as returned by list (no firewall rules, just count)."""

    model_config = ConfigDict(populate_by_name=True)

    id: str
    name: str
    description: str = ""
    created_at: str = Field(alias="createdAt")
    modified_at: str = Field(alias="modifiedAt")
    router_host_id: str = Field(alias="routerHostID")
    routable_cidrs: dict[str, dict[str, bool]] = Field(default_factory=dict, alias="routableCIDRs")
    firewall_rules_count: int = Field(default=0, alias="firewallRulesCount")


class Route(BaseModel):
    """A route with full firewall rules."""

    model_config = ConfigDict(populate_by_name=True)

    id: str
    name: str
    description: str = ""
    created_at: str = Field(alias="createdAt")
    modified_at: str = Field(alias="modifiedAt")
    router_host_id: str = Field(alias="routerHostID")
    routable_cidrs: dict[str, dict[str, bool]] = Field(default_factory=dict, alias="routableCIDRs")
    firewall_rules: list[FirewallRuleWithCIDR] = Field(default_factory=list, alias="firewallRules")


class Actor(BaseModel):
    """The entity that performed an audit log action."""

    type: str
    id: str | None = None
    name: str | None = None
    email: str | None = None
    issuer: str | None = None
    subject: str | None = None


class Target(BaseModel):
    """The entity acted upon in an audit log."""

    id: str
    type: str


class Event(BaseModel):
    """Audit log event details."""

    type: str
    before: dict[str, Any] | None = None
    after: dict[str, Any] | None = None


class AuditLog(BaseModel):
    """An audit log entry."""

    model_config = ConfigDict(populate_by_name=True)

    id: str
    organization_id: str = Field(alias="organizationID")
    timestamp: str
    actor: Actor
    target: Target
    event: Event


class Downloads(BaseModel):
    """Software download information."""

    dnclient: dict[str, Any] = Field(default_factory=dict)
    mobile: dict[str, str] = Field(default_factory=dict)
    container: dict[str, str] = Field(default_factory=dict)
    version_info: dict[str, Any] = Field(default_factory=dict, alias="versionInfo")


# --- Pagination ---


class PageInfo(BaseModel):
    """Page position within the result set."""

    count: int = 0
    start: int = 0


class PaginationMetadata(BaseModel):
    """Cursor-based pagination metadata."""

    model_config = ConfigDict(populate_by_name=True)

    total_count: int | None = Field(default=None, alias="totalCount")
    has_next_page: bool = Field(default=False, alias="hasNextPage")
    has_prev_page: bool = Field(default=False, alias="hasPrevPage")
    next_cursor: str | None = Field(default=None, alias="nextCursor")
    prev_cursor: str | None = Field(default=None, alias="prevCursor")
    page: PageInfo | None = None


# --- API Responses ---


class ApiError(BaseModel):
    """A single API error."""

    code: str
    message: str
    path: str | None = None


# --- Request Models ---


class HostCreate(BaseModel):
    """Request body for creating a host."""

    model_config = ConfigDict(populate_by_name=True)

    name: str
    network_id: str = Field(alias="networkID")
    role_id: str | None = Field(default=None, alias="roleID")
    ip_address: str | None = Field(default=None, alias="ipAddress")
    static_addresses: list[str] = Field(default_factory=list, alias="staticAddresses")
    listen_port: int = Field(default=0, alias="listenPort")
    is_lighthouse: bool = Field(default=False, alias="isLighthouse")
    is_relay: bool = Field(default=False, alias="isRelay")
    tags: list[str] = Field(default_factory=list)
    config_overrides: list[ConfigOverride] = Field(default_factory=list, alias="configOverrides")


class HostUpdate(BaseModel):
    """Request body for updating a host (PUT /v2/hosts/{id}, full replacement)."""

    model_config = ConfigDict(populate_by_name=True)

    name: str | None = None
    role_id: str | None = Field(default=None, alias="roleID")
    static_addresses: list[str] = Field(default_factory=list, alias="staticAddresses")
    listen_port: int = Field(default=0, alias="listenPort")
    tags: list[str] = Field(default_factory=list)
    config_overrides: list[ConfigOverride] = Field(default_factory=list, alias="configOverrides")


class RoleCreate(BaseModel):
    """Request body for creating a role."""

    model_config = ConfigDict(populate_by_name=True)

    name: str
    description: str = ""
    firewall_rules: list[FirewallRule] = Field(default_factory=list, alias="firewallRules")


class RoleUpdate(BaseModel):
    """Request body for updating a role (PUT, full replacement of firewall rules)."""

    model_config = ConfigDict(populate_by_name=True)

    description: str = ""
    firewall_rules: list[FirewallRule] = Field(default_factory=list, alias="firewallRules")


class TagCreate(BaseModel):
    """Request body for creating a tag."""

    model_config = ConfigDict(populate_by_name=True)

    name: str
    description: str = ""
    config_overrides: list[ConfigOverride] = Field(default_factory=list, alias="configOverrides")
    before: str | None = None
    after: str | None = None
    route_subscriptions: list[str] = Field(default_factory=list, alias="routeSubscriptions")


class TagUpdate(BaseModel):
    """Request body for updating a tag (PUT, full replacement)."""

    model_config = ConfigDict(populate_by_name=True)

    description: str = ""
    config_overrides: list[ConfigOverride] = Field(default_factory=list, alias="configOverrides")
    before: str | None = None
    after: str | None = None
    route_subscriptions: list[str] = Field(default_factory=list, alias="routeSubscriptions")


class NetworkCreate(BaseModel):
    """Request body for creating a network."""

    model_config = ConfigDict(populate_by_name=True)

    name: str
    description: str = ""
    cidr: str
    lighthouses_as_relays: bool = Field(default=False, alias="lighthousesAsRelays")


class NetworkUpdate(BaseModel):
    """Request body for updating a network (PUT, full replacement)."""

    model_config = ConfigDict(populate_by_name=True)

    name: str
    description: str = ""
    lighthouses_as_relays: bool = Field(default=False, alias="lighthousesAsRelays")


class RouteCreate(BaseModel):
    """Request body for creating a route."""

    model_config = ConfigDict(populate_by_name=True)

    name: str
    description: str = ""
    router_host_id: str | None = Field(default=None, alias="routerHostID")
    routable_cidrs: dict[str, dict[str, bool]] = Field(default_factory=dict, alias="routableCIDRs")
    firewall_rules: list[FirewallRuleWithCIDR] = Field(default_factory=list, alias="firewallRules")


class RouteUpdate(BaseModel):
    """Request body for updating a route (PUT, full replacement)."""

    model_config = ConfigDict(populate_by_name=True)

    name: str
    description: str = ""
    router_host_id: str | None = Field(default=None, alias="routerHostID")
    routable_cidrs: dict[str, dict[str, bool]] = Field(default_factory=dict, alias="routableCIDRs")
    firewall_rules: list[FirewallRuleWithCIDR] = Field(default_factory=list, alias="firewallRules")
