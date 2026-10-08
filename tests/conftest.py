"""Shared fixtures for tests."""

from __future__ import annotations

from typing import Any

import pytest

SAMPLE_HOST: dict[str, Any] = {
    "id": "host-AAAABBBBCCCCDDDDEEEEFFFFF1",
    "organizationID": "org-AAAABBBBCCCCDDDDEEEEFFFFF1",
    "networkID": "network-AAAABBBBCCCCDDDDEEEEFFF1",
    "roleID": "role-AAAABBBBCCCCDDDDEEEEFFFFF1",
    "name": "test-host",
    "ipAddress": "100.100.0.10",
    "staticAddresses": ["1.2.3.4:4242"],
    "listenPort": 4242,
    "isLighthouse": False,
    "isRelay": False,
    "isBlocked": False,
    "createdAt": "2025-01-01T00:00:00Z",
    "modifiedAt": "2025-01-01T00:00:00Z",
    "tags": ["env:prod"],
    "configOverrides": [],
    "metadata": {
        "lastSeenAt": "2025-01-01T00:00:00Z",
        "version": "0.8.4",
        "platform": "dnclient",
        "updateAvailable": False,
    },
}

SAMPLE_ROLE: dict[str, Any] = {
    "id": "role-AAAABBBBCCCCDDDDEEEEFFFFF1",
    "name": "test-role",
    "description": "A test role",
    "createdAt": "2025-01-01T00:00:00Z",
    "modifiedAt": "2025-01-01T00:00:00Z",
    "firewallRules": [
        {
            "protocol": "TCP",
            "description": "allow SSH",
            "allowedRoleID": "role-AAAABBBBCCCCDDDDEEEEFFFFF2",
            "allowedTags": ["env:prod", "tier:web"],
            "portRange": {"from": 22, "to": 22},
        },
        {
            "protocol": "ANY",
            "description": "allow all from role",
            "allowedRoleID": None,
            "allowedTags": [],
            "portRange": None,
        },
    ],
}

# The API sends allowedTags: null, not [], on rules without tags (seen on a live role).
SAMPLE_ROLE_NULL_TAGS: dict[str, Any] = {
    "id": "role-AAAABBBBCCCCDDDDEEEEFFFFF3",
    "name": "null-tags",
    "description": "",
    "createdAt": "2025-01-01T00:00:00Z",
    "modifiedAt": "2025-01-01T00:00:00Z",
    "firewallRules": [
        {
            "protocol": "ICMP",
            "description": "Ping",
            "allowedRoleID": None,
            "allowedTags": None,
            "portRange": None,
        },
        {
            "protocol": "TCP",
            "description": "SSH",
            "allowedRoleID": None,
            "allowedTags": ["ssh:allow"],
            "portRange": {"from": 22, "to": 22},
        },
    ],
}

SAMPLE_TAG: dict[str, Any] = {
    "name": "env:prod",
    "description": "Production hosts",
    "configOverrides": [{"key": "logging.level", "value": "info"}],
    "priority": 3,
    "hostCount": 10,
    "routeSubscriptions": ["route-AAAABBBBCCCCDDDDEEEEFFF1"],
}

SAMPLE_NETWORK: dict[str, Any] = {
    "id": "network-AAAABBBBCCCCDDDDEEEEFFF1",
    "cidr": "100.100.0.0/22",
    "organizationID": "org-AAAABBBBCCCCDDDDEEEEFFFFF1",
    "signingCAID": "ca-AAAABBBBCCCCDDDDEEEEFFFFF1",
    "createdAt": "2025-01-01T00:00:00Z",
    "name": "TestNetwork",
    "lighthousesAsRelays": False,
    "curve": "25519",
}

SAMPLE_ROUTE: dict[str, Any] = {
    "id": "route-AAAABBBBCCCCDDDDEEEEFFF1",
    "name": "test-route",
    "description": "",
    "createdAt": "2025-01-01T00:00:00Z",
    "modifiedAt": "2025-01-01T00:00:00Z",
    "routerHostID": "host-AAAABBBBCCCCDDDDEEEEFFFFF1",
    "routableCIDRs": {"192.168.14.0/26": {"install": True}},
    "firewallRules": [
        {
            "protocol": "TCP",
            "localCIDR": "192.168.14.56/32",
            "description": "allow SSH",
            "allowedRoleID": "role-AAAABBBBCCCCDDDDEEEEFFFFF1",
            "allowedTags": [],
            "portRange": {"from": 22, "to": 22},
        }
    ],
}

SAMPLE_ROUTE_LIST_ITEM: dict[str, Any] = {
    "id": "route-AAAABBBBCCCCDDDDEEEEFFF1",
    "name": "test-route",
    "description": "",
    "createdAt": "2025-01-01T00:00:00Z",
    "modifiedAt": "2025-01-01T00:00:00Z",
    "routerHostID": "host-AAAABBBBCCCCDDDDEEEEFFFFF1",
    "routableCIDRs": {"192.168.14.0/26": {"install": True}},
    "firewallRulesCount": 1,
}

SAMPLE_AUDIT_LOG: dict[str, Any] = {
    "id": "log-AAAABBBBCCCCDDDDEEEEFFFFF1",
    "organizationID": "org-AAAABBBBCCCCDDDDEEEEFFFFF1",
    "timestamp": "2025-01-01T00:00:00Z",
    "actor": {
        "type": "apiKey",
        "id": "dnkey-AAAABBBBCCCCDDDDEEEEFFFFF1",
        "name": "test key",
    },
    "target": {
        "id": "role-AAAABBBBCCCCDDDDEEEEFFFFF1",
        "type": "role",
    },
    "event": {
        "type": "CREATED",
        "before": None,
        "after": {"name": "test-role"},
    },
}

PAGINATION_METADATA: dict[str, Any] = {
    "hasNextPage": True,
    "hasPrevPage": False,
    "nextCursor": "bmV4dA.abc123",
}


@pytest.fixture
def settings_env(monkeypatch: pytest.MonkeyPatch) -> None:
    """Set required environment variables for Settings."""
    monkeypatch.setenv("DEFINED_API_KEY", "dnkey-test-key-12345")
