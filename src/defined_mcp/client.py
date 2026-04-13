"""Async HTTP client for the Defined Networking API."""

from __future__ import annotations

from typing import Any

import httpx

from defined_mcp.models import (
    AuditLog,
    Downloads,
    Host,
    HostCreate,
    HostUpdate,
    Network,
    NetworkCreate,
    NetworkUpdate,
    PaginationMetadata,
    Role,
    RoleCreate,
    RoleUpdate,
    Route,
    RouteCreate,
    RouteListItem,
    RouteUpdate,
    Tag,
    TagCreate,
    TagUpdate,
)
from defined_mcp.settings import Settings  # noqa: TC001 — used at runtime


class DefinedApiError(Exception):
    """Raised when the Defined API returns an error response."""

    def __init__(self, errors: list[dict[str, Any]], status_code: int) -> None:
        self.errors = errors
        self.status_code = status_code
        messages = "; ".join(e.get("message", str(e)) for e in errors)
        super().__init__(f"Defined API error {status_code}: {messages}")


class ListResponse[T]:
    """A paginated list response."""

    def __init__(self, data: list[T], metadata: PaginationMetadata) -> None:
        self.data = data
        self.metadata = metadata


class DefinedClient:
    """Async client for the Defined Networking API."""

    def __init__(self, settings: Settings) -> None:
        self._client = httpx.AsyncClient(
            base_url=settings.api_base_url,
            headers={"Authorization": f"Bearer {settings.api_key}"},
            timeout=30.0,
        )

    async def close(self) -> None:
        await self._client.aclose()

    async def _request(
        self,
        method: str,
        path: str,
        *,
        json: dict[str, Any] | None = None,
        params: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        clean_params = {k: v for k, v in (params or {}).items() if v is not None}
        response = await self._client.request(method, path, json=json, params=clean_params or None)
        if response.status_code >= 400:
            try:
                body = response.json()
                errors = body.get("errors", [{"message": response.text}])
            except Exception:
                errors = [{"message": response.text}]
            raise DefinedApiError(errors, response.status_code)
        return response.json()

    def _pagination_params(
        self,
        cursor: str | None,
        page_size: int | None,
        include_counts: bool,
    ) -> dict[str, Any]:
        params: dict[str, Any] = {}
        if cursor is not None:
            params["cursor"] = cursor
        if page_size is not None:
            params["pageSize"] = page_size
        if include_counts:
            params["includeCounts"] = "true"
        return params

    # --- Hosts ---

    async def list_hosts(
        self,
        *,
        cursor: str | None = None,
        page_size: int | None = None,
        include_counts: bool = False,
        role_id: str | None = None,
        is_blocked: bool | None = None,
        is_lighthouse: bool | None = None,
        is_relay: bool | None = None,
    ) -> ListResponse[Host]:
        params = self._pagination_params(cursor, page_size, include_counts)
        if role_id is not None:
            params["filter.roleID"] = role_id
        if is_blocked is not None:
            params["filter.isBlocked"] = str(is_blocked).lower()
        if is_lighthouse is not None:
            params["filter.isLighthouse"] = str(is_lighthouse).lower()
        if is_relay is not None:
            params["filter.isRelay"] = str(is_relay).lower()
        body = await self._request("GET", "/v1/hosts", params=params)
        hosts = [Host.model_validate(h) for h in body["data"]]
        meta = PaginationMetadata.model_validate(body.get("metadata", {}))
        return ListResponse(hosts, meta)

    async def get_host(self, host_id: str) -> Host:
        body = await self._request("GET", f"/v1/hosts/{host_id}")
        return Host.model_validate(body["data"])

    async def create_host(self, data: HostCreate) -> Host:
        body = await self._request("POST", "/v1/hosts", json=data.model_dump(by_alias=True, exclude_none=True))
        return Host.model_validate(body["data"])

    async def update_host(self, host_id: str, data: HostUpdate) -> Host:
        body = await self._request(
            "PUT",
            f"/v2/hosts/{host_id}",
            json=data.model_dump(by_alias=True, exclude_none=True),
        )
        return Host.model_validate(body["data"])

    async def delete_host(self, host_id: str) -> None:
        await self._request("DELETE", f"/v1/hosts/{host_id}")

    async def block_host(self, host_id: str) -> Host:
        body = await self._request("POST", f"/v1/hosts/{host_id}/block")
        return Host.model_validate(body["data"]["host"])

    async def unblock_host(self, host_id: str) -> Host:
        body = await self._request("POST", f"/v1/hosts/{host_id}/unblock")
        return Host.model_validate(body["data"]["host"])

    async def create_enrollment_code(self, host_id: str, *, lifetime_seconds: int | None = None) -> dict[str, Any]:
        json_body = {"lifetimeSeconds": lifetime_seconds} if lifetime_seconds else None
        body = await self._request("POST", f"/v1/hosts/{host_id}/enrollment-code", json=json_body)
        return body["data"]

    async def create_host_and_enrollment_code(
        self,
        data: HostCreate,
        *,
        lifetime_seconds: int | None = None,
    ) -> dict[str, Any]:
        payload = data.model_dump(by_alias=True, exclude_none=True)
        if lifetime_seconds is not None:
            payload["lifetimeSeconds"] = lifetime_seconds
        body = await self._request("POST", "/v1/host-and-enrollment-code", json=payload)
        return body["data"]

    # --- Roles ---

    async def list_roles(
        self,
        *,
        cursor: str | None = None,
        page_size: int | None = None,
        include_counts: bool = False,
    ) -> ListResponse[Role]:
        params = self._pagination_params(cursor, page_size, include_counts)
        body = await self._request("GET", "/v1/roles", params=params)
        roles = [Role.model_validate(r) for r in body["data"]]
        meta = PaginationMetadata.model_validate(body.get("metadata", {}))
        return ListResponse(roles, meta)

    async def get_role(self, role_id: str) -> Role:
        body = await self._request("GET", f"/v1/roles/{role_id}")
        return Role.model_validate(body["data"])

    async def create_role(self, data: RoleCreate) -> Role:
        body = await self._request("POST", "/v1/roles", json=data.model_dump(by_alias=True))
        return Role.model_validate(body["data"])

    async def update_role(self, role_id: str, data: RoleUpdate) -> Role:
        body = await self._request("PUT", f"/v1/roles/{role_id}", json=data.model_dump(by_alias=True))
        return Role.model_validate(body["data"])

    async def delete_role(self, role_id: str) -> None:
        await self._request("DELETE", f"/v1/roles/{role_id}")

    # --- Tags ---

    async def list_tags(
        self,
        *,
        cursor: str | None = None,
        page_size: int | None = None,
        include_counts: bool = False,
    ) -> ListResponse[Tag]:
        params = self._pagination_params(cursor, page_size, include_counts)
        body = await self._request("GET", "/v2/tags", params=params)
        tags = [Tag.model_validate(t) for t in body["data"]]
        meta = PaginationMetadata.model_validate(body.get("metadata", {}))
        return ListResponse(tags, meta)

    async def get_tag(self, tag: str) -> Tag:
        body = await self._request("GET", f"/v1/tags/{tag}")
        return Tag.model_validate(body["data"])

    async def create_tag(self, data: TagCreate) -> Tag:
        body = await self._request("POST", "/v1/tags", json=data.model_dump(by_alias=True))
        return Tag.model_validate(body["data"])

    async def update_tag(self, tag: str, data: TagUpdate) -> Tag:
        body = await self._request("PUT", f"/v1/tags/{tag}", json=data.model_dump(by_alias=True))
        return Tag.model_validate(body["data"])

    async def delete_tag(self, tag: str) -> None:
        await self._request("DELETE", f"/v1/tags/{tag}")

    # --- Networks ---

    async def list_networks(
        self,
        *,
        cursor: str | None = None,
        page_size: int | None = None,
        include_counts: bool = False,
    ) -> ListResponse[Network]:
        params = self._pagination_params(cursor, page_size, include_counts)
        body = await self._request("GET", "/v1/networks", params=params)
        networks = [Network.model_validate(n) for n in body["data"]]
        meta = PaginationMetadata.model_validate(body.get("metadata", {}))
        return ListResponse(networks, meta)

    async def get_network(self, network_id: str) -> Network:
        body = await self._request("GET", f"/v1/networks/{network_id}")
        return Network.model_validate(body["data"])

    async def create_network(self, data: NetworkCreate) -> Network:
        body = await self._request("POST", "/v1/networks", json=data.model_dump(by_alias=True))
        return Network.model_validate(body["data"])

    async def update_network(self, network_id: str, data: NetworkUpdate) -> Network:
        body = await self._request(
            "PUT",
            f"/v1/networks/{network_id}",
            json=data.model_dump(by_alias=True),
        )
        return Network.model_validate(body["data"])

    # --- Routes ---

    async def list_routes(
        self,
        *,
        cursor: str | None = None,
        page_size: int | None = None,
        include_counts: bool = False,
    ) -> ListResponse[RouteListItem]:
        params = self._pagination_params(cursor, page_size, include_counts)
        body = await self._request("GET", "/v1/routes", params=params)
        routes = [RouteListItem.model_validate(r) for r in body["data"]]
        meta = PaginationMetadata.model_validate(body.get("metadata", {}))
        return ListResponse(routes, meta)

    async def get_route(self, route_id: str) -> Route:
        body = await self._request("GET", f"/v1/routes/{route_id}")
        return Route.model_validate(body["data"])

    async def create_route(self, data: RouteCreate) -> Route:
        body = await self._request("POST", "/v1/routes", json=data.model_dump(by_alias=True))
        return Route.model_validate(body["data"])

    async def update_route(self, route_id: str, data: RouteUpdate) -> Route:
        body = await self._request(
            "PUT",
            f"/v1/routes/{route_id}",
            json=data.model_dump(by_alias=True),
        )
        return Route.model_validate(body["data"])

    async def delete_route(self, route_id: str) -> None:
        await self._request("DELETE", f"/v1/routes/{route_id}")

    # --- Audit Logs ---

    async def list_audit_logs(
        self,
        *,
        cursor: str | None = None,
        page_size: int | None = None,
        include_counts: bool = False,
        target_id: str | None = None,
        target_type: str | None = None,
    ) -> ListResponse[AuditLog]:
        params = self._pagination_params(cursor, page_size, include_counts)
        if target_id is not None:
            params["filter.targetID"] = target_id
        if target_type is not None:
            params["filter.targetType"] = target_type
        body = await self._request("GET", "/v1/audit-logs", params=params)
        logs = [AuditLog.model_validate(a) for a in body["data"]]
        meta = PaginationMetadata.model_validate(body.get("metadata", {}))
        return ListResponse(logs, meta)

    # --- Downloads ---

    async def list_downloads(self) -> Downloads:
        body = await self._request("GET", "/v1/downloads")
        return Downloads.model_validate(body["data"])
