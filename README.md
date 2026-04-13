# defined-mcp

MCP server for the [Defined Networking](https://www.defined.net/) API.

## Installation

```bash
uv tool install git+https://github.com/quickvm/defined-mcp.git
```

To install a specific version or branch:

```bash
uv tool install git+https://github.com/quickvm/defined-mcp.git@main
```

For local development:

```bash
git clone git@github.com:quickvm/defined-mcp.git
cd defined-mcp
uv tool install --editable .
```

## Configuration

Set the `DEFINED_API_KEY` environment variable to your Defined Networking API key.
Get one from your [admin panel](https://admin.defined.net/settings/api-keys).

```bash
export DEFINED_API_KEY=dnkey-...
```

## Usage

### Add to Claude Code

```bash
claude mcp add defined_mcp -- defined-mcp serve
```

Then restart Claude Code.

### Verify connectivity

```bash
defined-mcp check
```

### Run standalone

```bash
defined-mcp serve
```

## Available Tools

### Hosts
- `list_hosts` — List hosts with filters (role, blocked, lighthouse, relay)
- `get_host` — Get host details
- `create_host` — Create a host/lighthouse/relay
- `update_host` — Update a host (full replacement)
- `delete_host` — Delete a host
- `block_host` / `unblock_host` — Block/unblock a host
- `add_host_tag` / `remove_host_tag` — Add/remove a tag on a host
- `create_enrollment_code` — Generate enrollment code
- `create_host_and_enrollment_code` — Create host + enrollment code

### Roles & Firewall Rules
- `list_roles` / `get_role` — List/get roles with firewall rules
- `create_role` / `update_role` — Create/update roles (full replacement)
- `delete_role` — Delete a role
- `add_firewall_rule` — Add a firewall rule to a role (flat params, no JSON)
- `remove_firewall_rule` — Remove a firewall rule by index

### Tags
- `list_tags` / `get_tag` — List/get tags
- `create_tag` / `update_tag` — Create/update tags with config overrides
- `delete_tag` — Delete a tag
- `add_tag_config_override` — Add/replace a config override on a tag
- `remove_tag_config_override` — Remove a config override by key

### Networks
- `list_networks` / `get_network` — List/get networks
- `create_network` / `update_network` — Create/update networks

### Routes
- `list_routes` / `get_route` — List/get routes with firewall rules
- `create_route` / `update_route` — Create/update routes (full replacement)
- `delete_route` — Delete a route
- `add_route_firewall_rule` — Add a firewall rule to a route
- `remove_route_firewall_rule` — Remove a route firewall rule by index

### Other
- `list_audit_logs` — Audit log with filters
- `list_downloads` — Software download links (unauthenticated)

## Claude Code Skills

This repo includes a Claude Code skill for interactive network management.
When you run Claude Code from this repo, the `/network-architect` command is
available automatically.

To use the skill from any project, copy it to your Claude Code profile:

```bash
cp -r .claude/skills/network-architect ~/.claude/skills/
```

### `/network-architect audit`

Performs a security and configuration audit of your Defined Networking account.
Fetches all networks, roles, tags, and hosts, then reports:

- Roles with missing or overly permissive firewall rules
- Dead tags (zero hosts assigned)
- Hosts with no tags, outdated dnclient versions, or stale last-seen times
- Firewall coverage summary per role with port/protocol/tag details

### `/network-architect design`

Interactive firewall policy design session. Asks about your services, access
requirements, and segmentation needs, then proposes:

- Role structure (what each host type IS)
- Tag taxonomy (access tags like `ssh:allow`, identity tags like `user-type:admin`)
- Firewall rules per role in table format with AND logic (role + tags)

### `/network-architect apply`

Implements a network design using atomic tools (`add_firewall_rule`,
`add_host_tag`, etc.). Reads current state first, shows a diff, asks for
confirmation, then verifies after applying.

## License

[MIT](LICENSE)
