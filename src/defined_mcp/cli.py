"""CLI entrypoint for defined-mcp."""

from __future__ import annotations

import asyncio

import typer
from rich.console import Console

app = typer.Typer(help="Defined Networking MCP Server")
console = Console()


@app.command()
def serve(
    transport: str = "stdio",
) -> None:
    """Start the Defined MCP server."""
    from defined_mcp.server import mcp

    mcp.run(transport=transport)  # ty: ignore[invalid-argument-type]


@app.command()
def check() -> None:
    """Verify API key and list networks."""
    from defined_mcp.client import DefinedApiError, DefinedClient
    from defined_mcp.settings import Settings

    async def _check() -> None:
        settings = Settings()
        client = DefinedClient(settings)
        try:
            resp = await client.list_networks()
            console.print("[green]API key is valid.[/green]")
            for net in resp.data:
                console.print(f"  Network: {net.name} ({net.cidr}) — {net.id}")
        except DefinedApiError as e:
            console.print(f"[red]API error: {e}[/red]")
            raise typer.Exit(code=1) from e
        finally:
            await client.close()

    asyncio.run(_check())


if __name__ == "__main__":
    app()
