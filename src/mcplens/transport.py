"""MCP client transport: connect to a server over stdio or streamable HTTP
and enumerate its tools. Also parses client config files (Claude Desktop /
mcpServers format) and direct commands."""
from __future__ import annotations

import asyncio
import json
import os
import shlex
from contextlib import asynccontextmanager
from dataclasses import dataclass, field
from typing import Any, AsyncIterator, Optional

from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client, get_default_environment
from mcp.client.streamable_http import streamable_http_client

from .models import ToolInfo

LIST_TIMEOUT = 30.0
CALL_TIMEOUT = 20.0


@dataclass
class Target:
    """How to reach a server."""

    kind: str  # "stdio" or "http"
    label: str
    command: list[str] = field(default_factory=list)  # stdio
    env: dict[str, str] = field(default_factory=dict)  # stdio extra env
    url: str = ""  # http

    @classmethod
    def from_url(cls, url: str) -> "Target":
        return cls(kind="http", label=url, url=url)

    @classmethod
    def from_command(cls, command: str | list[str]) -> "Target":
        parts = shlex.split(command) if isinstance(command, str) else list(command)
        if not parts:
            raise ValueError("empty server command")
        return cls(kind="stdio", label=" ".join(parts), command=parts)

    @classmethod
    def from_config(cls, path: str, name: Optional[str] = None) -> "Target":
        with open(path, "r", encoding="utf-8") as fh:
            cfg = json.load(fh)
        servers = cfg.get("mcpServers") or cfg.get("servers") or cfg
        if not isinstance(servers, dict) or not servers:
            raise ValueError(f"no mcpServers found in config {path}")
        if name is None:
            if len(servers) != 1:
                raise ValueError(
                    f"config {path} has multiple servers {sorted(servers)}; pick one with --name"
                )
            name = next(iter(servers))
        if name not in servers:
            raise ValueError(f"server '{name}' not in config {path} (has: {sorted(servers)})")
        entry = servers[name]
        if entry.get("url"):
            return cls(kind="http", label=f"{name} ({entry['url']})", url=entry["url"])
        cmd = entry.get("command")
        if not cmd:
            raise ValueError(f"server '{name}' in {path} has neither 'command' nor 'url'")
        parts = [cmd] + [str(a) for a in entry.get("args", [])]
        env = {str(k): str(v) for k, v in (entry.get("env") or {}).items()}
        return cls(kind="stdio", label=f"{name}: {' '.join(parts)}", command=parts, env=env)


@asynccontextmanager
async def connect(target: Target, extra_env: Optional[dict[str, str]] = None,
                  cwd: Optional[str] = None) -> AsyncIterator[ClientSession]:
    """Yield an initialized ClientSession for the target."""
    if target.kind == "http":
        async with streamable_http_client(target.url) as streams:
            read, write = streams[0], streams[1]
            async with ClientSession(read, write) as session:
                await session.initialize()
                yield session
    else:
        env = get_default_environment()
        env.update(target.env)
        if extra_env:
            env.update(extra_env)
        params = StdioServerParameters(
            command=target.command[0],
            args=target.command[1:],
            env=env,
            cwd=cwd,
        )
        async with stdio_client(params) as (read, write):
            async with ClientSession(read, write) as session:
                await session.initialize()
                yield session


async def _list_tools(session: ClientSession) -> list[ToolInfo]:
    result = await asyncio.wait_for(session.list_tools(), timeout=LIST_TIMEOUT)
    return [ToolInfo.from_mcp(t) for t in result.tools]


def fetch_tools(target: Target) -> list[ToolInfo]:
    """Synchronously enumerate a server's tools."""
    async def _run() -> list[ToolInfo]:
        async with connect(target) as session:
            return await _list_tools(session)

    return asyncio.run(_run())


def result_text(result: Any) -> str:
    """Flatten a CallToolResult's content into plain text."""
    parts: list[str] = []
    for item in getattr(result, "content", None) or []:
        text = getattr(item, "text", None)
        if text is not None:
            parts.append(str(text))
        else:
            parts.append(str(item))
    structured = getattr(result, "structuredContent", None) or \
        getattr(result, "structured_content", None)
    if structured:
        parts.append(json.dumps(structured, default=str))
    return "\n".join(parts)
