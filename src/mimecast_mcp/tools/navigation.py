# Copyright 2026 MSPbots.ai
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
"""Tool discovery (kept for compatibility: every tool is always listed) and the connection check."""

from typing import Annotated, Literal

from mcp.server.fastmcp import FastMCP
from pydantic import Field

from .._json import compact as to_json
from ..api_client import MimecastClient
from ._common import LOCAL, READ_ONLY, ClientFactory, run_tool

DOMAINS: dict[str, tuple[str, list[str]]] = {
    "messages": (
        "Message tracking and held messages.",
        ["mimecast_find_message", "mimecast_get_message_info", "mimecast_list_held_messages", "mimecast_release_message", "mimecast_hold_message"],
    ),
    "threats": (
        "Targeted Threat Protection logs, remediation incidents and the audit log.",
        ["mimecast_get_ttp_logs", "mimecast_get_threat_incidents", "mimecast_get_audit_events"],
    ),
    "queue": ("Inbound and outbound email queues.", ["mimecast_get_queue_status"]),
}

Domain = Literal["messages", "threats", "queue"]


def register(mcp: FastMCP, client_factory: ClientFactory) -> None:
    @mcp.tool(annotations=LOCAL)
    async def mimecast_navigate(domain: Annotated[Domain, Field(description="Area to describe.")]) -> str:
        """Describe the tools of one Mimecast area. All tools are already callable; this changes nothing."""
        summary, tools = DOMAINS[domain]
        return to_json({"domain": domain, "summary": summary, "tools": tools})

    @mcp.tool(annotations=READ_ONLY)
    async def mimecast_status() -> str:
        """Check the Mimecast connection: gets an access token with the client id / secret; reports the host."""

        async def action(client: MimecastClient) -> dict:
            await client.token(force=True)
            return {"connected": True, "api_host": client.host, "domains": list(DOMAINS)}

        return await run_tool("mimecast_status", client_factory, action)
