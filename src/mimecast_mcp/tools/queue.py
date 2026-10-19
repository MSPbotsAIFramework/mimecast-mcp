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
"""Inbound and outbound email queues."""

from datetime import timedelta

from mcp.server.fastmcp import FastMCP

from ..api_client import MimecastClient
from ._common import READ_ONLY, ClientFactory, FromDate, ToDate, first, run_tool, window

QUEUE_DEFAULT = timedelta(hours=1)


def _latest(points: list) -> dict | None:
    rows = [p for p in points if isinstance(p, dict)]
    return max(rows, key=lambda p: str(p.get("date", ""))) if rows else None


def register(mcp: FastMCP, client_factory: ClientFactory) -> None:
    @mcp.tool(annotations=READ_ONLY)
    async def mimecast_get_queue_status(from_date: FromDate = None, to_date: ToDate = None) -> str:
        """Inbound and outbound email queue counts over time (default: the last hour), with the latest counts.

        A growing queue means mail is not being delivered. Requires Account | Dashboard | Read.
        """

        async def action(client: MimecastClient) -> dict:
            start, end = window(from_date, to_date, QUEUE_DEFAULT)
            body = first(await client.call("/api/email/get-email-queues", [{"start": start, "end": end}]))
            inbound = body.get("inboundEmailQueue") or []
            outbound = body.get("outboundEmailQueue") or []
            return {
                "start": start,
                "end": end,
                "latest_inbound": _latest(inbound),
                "latest_outbound": _latest(outbound),
                "inbound": inbound,
                "outbound": outbound,
            }

        return await run_tool("mimecast_get_queue_status", client_factory, action)
