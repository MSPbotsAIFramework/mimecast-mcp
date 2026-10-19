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
"""Message tracking and held messages."""

from typing import Annotated, Any, Literal

from mcp.server.fastmcp import FastMCP
from pydantic import Field

from .._json import error_envelope
from ..api_client import MimecastClient
from ._common import (
    DEFAULT_PAGE_SIZE,
    LOCAL,
    READ_ONLY,
    WRITES,
    ClientFactory,
    FromDate,
    PageSize,
    PageToken,
    ToDate,
    compact,
    first,
    listing,
    optional_time,
    run_tool,
)

# Delivery states of the message tracking API, plus the names earlier versions
# of this server accepted (mapped to the closest tracking states).
OFFICIAL_STATUSES = (
    "accepted", "processing", "bulk_processing", "delivery", "bulk_delivery", "held",
    "bounced", "deferred", "rejected", "archived", "system",
)
LEGACY_STATUSES = {"blocked": ["rejected"], "delivered": ["delivery", "archived"], "failed": ["bounced"], "queued": ["delivery"]}
Status = Literal[
    "accepted", "processing", "bulk_processing", "delivery", "bulk_delivery", "held",
    "bounced", "deferred", "rejected", "archived", "system",
    "blocked", "delivered", "failed", "queued",
]
MessageId = Annotated[str, Field(description="Mimecast message id (the id field of mimecast_find_message).", min_length=1)]


def register(mcp: FastMCP, client_factory: ClientFactory) -> None:
    @mcp.tool(annotations=READ_ONLY)
    async def mimecast_find_message(
        value: Annotated[str | None, Field(description="Subject text, or an internet message id such as <abc@example.org>.")] = None,
        sender_address: Annotated[str | None, Field(description="Sender email address or domain.")] = None,
        recipient_address: Annotated[str | None, Field(description="Recipient email address or domain.")] = None,
        from_date: FromDate = None,
        to_date: ToDate = None,
        status: Annotated[Status | None, Field(description="Delivery state to filter by.")] = None,
        page_size: PageSize = None,
        page_token: PageToken = None,
    ) -> str:
        """Track email through the gateway by sender, recipient, subject or message id, with delivery status.

        Requires Gateway | Tracking | Read. Use the returned id with mimecast_get_message_info.
        """

        async def action(client: MimecastClient) -> dict:
            options = compact({"from": sender_address, "to": recipient_address})
            query: dict[str, Any] = {
                "start": optional_time(from_date, "from_date"),
                "end": optional_time(to_date, "to_date"),
                "status": LEGACY_STATUSES.get(status, [status]) if status else None,
            }
            text = (value or "").strip()
            if text.startswith("<") and text.endswith(">") and "@" in text:
                query["messageId"] = text
            elif text:
                options["subject"] = text
            query["advancedTrackAndTraceOptions"] = options
            page = await client.call(
                "/api/message-finder/search", [compact(query)], page_size=page_size or DEFAULT_PAGE_SIZE, page_token=page_token
            )
            rows = first(page).get("trackedEmails") or []
            return listing(rows, "messages", page)

        return await run_tool("mimecast_find_message", client_factory, action)

    @mcp.tool(annotations=READ_ONLY)
    async def mimecast_get_message_info(id: MessageId) -> str:
        """Get one tracked message: recipients and delivery details, spam score and detection, retention.

        Requires Gateway | Tracking | Read.
        """

        async def action(client: MimecastClient) -> Any:
            page = await client.call("/api/message-finder/get-message-info", [{"id": id}])
            if not page.data:
                return error_envelope("not_found", f"Mimecast returned no details for message {id}.", False)
            return first(page)

        return await run_tool("mimecast_get_message_info", client_factory, action)

    @mcp.tool(annotations=LOCAL)
    async def mimecast_hold_message(
        id: MessageId,
        reason: Annotated[str | None, Field(description="Why the message should be held.")] = None,
    ) -> str:
        """Not available: the Mimecast API cannot put a message on hold. Returns an explanation.

        Messages are held by policy. To pull a delivered message from mailboxes use threat remediation in
        the Administration Console; to review held mail use mimecast_list_held_messages.
        """
        return error_envelope(
            "invalid_argument",
            "The Mimecast API has no endpoint to put a message on hold (messages are held by policy). "
            "Use mimecast_list_held_messages to review held mail, or threat remediation in the Mimecast "
            "Administration Console to remove a delivered message from mailboxes.",
            False,
        )

    @mcp.tool(annotations=READ_ONLY)
    async def mimecast_list_held_messages(
        search_field: Annotated[
            Literal["all", "subject", "sender", "recipient", "reasonCode", "senderIP"] | None,
            Field(description="Field that search_value matches (default all)."),
        ] = None,
        search_value: Annotated[str | None, Field(description="Text to look for.")] = None,
        from_date: FromDate = None,
        to_date: ToDate = None,
        page_size: PageSize = None,
        page_token: PageToken = None,
    ) -> str:
        """List messages held for review (all recipients): id, sender, recipient, subject, hold reason, policy.

        Requires Account | Dashboard | Read. The id is what mimecast_release_message needs.
        """

        async def action(client: MimecastClient) -> dict:
            query: dict[str, Any] = {"admin": True, "start": optional_time(from_date, "from_date"), "end": optional_time(to_date, "to_date")}
            if search_value and search_value.strip():
                query["searchBy"] = {"fieldName": search_field or "all", "value": search_value.strip()}
            page = await client.call(
                "/api/gateway/get-hold-message-list", [compact(query)], page_size=page_size or DEFAULT_PAGE_SIZE, page_token=page_token
            )
            return listing(page.data, "messages", page)

        return await run_tool("mimecast_list_held_messages", client_factory, action)

    @mcp.tool(annotations=WRITES)
    async def mimecast_release_message(
        id: Annotated[str, Field(description="Held message id from mimecast_list_held_messages.", min_length=1)],
        confirm: Annotated[bool | None, Field(description="Must be true, set only after the user approved releasing this message.")] = None,
    ) -> str:
        """Release a held message so it is delivered to its recipients. Needs confirm: true.

        Only when the user explicitly asks; held mail may be malicious. Requires Account | Monitoring | Held | Edit.
        """

        async def action(client: MimecastClient) -> dict:
            if confirm is not True:
                return {
                    "done": False,
                    "action": f"Release held message {id} for delivery",
                    "message": "Not done. Releasing delivers the message to its recipients: describe it to the user and "
                    "call again with confirm: true only after they approve it.",
                }
            page = await client.call("/api/gateway/hold-release", [{"id": id}], read=False)
            item = first(page)
            return {"done": bool(item.get("release", True)), "id": item.get("id", id)}

        return await run_tool("mimecast_release_message", client_factory, action)
