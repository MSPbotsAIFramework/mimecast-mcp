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
"""Email security policies: blocked senders, anti-spoofing bypass, and managed senders."""

from typing import Annotated, Any, Literal

from mcp.server.fastmcp import FastMCP
from pydantic import Field

from .._json import error_envelope
from ..api_client import MimecastClient
from ._common import DEFAULT_PAGE_SIZE, READ_ONLY, WRITES, ClientFactory, PageSize, PageToken, first, listing, run_tool

# policyType -> the endpoint that lists or fetches it. Both are the same
# "/api/policy/{type}/get-policy" path; kept as a dict so the set of supported
# types is one place and a bad Literal value cannot reach client.call.
POLICY_TYPES = {
    "blockedsenders": "/api/policy/blockedsenders/get-policy",
    "antispoofing-bypass": "/api/policy/antispoofing-bypass/get-policy",
}
PolicyType = Literal["blockedsenders", "antispoofing-bypass"]


def register(mcp: FastMCP, client_factory: ClientFactory) -> None:
    @mcp.tool(annotations=READ_ONLY)
    async def mimecast_list_policies(
        type: Annotated[PolicyType, Field(description="Policy type to list.")],
        page_size: PageSize = None,
        page_token: PageToken = None,
    ) -> str:
        """List email security policies of one type: blocked senders or anti-spoofing bypass.

        Requires Gateway | Policies | Read. Use the returned id with mimecast_get_policy.
        """

        async def action(client: MimecastClient) -> dict:
            page = await client.call(POLICY_TYPES[type], [{}], page_size=page_size or DEFAULT_PAGE_SIZE, page_token=page_token)
            return listing(page.data, "policies", page, type=type)

        return await run_tool("mimecast_list_policies", client_factory, action)

    @mcp.tool(annotations=READ_ONLY)
    async def mimecast_get_policy(
        type: Annotated[PolicyType, Field(description="Policy type.")],
        id: Annotated[str, Field(description="Policy id from mimecast_list_policies.", min_length=1)],
    ) -> str:
        """Get one email security policy's fields by type and id.

        Requires Gateway | Policies | Read.
        """

        async def action(client: MimecastClient) -> Any:
            page = await client.call(POLICY_TYPES[type], [{"id": id}])
            if not page.data:
                return error_envelope("not_found", f"Mimecast returned no {type} policy for id {id}.", False)
            return first(page)

        return await run_tool("mimecast_get_policy", client_factory, action)

    @mcp.tool(annotations=WRITES)
    async def mimecast_manage_sender(
        action: Annotated[Literal["permit", "block"], Field(description="Permit (always allow) or block this sender for the mailbox.")],
        sender: Annotated[str, Field(description="External sender email address.", min_length=1)],
        to: Annotated[str, Field(description="Internal recipient mailbox address this applies to.", min_length=1)],
        confirm: Annotated[bool | None, Field(description="Must be true, set only after the user approved this change.")] = None,
    ) -> str:
        """Permit or block one external sender for one internal mailbox. Needs confirm: true.

        Changes mail flow for that sender/mailbox pair going forward; only when the user explicitly asks. Requires Gateway | Managed Senders | Edit.
        """

        async def perform(client: MimecastClient) -> dict:
            if confirm is not True:
                return {
                    "done": False,
                    "action": f"{action.capitalize()} sender {sender} for mailbox {to}",
                    "message": "Not done. This changes mail flow for this sender/mailbox pair going forward: describe "
                    "it to the user and call again with confirm: true only after they approve it.",
                }
            page = await client.call("/api/managedsender/permit-or-block-sender", [{"action": action, "sender": sender, "to": to}], read=False)
            item = first(page)
            return {
                "done": True,
                "id": item.get("id"),
                "sender": item.get("sender", sender),
                "to": item.get("to", to),
                "type": item.get("type", "Permit" if action == "permit" else "Block"),
            }

        return await run_tool("mimecast_manage_sender", client_factory, perform)
