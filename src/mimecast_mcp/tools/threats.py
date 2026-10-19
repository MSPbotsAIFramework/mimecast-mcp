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
"""Targeted Threat Protection logs, threat remediation incidents and audit events."""

from datetime import timedelta
from typing import Annotated, Any, Literal

from mcp.server.fastmcp import FastMCP
from pydantic import Field

from ..api_client import MimecastClient
from ._common import (
    DEFAULT_PAGE_SIZE,
    READ_ONLY,
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
    window,
)

TTP = {
    "url": ("/api/ttp/url/get-logs", "clickLogs"),
    "attachment": ("/api/ttp/attachment/get-logs", "attachmentLogs"),
    "impersonation": ("/api/ttp/impersonation/get-logs", "impersonationLogs"),
}

# Display names an agent may use -> audit category codes (/api/audit/get-categories).
AUDIT_CATEGORY_ALIASES = {
    "administration": "account_logs",
    "admin": "account_logs",
    "account": "account_logs",
    "policy": "policy_logs",
    "authentication": "authentication_logs",
    "auth": "authentication_logs",
    "archive": "archive_service_logs",
    "journaling": "journaling_logs",
    "branding": "branding_logs",
    "awareness": "awareness_training_logs",
    "reporting": "reporting_logs",
    "integrations": "integrations_and_apis",
    "continuity": "continuity_services_logs",
}
AUDIT_DEFAULT = timedelta(days=7)
AUDIT_MAX_AGE = timedelta(days=60)
INCIDENT_DEFAULT = timedelta(days=30)


def register(mcp: FastMCP, client_factory: ClientFactory) -> None:
    @mcp.tool(annotations=READ_ONLY)
    async def mimecast_get_threat_incidents(
        type: Annotated[
            Literal["notify_only", "automatic", "manual", "restore"] | None, Field(description="Incident type to return.")
        ] = None,
        search_field: Annotated[Literal["all", "code", "file_hash", "reason"] | None, Field(description="Field that search_value matches (default all).")] = None,
        search_value: Annotated[str | None, Field(description="Text to look for, e.g. an incident code or file hash.")] = None,
        from_date: FromDate = None,
        to_date: ToDate = None,
        page_size: PageSize = None,
        page_token: PageToken = None,
    ) -> str:
        """List threat remediation incidents (malicious mail removed from mailboxes): code, type, counts.

        Defaults to the last 30 days. Requires Services | Threat Remediation | Read.
        """

        async def action(client: MimecastClient) -> dict:
            start, end = window(from_date, to_date, INCIDENT_DEFAULT)
            query: dict[str, Any] = {"start": start, "end": end}
            if type:
                query["filterBy"] = [{"fieldName": "type", "value": type}]
            if search_value and search_value.strip():
                query["searchBy"] = {"fieldName": search_field or "all", "value": search_value.strip()}
            page = await client.call(
                "/api/ttp/remediation/find-incidents", [query], page_size=page_size or DEFAULT_PAGE_SIZE, page_token=page_token
            )
            return listing(first(page).get("incidents") or [], "incidents", page, start=start, end=end)

        return await run_tool("mimecast_get_threat_incidents", client_factory, action)

    @mcp.tool(annotations=READ_ONLY)
    async def mimecast_get_ttp_logs(
        type: Annotated[Literal["url", "attachment", "impersonation"], Field(description="url clicks, attachment sandbox results or impersonation hits.")],
        from_date: Annotated[str | None, Field(description="Start, ISO 8601 with a zone (default: start of today).")] = None,
        to_date: ToDate = None,
        page_size: PageSize = None,
        page_token: PageToken = None,
    ) -> str:
        """Targeted Threat Protection logs: URL clicks, attachment sandboxing or impersonation detections.

        Requires Monitoring | URL / Attachment / Impersonation Protection | Read for the chosen type.
        """

        async def action(client: MimecastClient) -> dict:
            path, key = TTP[type]
            query = compact({"from": optional_time(from_date, "from_date"), "to": optional_time(to_date, "to_date")})
            page = await client.call(path, [query], page_size=page_size or DEFAULT_PAGE_SIZE, page_token=page_token)
            # The rows are nested: data[0].clickLogs / attachmentLogs / impersonationLogs.
            return listing(first(page).get(key) or [], "logs", page, type=type)

        return await run_tool("mimecast_get_ttp_logs", client_factory, action)

    @mcp.tool(annotations=READ_ONLY)
    async def mimecast_get_audit_events(
        from_date: Annotated[str | None, Field(description="Start, ISO 8601 with a zone; within the last 60 days (default: 7 days before to_date).")] = None,
        to_date: Annotated[str | None, Field(description="End, ISO 8601 with a zone (default: now).")] = None,
        categories: Annotated[
            list[str] | None, Field(description='Category codes such as ["account_logs", "policy_logs"]; omit for all.')
        ] = None,
        page_size: PageSize = None,
        page_token: PageToken = None,
        query: Annotated[str | None, Field(description="Text to look for in the events.")] = None,
    ) -> str:
        """Audit log of administrative activity: who changed what and when (last 60 days).

        Requires Account | Logs | Read. Display names such as "administration" map to account_logs.
        """

        async def action(client: MimecastClient) -> dict:
            start, end = window(from_date, to_date, AUDIT_DEFAULT, AUDIT_MAX_AGE)
            codes = [AUDIT_CATEGORY_ALIASES.get(c.strip().lower(), c.strip()) for c in categories or [] if c.strip()]
            body = compact({"startDateTime": start, "endDateTime": end, "categories": codes, "query": (query or "").strip()})
            page = await client.call("/api/audit/get-audit-events", [body], page_size=page_size or DEFAULT_PAGE_SIZE, page_token=page_token)
            result = listing(page.data, "events", page, start=start, end=end)
            if not page.data:
                result["hint"] = (
                    "No audit events in this window. History covers the last 60 days; omit categories to search every log."
                )
            return result

        return await run_tool("mimecast_get_audit_events", client_factory, action)
