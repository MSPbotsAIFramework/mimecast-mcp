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
"""FastMCP factory and the per-request credential middleware."""

import contextvars
import re
import uuid
from collections.abc import Callable

from mcp.server.fastmcp import FastMCP
from mcp.server.transport_security import TransportSecuritySettings
from starlette.requests import Request
from starlette.responses import JSONResponse
from starlette.types import ASGIApp, Receive, Scope, Send

from ._arguments import EnvelopeFastMCP
from .api_client import MimecastClient, MimecastCredentials
from .config import GLOBAL_HOST, Settings, normalize_region

HEADER_CLIENT_ID = "X-Mimecast-Client-ID"
HEADER_CLIENT_SECRET = "X-Mimecast-Client-Secret"
HEADER_REGION = "X-Mimecast-Region"  # optional
REQUIRED_HEADERS = [HEADER_CLIENT_ID, HEADER_CLIENT_SECRET]

_PLACEHOLDER = re.compile(r"^\$\{.*\}$")

# Per-request isolation: the middleware sets these for the duration of one
# HTTP request and resets them in `finally`. Nothing credential-related is
# ever stored at module level.
_credentials_var: contextvars.ContextVar[MimecastCredentials | None] = contextvars.ContextVar("mimecast_credentials", default=None)
request_id_var: contextvars.ContextVar[str] = contextvars.ContextVar("mimecast_request_id", default="-")

INSTRUCTIONS = (
    "Mimecast is an email security gateway: it filters inbound and outbound mail, "
    "holds suspicious messages for review, rewrites and scans links and attachments "
    "(Targeted Threat Protection) and can remediate (remove) malicious mail from mailboxes.\n"
    "Usage:\n"
    "- Where is an email: mimecast_find_message(sender_address / recipient_address / "
    "value, from_date, to_date) -> mimecast_get_message_info(id).\n"
    "- Held mail: mimecast_list_held_messages -> mimecast_release_message(id, confirm).\n"
    "- Threats: mimecast_get_ttp_logs(type url|attachment|impersonation), "
    "mimecast_get_threat_incidents; admin changes: mimecast_get_audit_events.\n"
    "- Mail flow: mimecast_get_queue_status.\n"
    "Dates are ISO 8601 with a zone (2026-03-01T00:00:00Z or +0000). Lists return "
    "next_page_token; pass it back as page_token. Releasing a held message delivers it, "
    "so only do it when the user explicitly asks. Each tool needs the matching "
    "permission on the API application's role; a permission error names it."
)


def get_client_from_context() -> MimecastClient | None:
    """The client for the current request, or None outside a request."""
    credentials = _credentials_var.get()
    if credentials is None:
        return None
    return MimecastClient(credentials)


def _clean(value: str | None) -> str | None:
    text = (value or "").strip()
    if not text or _PLACEHOLDER.match(text):
        return None
    return text


def _error(scope: Scope, receive: Receive, send: Send, status: int, error: str, message: str):
    return JSONResponse({"error": error, "message": message, "required_headers": REQUIRED_HEADERS}, status_code=status)(
        scope, receive, send
    )


class GatewayCredentialsMiddleware:
    """Reads the Mimecast API 2.0 application credentials (and optional region) on /mcp requests.

    Missing required headers -> 401 listing them. An unknown region does not block the
    request (tools/list must work with any values); tools report it instead and never
    call any host.
    """

    def __init__(self, app: ASGIApp):
        self.app = app

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http" or not scope.get("path", "").startswith("/mcp"):
            await self.app(scope, receive, send)
            return

        request = Request(scope)
        client_id = _clean(request.headers.get(HEADER_CLIENT_ID))
        client_secret = _clean(request.headers.get(HEADER_CLIENT_SECRET))
        missing = [name for name, value in ((HEADER_CLIENT_ID, client_id), (HEADER_CLIENT_SECRET, client_secret)) if not value]
        if missing:
            await _error(scope, receive, send, 401, "Missing credentials", f"Missing header(s): {', '.join(missing)}")
            return
        host = normalize_region(_clean(request.headers.get(HEADER_REGION)))
        header_error = None
        if host is None:
            header_error = (
                f"{HEADER_REGION} must be a region code (us, eu, uk, de, ...), us-api / uk-api / de-api, or a *.services.mimecast.com host"
            )
            # Never the caller's value: the client is built on the allow-listed
            # global host, and tools return header_error before any request.
            host = GLOBAL_HOST

        request_id = (request.headers.get("x-request-id") or "").strip()[:64] or uuid.uuid4().hex[:12]
        creds_token = _credentials_var.set(MimecastCredentials(client_id, client_secret, host, header_error))
        rid_token = request_id_var.set(request_id)
        try:
            await self.app(scope, receive, send)
        finally:
            _credentials_var.reset(creds_token)
            request_id_var.reset(rid_token)


def create_mcp_server(settings: Settings | None = None) -> FastMCP:
    """Build the FastMCP server and register every tool."""
    mcp = EnvelopeFastMCP(
        name="mimecast-mcp",
        instructions=INSTRUCTIONS,
        # The service sits behind the gateway, so Host is never localhost;
        # DNS-rebinding protection would reject those requests with 421.
        transport_security=TransportSecuritySettings(enable_dns_rebinding_protection=False),
        stateless_http=True,
    )

    client_factory: Callable[[], MimecastClient | None] = get_client_from_context

    from .tools import messages, navigation, queue, threats

    for module in (navigation, messages, threats, queue):
        module.register(mcp, client_factory)

    return mcp
