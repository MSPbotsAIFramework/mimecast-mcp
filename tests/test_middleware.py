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
"""Credential middleware: 401 / 400 on bad headers, region hosts, per-request isolation."""

import asyncio

import pytest
from starlette.testclient import TestClient

from mimecast_mcp.__main__ import build_http_app
from mimecast_mcp.config import normalize_region
from mimecast_mcp.server import GatewayCredentialsMiddleware, _credentials_var, create_mcp_server, get_client_from_context

MCP_HEADERS = {"Accept": "application/json, text/event-stream"}
LIST_TOOLS = {"jsonrpc": "2.0", "id": 1, "method": "tools/list", "params": {}}
CREDS = {"X-Mimecast-Client-ID": "id", "X-Mimecast-Client-Secret": "secret"}


def _client() -> TestClient:
    return TestClient(build_http_app(create_mcp_server()))


def test_health_is_local():
    with _client() as client:
        resp = client.get("/health")
    assert resp.status_code == 200
    assert resp.json() == {"status": "ok"}


@pytest.mark.parametrize(
    "headers",
    [
        {},
        {"X-Mimecast-Client-ID": "id"},
        {"X-Mimecast-Client-Secret": "secret"},
        {"X-Mimecast-Client-ID": "id", "X-Mimecast-Client-Secret": " "},
        {"X-Mimecast-Client-ID": "${MIMECAST_CLIENT_ID}", "X-Mimecast-Client-Secret": "secret"},
    ],
)
def test_missing_credentials_return_401(headers):
    with _client() as client:
        resp = client.post("/mcp", json=LIST_TOOLS, headers=MCP_HEADERS | headers)
    assert resp.status_code == 401
    assert resp.json()["required_headers"] == ["X-Mimecast-Client-ID", "X-Mimecast-Client-Secret"]


def test_unknown_region_returns_400():
    with _client() as client:
        resp = client.post("/mcp", json=LIST_TOOLS, headers=MCP_HEADERS | CREDS | {"X-Mimecast-Region": "evil.example.net"})
    assert resp.status_code == 400


@pytest.mark.parametrize(
    "value,expected",
    [
        (None, "api.services.mimecast.com"),
        ("", "api.services.mimecast.com"),
        ("us", "api.services.mimecast.com"),
        ("EU", "api.services.mimecast.com"),
        ("za", "api.services.mimecast.com"),
        ("global", "api.services.mimecast.com"),
        ("uk-api", "uk-api.services.mimecast.com"),
        ("US-API", "us-api.services.mimecast.com"),
        ("https://de-api.services.mimecast.com/", "de-api.services.mimecast.com"),
        ("api.services.mimecast.com", "api.services.mimecast.com"),
        ("fr-api", None),
        ("api.services.mimecast.com.example.net", None),
    ],
)
def test_normalize_region(value, expected):
    assert normalize_region(value) == expected


def test_tools_list_over_http():
    with _client() as client:
        resp = client.post("/mcp", json=LIST_TOOLS, headers=MCP_HEADERS | CREDS)
    assert resp.status_code == 200
    for name in ("mimecast_find_message", "mimecast_release_message", "mimecast_get_audit_events"):
        assert name in resp.text


async def _receive():
    return {"type": "http.request", "body": b"", "more_body": False}


async def _send(_message):
    return None


def _run_middleware(headers: list[tuple[bytes, bytes]]) -> dict:
    seen: dict = {}

    async def app(scope, receive, send):
        seen["credentials"] = _credentials_var.get()
        seen["client"] = get_client_from_context()
        await send({"type": "http.response.start", "status": 200, "headers": []})
        await send({"type": "http.response.body", "body": b""})

    asyncio.run(GatewayCredentialsMiddleware(app)({"type": "http", "path": "/mcp", "headers": headers}, _receive, _send))
    return seen


def test_credentials_and_region_reach_context_and_are_reset():
    seen = _run_middleware([(b"x-mimecast-client-id", b" id-1 "), (b"x-mimecast-client-secret", b"s"), (b"x-mimecast-region", b"uk-api")])
    assert seen["credentials"].client_id == "id-1"
    assert seen["client"].base_url == "https://uk-api.services.mimecast.com"
    assert _credentials_var.get() is None


def test_concurrent_requests_do_not_share_credentials():
    observed: list[tuple[str, str]] = []

    async def app(scope, receive, send):
        before = _credentials_var.get().client_id
        await asyncio.sleep(0.01)
        observed.append((before, _credentials_var.get().client_id))
        await send({"type": "http.response.start", "status": 200, "headers": []})
        await send({"type": "http.response.body", "body": b""})

    middleware = GatewayCredentialsMiddleware(app)

    def scope(client_id: bytes) -> dict:
        return {"type": "http", "path": "/mcp", "headers": [(b"x-mimecast-client-id", client_id), (b"x-mimecast-client-secret", b"s")]}

    async def both():
        await asyncio.gather(middleware(scope(b"tenant-a"), _receive, _send), middleware(scope(b"tenant-b"), _receive, _send))

    asyncio.run(both())
    assert sorted(observed) == [("tenant-a", "tenant-a"), ("tenant-b", "tenant-b")]


def test_credentials_repr_hides_secret():
    seen = _run_middleware([(b"x-mimecast-client-id", b"id"), (b"x-mimecast-client-secret", b"very-secret-value")])
    assert "very-secret-value" not in repr(seen["credentials"])
