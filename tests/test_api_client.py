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
"""Token flow, request shapes, paging, retries, fail[] handling and routes against a mocked Mimecast API."""

import json
from datetime import UTC, datetime, timedelta
from urllib.parse import parse_qs

import httpx
import pytest

from mimecast_mcp import api_client
from mimecast_mcp.api_client import MimecastClient, MimecastCredentials, MimecastError
from mimecast_mcp.server import _credentials_var, create_mcp_server
from mimecast_mcp.tools._common import parse_datetime, window

CREDS = MimecastCredentials("id-1", "secret-1", "api.services.mimecast.com")


@pytest.fixture(autouse=True)
def isolated(monkeypatch):
    async def instant(_seconds):
        return None

    monkeypatch.setattr(api_client.asyncio, "sleep", instant)
    api_client._token_cache.clear()


class Recorder:
    """Mock transport: /oauth/token issues tokens; other paths reply from routes."""

    def __init__(self, routes=None, default=None, token_status=200):
        self.requests: list[httpx.Request] = []
        self.routes = routes or {}
        self.default = default if default is not None else {"meta": {"status": 200}, "data": [], "fail": []}
        self.token_status = token_status
        self.tokens = 0

    def __call__(self, request: httpx.Request) -> httpx.Response:
        self.requests.append(request)
        if request.url.path == "/oauth/token":
            if self.token_status != 200:
                return httpx.Response(self.token_status, json={"fail": [{"code": "invalid_client_identifier", "message": "Client credentials are invalid"}]})
            self.tokens += 1
            return httpx.Response(200, json={"access_token": f"tok-{self.tokens}", "token_type": "Bearer", "expires_in": 1800})
        reply = self.routes.get(request.url.path, self.default)
        if callable(reply):
            return reply(request)
        return httpx.Response(200, json=reply)

    def api(self) -> list[httpx.Request]:
        return [r for r in self.requests if r.url.path != "/oauth/token"]


def ok(data, next_token=None):
    meta = {"status": 200}
    if next_token:
        meta["pagination"] = {"pageSize": 50, "next": next_token}
    return {"meta": meta, "data": data, "fail": []}


async def _call(monkeypatch, recorder: Recorder, tool: str, args: dict):
    http = httpx.AsyncClient(transport=httpx.MockTransport(recorder))
    monkeypatch.setattr(api_client, "_get_shared_http_client", lambda: http)
    ctx = _credentials_var.set(CREDS)
    try:
        content, _ = await create_mcp_server().call_tool(tool, args)
    finally:
        _credentials_var.reset(ctx)
    return json.loads(content[0].text)


def _client(recorder: Recorder) -> MimecastClient:
    return MimecastClient(CREDS, httpx.AsyncClient(transport=httpx.MockTransport(recorder)))


def _body(request: httpx.Request) -> dict:
    return json.loads(request.content)


async def test_token_then_bearer_and_cache():
    rec = Recorder()
    client = _client(rec)
    await client.call("/api/audit/get-audit-events", [{}])
    await client.call("/api/audit/get-audit-events", [{}])
    token_request = rec.requests[0]
    assert str(token_request.url) == "https://api.services.mimecast.com/oauth/token"
    assert parse_qs(token_request.content.decode()) == {"grant_type": ["client_credentials"], "client_id": ["id-1"], "client_secret": ["secret-1"]}
    assert rec.tokens == 1
    assert [r.headers["authorization"] for r in rec.api()] == ["Bearer tok-1", "Bearer tok-1"]


async def test_token_cache_is_per_secret():
    rec = Recorder()
    await _client(rec).call("/x", [{}])
    other = MimecastClient(MimecastCredentials("id-1", "another-secret", CREDS.host), httpx.AsyncClient(transport=httpx.MockTransport(rec)))
    await other.call("/x", [{}])
    assert rec.tokens == 2


async def test_401_refreshes_token_once():
    replies = iter([httpx.Response(401, json={"fail": [{"code": "token_expired", "message": "Access Token Expired"}]}), httpx.Response(200, json=ok([{"a": 1}]))])
    rec = Recorder({"/x": lambda r: next(replies)})
    page = await _client(rec).call("/x", [{}])
    assert page.data == [{"a": 1}]
    assert rec.tokens == 2
    assert rec.api()[1].headers["authorization"] == "Bearer tok-2"


async def test_bad_client_credentials_are_unauthorized(monkeypatch):
    out = await _call(monkeypatch, Recorder(token_status=401), "mimecast_status", {})
    assert out["error"]["code"] == "unauthorized"
    assert "Client credentials are invalid" in out["error"]["message"]
    assert "secret-1" not in json.dumps(out)


async def test_pagination_meta_and_next_token():
    rec = Recorder({"/x": ok([{"a": 1}], next_token="tok-next")})
    page = await _client(rec).call("/x", [{"k": "v"}], page_size=25, page_token="abc")
    assert _body(rec.api()[0]) == {"meta": {"pagination": {"pageSize": 25, "pageToken": "abc"}}, "data": [{"k": "v"}]}
    assert page.next_token == "tok-next"


async def test_fail_without_data_becomes_error():
    rec = Recorder({"/x": {"meta": {"status": 200}, "data": [], "fail": [{"key": {}, "errors": [{"code": "err_validation_blank", "message": "start is blank", "retryable": False}]}]}})
    with pytest.raises(MimecastError) as exc:
        await _client(rec).call("/x", [{}])
    assert exc.value.status_code == 400
    assert "start is blank" in exc.value.message


async def test_read_retried_on_5xx_write_not():
    replies = iter([httpx.Response(503), httpx.Response(200, json=ok([]))])
    rec = Recorder({"/read": lambda r: next(replies), "/write": lambda r: httpx.Response(502)})
    client = _client(rec)
    await client.call("/read", [{}])
    with pytest.raises(MimecastError):
        await client.call("/write", [{}], read=False)
    assert [r.url.path for r in rec.api()] == ["/read", "/read", "/write"]


async def test_write_retried_on_429():
    replies = iter([httpx.Response(429, headers={"X-RateLimit-Reset": "500"}), httpx.Response(200, json=ok([{"id": "h1", "release": True}]))])
    rec = Recorder({"/w": lambda r: next(replies)})
    page = await _client(rec).call("/w", [{"id": "h1"}], read=False)
    assert page.data[0]["release"] is True


@pytest.mark.parametrize(
    "value,expected",
    [
        ("2026-03-01T10:15:30Z", "2026-03-01T10:15:30+0000"),
        ("2026-03-01T10:15:30+0000", "2026-03-01T10:15:30+0000"),
        ("2026-03-01T12:15:30+02:00", "2026-03-01T10:15:30+0000"),
        ("2026-03-01", "2026-03-01T00:00:00+0000"),
    ],
)
def test_date_formats(value, expected):
    from mimecast_mcp.tools._common import mimecast_time

    assert mimecast_time(parse_datetime(value, "d")) == expected


@pytest.mark.parametrize("value", ["2026-03-01T10:15:30", "yesterday"])
def test_bad_dates(value):
    with pytest.raises(ValueError):
        parse_datetime(value, "from_date")


def test_window_defaults_and_limits():
    now = datetime(2026, 5, 10, 12, 0, tzinfo=UTC)
    assert window(None, None, timedelta(days=7), now=now) == ("2026-05-03T12:00:00+0000", "2026-05-10T12:00:00+0000")
    with pytest.raises(ValueError):
        window("2026-05-09T00:00:00Z", "2026-05-08T00:00:00Z", timedelta(days=1), now=now)
    with pytest.raises(ValueError):
        window("2026-01-01T00:00:00Z", None, timedelta(days=1), timedelta(days=60), now=now)


async def test_find_message_shape(monkeypatch):
    rec = Recorder({"/api/message-finder/search": ok([{"trackedEmails": [{"id": "m1"}, {"id": "m2"}]}], next_token="n2")})
    out = await _call(
        monkeypatch,
        rec,
        "mimecast_find_message",
        {"value": "Invoice", "sender_address": "a@x.org", "recipient_address": "b@y.org", "from_date": "2026-03-01T00:00:00Z", "status": "delivered", "page_size": 10},
    )
    assert out == {"messages": [{"id": "m1"}, {"id": "m2"}], "count": 2, "has_more": True, "next_page_token": "n2"}
    body = _body(rec.api()[0])
    assert body["meta"] == {"pagination": {"pageSize": 10}}
    assert body["data"] == [
        {
            "start": "2026-03-01T00:00:00+0000",
            "status": ["delivery", "archived"],
            "advancedTrackAndTraceOptions": {"from": "a@x.org", "to": "b@y.org", "subject": "Invoice"},
        }
    ]


async def test_find_message_by_message_id(monkeypatch):
    rec = Recorder({"/api/message-finder/search": ok([{"trackedEmails": []}])})
    await _call(monkeypatch, rec, "mimecast_find_message", {"value": "<abc@mail.example.org>", "status": "held"})
    assert _body(rec.api()[0])["data"] == [{"status": ["held"], "messageId": "<abc@mail.example.org>"}]


async def test_message_info(monkeypatch):
    rec = Recorder({"/api/message-finder/get-message-info": ok([{"id": "m1", "status": "Delivered"}])})
    out = await _call(monkeypatch, rec, "mimecast_get_message_info", {"id": "m1"})
    assert out == {"id": "m1", "status": "Delivered"}
    assert _body(rec.api()[0])["data"] == [{"id": "m1"}]


async def test_hold_message_is_unsupported_and_calls_nothing(monkeypatch):
    rec = Recorder()
    out = await _call(monkeypatch, rec, "mimecast_hold_message", {"id": "m1", "reason": "x"})
    assert out["error"]["code"] == "invalid_argument"
    assert "mimecast_list_held_messages" in out["error"]["message"]
    assert rec.requests == []


async def test_held_list(monkeypatch):
    rec = Recorder({"/api/gateway/get-hold-message-list": ok([{"id": "h1"}])})
    out = await _call(monkeypatch, rec, "mimecast_list_held_messages", {"search_field": "sender", "search_value": "bad@x.org"})
    assert out["messages"] == [{"id": "h1"}]
    assert _body(rec.api()[0])["data"] == [{"admin": True, "searchBy": {"fieldName": "sender", "value": "bad@x.org"}}]


async def test_release_needs_confirm(monkeypatch):
    rec = Recorder()
    out = await _call(monkeypatch, rec, "mimecast_release_message", {"id": "h1"})
    assert out["done"] is False
    assert rec.requests == []


async def test_release_confirmed(monkeypatch):
    rec = Recorder({"/api/gateway/hold-release": ok([{"id": "h1", "release": True}])})
    out = await _call(monkeypatch, rec, "mimecast_release_message", {"id": "h1", "confirm": True})
    assert out == {"done": True, "id": "h1"}
    assert _body(rec.api()[0]) == {"data": [{"id": "h1"}]}


async def test_release_failure_is_reported(monkeypatch):
    fail = {"meta": {"status": 200}, "data": [], "fail": [{"key": {"id": "h1"}, "errors": [{"code": "err_hold_not_found", "message": "Held message not found"}]}]}
    out = await _call(monkeypatch, Recorder({"/api/gateway/hold-release": fail}), "mimecast_release_message", {"id": "h1", "confirm": True})
    assert out["error"]["code"] == "not_found"


async def test_queue_status(monkeypatch):
    data = [{"inboundEmailQueue": [{"date": "2026-03-01T10:00:00+0000", "count": 3}, {"date": "2026-03-01T10:30:00+0000", "count": 7}], "outboundEmailQueue": []}]
    rec = Recorder({"/api/email/get-email-queues": ok(data)})
    out = await _call(monkeypatch, rec, "mimecast_get_queue_status", {"from_date": "2026-03-01T09:00:00Z", "to_date": "2026-03-01T11:00:00Z"})
    assert out["latest_inbound"] == {"date": "2026-03-01T10:30:00+0000", "count": 7}
    assert out["latest_outbound"] is None
    assert _body(rec.api()[0])["data"] == [{"start": "2026-03-01T09:00:00+0000", "end": "2026-03-01T11:00:00+0000"}]


async def test_threat_incidents(monkeypatch):
    rec = Recorder({"/api/ttp/remediation/find-incidents": ok([{"incidents": [{"code": "TR-1"}]}])})
    out = await _call(
        monkeypatch, rec, "mimecast_get_threat_incidents",
        {"type": "manual", "search_value": "abc", "from_date": "2026-03-01T00:00:00Z", "to_date": "2026-03-02T00:00:00Z"},
    )
    assert out["incidents"] == [{"code": "TR-1"}] and out["count"] == 1
    assert _body(rec.api()[0])["data"] == [
        {
            "start": "2026-03-01T00:00:00+0000",
            "end": "2026-03-02T00:00:00+0000",
            "filterBy": [{"fieldName": "type", "value": "manual"}],
            "searchBy": {"fieldName": "all", "value": "abc"},
        }
    ]


@pytest.mark.parametrize(
    "kind,path,key",
    [
        ("url", "/api/ttp/url/get-logs", "clickLogs"),
        ("attachment", "/api/ttp/attachment/get-logs", "attachmentLogs"),
        ("impersonation", "/api/ttp/impersonation/get-logs", "impersonationLogs"),
    ],
)
async def test_ttp_logs(monkeypatch, kind, path, key):
    rec = Recorder({path: ok([{key: [{"n": 1}, {"n": 2}]}])})
    out = await _call(monkeypatch, rec, "mimecast_get_ttp_logs", {"type": kind, "to_date": "2026-03-01T00:00:00Z"})
    assert out == {"logs": [{"n": 1}, {"n": 2}], "count": 2, "has_more": False, "type": kind}
    assert _body(rec.api()[0])["data"] == [{"to": "2026-03-01T00:00:00+0000"}]


async def test_audit_events(monkeypatch):
    now = datetime.now(UTC).replace(microsecond=0)
    rec = Recorder({"/api/audit/get-audit-events": ok([{"id": "e1"}])})
    start = (now - timedelta(days=2)).strftime("%Y-%m-%dT%H:%M:%SZ")
    out = await _call(monkeypatch, rec, "mimecast_get_audit_events", {"from_date": start, "categories": ["Administration", "policy_logs"], "query": "rule"})
    assert out["events"] == [{"id": "e1"}]
    sent = _body(rec.api()[0])["data"][0]
    assert sent["categories"] == ["account_logs", "policy_logs"]
    assert sent["query"] == "rule"
    assert sent["startDateTime"].endswith("+0000") and sent["endDateTime"].endswith("+0000")


async def test_audit_events_too_old(monkeypatch):
    rec = Recorder()
    out = await _call(monkeypatch, rec, "mimecast_get_audit_events", {"from_date": "2020-01-01T00:00:00Z"})
    assert out["error"]["code"] == "invalid_argument"
    assert rec.requests == []


async def test_status(monkeypatch):
    out = await _call(monkeypatch, Recorder(), "mimecast_status", {})
    assert out == {"connected": True, "api_host": "api.services.mimecast.com", "domains": ["messages", "threats", "queue"]}
