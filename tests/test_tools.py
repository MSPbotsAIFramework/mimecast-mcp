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
"""tools/list snapshot, annotations and error-envelope mapping. No network access."""

import asyncio
import json

import pytest

from mimecast_mcp.api_client import MimecastError
from mimecast_mcp.server import INSTRUCTIONS, create_mcp_server
from mimecast_mcp.tools.navigation import DOMAINS

P = {"page_size", "page_token"}
D = {"from_date", "to_date"}

# Tool name -> (parameters the earlier version declared, required parameters).
# Names and these parameters are a public contract. (get_threat_incidents'
# earlier `status` filter is gone: the API has no such field, it never filtered.)
EXPECTED: dict[str, tuple[set[str], set[str]]] = {
    "mimecast_navigate": ({"domain"}, {"domain"}),
    "mimecast_status": (set(), set()),
    "mimecast_find_message": ({"value", "sender_address", "recipient_address", "status"} | D | P, set()),
    "mimecast_get_message_info": ({"id"}, {"id"}),
    "mimecast_hold_message": ({"id", "reason"}, {"id"}),
    "mimecast_release_message": ({"id"}, {"id"}),
    "mimecast_list_held_messages": ({"search_field", "search_value"} | D | P, set()),
    "mimecast_get_queue_status": (set(), set()),
    "mimecast_get_threat_incidents": (P, set()),
    "mimecast_get_ttp_logs": ({"type"} | D | P, {"type"}),
    "mimecast_get_audit_events": ({"categories"} | D | P, set()),
}


@pytest.fixture(scope="module")
def tools():
    return {t.name: t for t in asyncio.run(create_mcp_server().list_tools())}


def test_tool_names_are_stable(tools):
    assert set(tools) == set(EXPECTED)
    assert len(tools) == 11


@pytest.mark.parametrize("name", sorted(EXPECTED))
def test_params(tools, name):
    schema = tools[name].inputSchema
    params, required = EXPECTED[name]
    assert params <= set(schema["properties"])
    assert set(schema.get("required", [])) == required


@pytest.mark.parametrize("name", sorted(EXPECTED))
def test_description_budget(tools, name):
    description = (tools[name].description or "").strip()
    assert description, f"{name} has no description"
    assert len(description) <= 500
    assert len(description.splitlines()[0]) <= 100


@pytest.mark.parametrize("name", sorted(EXPECTED))
def test_annotations(tools, name):
    annotations = tools[name].annotations
    assert annotations is not None
    if name == "mimecast_release_message":
        assert annotations.readOnlyHint is False
        assert "explicitly ask" in tools[name].description
    else:
        assert annotations.readOnlyHint is True and not annotations.destructiveHint
    assert (annotations.openWorldHint is False) is (name in {"mimecast_navigate", "mimecast_hold_message"})


def test_enums(tools):
    status = tools["mimecast_find_message"].inputSchema["properties"]["status"]["anyOf"][0]["enum"]
    # every value the earlier version accepted is still accepted
    assert {"accepted", "blocked", "bounced", "deferred", "delivered", "failed", "held", "processing", "queued"} <= set(status)
    assert tools["mimecast_get_ttp_logs"].inputSchema["properties"]["type"]["enum"] == ["url", "attachment", "impersonation"]
    assert tools["mimecast_find_message"].inputSchema["properties"]["page_size"]["anyOf"][0]["maximum"] == 100


def test_navigate_lists_every_tool():
    listed = {tool for _, names in DOMAINS.values() for tool in names}
    assert listed | {"mimecast_navigate", "mimecast_status"} == set(EXPECTED)


def test_instructions_budget():
    assert len(INSTRUCTIONS) <= 1500
    assert "\n" in INSTRUCTIONS


@pytest.mark.parametrize(
    "status,code,retryable",
    [
        (401, "unauthorized", False),
        (403, "unauthorized", False),
        (404, "not_found", False),
        (400, "invalid_argument", False),
        (429, "rate_limited", True),
        (500, "upstream_error", True),
        (0, "upstream_error", True),
    ],
)
def test_error_envelope(status, code, retryable):
    envelope = json.loads(MimecastError(status, "boom").to_envelope())
    assert envelope == {"error": {"code": code, "message": "boom", "retryable": retryable}}


def test_tool_without_credentials_returns_not_configured():
    content, _ = asyncio.run(create_mcp_server().call_tool("mimecast_find_message", {}))
    assert json.loads(content[0].text)["error"]["code"] == "not_configured"
