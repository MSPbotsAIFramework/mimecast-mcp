# Mimecast MCP Server

An [MCP](https://modelcontextprotocol.io) server for the [Mimecast](https://www.mimecast.com) API 2.0,
the email security gateway MSPs run in front of their clients' mailboxes. It lets an AI agent track
where an email went, review and release held messages, read Targeted Threat Protection logs (URL
clicks, attachment sandboxing, impersonation), list threat remediation incidents, read the audit log
of administrative changes and check the inbound / outbound mail queues.

- Transport: MCP Streamable HTTP at `POST /mcp`, health probe at `GET /health`
- Stateless and multi-tenant: credentials arrive on every request as HTTP headers and are
  never stored; every tool is listed from the first `tools/list`
- Python 3.12, [uv](https://docs.astral.sh/uv/), FastMCP, httpx
- License: Apache-2.0, Copyright 2026 MSPbots.ai

<div align="center">

## MSPbots Connector

**The MCP Gateway built for MSPs: visible, controlled, and your data stays where it belongs.**

[**Get started at connect.mspbots.ai →**](https://connect.mspbots.ai)

</div>

---

MSPbots Connector gives your AI clients one MCP URL to reach your entire MSP stack (RMM, PSA, documentation, security, finance), and gives you control over who can call which tool and a record of everything that was called.

**Hosted service: [connect.mspbots.ai](https://connect.mspbots.ai)** · Free to use.

### Why Connector

![MSPbots Connector](https://stgoss.mspbots.ai/files/mcp/mspbots-mcp.png)

| | |
|---|---|
| **Visible** | Every tool call is logged: who, which vendor, when. Usage dashboard, CSV export, SIEM streaming. |
| **Controlled** | Role-based, per-tool allowlist. Deny by default. |
| **Protected** | Credentials encrypted per record. AI clients never see your vendor passwords or tokens. |
| **MSP-native** | Built for the MSP stack only: RMM, PSA, documentation, security, finance. |

### Quick start

1. **Sign up** at [connect.mspbots.ai](https://connect.mspbots.ai).
2. **Connect your vendors.** Pick from 150+ connectors and authorize each one on the vendor's own page, or bring your own API keys. No extra vendor accounts needed.
3. **Set access.** Create roles and decide which tools each role may call. Nothing is allowed until you allow it.
4. **Add your MCP URL to your AI client.** Copy the URL from your Connector dashboard into Claude, ChatGPT, Cursor, VS Code, Gemini, Codex, or any MCP-capable client.
5. **Ask your AI to do real work**, and watch every call appear in the audit log.

### Features

**Unified gateway**
- One MCP URL for all your AI clients
- 150+ connectors across the MSP stack
- Custom MCP servers supported, free
- Authorization happens on each vendor's own page; the AI never sees passwords or tokens
- Bring your own credentials: use the vendor API keys you already have
- Multiple accounts per app; connect once, reuse across AI clients
- Tool search: finds the right action for the task
- One sign-in; vendor credentials are injected behind the scenes and OAuth tokens refresh automatically

**Visibility**
- Audit log for every tool call (who, which vendor, when)
- Usage dashboard: call volume, top vendors, error rate, per-user activity
- Export audit logs to CSV, or stream to Loki, Graylog, or LogScale (SIEM)
- Optional recording of tool arguments and result summaries (off by default, enabled per organization)

**Control**
- Per-role, per-tool allowlist, deny by default
- owner / admin / member roles
- SCIM provisioning with Entra ID, Okta, JumpCloud, and Google Workspace

**Security**
- Credentials encrypted one record at a time (AES-256-GCM, per-record key)
- AI clients authenticate with OAuth 2.1 + PKCE
- Vendor responses are scanned for prompt-injection patterns and returned as structured data. This is one layer of defense, not a guarantee against every attack.
- Static egress IP for customer firewall and API allowlisting

### Pricing

**Free.**

Links: [connect.mspbots.ai](https://connect.mspbots.ai) · [mspbots.ai](https://mspbots.ai)

---

## Authentication headers

| Header | Required | Type | Default | Allowed values | Description | Example |
|---|---|---|---|---|---|---|
| `X-Mimecast-Client-ID` | Yes | string | none | - | API 2.0 application client id | `your-client-id` |
| `X-Mimecast-Client-Secret` | Yes | string | none | - | API 2.0 application client secret | `your-client-secret` |
| `X-Mimecast-Region` | No | string | global | a region code (`us`, `eu`, `uk`, `de`, `ca`, `za`, `au`, ...), `us-api`, `uk-api`, `de-api`, or a `*.services.mimecast.com` host | API gateway to use | `us` |

Where to get them: in the Mimecast Administration Console go to Administration > Services > API and
Platform Integrations > Available Integrations, and choose Generate Keys on the Mimecast API 2.0 tile.
Give the application a role with only the permissions the tools below need.

How they are used: the server exchanges the client id and secret for an access token
(`POST https://api.services.mimecast.com/oauth/token`, client credentials grant, 30 minute lifetime,
cached in memory per credential set and renewed on expiry) and sends it as `Authorization: Bearer`.
Region codes all use the global gateway, which serves every account and fails over between regions;
`us-api`, `uk-api` and `de-api` pin traffic to that regional gateway (data residency, no failover).

A request to `/mcp` without the client id or secret gets HTTP 401. An unknown region does not block
the request (tools/list still works); every tool call then returns an `invalid_argument` error naming
the accepted values, and nothing is sent to any host.

## Tools

All tools return a JSON string. Lists take `page_size` (max 100) and `page_token`, and return
`{count, has_more, next_page_token}`. Dates are ISO 8601 with a zone (`2026-03-01T00:00:00Z` or
`+0000`).

| Area | Tool | Mimecast permission |
|---|---|---|
| Overview | `mimecast_navigate` (**domain**), `mimecast_status` | - |
| Messages | `mimecast_find_message` (value, sender_address, recipient_address, from_date, to_date, status) | Gateway / Tracking / Read |
| | `mimecast_get_message_info` (**id**) | Gateway / Tracking / Read |
| | `mimecast_list_held_messages` (search_field, search_value, from_date, to_date) | Account / Dashboard / Read |
| | `mimecast_release_message` (**id**, confirm) - delivers the held message | Account / Monitoring / Held / Edit |
| | `mimecast_hold_message` (**id**, reason) - not available, see below | - |
| Threats | `mimecast_get_ttp_logs` (**type**: url, attachment, impersonation; from_date, to_date) | Monitoring / URL, Attachment or Impersonation Protection / Read |
| | `mimecast_get_threat_incidents` (type, search_field, search_value, from_date, to_date) | Services / Threat Remediation / Read |
| | `mimecast_get_audit_events` (from_date, to_date, categories, query) | Account / Logs / Read |
| Queues | `mimecast_get_queue_status` (from_date, to_date) | Account / Dashboard / Read |

**Bold** parameters are required. `mimecast_release_message` returns `{"done": false, ...}` until it
is called again with `confirm: true` after the user approved releasing that message.

Errors come back as a JSON envelope instead of an exception:

```json
{"error": {"code": "unauthorized", "message": "Mimecast rejected the client id / client secret (...)", "retryable": false}}
```

`code` is one of `not_configured`, `unauthorized`, `not_found`, `invalid_argument`,
`rate_limited`, `upstream_error`. Mimecast reports per-item failures inside an HTTP 200 response
(`fail`); those become the same envelope. Reads are retried with backoff on 429 (honouring
`X-RateLimit-Reset`), 5xx and network errors; a release only on 429, so it never runs twice. An
expired or revoked token is renewed once automatically.

## Run locally

```bash
uv sync
uv run python -m mimecast_mcp          # listens on 0.0.0.0:8080
```

or with Docker:

```bash
docker build --platform linux/amd64 -t mimecast-mcp:dev .
docker run --rm -p 8080:8080 mimecast-mcp:dev
```

Configuration (environment variables, all optional): `MCP_HTTP_HOST` (default `0.0.0.0`),
`MCP_HTTP_PORT` (default `8080`), `LOG_LEVEL` (default `INFO`). Credentials are never read
from the environment.

## Testing example

```bash
# list tools
curl -s http://localhost:8080/mcp \
  -H "Content-Type: application/json" \
  -H "Accept: application/json, text/event-stream" \
  -H "X-Mimecast-Client-ID: your-client-id" \
  -H "X-Mimecast-Client-Secret: your-client-secret" \
  -d '{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{}}'

# where did mail from a sender go today
curl -s http://localhost:8080/mcp \
  -H "Content-Type: application/json" \
  -H "Accept: application/json, text/event-stream" \
  -H "X-Mimecast-Client-ID: your-client-id" \
  -H "X-Mimecast-Client-Secret: your-client-secret" \
  -d '{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"mimecast_find_message","arguments":{"sender_address":"billing@example.org"}}}'
```

Unit tests (no network access needed):

```bash
uv run pytest
```

## Delivery notes

- **Tool names (10 earlier + 1 new).** The ten earlier names and their required parameters are
  unchanged. New: `mimecast_list_held_messages`, because releasing needs the held-message id, which
  only that list returns (message tracking ids are different).
- **API source.** The official Mimecast API 2.0 OpenAPI documents published on
  developer.services.mimecast.com (Email Security Cloud Gateway, Security Events, Audit Events,
  Threat Management) and its API Overview (token, pagination, regional gateways, rate limits).
- **Routes fixed.** Earlier versions called endpoints that do not exist in the API:
  `/api/gateway/release-message` (now `/api/gateway/hold-release`), `/api/gateway/get-queue-stats`
  (now `/api/email/get-email-queues`, which needs a time window: default the last hour) and
  `/api/ttp/remediation/get-incidents` (now `/api/ttp/remediation/find-incidents`, default the
  last 30 days).
- **Results fixed.** Message tracking and remediation results are nested in the response
  (`trackedEmails`, `incidents`); earlier versions returned the wrapper, so the count was always 1.
- **Message tracking filters** now use the API's fields: sender / recipient go to the advanced
  tracking options, `value` searches the subject (or is used as the internet message id when it
  looks like `<id@host>`), and `status` uses the tracking states. The earlier status names map to
  them: delivered = delivery + archived, blocked = rejected, failed = bounced, queued = delivery.
- **`mimecast_hold_message` is not available**: the API has no call that puts a message on hold
  (messages are held by policy). The tool stays for compatibility and returns `invalid_argument`
  pointing to the held-message list and to threat remediation in the console.
- **Removed**: the `status` filter of `mimecast_get_threat_incidents` (the API has no such field, so
  it never filtered); it is replaced by `type` (notify_only, automatic, manual, restore) and a
  search on code / file hash / reason. The incident `type` filter is sent as
  `{"fieldName": "type", "value": ...}`, the API's usual filter form; the reference's wording for
  this endpoint is ambiguous and it has not been checked against a live account.
- **Release needs confirmation** (`confirm: true`): releasing delivers mail that a policy held,
  possibly malicious.
- **Not included**: the message "card" UI resource of older versions (an MCP Apps HTML view); the
  tools return the same data as JSON. Credentials from environment variables are not supported:
  they would be shared by every caller.

## License

Apache License 2.0 - see [LICENSE](LICENSE) and [NOTICE](NOTICE).
