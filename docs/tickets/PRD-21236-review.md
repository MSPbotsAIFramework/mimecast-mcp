# PRD-21236 · Code review

## Round 1 · 2026-10-30 · reviewed dev/PRD-21236 @ 29044ef (base main @ 08e5f15)

Status: frozen @ 29044ef

Verdict: approved

### Scope

Reviewed `git diff 08e5f15...29044ef` in `MSPbotsAIFramework/mimecast-mcp`: new module
`src/mimecast_mcp/tools/policies.py` (3 tools), wiring in `navigation.py` / `server.py`,
7 new tests in `tests/test_api_client.py`, contract updates in `tests/test_tools.py`,
`README.md`, `pyproject.toml`, `uv.lock`, plus `docs/tickets/PRD-21236.md` /
`PRD-21236.ac.json`.

### Verification performed

- `uv sync && uv run pytest -q` on `29044ef`: 155 passed, 1 skipped (pre-existing,
  unrelated contract-baseline skip) — matches the Self-test section's claim exactly.
- `grep -rnP '[\x{4e00}-\x{9fff}]' --exclude-dir=.git --exclude-dir=.venv .`: no output
  (no Chinese in the repo).
- README "MSPbots Connector" section diffed against
  `vendor-mcp-development/reference/readme-connector-section.md`: content identical
  (only trailing blank-line/heading artifacts from my own `sed` extraction, not real
  differences).
- Ran the server locally (`MCP_HTTP_PORT=18123 uv run python -m mimecast_mcp`):
  `GET /health` → 200; `POST /mcp tools/list` with no `X-Mimecast-*` headers → 401
  before dispatch, matching TC9 and the gateway-isolation claim.
- Read `api_client.py`'s `call()` retry logic: the `mimecast_manage_sender` write uses
  `read=False`, so it is retried only on 429 (request never reached Mimecast) and never
  on 5xx/timeout — a write is never silently replayed after an ambiguous failure, same
  safety property as the existing `mimecast_release_message`.
- Confirmed `tests/contract_types.json` was correctly **not** extended for the 3 new
  tools (diverges from the Tech design's change-list item 5): that file holds only
  *previous*-version parameter types for backward-compatibility testing, and the repo's
  own prior addition (`mimecast_list_held_messages`) also has no entry. Self-test
  explains this divergence; it is a sound technical-design adjustment within flow ②'s
  discretion (`references/handoff.md` — tech design is dev's to adjust as long as
  user-visible behavior is unchanged), not a dropped requirement: no AC depends on
  `contract_types.json`, and `test_contract_types.py` skips tools/params it has no
  baseline entry for.

### Findings

None (0 must-fix, 0 suggestions).

Notes, not findings: the design's two non-blocking Open Questions (OQ1 `address-alteration`
policy type not shipped; OQ2 full policy CRUD out of scope) are reasonable blast-radius
decisions, documented in both the Product design and the README Delivery notes, and the
dev-added manual case (needs a real vendor account) is correctly recorded as `blocked`
with a reason rather than silently skipped or counted against the exit gate.

### Conclusion

Implementation matches the technical design and acceptance criteria; gates and all
10 design-authored test cases pass with verifiable evidence; no scope creep, no new
dependency, no credential handling issue, no migration (server is stateless). Approved
for merge into `main`.
