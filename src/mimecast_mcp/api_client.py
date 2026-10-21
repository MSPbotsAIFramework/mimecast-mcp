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
"""Async client for the Mimecast API 2.0 (OAuth 2.0 client credentials, JSON POST endpoints)."""

import asyncio
import hashlib
import logging
import time
from dataclasses import dataclass
from http.cookiejar import CookieJar, DefaultCookiePolicy
from typing import Any

import httpx

from ._json import error_envelope

logger = logging.getLogger("mimecast_mcp.api")

_TIMEOUT = httpx.Timeout(connect=5.0, read=30.0, write=10.0, pool=5.0)
_MAX_RETRIES = 3
_MAX_BACKOFF_SECONDS = 20.0
# Whole-call budget including retries; the gateway times a tool call out at 120s.
_CALL_BUDGET_SECONDS = 100.0
# Tokens live 30 minutes; refresh a little early.
_TOKEN_MARGIN_SECONDS = 120.0

# One connection pool for the process. It never holds credentials: the
# Authorization header is set per request.
_shared_http_client: httpx.AsyncClient | None = None


class _RejectAllCookies(DefaultCookiePolicy):
    """Never store or send a cookie: the HTTP client is shared by every tenant."""

    def set_ok(self, cookie, request) -> bool:  # noqa: ANN001 - stdlib signature
        return False

    def return_ok(self, cookie, request) -> bool:  # noqa: ANN001 - stdlib signature
        return False


def _no_cookies() -> CookieJar:
    # A plain CookieJar: httpx uses it as is (an httpx.Cookies would be copied into a default jar).
    return CookieJar(policy=_RejectAllCookies())


def _get_shared_http_client() -> httpx.AsyncClient:
    global _shared_http_client
    if _shared_http_client is None:
        _shared_http_client = httpx.AsyncClient(cookies=_no_cookies(), timeout=_TIMEOUT, follow_redirects=False)
    return _shared_http_client


# Access tokens by sha256(host, client id, client secret). Only the derived
# token is kept, never the secret, and a different secret never reuses a token.
_token_cache: dict[str, tuple[str, float]] = {}
_MAX_CACHED_TOKENS = 1000


# status_code -> (error code, retryable). 0 means no HTTP response at all
# (connection error or timeout).
_STATUS_TO_CODE: dict[int, tuple[str, bool]] = {
    0: ("upstream_error", True),
    400: ("invalid_argument", False),
    401: ("unauthorized", False),
    403: ("unauthorized", False),
    404: ("not_found", False),
    409: ("invalid_argument", False),
    422: ("invalid_argument", False),
    429: ("rate_limited", True),
}


def classify_status(status_code: int) -> tuple[str, bool]:
    if status_code in _STATUS_TO_CODE:
        return _STATUS_TO_CODE[status_code]
    if status_code >= 500:
        return "upstream_error", True
    if status_code >= 400:
        return "invalid_argument", False
    return "upstream_error", True


class MimecastError(Exception):
    def __init__(self, status_code: int, message: str):
        self.status_code = status_code
        self.message = message
        super().__init__(f"Mimecast API error {status_code}: {message}")

    def to_envelope(self) -> str:
        code, retryable = classify_status(self.status_code)
        return error_envelope(code, self.message, retryable)


@dataclass(frozen=True)
class MimecastCredentials:
    client_id: str
    client_secret: str
    host: str
    # Set when a header value is malformed: tools then return invalid_argument
    # instead of calling Mimecast, while tools/list still works.
    header_error: str | None = None

    def __repr__(self) -> str:  # never leak the secret into logs or tracebacks
        return f"MimecastCredentials(host={self.host!r}, client_id={self.client_id!r}, client_secret=<redacted>)"

    def cache_key(self) -> str:
        return hashlib.sha256(f"{self.host}\0{self.client_id}\0{self.client_secret}".encode()).hexdigest()


@dataclass
class Page:
    data: list[Any]
    next_token: str | None


class MimecastClient:
    """Thin wrapper over the Mimecast API 2.0 for one caller's application credentials."""

    def __init__(self, credentials: MimecastCredentials, http_client: httpx.AsyncClient | None = None):
        self._credentials = credentials
        self._http = http_client
        self.header_error = credentials.header_error
        self.host = credentials.host
        self.base_url = f"https://{credentials.host}"

    def _http_client(self) -> httpx.AsyncClient:
        return self._http or _get_shared_http_client()

    async def token(self, force: bool = False) -> str:
        key = self._credentials.cache_key()
        cached = _token_cache.get(key)
        if cached and not force and cached[1] > time.monotonic():
            return cached[0]
        token, ttl = await self._fetch_token()
        if len(_token_cache) >= _MAX_CACHED_TOKENS:
            _token_cache.clear()
        _token_cache[key] = (token, time.monotonic() + max(60.0, ttl - _TOKEN_MARGIN_SECONDS))
        return token

    async def _fetch_token(self) -> tuple[str, float]:
        form = {
            "grant_type": "client_credentials",
            "client_id": self._credentials.client_id,
            "client_secret": self._credentials.client_secret,
        }
        attempt = 0
        while True:
            try:
                resp = await self._http_client().post(f"{self.base_url}/oauth/token", data=form, headers={"Accept": "application/json"})
            except httpx.TimeoutException:
                raise MimecastError(0, "Timed out getting a Mimecast access token") from None
            except httpx.RequestError as e:
                raise MimecastError(0, f"Network error getting a Mimecast access token: {type(e).__name__}") from None
            logger.info("mimecast_api method=POST path=/oauth/token status=%s attempt=%d", resp.status_code, attempt)
            if (resp.status_code == 429 or resp.status_code >= 500) and attempt < _MAX_RETRIES:
                attempt += 1
                await asyncio.sleep(_retry_delay(resp, attempt - 1))
                continue
            if resp.status_code in (400, 401, 403):
                raise MimecastError(401, f"Mimecast rejected the client id / client secret ({_error_message(resp, '/oauth/token')})")
            if resp.status_code >= 400:
                raise MimecastError(resp.status_code, _error_message(resp, "/oauth/token"))
            try:
                payload = resp.json()
                return str(payload["access_token"]), float(payload.get("expires_in") or 1800)
            except (ValueError, KeyError, TypeError):
                raise MimecastError(502, "Mimecast returned no access token") from None

    async def call(
        self,
        path: str,
        data: list[dict[str, Any]] | None = None,
        *,
        read: bool = True,
        page_size: int | None = None,
        page_token: str | None = None,
    ) -> Page:
        """POST ``{"meta": {...}, "data": data}`` to ``path``.

        Mimecast reports per-item failures in ``fail`` with HTTP 200; when nothing
        succeeded they become a MimecastError.
        """
        body: dict[str, Any] = {"data": data if data is not None else []}
        pagination = {k: v for k, v in (("pageSize", page_size), ("pageToken", page_token)) if v}
        if pagination:
            body["meta"] = {"pagination": pagination}

        url = f"{self.base_url}{path}"
        started = time.monotonic()
        attempt = 0
        refreshed = False
        while True:
            t0 = time.monotonic()
            resp: httpx.Response | None = None
            error: MimecastError | None = None
            token = await self.token()
            try:
                resp = await self._http_client().post(
                    url,
                    json=body,
                    headers={"Authorization": f"Bearer {token}", "Accept": "application/json", "User-Agent": "MSPbotsMimecastMCP/1.0"},
                )
                status = resp.status_code
            except httpx.TimeoutException:
                status, error = 0, MimecastError(0, f"Timed out calling Mimecast ({path})")
            except httpx.RequestError as e:
                status, error = 0, MimecastError(0, f"Network error calling Mimecast ({path}): {type(e).__name__}")

            logger.info("mimecast_api method=POST path=%s status=%s ms=%d attempt=%d", path, status, (time.monotonic() - t0) * 1000, attempt)

            if status == 401 and not refreshed:
                # The cached token may have been revoked or expired early.
                refreshed = True
                await self.token(force=True)
                continue

            # 429 is refused before processing, so any call may retry it; other
            # failures are retried only for reads, so a change never runs twice.
            retryable = status == 429 or (read and (status == 0 or status >= 500))
            if retryable and attempt < _MAX_RETRIES:
                delay = _retry_delay(resp, attempt)
                if time.monotonic() - started + delay < _CALL_BUDGET_SECONDS:
                    attempt += 1
                    await asyncio.sleep(delay)
                    continue
            if error is not None:
                raise error
            assert resp is not None
            if resp.status_code >= 400:
                raise MimecastError(resp.status_code, _error_message(resp, path))
            try:
                payload = resp.json() if resp.content.strip() else {}
            except ValueError:
                raise MimecastError(502, f"Mimecast returned a non-JSON response for {path}") from None
            payload = payload if isinstance(payload, dict) else {"data": payload}
            rows = payload.get("data")
            rows = rows if isinstance(rows, list) else ([] if rows is None else [rows])
            failures = payload.get("fail") or []
            if failures and not rows:
                raise _failure_error(failures, path)
            pagination_meta = (payload.get("meta") or {}).get("pagination") or {}
            return Page(rows, pagination_meta.get("next") or None)


def _failure_error(failures: list[Any], path: str) -> MimecastError:
    messages: list[str] = []
    codes: list[str] = []
    for item in failures:
        for err in (item.get("errors") if isinstance(item, dict) else None) or []:
            if isinstance(err, dict):
                codes.append(str(err.get("code") or ""))
                messages.append(str(err.get("message") or err.get("code") or "error"))
    text = "; ".join(messages)[:500] or "request failed"
    joined = " ".join(codes).lower()
    if any(word in joined for word in ("not_found", "no_record", "not_exist", "unknown_id")):
        status = 404
    elif any(word in joined for word in ("access_denied", "forbidden", "permission", "unauthori")):
        status = 403
    elif "rate" in joined:
        status = 429
    else:
        status = 400
    return MimecastError(status, f"Mimecast could not process {path}: {text}")


def _retry_delay(resp: httpx.Response | None, attempt: int) -> float:
    if resp is not None:
        reset_ms = resp.headers.get("X-RateLimit-Reset")
        if reset_ms:
            try:
                return max(0.0, min(float(reset_ms) / 1000.0, _MAX_BACKOFF_SECONDS))
            except ValueError:
                pass
        retry_after = resp.headers.get("Retry-After")
        if retry_after:
            try:
                return max(0.0, min(float(retry_after), _MAX_BACKOFF_SECONDS))
            except ValueError:
                pass
    return min(float(2**attempt), _MAX_BACKOFF_SECONDS)


def _error_message(resp: httpx.Response, path: str) -> str:
    fallback = f"Mimecast returned HTTP {resp.status_code} for {path}"
    try:
        payload = resp.json()
    except ValueError:
        text = resp.text.strip()
        if text.lower().startswith("<"):
            return fallback  # an HTML error page, not useful to the agent
        return f"{fallback}: {text[:300]}" if text else fallback
    if isinstance(payload, dict):
        for item in payload.get("fail") or []:
            if isinstance(item, dict):
                errors = item.get("errors") or [item]
                text = "; ".join(str(e.get("message") or e.get("code")) for e in errors if isinstance(e, dict))
                if text:
                    return f"{fallback}: {text[:500]}"
        message = payload.get("error_description") or payload.get("message") or payload.get("error")
        if isinstance(message, dict):
            message = message.get("message")
        if message:
            return f"{fallback}: {str(message)[:500]}"
    return fallback
