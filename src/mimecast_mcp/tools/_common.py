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
"""Shared argument types, date handling, paging and the error-handling wrapper."""

import logging
import time
from collections.abc import Awaitable, Callable
from datetime import UTC, datetime, timedelta
from typing import Annotated, Any

from mcp.types import ToolAnnotations
from pydantic import Field

from .._json import dump_json_capped, error_envelope
from ..api_client import MimecastClient, MimecastError, Page
from ..config import MAX_PAGE_SIZE

logger = logging.getLogger("mimecast_mcp.tools")

ClientFactory = Callable[[], MimecastClient | None]

READ_ONLY = ToolAnnotations(readOnlyHint=True, idempotentHint=True, openWorldHint=True)
LOCAL = ToolAnnotations(readOnlyHint=True, idempotentHint=True, openWorldHint=False)
WRITES = ToolAnnotations(readOnlyHint=False, destructiveHint=False, idempotentHint=True, openWorldHint=True)

NOT_CONFIGURED = error_envelope(
    "not_configured", "Mimecast credentials are missing for this request (X-Mimecast-Client-ID / X-Mimecast-Client-Secret).", False
)

DEFAULT_PAGE_SIZE = 50
PageSize = Annotated[int | None, Field(description=f"Results per page (default {DEFAULT_PAGE_SIZE}, max {MAX_PAGE_SIZE}).", ge=1, le=MAX_PAGE_SIZE)]
PageToken = Annotated[str | None, Field(description="next_page_token from the previous page.")]
DATE_HINT = "ISO 8601 with a zone, e.g. 2026-03-01T00:00:00Z or 2026-03-01T00:00:00+0000"
FromDate = Annotated[str | None, Field(description=f"Start, {DATE_HINT}.")]
ToDate = Annotated[str | None, Field(description=f"End, {DATE_HINT}.")]


def compact(values: dict[str, Any]) -> dict[str, Any]:
    return {k: v for k, v in values.items() if v is not None and v != "" and v != [] and v != {}}


def parse_datetime(value: str, name: str) -> datetime:
    """A zone-aware datetime from ISO 8601 (Z, +00:00 or +0000); a bare date is midnight UTC."""
    text = value.strip()
    if len(text) == 10:
        text += "T00:00:00Z"
    if text.endswith(("Z", "z")):
        text = text[:-1] + "+00:00"
    elif len(text) >= 5 and text[-5] in "+-" and text[-4:].isdigit() and text[-3] != ":":
        text = f"{text[:-2]}:{text[-2:]}"
    try:
        parsed = datetime.fromisoformat(text)
    except ValueError:
        raise ValueError(f"{name} is not a valid date-time; use {DATE_HINT}.") from None
    if parsed.tzinfo is None:
        raise ValueError(f"{name} needs a time zone (Z or an offset); use {DATE_HINT}.")
    return parsed.astimezone(UTC)


def mimecast_time(value: datetime) -> str:
    """Mimecast's date-time format: yyyy-MM-dd'T'HH:mm:ss+0000."""
    return value.astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%S+0000")


def optional_time(value: str | None, name: str) -> str | None:
    if value is None or not value.strip():
        return None
    return mimecast_time(parse_datetime(value, name))


def window(
    from_date: str | None,
    to_date: str | None,
    default: timedelta,
    max_age: timedelta | None = None,
    now: datetime | None = None,
) -> tuple[str, str]:
    """(start, end) in Mimecast format; end defaults to now, start to end - default."""
    now = now or datetime.now(UTC)
    end = parse_datetime(to_date, "to_date") if to_date and to_date.strip() else now
    start = parse_datetime(from_date, "from_date") if from_date and from_date.strip() else end - default
    if end < start:
        raise ValueError(f"to_date {mimecast_time(end)} is before from_date {mimecast_time(start)}.")
    if max_age is not None and start < now - max_age:
        raise ValueError(f"from_date {mimecast_time(start)} is older than Mimecast keeps ({max_age.days} days); narrow it.")
    return mimecast_time(start), mimecast_time(end)


def listing(rows: list[Any], key: str, page: Page, **extra: Any) -> dict:
    return compact({key: rows, "count": len(rows), "has_more": bool(page.next_token), "next_page_token": page.next_token} | extra)


def first(page: Page) -> dict:
    """Mimecast nests one result object inside ``data``; return it (or {})."""
    item = page.data[0] if page.data else {}
    return item if isinstance(item, dict) else {}


async def run_tool(
    name: str,
    client_factory: ClientFactory,
    action: Callable[[MimecastClient], Awaitable[Any]],
) -> str:
    """Resolve the caller's client, run ``action``, and always return a string.

    Errors never escape as exceptions: they become the standard error envelope.
    """
    client = client_factory()
    if client is None:
        return NOT_CONFIGURED
    if client.header_error:
        return error_envelope("invalid_argument", client.header_error, False)
    started = time.monotonic()
    try:
        value = await action(client)
    except MimecastError as e:
        logger.info("tool=%s outcome=error status=%s ms=%d", name, e.status_code, _ms(started))
        return e.to_envelope()
    except ValueError as e:
        logger.info("tool=%s outcome=invalid_argument ms=%d", name, _ms(started))
        return error_envelope("invalid_argument", str(e), False)
    except Exception as e:  # noqa: BLE001 - tools must never raise
        logger.warning("tool=%s outcome=unexpected error=%s ms=%d", name, type(e).__name__, _ms(started))
        return error_envelope("upstream_error", f"Unexpected error: {type(e).__name__}", True)
    logger.info("tool=%s outcome=ok ms=%d", name, _ms(started))
    if value is None:
        value = {"done": True}
    return value if isinstance(value, str) else dump_json_capped(value)


def _ms(started: float) -> int:
    return int((time.monotonic() - started) * 1000)
