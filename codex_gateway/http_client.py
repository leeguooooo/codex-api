from __future__ import annotations

import asyncio
from typing import Any

import httpx

_clients: dict[str, httpx.AsyncClient] = {}
_lock = asyncio.Lock()
_HTTP2_OK: bool

try:
    import h2  # noqa: F401

    _HTTP2_OK = True
except Exception:
    _HTTP2_OK = False


async def get_async_client(name: str = "default") -> httpx.AsyncClient:
    async with _lock:
        client = _clients.get(name)
        if client is not None:
            return client
        limits = httpx.Limits(max_connections=50, max_keepalive_connections=20, keepalive_expiry=30.0)
        client = httpx.AsyncClient(http2=_HTTP2_OK, timeout=None, limits=limits)
        _clients[name] = client
        return client


async def aclose_all() -> None:
    async with _lock:
        clients = list(_clients.values())
        _clients.clear()
    for c in clients:
        try:
            await c.aclose()
        except Exception:
            pass


def _parse_retry_delay(resp: httpx.Response) -> float | None:
    """
    Parse Retry-After delay from response.
    Checks:
      1. Retry-After header (seconds or HTTP date)
      2. Gemini-style error body: error.details[].retryDelay (e.g. "0.847655010s")
    Returns delay in seconds or None.
    """
    # Check Retry-After header first
    retry_after = resp.headers.get("retry-after")
    if retry_after:
        try:
            return float(retry_after)
        except ValueError:
            pass  # Could be HTTP date, ignore for simplicity

    # Check Gemini-style error body for retryDelay
    try:
        body = resp.json() if resp.is_closed else None
        if body and isinstance(body, dict):
            details = body.get("error", {}).get("details", [])
            for detail in details:
                if detail.get("@type") == "type.googleapis.com/google.rpc.RetryInfo":
                    delay_str = detail.get("retryDelay", "")
                    if delay_str.endswith("s"):
                        return float(delay_str[:-1])
    except Exception:
        pass

    return None


async def request_json_with_retries(
    *,
    client: httpx.AsyncClient,
    method: str,
    url: str,
    timeout_s: float,
    retries: int = 2,
    backoff_s: float = 0.4,
    retry_statuses: set[int] | None = None,
    **kwargs: Any,
) -> httpx.Response:
    if retry_statuses is None:
        retry_statuses = {429, 500, 502, 503, 504}
    attempt = 0
    while True:
        attempt += 1
        try:
            resp = await client.request(method, url, timeout=timeout_s, **kwargs)
        except httpx.HTTPError:
            if attempt > retries + 1:
                raise
            await asyncio.sleep(backoff_s * (2 ** (attempt - 1)))
            continue
        if resp.status_code not in retry_statuses or attempt > retries + 1:
            return resp
        try:
            await resp.aread()
        except Exception:
            pass

        # Smart backoff: use Retry-After if available, otherwise exponential
        delay = _parse_retry_delay(resp)
        if delay is None:
            delay = backoff_s * (2 ** (attempt - 1))
        # Cap delay to avoid absurdly long waits
        delay = min(delay, 30.0)
        await asyncio.sleep(delay)
