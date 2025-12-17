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
        await asyncio.sleep(backoff_s * (2 ** (attempt - 1)))
