from __future__ import annotations

import json
import time
from collections.abc import AsyncIterator
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .config import settings
from .http_client import get_async_client, request_json_with_retries
from .openai_compat import ChatCompletionRequest, ChatMessage

_ANTHROPIC_VERSION = "2023-06-01"
_DEFAULT_OAUTH_CLIENT_ID = "9d1c250a-e61b-44d9-88ed-5944d1962f5e"


@dataclass(frozen=True)
class ClaudeOAuthCreds:
    access_token: str | None
    refresh_token: str | None
    expires_at_s: int | None
    token_type: str | None


def _load_creds(path: Path) -> ClaudeOAuthCreds:
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return ClaudeOAuthCreds(None, None, None, None)
    if not isinstance(raw, dict):
        return ClaudeOAuthCreds(None, None, None, None)
    access_token = raw.get("access_token")
    refresh_token = raw.get("refresh_token")
    expires_at_s = raw.get("expires_at_s")
    token_type = raw.get("token_type")
    return ClaudeOAuthCreds(
        access_token if isinstance(access_token, str) else None,
        refresh_token if isinstance(refresh_token, str) else None,
        int(expires_at_s) if isinstance(expires_at_s, (int, float)) else None,
        token_type if isinstance(token_type, str) else None,
    )


def _save_creds(path: Path, creds: ClaudeOAuthCreds) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    payload: dict[str, Any] = {}
    if creds.access_token:
        payload["access_token"] = creds.access_token
    if creds.refresh_token:
        payload["refresh_token"] = creds.refresh_token
    if creds.expires_at_s is not None:
        payload["expires_at_s"] = int(creds.expires_at_s)
    if creds.token_type:
        payload["token_type"] = creds.token_type
    path.write_text(json.dumps(payload, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    try:
        path.chmod(0o600)
    except Exception:
        pass


def _is_expired(expires_at_s: int | None, *, skew_s: int = 90) -> bool:
    if not expires_at_s:
        return True
    return expires_at_s <= int(time.time()) + skew_s


async def _refresh_access_token(
    *,
    refresh_token: str,
    oauth_client_id: str,
    base_url: str,
    timeout_s: int,
) -> ClaudeOAuthCreds:
    url = f"{base_url.rstrip('/')}/v1/oauth/token"
    payload = {
        "client_id": oauth_client_id,
        "grant_type": "refresh_token",
        "refresh_token": refresh_token,
    }
    client = await get_async_client("claude-oauth")
    resp = await request_json_with_retries(
        client=client,
        method="POST",
        url=url,
        timeout_s=timeout_s,
        json=payload,
        headers={"Accept": "application/json"},
    )
    resp.raise_for_status()
    data = resp.json()
    if not isinstance(data, dict):
        raise ValueError("Claude OAuth refresh: invalid JSON response")
    access_token = data.get("access_token")
    new_refresh = data.get("refresh_token") or refresh_token
    expires_in = data.get("expires_in")
    token_type = data.get("token_type") or "Bearer"
    if not isinstance(access_token, str) or not access_token:
        raise ValueError("Claude OAuth refresh: missing access_token")
    expires_at_s = None
    if isinstance(expires_in, (int, float)) and expires_in > 0:
        expires_at_s = int(time.time() + int(expires_in))
    return ClaudeOAuthCreds(access_token, str(new_refresh), expires_at_s, str(token_type))


async def maybe_refresh_claude_oauth(creds_path: str) -> ClaudeOAuthCreds:
    path = Path(creds_path).expanduser()
    creds = _load_creds(path)
    if creds.access_token and not _is_expired(creds.expires_at_s):
        return creds
    if not creds.refresh_token:
        return creds

    oauth_client_id = settings.claude_oauth_client_id or _DEFAULT_OAUTH_CLIENT_ID
    base_url = settings.claude_oauth_base_url
    refreshed = await _refresh_access_token(
        refresh_token=creds.refresh_token,
        oauth_client_id=oauth_client_id,
        base_url=base_url,
        timeout_s=settings.timeout_seconds,
    )
    _save_creds(path, refreshed)
    return refreshed


def _parse_data_url(data_url: str) -> tuple[str, str] | None:
    # data:<mime>;base64,<payload>
    if not data_url.startswith("data:"):
        return None
    header, _, b64 = data_url.partition(",")
    if not b64:
        return None
    if ";base64" not in header:
        return None
    mime = header[5:].split(";", 1)[0].strip() or "application/octet-stream"
    return mime, b64


def _content_to_anthropic_blocks(content: object) -> list[dict[str, Any]]:
    if isinstance(content, str):
        text = content.strip()
        return [{"type": "text", "text": text}] if text else []
    if not isinstance(content, list):
        return []

    blocks: list[dict[str, Any]] = []
    for item in content:
        if not isinstance(item, dict):
            continue
        t = item.get("type")
        if t == "text":
            text = item.get("text")
            if isinstance(text, str) and text.strip():
                blocks.append({"type": "text", "text": text})
        elif t == "image_url":
            image_url = item.get("image_url")
            if isinstance(image_url, dict):
                url = image_url.get("url")
            else:
                url = None
            if not isinstance(url, str):
                continue
            parsed = _parse_data_url(url)
            if not parsed:
                continue
            mime, b64 = parsed
            if len(b64) > settings.max_image_bytes * 2:
                continue
            blocks.append(
                {
                    "type": "image",
                    "source": {"type": "base64", "media_type": mime, "data": b64},
                }
            )
    return blocks


def _openai_messages_to_anthropic(req: ChatCompletionRequest) -> tuple[str | None, list[dict[str, Any]]]:
    system_parts: list[str] = []
    out: list[dict[str, Any]] = []

    for msg in req.messages:
        if not isinstance(msg, ChatMessage):
            continue
        role = (msg.role or "").strip()
        blocks = _content_to_anthropic_blocks(getattr(msg, "content", None))

        if role == "system":
            for b in blocks:
                if b.get("type") == "text":
                    system_parts.append(str(b.get("text") or ""))
            continue

        if role not in {"user", "assistant"}:
            continue
        if not blocks:
            continue
        out.append({"role": role, "content": blocks})

    system = "\n\n".join([p for p in (s.strip() for s in system_parts) if p]) or None
    return system, out


def _extract_text_from_anthropic_response(data: Any) -> str:
    if not isinstance(data, dict):
        return ""
    content = data.get("content")
    if isinstance(content, list):
        parts: list[str] = []
        for item in content:
            if isinstance(item, dict) and item.get("type") == "text":
                t = item.get("text")
                if isinstance(t, str):
                    parts.append(t)
        return "".join(parts)
    return ""


def _extract_usage_from_anthropic_response(data: Any) -> dict[str, int] | None:
    if not isinstance(data, dict):
        return None
    usage = data.get("usage")
    if not isinstance(usage, dict):
        return None
    in_tokens = int(usage.get("input_tokens") or 0)
    out_tokens = int(usage.get("output_tokens") or 0)
    return {"prompt_tokens": in_tokens, "completion_tokens": out_tokens, "total_tokens": in_tokens + out_tokens}


async def generate_oauth(
    *,
    req: ChatCompletionRequest,
    model_name: str,
) -> tuple[str, dict[str, int] | None]:
    creds = await maybe_refresh_claude_oauth(settings.claude_oauth_creds_path)
    if not creds.access_token:
        raise RuntimeError("Claude OAuth: missing access_token (set up OAuth credentials first)")

    system, messages = _openai_messages_to_anthropic(req)
    max_tokens = int(req.max_tokens or 1024)
    payload: dict[str, Any] = {
        "model": model_name,
        "max_tokens": max_tokens,
        "messages": messages,
    }
    if system:
        payload["system"] = system

    headers = {
        "Authorization": f"Bearer {creds.access_token}",
        "anthropic-version": _ANTHROPIC_VERSION,
        "Accept": "application/json",
    }
    url = f"{settings.claude_api_base_url.rstrip('/')}/v1/messages"
    client = await get_async_client("claude")
    resp = await request_json_with_retries(
        client=client,
        method="POST",
        url=url,
        timeout_s=settings.timeout_seconds,
        json=payload,
        headers=headers,
    )
    resp.raise_for_status()
    data = resp.json()

    return _extract_text_from_anthropic_response(data), _extract_usage_from_anthropic_response(data)


async def _iter_sse_events(resp: httpx.Response) -> AsyncIterator[tuple[str | None, str]]:
    event: str | None = None
    data_lines: list[str] = []
    async for line in resp.aiter_lines():
        if line is None:
            continue
        if line.startswith(":"):
            continue
        if not line.strip():
            if data_lines:
                yield event, "\n".join(data_lines)
            event = None
            data_lines = []
            continue
        if line.startswith("event:"):
            event = line[len("event:") :].strip() or None
            continue
        if line.startswith("data:"):
            data_lines.append(line[len("data:") :].lstrip())
            continue
    if data_lines:
        yield event, "\n".join(data_lines)


def _extract_delta_text(obj: Any) -> str:
    if not isinstance(obj, dict):
        return ""
    delta = obj.get("delta")
    if isinstance(delta, dict):
        t = delta.get("text")
        if isinstance(t, str) and t:
            return t
    t2 = obj.get("text")
    if isinstance(t2, str) and t2:
        return t2
    content_block = obj.get("content_block")
    if isinstance(content_block, dict):
        t3 = content_block.get("text")
        if isinstance(t3, str) and t3:
            return t3
    message = obj.get("message")
    if isinstance(message, dict):
        return _extract_text_from_anthropic_response(message)
    return ""


def _extract_stream_usage(obj: Any) -> dict[str, int] | None:
    if not isinstance(obj, dict):
        return None
    if "usage" in obj:
        return _extract_usage_from_anthropic_response(obj)
    msg = obj.get("message")
    if isinstance(msg, dict):
        return _extract_usage_from_anthropic_response(msg)
    return None


async def iter_oauth_stream_events(
    *,
    req: ChatCompletionRequest,
    model_name: str,
) -> AsyncIterator[dict]:
    creds = await maybe_refresh_claude_oauth(settings.claude_oauth_creds_path)
    if not creds.access_token:
        raise RuntimeError("Claude OAuth: missing access_token (set up OAuth credentials first)")

    system, messages = _openai_messages_to_anthropic(req)
    max_tokens = int(req.max_tokens or 1024)
    payload: dict[str, Any] = {
        "model": model_name,
        "max_tokens": max_tokens,
        "messages": messages,
        "stream": True,
    }
    if system:
        payload["system"] = system

    headers = {
        "Authorization": f"Bearer {creds.access_token}",
        "anthropic-version": _ANTHROPIC_VERSION,
        "Accept": "text/event-stream",
    }
    url = f"{settings.claude_api_base_url.rstrip('/')}/v1/messages"

    usage: dict[str, int] | None = None
    client = await get_async_client("claude-stream")
    async with client.stream("POST", url, json=payload, headers=headers, timeout=settings.timeout_seconds) as resp:
        resp.raise_for_status()
        async for _, data in _iter_sse_events(resp):
                if not data or data.strip() == "[DONE]":
                    continue
                try:
                    obj = json.loads(data)
                except Exception:
                    continue
                delta = _extract_delta_text(obj)
                if delta:
                    yield {
                        "type": "assistant",
                        "message": {"role": "assistant", "content": [{"type": "text", "text": delta}]},
                    }
                maybe_usage = _extract_stream_usage(obj)
                if maybe_usage:
                    usage = maybe_usage

    if usage:
        yield {"type": "result", "usage": {"input_tokens": usage["prompt_tokens"], "output_tokens": usage["completion_tokens"]}}
