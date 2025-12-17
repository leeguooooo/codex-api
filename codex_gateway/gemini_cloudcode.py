from __future__ import annotations

import base64
import json
import re
import shutil
import time
from collections.abc import AsyncIterator, Callable
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .config import settings
from .http_client import get_async_client, request_json_with_retries
from .openai_compat import ChatCompletionRequest, ChatMessage


@dataclass(frozen=True)
class GeminiOAuthCreds:
    access_token: str | None
    refresh_token: str | None
    expiry_date_ms: int | None
    token_type: str | None
    scope: str | None
    project_id: str | None


_OAUTH_CLIENT_ID_RE = re.compile(rb"[0-9]{6,}-[a-z0-9]{10,}\.apps\.googleusercontent\.com")
_OAUTH_CLIENT_SECRET_RE = re.compile(rb"GOCSPX-[A-Za-z0-9_-]{10,}")
_CACHED_OAUTH_CLIENT: tuple[str, str] | None = None


def _scan_bytes_for_oauth_client(data: bytes) -> tuple[str | None, str | None]:
    cid = None
    sec = None
    m1 = _OAUTH_CLIENT_ID_RE.search(data)
    if m1:
        cid = m1.group(0).decode("ascii", errors="ignore")
    m2 = _OAUTH_CLIENT_SECRET_RE.search(data)
    if m2:
        sec = m2.group(0).decode("ascii", errors="ignore")
    return cid, sec


def _scan_file_for_oauth_client(path: Path) -> tuple[str | None, str | None]:
    try:
        data = path.read_bytes()
    except Exception:
        return None, None
    return _scan_bytes_for_oauth_client(data)


def _scan_gemini_install_for_oauth_client(entrypoint: Path) -> tuple[str | None, str | None]:
    """
    Try to find the Gemini CLI OAuth client id/secret from the installed gemini-cli package.
    Homebrew layout example:
      .../Cellar/gemini-cli/<ver>/libexec/lib/node_modules/@google/gemini-cli-core/.../oauth2.js
    """
    entrypoint = entrypoint.resolve()
    roots: list[Path] = []
    # Prefer a Homebrew-style package root that contains both `bin/` and `libexec/`.
    for parent in [entrypoint.parent, *entrypoint.parents]:
        if (parent / "bin").exists() and (parent / "libexec").exists():
            roots.append(parent)
            break
    roots.append(entrypoint.parent)

    candidates: list[Path] = []
    for root in roots:
        candidates.extend(
            [
                root
                / "libexec/lib/node_modules/@google/gemini-cli/node_modules/@google/gemini-cli-core/dist/src/code_assist/oauth2.js",
                root / "libexec/lib/node_modules/@google/gemini-cli-core/dist/src/code_assist/oauth2.js",
                root / "lib/node_modules/@google/gemini-cli-core/dist/src/code_assist/oauth2.js",
            ]
        )

    for c in candidates:
        if c.exists() and c.is_file():
            cid, sec = _scan_file_for_oauth_client(c)
            if cid and sec:
                return cid, sec

    # Fallback: shallow search under likely package roots (bounded).
    for root in roots:
        pkg_root = root / "libexec/lib/node_modules"
        if not pkg_root.exists():
            pkg_root = root / "lib/node_modules"
        if not pkg_root.exists():
            continue
        scanned = 0
        try:
            for p in pkg_root.rglob("oauth2.js"):
                scanned += 1
                if scanned > 2000:
                    break
                if p.is_file():
                    cid, sec = _scan_file_for_oauth_client(p)
                    if cid and sec:
                        return cid, sec
        except Exception:
            continue

    return None, None


def resolve_gemini_oauth_client() -> tuple[str, str]:
    """
    Resolve the OAuth client id/secret used to refresh Gemini CLI tokens.
    Priority:
      1) env `GEMINI_OAUTH_CLIENT_ID` / `GEMINI_OAUTH_CLIENT_SECRET`
      2) auto-detect by scanning the installed `gemini` CLI binary
    """
    global _CACHED_OAUTH_CLIENT
    if _CACHED_OAUTH_CLIENT:
        return _CACHED_OAUTH_CLIENT

    if settings.gemini_oauth_client_id and settings.gemini_oauth_client_secret:
        _CACHED_OAUTH_CLIENT = (settings.gemini_oauth_client_id, settings.gemini_oauth_client_secret)
        return _CACHED_OAUTH_CLIENT

    bin_path = shutil.which(settings.gemini_bin) or settings.gemini_bin
    try:
        p = Path(bin_path)
        if not p.exists():
            raise FileNotFoundError(bin_path)
        found_id, found_secret = _scan_gemini_install_for_oauth_client(p)
    except Exception as e:
        raise RuntimeError(
            "Gemini OAuth client credentials are missing and auto-detection failed. "
            "Set GEMINI_OAUTH_CLIENT_ID / GEMINI_OAUTH_CLIENT_SECRET."
        ) from e

    if not found_id or not found_secret:
        raise RuntimeError(
            "Gemini OAuth client credentials are missing and could not be detected from `gemini` binary. "
            "Set GEMINI_OAUTH_CLIENT_ID / GEMINI_OAUTH_CLIENT_SECRET."
        )

    _CACHED_OAUTH_CLIENT = (found_id, found_secret)
    return _CACHED_OAUTH_CLIENT


def _load_oauth_creds(path: str) -> GeminiOAuthCreds:
    p = Path(path).expanduser()
    try:
        raw = json.loads(p.read_text(encoding="utf-8"))
    except Exception:
        raw = {}
    if not isinstance(raw, dict):
        raw = {}

    def _get_str(name: str) -> str | None:
        v = raw.get(name)
        if isinstance(v, str) and v.strip():
            return v.strip()
        return None

    expiry = raw.get("expiry_date")
    expiry_ms: int | None = None
    if isinstance(expiry, (int, float)):
        expiry_ms = int(expiry)

    return GeminiOAuthCreds(
        access_token=_get_str("access_token"),
        refresh_token=_get_str("refresh_token"),
        expiry_date_ms=expiry_ms,
        token_type=_get_str("token_type"),
        scope=_get_str("scope"),
        project_id=_get_str("project_id") or _get_str("projectId"),
    )


def load_gemini_creds(path: str | Path) -> GeminiOAuthCreds:
    return _load_oauth_creds(str(path))


def _is_expired(expiry_date_ms: int | None, *, skew_seconds: int = 60) -> bool:
    if not expiry_date_ms:
        return True
    now_ms = int(time.time() * 1000)
    return expiry_date_ms <= (now_ms + skew_seconds * 1000)


async def _refresh_access_token(
    *,
    refresh_token: str,
    timeout_seconds: int,
) -> dict[str, Any]:
    client_id, client_secret = resolve_gemini_oauth_client()
    data = {
        "client_id": client_id,
        "client_secret": client_secret,
        "grant_type": "refresh_token",
        "refresh_token": refresh_token,
    }
    client = await get_async_client("gemini-oauth")
    resp = await request_json_with_retries(
        client=client,
        method="POST",
        url="https://oauth2.googleapis.com/token",
        timeout_s=timeout_seconds,
        data=data,
        headers={"Accept": "application/json"},
    )
    resp.raise_for_status()
    obj = resp.json()
    if not isinstance(obj, dict):
        raise RuntimeError("Gemini OAuth refresh failed: invalid JSON response")
    return obj


async def get_gemini_access_token(*, timeout_seconds: int) -> str:
    creds_path = settings.gemini_oauth_creds_path
    creds = _load_oauth_creds(creds_path)
    if creds.access_token and not _is_expired(creds.expiry_date_ms):
        return creds.access_token
    if not creds.refresh_token:
        raise RuntimeError(
            f"Gemini OAuth refresh_token missing. Ensure Gemini CLI is logged in and `{creds_path}` exists."
        )

    token_resp = await _refresh_access_token(refresh_token=creds.refresh_token, timeout_seconds=timeout_seconds)
    access = token_resp.get("access_token")
    expires_in = token_resp.get("expires_in")
    if not isinstance(access, str) or not access.strip():
        raise RuntimeError("Gemini OAuth refresh failed: missing access_token")

    expiry_ms = None
    if isinstance(expires_in, (int, float)):
        expiry_ms = int(time.time() * 1000) + int(expires_in) * 1000

    # Best-effort persist back to the Gemini CLI creds file (no secrets logged).
    p = Path(creds_path).expanduser()
    try:
        raw = json.loads(p.read_text(encoding="utf-8"))
        if not isinstance(raw, dict):
            raw = {}
    except Exception:
        raw = {}
    raw["access_token"] = access.strip()
    if expiry_ms is not None:
        raw["expiry_date"] = expiry_ms
    # Keep existing refresh_token / scope / token_type / id_token.
    try:
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(json.dumps(raw, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    except Exception:
        pass

    return access.strip()


async def resolve_gemini_project_id(*, access_token: str, timeout_seconds: int) -> str:
    """
    Cloud Code Assist requires a valid GCP project id.
    Priority:
      1) GEMINI_PROJECT_ID env (operator-set)
      2) cached `project_id` in the Gemini OAuth creds json
      3) auto-select first ACTIVE project from Cloud Resource Manager
    """
    if settings.gemini_project_id:
        return settings.gemini_project_id

    creds_path = settings.gemini_oauth_creds_path
    creds = _load_oauth_creds(creds_path)
    if creds.project_id:
        return creds.project_id

    url = "https://cloudresourcemanager.googleapis.com/v1/projects?pageSize=10"
    headers = {"Authorization": f"Bearer {access_token}", "Accept": "application/json"}
    client = await get_async_client("gemini-cloudresourcemanager")
    resp = await request_json_with_retries(
        client=client,
        method="GET",
        url=url,
        timeout_s=timeout_seconds,
        headers=headers,
    )
    resp.raise_for_status()
    obj = resp.json()
    project_id: str | None = None
    if isinstance(obj, dict) and isinstance(obj.get("projects"), list):
        for item in obj["projects"]:
            if not isinstance(item, dict):
                continue
            if item.get("lifecycleState") != "ACTIVE":
                continue
            pid = item.get("projectId")
            if isinstance(pid, str) and pid.strip():
                project_id = pid.strip()
                break
    if not project_id:
        raise RuntimeError("gemini cloudcode: could not resolve a valid GCP project_id; set GEMINI_PROJECT_ID")

    # Best-effort cache into the creds file for faster future startups.
    p = Path(creds_path).expanduser()
    try:
        raw = json.loads(p.read_text(encoding="utf-8"))
        if not isinstance(raw, dict):
            raw = {}
    except Exception:
        raw = {}
    raw["project_id"] = project_id
    try:
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(json.dumps(raw, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    except Exception:
        pass

    return project_id


def _content_parts(content: Any) -> list[dict[str, Any]]:
    if content is None:
        return []
    if isinstance(content, str):
        return [{"type": "text", "text": content}]
    if isinstance(content, dict):
        return [content]
    if isinstance(content, list):
        return [p for p in content if isinstance(p, dict)]
    return [{"type": "text", "text": str(content)}]


def _decode_data_url(url: str) -> tuple[bytes, str]:
    # data:<mime>;base64,<payload>
    raw = (url or "").strip()
    if not raw.startswith("data:"):
        raise ValueError("image_url must be a data: URL for Gemini CloudCode mode")
    try:
        header, b64 = raw.split(",", 1)
    except ValueError as e:
        raise ValueError("invalid data URL") from e
    if ";base64" not in header:
        raise ValueError("data URL must be base64-encoded")
    mime = header[len("data:") :].split(";", 1)[0].strip().lower() or "application/octet-stream"
    data = base64.b64decode(b64, validate=False)
    return data, mime


def _messages_to_cloudcode_payload(
    messages: list[ChatMessage],
    *,
    project_id: str,
    model_name: str,
    reasoning_effort: str,
) -> dict[str, Any]:
    payload: dict[str, Any] = {"project": project_id, "request": {"contents": []}, "model": model_name}

    # Collapse all system/developer messages into a single systemInstruction block.
    sys_text_parts: list[str] = []
    for m in messages:
        if m.role in {"system", "developer"}:
            text = ""
            for part in _content_parts(m.content):
                if part.get("type") == "text" and isinstance(part.get("text"), str):
                    text += part["text"]
            if text.strip():
                sys_text_parts.append(text.strip())
    if sys_text_parts:
        payload["request"]["systemInstruction"] = {
            "role": "user",
            "parts": [{"text": "\n\n".join(sys_text_parts)}],
        }

    # Best-effort thinking budget mapping (compute only; do not ask for thought text).
    # Cloud Code Assist request schema evolves; keep this conservative to avoid 400s.
    # Only include thinking config when explicitly requesting >low effort.
    budget_map = {"medium": 1024, "high": 8192, "xhigh": 16384}
    budget = budget_map.get(reasoning_effort)
    if budget is not None:
        payload["request"].setdefault("generationConfig", {})
        payload["request"]["generationConfig"]["thinkingConfig"] = {
            "thinkingBudget": budget,
            "includeThoughts": False,
        }

    for m in messages:
        if m.role in {"system", "developer"}:
            continue
        role = "user" if m.role in {"user", "tool"} else "model"
        node: dict[str, Any] = {"role": role, "parts": []}
        for part in _content_parts(m.content):
            ptype = part.get("type")
            if ptype == "text" and isinstance(part.get("text"), str):
                node["parts"].append({"text": part["text"]})
                continue
            if ptype in {"image_url", "input_image"}:
                image = part.get("image_url")
                url = None
                if isinstance(image, dict) and isinstance(image.get("url"), str):
                    url = image["url"]
                elif isinstance(image, str):
                    url = image
                if not isinstance(url, str) or not url.strip():
                    continue
                data, mime = _decode_data_url(url)
                if settings.max_image_bytes > 0 and len(data) > settings.max_image_bytes:
                    raise ValueError(f"Image too large ({len(data)} bytes > {settings.max_image_bytes})")
                node["parts"].append(
                    {
                        "inlineData": {
                            "mime_type": mime,
                            "data": base64.b64encode(data).decode("ascii"),
                        }
                    }
                )
                continue
        if node["parts"]:
            payload["request"]["contents"].append(node)
    return payload


def _extract_text_from_cloudcode_response(obj: dict[str, Any]) -> str:
    # Cloud Code Assist wraps the Gemini response under a top-level `response` field.
    if isinstance(obj.get("response"), dict):
        obj = obj["response"]  # type: ignore[assignment]
    # Official Gemini format: candidates[0].content.parts[].text
    candidates = obj.get("candidates")
    if not isinstance(candidates, list) or not candidates:
        return ""
    content = (candidates[0] or {}).get("content")
    if not isinstance(content, dict):
        return ""
    parts = content.get("parts")
    if not isinstance(parts, list):
        return ""
    out: list[str] = []
    for p in parts:
        if isinstance(p, dict) and isinstance(p.get("text"), str):
            out.append(p["text"])
    return "".join(out)


def _extract_usage_from_cloudcode_response(obj: dict[str, Any]) -> dict[str, int] | None:
    if isinstance(obj.get("response"), dict):
        obj = obj["response"]  # type: ignore[assignment]
    usage = obj.get("usageMetadata")
    if not isinstance(usage, dict):
        return None
    prompt = int(usage.get("promptTokenCount") or 0)
    completion = int(usage.get("candidatesTokenCount") or 0)
    # Some backends report a totalTokenCount that doesn't equal prompt+completion.
    # For OpenAI-compatible usage, keep total_tokens consistent.
    total = prompt + completion
    return {
        "prompt_tokens": prompt,
        "completion_tokens": completion,
        "total_tokens": total,
    }


def _cloudcode_headers(access_token: str, *, stream: bool) -> dict[str, str]:
    headers = {
        "Authorization": f"Bearer {access_token}",
        "Content-Type": "application/json",
        # Match Gemini CLI-ish defaults (helps upstream accept the request).
        "User-Agent": "google-api-nodejs-client/9.15.1",
        "X-Goog-Api-Client": "gl-node/22.17.0",
        "Client-Metadata": "ideType=IDE_UNSPECIFIED,platform=PLATFORM_UNSPECIFIED,pluginType=GEMINI",
    }
    headers["Accept"] = "text/event-stream" if stream else "application/json"
    return headers


async def generate_cloudcode(
    req: ChatCompletionRequest,
    *,
    model_name: str,
    reasoning_effort: str,
    timeout_seconds: int,
) -> tuple[str, dict[str, int] | None]:
    access = await get_gemini_access_token(timeout_seconds=min(timeout_seconds, 30))
    project_id = await resolve_gemini_project_id(access_token=access, timeout_seconds=min(timeout_seconds, 30))
    payload = _messages_to_cloudcode_payload(
        req.messages,
        project_id=project_id,
        model_name=model_name,
        reasoning_effort=reasoning_effort,
    )
    url = f"{settings.gemini_cloudcode_base_url}/v1internal:generateContent"
    client = await get_async_client("gemini-cloudcode")
    resp = await request_json_with_retries(
        client=client,
        method="POST",
        url=url,
        timeout_s=timeout_seconds,
        json=payload,
        headers=_cloudcode_headers(access, stream=False),
    )
    if resp.status_code < 200 or resp.status_code >= 300:
        detail = (resp.text or "").strip()
        if len(detail) > 2000:
            detail = detail[:2000] + "…"
        raise RuntimeError(f"gemini cloudcode failed: {resp.status_code} {detail}".strip())
    obj = resp.json()
    if not isinstance(obj, dict):
        return "", None
    return _extract_text_from_cloudcode_response(obj), _extract_usage_from_cloudcode_response(obj)


async def iter_cloudcode_stream_events(
    req: ChatCompletionRequest,
    *,
    model_name: str,
    reasoning_effort: str,
    timeout_seconds: int,
    event_callback: Callable[[dict], None] | None = None,
) -> AsyncIterator[dict]:
    """
    Yield Gemini-CLI-like stream-json events:
      - {"type":"message","role":"assistant","content":"..."}
      - {"type":"result","stats":{...}}  (optional final usage)
    This lets the gateway reuse existing delta assembly code for Gemini.
    """
    access = await get_gemini_access_token(timeout_seconds=min(timeout_seconds, 30))
    project_id = await resolve_gemini_project_id(access_token=access, timeout_seconds=min(timeout_seconds, 30))
    payload = _messages_to_cloudcode_payload(
        req.messages,
        project_id=project_id,
        model_name=model_name,
        reasoning_effort=reasoning_effort,
    )
    url = f"{settings.gemini_cloudcode_base_url}/v1internal:streamGenerateContent?alt=sse"

    last_usage: dict[str, int] | None = None
    client = await get_async_client("gemini-cloudcode-stream")
    async with client.stream(
        "POST",
        url,
        json=payload,
        headers=_cloudcode_headers(access, stream=True),
        timeout=timeout_seconds,
    ) as resp:
        if resp.status_code < 200 or resp.status_code >= 300:
            detail = (await resp.aread()).decode(errors="ignore").strip()
            if len(detail) > 2000:
                detail = detail[:2000] + "…"
            raise RuntimeError(f"gemini cloudcode failed: {resp.status_code} {detail}".strip())
        async for line in resp.aiter_lines():
            raw = (line or "").strip()
            if not raw:
                continue
            if not raw.startswith("data:"):
                continue
            data = raw[len("data:") :].strip()
            if not data:
                continue
            if data == "[DONE]":
                break
            try:
                obj = json.loads(data)
            except Exception:
                continue
            if not isinstance(obj, dict):
                continue
            text = _extract_text_from_cloudcode_response(obj)
            if text:
                evt = {"type": "message", "role": "assistant", "content": text}
                if event_callback:
                    event_callback(evt)
                yield evt
            usage = _extract_usage_from_cloudcode_response(obj)
            if usage:
                last_usage = usage

    if last_usage:
        evt = {
            "type": "result",
            "stats": {
                "input_tokens": last_usage["prompt_tokens"],
                "output_tokens": last_usage["completion_tokens"],
                "total_tokens": last_usage["total_tokens"],
            },
        }
        if event_callback:
            event_callback(evt)
        yield evt
