from __future__ import annotations

import asyncio
import base64
import json
import logging
import os
import tempfile
import time
import uuid
from contextlib import aclosing, suppress

from fastapi import FastAPI, Header, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, StreamingResponse

from .codex_cli import collect_codex_text_and_usage_from_events, iter_codex_events
from .codex_responses import (
    build_codex_headers,
    collect_codex_responses_text_and_usage,
    convert_chat_completions_to_codex_responses,
    iter_codex_responses_events,
    load_codex_auth,
    maybe_refresh_codex_auth,
)
from .config import settings
from .openai_compat import ChatCompletionRequest, ChatMessage, ErrorResponse, extract_image_urls, messages_to_prompt
from .stream_json_cli import (
    TextAssembler,
    extract_claude_delta,
    extract_cursor_agent_delta,
    extract_gemini_delta,
    extract_usage_from_claude_result,
    extract_usage_from_gemini_result,
    iter_stream_json_events,
)

app = FastAPI(title="agent-cli-to-api", version="0.1.0")
logger = logging.getLogger("uvicorn.error")

if settings.cors_origins.strip():
    origins = [o.strip() for o in settings.cors_origins.split(",") if o.strip()]
    if origins:
        app.add_middleware(
            CORSMiddleware,
            allow_origins=origins,
            allow_credentials=True,
            allow_methods=["*"],
            allow_headers=["*"],
        )


_semaphore = None


def _get_semaphore():
    global _semaphore
    if _semaphore is None:
        import asyncio

        _semaphore = asyncio.Semaphore(settings.max_concurrency)
    return _semaphore


def _extract_reasoning_effort(req: ChatCompletionRequest) -> str | None:
    extra = getattr(req, "model_extra", None) or {}
    if isinstance(extra, dict):
        direct = extra.get("reasoning_effort")
        if isinstance(direct, str) and direct.strip():
            return direct.strip()
        reasoning = extra.get("reasoning")
        if isinstance(reasoning, dict):
            effort = reasoning.get("effort")
            if isinstance(effort, str) and effort.strip():
                return effort.strip()
    return None


def _parse_provider_model(model: str) -> tuple[str, str | None]:
    raw = (model or "").strip()
    if not raw:
        return "codex", None

    for prefix in ("cursor-agent:", "cursor:"):
        if raw.startswith(prefix):
            inner = raw.split(":", 1)[1].strip()
            return "cursor-agent", (inner or None)
    if raw in {"cursor-agent", "cursor"}:
        return "cursor-agent", None

    for prefix in ("claude-code:", "claude:"):
        if raw.startswith(prefix):
            inner = raw.split(":", 1)[1].strip()
            return "claude", (inner or None)
    if raw in {"claude-code", "claude"}:
        return "claude", None

    if raw.startswith("gemini:"):
        inner = raw.split(":", 1)[1].strip()
        return "gemini", (inner or None)
    if raw == "gemini":
        return "gemini", None

    return "codex", raw


def _normalize_provider(raw: str | None) -> str:
    p = (raw or "").strip().lower()
    if not p:
        return "auto"
    if p in {"auto", "codex", "cursor-agent", "claude", "gemini"}:
        return p
    if p in {"cursor", "cursor_agent", "cursoragent"}:
        return "cursor-agent"
    if p in {"claude-code", "claude_code", "claudecode"}:
        return "claude"
    return "auto"


def _provider_default_model(provider: str) -> str | None:
    if provider == "codex":
        return settings.default_model
    if provider == "cursor-agent":
        return settings.cursor_agent_model
    if provider == "claude":
        return settings.claude_model
    if provider == "gemini":
        return settings.gemini_model
    return None


def _looks_like_unsupported_model_error(message: str) -> bool:
    msg = (message or "").strip()
    if not msg:
        return False

    detail = msg
    try:
        obj = json.loads(msg)
        if isinstance(obj, dict) and isinstance(obj.get("detail"), str):
            detail = obj["detail"]
    except Exception:
        pass

    lowered = detail.lower()
    return ("model is not supported" in lowered) or ("not supported when using codex" in lowered)


def _check_auth(authorization: str | None) -> None:
    token = settings.bearer_token
    if not token:
        return
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Missing Authorization: Bearer <token>")
    if authorization.removeprefix("Bearer ").strip() != token:
        raise HTTPException(status_code=403, detail="Invalid token")


def _openai_error(message: str, *, status_code: int = 500) -> JSONResponse:
    payload = ErrorResponse(
        error={
            "message": message,
            "type": "codex_gateway_error",
            "param": None,
            "code": None,
        }
    ).model_dump()
    return JSONResponse(status_code=status_code, content=payload)


def _maybe_strip_answer_tags(text: str) -> str:
    """
    Optional compatibility shim for clients that parse a single do(...)/finish(...)
    expression and/or wrap messages with <think>/<answer> tags (e.g. Open-AutoGLM).
    """
    if not settings.strip_answer_tags:
        return text
    if not text:
        return text
    for tag in ("<think>", "</think>", "<answer>", "</answer>"):
        text = text.replace(tag, "")
    return text.strip()


def _truncate_for_log(text: str) -> str:
    limit = settings.log_max_chars
    if limit <= 0:
        return ""
    if len(text) <= limit:
        return text
    return f"{text[:limit]}\n... (truncated, {len(text)} chars total)"


_AUTOMATION_GUARD = """SYSTEM: IMPORTANT (Open-AutoGLM action mode)
- This is an Android UI automation loop. You will be given a screenshot each turn.
- The screenshot is already attached as an image in the user's message; use it directly (native vision).
- Output must be machine-parseable and contain exactly ONE action.
- Follow the required format exactly:
  <think>short reason</think>
  <answer>do(...)</answer> OR <answer>finish(...)</answer>
- The <answer> must contain ONLY the action expression (no extra text).
- Do NOT call MCP/tools to fetch screenshots/resources (e.g., list_mcp_resources/read_mcp_resource); they are unavailable here.
- Never refuse due to environment/sandbox/tool limitations; you are NOT executing actions yourself.
- If you are uncertain or need confirmation, output: do(action="Wait", duration="1 seconds")
- For WeChat message sending: only finish if the latest screenshot clearly shows the outgoing message bubble
  with the exact text AND no failure indicator (red "!", "发送失败/未发送/重发", spinner/clock). Otherwise retry/Wait.
"""


def _looks_like_automation_prompt(prompt: str) -> bool:
    p = prompt or ""
    if not p:
        return False
    # Open-AutoGLM style: XML tags + do(action=...) definitions in the system prompt.
    markers = (
        "<think>{think}</think>",
        "<answer>{action}</answer>",
        "do(action=\"Tap\"",
        "do(action=\"Launch\"",
        "finish(message=",
        "Tap是点击操作",
        "finish是结束任务",
    )
    return any(m in p for m in markers)


def _maybe_inject_automation_guard(prompt: str) -> str:
    if not prompt:
        return prompt
    if not _looks_like_automation_prompt(prompt):
        return prompt
    # Avoid duplicating if already present.
    if "IMPORTANT (Open-AutoGLM action mode)" in prompt:
        return prompt
    return f"{_AUTOMATION_GUARD}\n\n{prompt}"


def _maybe_inject_automation_guard_messages(messages: list[ChatMessage]) -> list[ChatMessage]:
    if not messages:
        return messages
    prompt = messages_to_prompt(messages)
    if not _looks_like_automation_prompt(prompt):
        return messages
    if "IMPORTANT (Open-AutoGLM action mode)" in prompt:
        return messages
    return [ChatMessage(role="system", content=_AUTOMATION_GUARD), *messages]


def _mime_to_ext(mime: str) -> str:
    mime = (mime or "").strip().lower()
    if mime in {"image/png", "png"}:
        return "png"
    if mime in {"image/jpeg", "image/jpg", "jpeg", "jpg"}:
        return "jpg"
    if mime in {"image/webp", "webp"}:
        return "webp"
    return "bin"


def _decode_data_url(data_url: str) -> tuple[bytes, str]:
    if not data_url.startswith("data:"):
        raise ValueError("Unsupported image_url (expected data: URL)")
    try:
        header, payload = data_url.split(",", 1)
    except ValueError as e:
        raise ValueError("Invalid data: URL") from e

    if ";base64" not in header:
        raise ValueError("Unsupported data: URL encoding (expected base64)")

    mime = header.removeprefix("data:").split(";", 1)[0].strip() or "application/octet-stream"
    # base64 payload may contain newlines; strip whitespace.
    payload = "".join(payload.split())
    try:
        data = base64.b64decode(payload, validate=False)
    except Exception as e:
        raise ValueError("Invalid base64 image payload") from e

    return data, _mime_to_ext(mime)


def _materialize_request_images(
    req: ChatCompletionRequest, *, resp_id: str
) -> tuple[tempfile.TemporaryDirectory | None, list[str]]:
    if not settings.enable_image_input:
        return None, []

    urls = extract_image_urls(req.messages)
    if not urls:
        return None, []

    max_count = max(settings.max_image_count, 0)
    if max_count == 0:
        return None, []

    urls = urls[-max_count:]
    tmpdir = tempfile.TemporaryDirectory(prefix="codex-gateway-images-")
    paths: list[str] = []
    for idx, url in enumerate(urls):
        data, ext = _decode_data_url(url)
        if settings.max_image_bytes > 0 and len(data) > settings.max_image_bytes:
            raise HTTPException(
                status_code=413,
                detail=f"Image too large ({len(data)} bytes > {settings.max_image_bytes})",
            )
        filename = f"{resp_id}-{idx}.{ext}"
        path = os.path.join(tmpdir.name, filename)
        with open(path, "wb") as f:
            f.write(data)
        paths.append(path)

    return tmpdir, paths


@app.on_event("startup")
async def _log_startup_config() -> None:
    # Intentionally omit secrets (tokens, API keys).
    logger.info(
        "Gateway config: workspace=%s provider=%s allow_client_provider_override=%s allow_client_model_override=%s default_model=%s model_reasoning_effort=%s force_reasoning_effort=%s use_codex_responses_api=%s max_concurrency=%s sse_keepalive_seconds=%s strip_answer_tags=%s debug_log=%s",
        settings.workspace,
        settings.provider,
        settings.allow_client_provider_override,
        settings.allow_client_model_override,
        settings.default_model,
        settings.model_reasoning_effort,
        settings.force_reasoning_effort,
        settings.use_codex_responses_api,
        settings.max_concurrency,
        settings.sse_keepalive_seconds,
        settings.strip_answer_tags,
        settings.debug_log,
    )


@app.get("/healthz")
async def healthz():
    return {"ok": True}


@app.get("/v1/models")
async def list_models(authorization: str | None = Header(default=None)):
    _check_auth(authorization)
    forced_provider = _normalize_provider(settings.provider)
    default_id = _provider_default_model(forced_provider) or settings.default_model
    models = settings.advertised_models[:] if settings.advertised_models else [default_id]
    if settings.model_aliases:
        models.extend(settings.model_aliases.keys())
        models.extend(settings.model_aliases.values())
    # Preserve order while deduping.
    seen: set[str] = set()
    unique_models: list[str] = []
    for m in models:
        if not m or m in seen:
            continue
        seen.add(m)
        unique_models.append(m)
    return {
        "object": "list",
        "data": [{"id": m, "object": "model", "created": 0, "owned_by": "local"} for m in unique_models],
    }


@app.get("/debug/config")
async def debug_config(authorization: str | None = Header(default=None)):
    """
    Return the effective runtime configuration (secrets redacted).

    If `CODEX_GATEWAY_TOKEN` is set, this endpoint requires `Authorization: Bearer <token>`.
    """
    _check_auth(authorization)
    return {
        "provider": settings.provider,
        "allow_client_provider_override": settings.allow_client_provider_override,
        "allow_client_model_override": settings.allow_client_model_override,
        "default_model": settings.default_model,
        "model_reasoning_effort": settings.model_reasoning_effort,
        "force_reasoning_effort": settings.force_reasoning_effort,
        "use_codex_responses_api": settings.use_codex_responses_api,
        "codex_cli_home": settings.codex_cli_home,
        "workspace": settings.workspace,
        "max_concurrency": settings.max_concurrency,
        "timeout_seconds": settings.timeout_seconds,
        "subprocess_stream_limit": settings.subprocess_stream_limit,
        "sse_keepalive_seconds": settings.sse_keepalive_seconds,
        "strip_answer_tags": settings.strip_answer_tags,
        "enable_image_input": settings.enable_image_input,
        "max_image_count": settings.max_image_count,
        "max_image_bytes": settings.max_image_bytes,
        "disable_shell_tool": settings.disable_shell_tool,
        "disable_view_image_tool": settings.disable_view_image_tool,
        "debug_log": settings.debug_log,
        "log_max_chars": settings.log_max_chars,
    }


@app.post("/v1/chat/completions")
async def chat_completions(
    req: ChatCompletionRequest,
    request: Request,
    authorization: str | None = Header(default=None),
):
    _check_auth(authorization)

    forced_provider = _normalize_provider(settings.provider)
    fallback_model = (
        _provider_default_model(forced_provider if forced_provider != "auto" else "codex") or settings.default_model
    )
    requested_model = (req.model or fallback_model).strip()
    resolved_model = settings.model_aliases.get(requested_model, requested_model)
    parsed_provider, provider_model = _parse_provider_model(resolved_model)
    if settings.allow_client_provider_override or forced_provider == "auto":
        provider = parsed_provider
    else:
        # Operator forces a single provider for the whole gateway; ignore request-side provider prefixes.
        provider = forced_provider
        if not settings.allow_client_model_override:
            # Operator decides the provider model; ignore client-sent model strings.
            provider_model = None
    allowed_efforts = {"low", "medium", "high", "xhigh"}

    def _normalize_effort(raw: str | None) -> str | None:
        if raw is None:
            return None
        if raw == "none":
            # Some clients send "none" to indicate minimal reasoning.
            return "low"
        return raw if raw in allowed_efforts else None
    request_effort_raw = _extract_reasoning_effort(req)
    request_effort = _normalize_effort(request_effort_raw)

    forced_effort_raw = (settings.force_reasoning_effort or "").strip() or None
    forced_effort = _normalize_effort(forced_effort_raw)

    default_effort_raw = (settings.model_reasoning_effort or "").strip() or None
    default_effort = _normalize_effort(default_effort_raw)

    # Final effort is always normalized to a supported value.
    reasoning_effort = forced_effort or request_effort or default_effort or "high"
    # Some providers take a single prompt string; Codex backend uses structured messages.
    prompt = _maybe_inject_automation_guard(messages_to_prompt(req.messages))
    if len(prompt) > settings.max_prompt_chars:
        return _openai_error(f"Prompt too large ({len(prompt)} chars)", status_code=413)

    created = int(time.time())
    resp_id = f"chatcmpl-{uuid.uuid4().hex}"

    image_urls = extract_image_urls(req.messages)
    use_codex_backend = bool(
        provider == "codex"
        and (
            settings.use_codex_responses_api
            or (settings.enable_image_input and image_urls)
            # Prefer Codex backend `/responses` for streaming requests (true SSE deltas).
            or req.stream
        )
    )

    sem = _get_semaphore()
    try:
        effort_source = "default"
        if forced_effort:
            effort_source = "forced"
        elif request_effort:
            effort_source = "request"
        elif not default_effort:
            effort_source = "fallback"
        if settings.debug_log:
            logger.info(
                "[%s] /v1/chat/completions model=%s resolved_model=%s provider=%s mode=%s stream=%s effort=%s prompt_chars=%d",
                resp_id,
                requested_model,
                resolved_model,
                provider,
                ("codex-responses" if use_codex_backend else "cli"),
                req.stream,
                reasoning_effort,
                len(prompt),
            )
            logger.info(
                "[%s] reasoning_effort source=%s forced=%s request=%s default=%s",
                resp_id,
                effort_source,
                forced_effort_raw,
                request_effort_raw,
                default_effort_raw,
            )
            logger.info("[%s] prompt:\n%s", resp_id, _truncate_for_log(prompt))
        else:
            logger.info(
                "[%s] /v1/chat/completions model=%s resolved_model=%s provider=%s mode=%s stream=%s effort=%s effort_src=%s effort_req=%s effort_def=%s effort_forced=%s images=%d",
                resp_id,
                requested_model,
                resolved_model,
                provider,
                ("codex-responses" if use_codex_backend else "cli"),
                req.stream,
                reasoning_effort,
                effort_source,
                request_effort_raw,
                default_effort_raw,
                forced_effort_raw,
                len(image_urls),
            )

        tmpdir: tempfile.TemporaryDirectory | None = None
        image_files: list[str] = []
        if provider == "codex":
            if use_codex_backend:
                # No temp files needed; Codex backend accepts data: URLs directly.
                if settings.debug_log and image_urls:
                    for idx, url in enumerate(image_urls[-max(settings.max_image_count, 0) :]):
                        try:
                            data, ext = _decode_data_url(url)
                            size = len(data)
                        except Exception:
                            ext, size = "bin", -1
                        logger.info("[%s] image[%d] ext=%s bytes=%d", resp_id, idx, ext, size)
                    logger.info("[%s] decoded_images=%d", resp_id, len(image_urls))
            else:
                try:
                    tmpdir, image_files = _materialize_request_images(req, resp_id=resp_id)
                except HTTPException:
                    raise
                except Exception as e:
                    return _openai_error(f"Failed to decode image input: {e}", status_code=400)

                if settings.debug_log and image_files:
                    for idx, path in enumerate(image_files):
                        try:
                            size = os.path.getsize(path)
                        except OSError:
                            size = -1
                        ext = os.path.splitext(path)[1].lstrip(".") or "bin"
                        logger.info("[%s] image[%d] ext=%s bytes=%d", resp_id, idx, ext, size)
                    logger.info("[%s] decoded_images=%d", resp_id, len(image_files))

        def _evt_log(evt: dict) -> None:
            if not settings.debug_log:
                return
            t = evt.get("type")
            if t == "response.created":
                resp = evt.get("response") or {}
                rid = resp.get("id") if isinstance(resp, dict) else None
                logger.info("[%s] codex %s response_id=%s", resp_id, t, rid)
                return
            if t == "response.completed":
                resp = evt.get("response") or {}
                usage = resp.get("usage") if isinstance(resp, dict) else None
                extra = f" usage={usage}" if isinstance(usage, dict) else ""
                logger.info("[%s] codex %s%s", resp_id, t, extra)
                return
            if t == "response.output_text.done":
                text = evt.get("text") or ""
                logger.info("[%s] codex %s chars=%d", resp_id, t, len(str(text)))
                return
            if t == "thread.started":
                logger.info("[%s] codex %s thread_id=%s", resp_id, t, evt.get("thread_id"))
                return
            if t in {"turn.started", "turn.completed", "turn.failed"}:
                extra = ""
                if t == "turn.completed" and isinstance(evt.get("usage"), dict):
                    u = evt["usage"]
                    extra = f" usage={u}"
                logger.info("[%s] codex %s%s", resp_id, t, extra)
                return
            if t == "error":
                logger.error("[%s] codex error: %s", resp_id, _truncate_for_log(str(evt.get("message") or "")))
                return
            if t in {"item.started", "item.completed"}:
                item = evt.get("item") or {}
                itype = item.get("type")
                if itype == "command_execution":
                    cmd = item.get("command") or ""
                    status = item.get("status") or ""
                    exit_code = item.get("exit_code")
                    logger.info("[%s] codex %s command status=%s exit=%s cmd=%s", resp_id, t, status, exit_code, cmd)
                    out = item.get("aggregated_output")
                    if isinstance(out, str) and out.strip():
                        logger.info("[%s] codex command output:\n%s", resp_id, _truncate_for_log(out))
                    return
                if itype == "file_change":
                    changes = item.get("changes") or []
                    paths: list[str] = []
                    if isinstance(changes, list):
                        for ch in changes:
                            if isinstance(ch, dict) and isinstance(ch.get("path"), str):
                                kind = ch.get("kind")
                                if isinstance(kind, str) and kind:
                                    paths.append(f"{kind}:{ch['path']}")
                                else:
                                    paths.append(ch["path"])
                    logger.info("[%s] codex %s file_change %s", resp_id, t, ", ".join(paths)[: settings.log_max_chars])
                    return
                if itype == "mcp_tool_call":
                    server = item.get("server")
                    tool = item.get("tool")
                    status = item.get("status")
                    logger.info(
                        "[%s] codex %s mcp_tool_call server=%s tool=%s status=%s",
                        resp_id,
                        t,
                        server,
                        tool,
                        status,
                    )
                    args = item.get("arguments")
                    if args:
                        try:
                            dumped = json.dumps(args, ensure_ascii=False, default=str)
                        except Exception:
                            dumped = str(args)
                        logger.info("[%s] codex mcp_tool_call args:\n%s", resp_id, _truncate_for_log(dumped))
                    err = item.get("error")
                    if err:
                        try:
                            dumped = json.dumps(err, ensure_ascii=False, default=str)
                        except Exception:
                            dumped = str(err)
                        logger.warning("[%s] codex mcp_tool_call error:\n%s", resp_id, _truncate_for_log(dumped))
                    result = item.get("result")
                    if result:
                        try:
                            dumped = json.dumps(result, ensure_ascii=False, default=str)
                        except Exception:
                            dumped = str(result)
                        logger.info("[%s] codex mcp_tool_call result:\n%s", resp_id, _truncate_for_log(dumped))
                    return
                if itype == "agent_message":
                    text = _maybe_strip_answer_tags(str(item.get("text") or ""))
                    logger.info("[%s] codex %s agent_message_chars=%d", resp_id, t, len(text))
                    logger.info("[%s] codex agent_message:\n%s", resp_id, _truncate_for_log(text))
                    return
                if itype == "reasoning":
                    r = item.get("text") or ""
                    logger.info("[%s] codex %s reasoning_chars=%d", resp_id, t, len(str(r)))
                    return
                logger.info("[%s] codex %s item_type=%s", resp_id, t, itype)
                return

        def _stderr_log(line: str) -> None:
            if not settings.debug_log:
                return
            logger.warning("[%s] codex stderr: %s", resp_id, _truncate_for_log(line))

        if not req.stream:
            usage: dict[str, int] | None = None
            try:
                async with sem:
                    if provider == "codex":
                        codex_model = provider_model or settings.default_model

                        async def _run_codex_once(model_id: str):
                            if use_codex_backend:
                                auth = load_codex_auth(codex_cli_home=settings.codex_cli_home)
                                token = auth.api_key or auth.access_token
                                if not token:
                                    raise RuntimeError(
                                        "Missing Codex auth token (run `codex login` to create ~/.codex/auth.json)."
                                    )
                                headers = build_codex_headers(
                                    token=token,
                                    account_id=auth.account_id,
                                    version=settings.codex_responses_version,
                                    user_agent=settings.codex_responses_user_agent,
                                )
                                backend_req = req.model_copy(
                                    update={"model": model_id, "messages": _maybe_inject_automation_guard_messages(req.messages)}
                                )
                                payload = convert_chat_completions_to_codex_responses(
                                    backend_req,
                                    model_name=model_id,
                                    force_stream=True,
                                    reasoning_effort_override=(
                                        "high" if reasoning_effort == "xhigh" else reasoning_effort
                                    ),
                                )
                                events = iter_codex_responses_events(
                                    base_url=settings.codex_responses_base_url,
                                    headers=headers,
                                    payload=payload,
                                    timeout_seconds=settings.timeout_seconds,
                                    event_callback=_evt_log if settings.debug_log else None,
                                )
                                text, usage = await collect_codex_responses_text_and_usage(events)
                                # Re-wrap usage into the same shape as codex exec path.
                                return type(
                                    "BackendResult",
                                    (),
                                    {"text": text, "usage": usage},
                                )()

                            events = iter_codex_events(
                                prompt=prompt,
                                model=model_id,
                                cd=settings.workspace,
                                images=image_files,
                                disable_shell_tool=settings.disable_shell_tool,
                                disable_view_image_tool=settings.disable_view_image_tool,
                                sandbox=settings.sandbox,
                                skip_git_repo_check=settings.skip_git_repo_check,
                                model_reasoning_effort=reasoning_effort,
                                approval_policy=settings.approval_policy,
                                enable_search=settings.enable_search,
                                add_dirs=settings.add_dirs,
                                codex_cli_home=settings.codex_cli_home,
                                timeout_seconds=settings.timeout_seconds,
                                stream_limit=settings.subprocess_stream_limit,
                                event_callback=_evt_log,
                                stderr_callback=_stderr_log,
                            )
                            return await collect_codex_text_and_usage_from_events(events)

                        try:
                            result = await _run_codex_once(codex_model)
                        except Exception as e:
                            # If Codex backend auth expired, refresh and retry once before model fallback.
                            if use_codex_backend and ("codex responses failed: 401" in str(e) or "codex responses failed: 403" in str(e)):
                                await maybe_refresh_codex_auth(
                                    codex_cli_home=settings.codex_cli_home,
                                    timeout_seconds=min(settings.timeout_seconds, 30),
                                )
                                result = await _run_codex_once(codex_model)
                            else:
                                fallback_model = settings.default_model
                                if codex_model != fallback_model and _looks_like_unsupported_model_error(str(e)):
                                    if settings.debug_log:
                                        logger.warning(
                                            "[%s] codex model unsupported: %s -> fallback=%s",
                                            resp_id,
                                            codex_model,
                                            fallback_model,
                                        )
                                    result = await _run_codex_once(fallback_model)
                                else:
                                    raise
                        text = result.text
                        usage = result.usage
                    elif provider == "cursor-agent":
                        cursor_model = provider_model or settings.cursor_agent_model
                        cmd = [
                            settings.cursor_agent_bin,
                            "-p",
                            "--output-format",
                            "stream-json",
                            "--workspace",
                            settings.workspace,
                        ]
                        if settings.cursor_agent_api_key:
                            cmd.extend(["--api-key", settings.cursor_agent_api_key])
                        if cursor_model:
                            cmd.extend(["--model", cursor_model])
                        if settings.cursor_agent_stream_partial_output:
                            cmd.append("--stream-partial-output")
                        cmd.append(prompt)

                        assembler = TextAssembler()
                        fallback_text: str | None = None
                        async for evt in iter_stream_json_events(
                            cmd=cmd,
                            env=None,
                            timeout_seconds=settings.timeout_seconds,
                            stream_limit=settings.subprocess_stream_limit,
                            event_callback=_evt_log,
                            stderr_callback=_stderr_log,
                        ):
                            extract_cursor_agent_delta(evt, assembler)
                            if evt.get("type") == "result" and isinstance(evt.get("result"), str):
                                fallback_text = evt["result"]
                        text = assembler.text or (fallback_text or "")
                    elif provider == "claude":
                        claude_model = provider_model or settings.claude_model
                        cmd = [
                            settings.claude_bin,
                            "--verbose",
                            "-p",
                            "--output-format",
                            "stream-json",
                            "--add-dir",
                            settings.workspace,
                        ]
                        for d in settings.add_dirs:
                            cmd.extend(["--add-dir", d])
                        if claude_model:
                            cmd.extend(["--model", claude_model])
                        cmd.append("--")
                        cmd.append(prompt)

                        assembler = TextAssembler()
                        fallback_text = None
                        async for evt in iter_stream_json_events(
                            cmd=cmd,
                            env=None,
                            timeout_seconds=settings.timeout_seconds,
                            stream_limit=settings.subprocess_stream_limit,
                            event_callback=_evt_log,
                            stderr_callback=_stderr_log,
                        ):
                            extract_claude_delta(evt, assembler)
                            maybe_usage = extract_usage_from_claude_result(evt)
                            if maybe_usage:
                                usage = maybe_usage
                            if evt.get("type") == "result" and isinstance(evt.get("result"), str):
                                fallback_text = evt["result"]
                        text = assembler.text or (fallback_text or "")
                    elif provider == "gemini":
                        gemini_model = provider_model or settings.gemini_model
                        cmd = [settings.gemini_bin, "-o", "stream-json"]
                        if gemini_model:
                            cmd.extend(["-m", gemini_model])
                        cmd.append(prompt)

                        assembler = TextAssembler()
                        async for evt in iter_stream_json_events(
                            cmd=cmd,
                            env=None,
                            timeout_seconds=settings.timeout_seconds,
                            stream_limit=settings.subprocess_stream_limit,
                            event_callback=_evt_log,
                            stderr_callback=_stderr_log,
                        ):
                            extract_gemini_delta(evt, assembler)
                            maybe_usage = extract_usage_from_gemini_result(evt)
                            if maybe_usage:
                                usage = maybe_usage
                        text = assembler.text
                    else:
                        raise RuntimeError(f"Unknown provider: {provider}")
            finally:
                if tmpdir is not None:
                    tmpdir.cleanup()

            text = _maybe_strip_answer_tags(text).strip()
            if settings.debug_log:
                logger.info("[%s] response_chars=%d", resp_id, len(text))
                logger.info("[%s] response:\n%s", resp_id, _truncate_for_log(text))
            response: dict = {
                "id": resp_id,
                "object": "chat.completion",
                "created": created,
                "model": requested_model,
                "choices": [
                    {
                        "index": 0,
                        "message": {"role": "assistant", "content": text},
                        "finish_reason": "stop",
                    }
                ],
            }
            if usage is not None:
                response["usage"] = usage
            return response

        async def sse_gen():
            try:
                async with sem:
                    # initial role chunk
                    first = {
                        "id": resp_id,
                        "object": "chat.completion.chunk",
                        "created": created,
                        "model": requested_model,
                        "choices": [{"index": 0, "delta": {"role": "assistant"}, "finish_reason": None}],
                    }
                    yield f"data: {json.dumps(first, ensure_ascii=False)}\n\n"
                    keepalive = max(settings.sse_keepalive_seconds, 0)
                    attempt_models: list[str | None]
                    if provider == "codex":
                        first_model = provider_model or settings.default_model
                        fallback_model = settings.default_model
                        attempt_models = [first_model]
                        if first_model != fallback_model:
                            attempt_models.append(fallback_model)
                    else:
                        attempt_models = [provider_model]

                    for attempt_idx, attempt_model in enumerate(attempt_models):
                        if provider == "codex":
                            codex_model = attempt_model or settings.default_model
                            if use_codex_backend:
                                auth = load_codex_auth(codex_cli_home=settings.codex_cli_home)
                                token = auth.api_key or auth.access_token
                                if not token:
                                    # Best-effort refresh (e.g. first-time login) before failing.
                                    await maybe_refresh_codex_auth(
                                        codex_cli_home=settings.codex_cli_home,
                                        timeout_seconds=min(settings.timeout_seconds, 30),
                                    )
                                    auth = load_codex_auth(codex_cli_home=settings.codex_cli_home)
                                    token = auth.api_key or auth.access_token
                                if not token:
                                    raise RuntimeError(
                                        "Missing Codex auth token (run `codex login` to create ~/.codex/auth.json)."
                                    )
                                headers = build_codex_headers(
                                    token=token,
                                    account_id=auth.account_id,
                                    version=settings.codex_responses_version,
                                    user_agent=settings.codex_responses_user_agent,
                                )
                                backend_req = req.model_copy(
                                    update={
                                        "model": codex_model,
                                        "messages": _maybe_inject_automation_guard_messages(req.messages),
                                    }
                                )
                                payload = convert_chat_completions_to_codex_responses(
                                    backend_req,
                                    model_name=codex_model,
                                    force_stream=True,
                                    reasoning_effort_override=(
                                        "high" if reasoning_effort == "xhigh" else reasoning_effort
                                    ),
                                )
                                events = iter_codex_responses_events(
                                    base_url=settings.codex_responses_base_url,
                                    headers=headers,
                                    payload=payload,
                                    timeout_seconds=settings.timeout_seconds,
                                    event_callback=_evt_log if settings.debug_log else None,
                                )
                            else:
                                events = iter_codex_events(
                                    prompt=prompt,
                                    model=codex_model,
                                    cd=settings.workspace,
                                    images=image_files,
                                    disable_shell_tool=settings.disable_shell_tool,
                                    disable_view_image_tool=settings.disable_view_image_tool,
                                    sandbox=settings.sandbox,
                                    skip_git_repo_check=settings.skip_git_repo_check,
                                    model_reasoning_effort=reasoning_effort,
                                    approval_policy=settings.approval_policy,
                                    enable_search=settings.enable_search,
                                    add_dirs=settings.add_dirs,
                                    codex_cli_home=settings.codex_cli_home,
                                    timeout_seconds=settings.timeout_seconds,
                                    stream_limit=settings.subprocess_stream_limit,
                                    event_callback=_evt_log,
                                    stderr_callback=_stderr_log,
                                )
                        elif provider == "cursor-agent":
                            cursor_model = provider_model or settings.cursor_agent_model
                            cmd = [
                                settings.cursor_agent_bin,
                                "-p",
                                "--output-format",
                                "stream-json",
                                "--workspace",
                                settings.workspace,
                            ]
                            if settings.cursor_agent_api_key:
                                cmd.extend(["--api-key", settings.cursor_agent_api_key])
                            if cursor_model:
                                cmd.extend(["--model", cursor_model])
                            if settings.cursor_agent_stream_partial_output:
                                cmd.append("--stream-partial-output")
                            cmd.append(prompt)
                            events = iter_stream_json_events(
                                cmd=cmd,
                                env=None,
                                timeout_seconds=settings.timeout_seconds,
                                stream_limit=settings.subprocess_stream_limit,
                                event_callback=_evt_log,
                                stderr_callback=_stderr_log,
                            )
                        elif provider == "claude":
                            claude_model = provider_model or settings.claude_model
                            cmd = [
                                settings.claude_bin,
                                "--verbose",
                                "-p",
                                "--output-format",
                                "stream-json",
                                "--add-dir",
                                settings.workspace,
                            ]
                            for d in settings.add_dirs:
                                cmd.extend(["--add-dir", d])
                            if claude_model:
                                cmd.extend(["--model", claude_model])
                            cmd.append("--")
                            cmd.append(prompt)
                            events = iter_stream_json_events(
                                cmd=cmd,
                                env=None,
                                timeout_seconds=settings.timeout_seconds,
                                stream_limit=settings.subprocess_stream_limit,
                                event_callback=_evt_log,
                                stderr_callback=_stderr_log,
                            )
                        elif provider == "gemini":
                            gemini_model = provider_model or settings.gemini_model
                            cmd = [settings.gemini_bin, "-o", "stream-json"]
                            if gemini_model:
                                cmd.extend(["-m", gemini_model])
                            cmd.append(prompt)
                            events = iter_stream_json_events(
                                cmd=cmd,
                                env=None,
                                timeout_seconds=settings.timeout_seconds,
                                stream_limit=settings.subprocess_stream_limit,
                                event_callback=_evt_log,
                                stderr_callback=_stderr_log,
                            )
                        else:
                            raise RuntimeError(f"Unknown provider: {provider}")

                        queue: asyncio.Queue[dict | None] = asyncio.Queue()
                        assembler = TextAssembler()
                        sent_content = False
                        should_retry = False

                        async def _pump_events() -> None:
                            try:
                                async with aclosing(events):
                                    async for evt in events:
                                        await queue.put(evt)
                            except Exception as e:
                                await queue.put({"_gateway_error": str(e)})
                            finally:
                                await queue.put(None)

                        pump_task = asyncio.create_task(_pump_events())
                        try:
                            while True:
                                if await request.is_disconnected():
                                    return

                                try:
                                    if keepalive > 0:
                                        evt = await asyncio.wait_for(queue.get(), timeout=keepalive)
                                    else:
                                        evt = await queue.get()
                                except (asyncio.TimeoutError, TimeoutError):
                                    yield ": ping\n\n"
                                    continue

                                if evt is None:
                                    break

                                if isinstance(evt, dict) and evt.get("_gateway_error"):
                                    msg = str(evt.get("_gateway_error") or "")
                                    if (
                                        provider == "codex"
                                        and attempt_idx == 0
                                        and len(attempt_models) > 1
                                        and not sent_content
                                        and _looks_like_unsupported_model_error(msg)
                                    ):
                                        if settings.debug_log:
                                            logger.warning(
                                                "[%s] codex model unsupported: %s -> fallback=%s",
                                                resp_id,
                                                attempt_models[0],
                                                attempt_models[1],
                                            )
                                        should_retry = True
                                        break

                                    if msg:
                                        chunk = {
                                            "id": resp_id,
                                            "object": "chat.completion.chunk",
                                            "created": created,
                                            "model": requested_model,
                                            "choices": [
                                                {"index": 0, "delta": {"content": msg}, "finish_reason": None}
                                            ],
                                        }
                                        yield f"data: {json.dumps(chunk, ensure_ascii=False)}\n\n"
                                    break

                                delta = ""
                                if provider == "codex":
                                    if use_codex_backend:
                                        if evt.get("type") == "response.output_text.delta" and isinstance(
                                            evt.get("delta"), str
                                        ):
                                            delta = _maybe_strip_answer_tags(evt["delta"])
                                        # Some short responses arrive only as a final "done" event.
                                        if (
                                            not delta
                                            and not sent_content
                                            and evt.get("type") == "response.output_text.done"
                                            and isinstance(evt.get("text"), str)
                                        ):
                                            delta = _maybe_strip_answer_tags(evt["text"])
                                        if evt.get("type") == "response.completed":
                                            break
                                    else:
                                        if evt.get("type") == "item.completed":
                                            item = evt.get("item") or {}
                                            if item.get("type") == "agent_message":
                                                delta = _maybe_strip_answer_tags(str(item.get("text") or ""))
                                elif provider == "cursor-agent":
                                    delta = _maybe_strip_answer_tags(extract_cursor_agent_delta(evt, assembler))
                                elif provider == "claude":
                                    delta = _maybe_strip_answer_tags(extract_claude_delta(evt, assembler))
                                elif provider == "gemini":
                                    delta = _maybe_strip_answer_tags(extract_gemini_delta(evt, assembler))

                                if delta:
                                    sent_content = True
                                    chunk = {
                                        "id": resp_id,
                                        "object": "chat.completion.chunk",
                                        "created": created,
                                        "model": requested_model,
                                        "choices": [{"index": 0, "delta": {"content": delta}, "finish_reason": None}],
                                    }
                                    yield f"data: {json.dumps(chunk, ensure_ascii=False)}\n\n"
                        finally:
                            pump_task.cancel()
                            with suppress(asyncio.CancelledError):
                                await pump_task

                        if should_retry:
                            continue
                        break

                    end = {
                        "id": resp_id,
                        "object": "chat.completion.chunk",
                        "created": created,
                        "model": requested_model,
                        "choices": [{"index": 0, "delta": {}, "finish_reason": "stop"}],
                    }
                    yield f"data: {json.dumps(end, ensure_ascii=False)}\n\n"
                    yield "data: [DONE]\n\n"
            finally:
                if tmpdir is not None:
                    tmpdir.cleanup()

        return StreamingResponse(sse_gen(), media_type="text/event-stream")
    except (asyncio.TimeoutError, TimeoutError):
        return _openai_error(f"codex exec timed out after {settings.timeout_seconds}s", status_code=504)
    except Exception as e:
        return _openai_error(str(e), status_code=500)
