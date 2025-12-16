from __future__ import annotations

import json
import os
from dataclasses import dataclass, field
from typing import Literal

SandboxMode = Literal["read-only", "workspace-write", "danger-full-access"]
ApprovalPolicy = Literal["untrusted", "on-failure", "on-request", "never"]
GatewayProvider = Literal["auto", "codex", "cursor-agent", "claude", "gemini"]

_GATEWAY_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), os.pardir))
_DEFAULT_CODEX_CLI_HOME = os.path.join(_GATEWAY_ROOT, ".codex-gateway-home")


def _env_bool(name: str, default: bool) -> bool:
    raw = os.environ.get(name)
    if raw is None:
        return default
    raw = raw.strip().lower()
    return raw in {"1", "true", "t", "yes", "y", "on"}


def _env_int(name: str, default: int) -> int:
    raw = os.environ.get(name)
    if raw is None:
        return default
    try:
        return int(raw)
    except ValueError:
        return default


def _env_str(name: str, default: str) -> str:
    raw = os.environ.get(name)
    if raw is None:
        return default
    return raw


def _env_csv(name: str) -> list[str]:
    raw = os.environ.get(name)
    if not raw:
        return []
    items: list[str] = []
    for part in raw.split(","):
        part = part.strip()
        if part:
            items.append(part)
    return items


def _env_json_dict_str_str(name: str) -> dict[str, str]:
    raw = os.environ.get(name)
    if not raw:
        return {}
    try:
        obj = json.loads(raw)
    except Exception:
        return {}
    if not isinstance(obj, dict):
        return {}
    out: dict[str, str] = {}
    for k, v in obj.items():
        if isinstance(k, str) and isinstance(v, str):
            out[k] = v
    return out


@dataclass(frozen=True)
class Settings:
    host: str = os.environ.get("CODEX_GATEWAY_HOST", "127.0.0.1")
    port: int = _env_int("CODEX_GATEWAY_PORT", 8000)

    # If set, requests must include `Authorization: Bearer <token>`.
    bearer_token: str | None = os.environ.get("CODEX_GATEWAY_TOKEN")

    # Working directory for `codex exec --cd ...`.
    workspace: str = os.environ.get("CODEX_WORKSPACE", os.getcwd())

    # Optional HOME override for the Codex CLI subprocess. Use this to point at a minimal
    # `~/.codex/config.toml` (e.g. without MCP servers) for much lower latency.
    codex_cli_home: str | None = (
        None
        if _env_bool("CODEX_USE_SYSTEM_CODEX_HOME", False)
        else (os.environ.get("CODEX_CLI_HOME") or _DEFAULT_CODEX_CLI_HOME)
    )

    # Codex CLI options.
    default_model: str = os.environ.get("CODEX_MODEL", "gpt-5.1")
    # Some local Codex configs default to xhigh, which is not accepted by all models.
    model_reasoning_effort: str | None = (
        _env_str("CODEX_MODEL_REASONING_EFFORT", "low").strip() or None
    )
    # If set, overrides any request-provided reasoning effort.
    force_reasoning_effort: str | None = (_env_str("CODEX_FORCE_REASONING_EFFORT", "").strip() or None)
    sandbox: SandboxMode = os.environ.get("CODEX_SANDBOX", "read-only")  # type: ignore[assignment]
    approval_policy: ApprovalPolicy = os.environ.get("CODEX_APPROVAL_POLICY", "never")  # type: ignore[assignment]
    skip_git_repo_check: bool = _env_bool("CODEX_SKIP_GIT_REPO_CHECK", True)
    enable_search: bool = _env_bool("CODEX_ENABLE_SEARCH", False)
    add_dirs: list[str] = field(default_factory=lambda: _env_csv("CODEX_ADD_DIRS"))
    model_aliases: dict[str, str] = field(default_factory=lambda: _env_json_dict_str_str("CODEX_MODEL_ALIASES"))
    advertised_models: list[str] = field(default_factory=lambda: _env_csv("CODEX_ADVERTISED_MODELS"))
    disable_shell_tool: bool = _env_bool("CODEX_DISABLE_SHELL_TOOL", True)
    # Avoid Codex preferring the MCP-based image tool over native vision input.
    disable_view_image_tool: bool = _env_bool("CODEX_DISABLE_VIEW_IMAGE_TOOL", True)

    # Use Codex backend `/responses` API (like Codex CLI) instead of `codex exec`.
    # This avoids MCP/tool-call flakiness and provides true token streaming.
    use_codex_responses_api: bool = _env_bool("CODEX_USE_CODEX_RESPONSES_API", False)
    codex_responses_base_url: str = _env_str(
        "CODEX_CODEX_BASE_URL",
        "https://chatgpt.com/backend-api/codex",
    )
    codex_responses_version: str = _env_str("CODEX_CODEX_VERSION", "0.21.0")
    codex_responses_user_agent: str = _env_str(
        "CODEX_CODEX_USER_AGENT",
        "codex_cli_rs/0.50.0 (Mac OS 26.0.1; arm64) Apple_Terminal/464",
    )

    # Optional other agent CLIs (multi-provider).
    # Provider routing:
    # - "auto": choose provider from request `model` prefixes (legacy behavior).
    # - otherwise: force a single provider for the whole gateway (operator-controlled).
    provider: GatewayProvider = _env_str("CODEX_PROVIDER", "auto").strip().lower()  # type: ignore[assignment]
    # If true, always allow request `model` prefixes (cursor:/claude:/gemini:) to override provider.
    allow_client_provider_override: bool = _env_bool("CODEX_ALLOW_CLIENT_PROVIDER_OVERRIDE", False)
    # If true, allow the client to choose the provider-specific model (e.g. pass `gpt-5.2` to Codex,
    # or pass `sonnet` to Claude) via the request `model` field. When false, the gateway uses its
    # configured defaults (e.g. CURSOR_AGENT_MODEL / CLAUDE_MODEL / GEMINI_MODEL) and ignores the
    # client-sent model string (still accepted for OpenAI client compatibility).
    allow_client_model_override: bool = _env_bool("CODEX_ALLOW_CLIENT_MODEL_OVERRIDE", False)

    cursor_agent_bin: str = os.environ.get("CURSOR_AGENT_BIN", "cursor-agent")
    # Cursor Agent workspace can be decoupled from CODEX_WORKSPACE to avoid leaking/reading a repo
    # when using cursor-agent for non-coding tasks (e.g. phone UI automation).
    cursor_agent_workspace: str | None = (_env_str("CURSOR_AGENT_WORKSPACE", "").strip() or None)
    cursor_agent_api_key: str | None = os.environ.get("CURSOR_AGENT_API_KEY") or os.environ.get("CURSOR_API_KEY")
    cursor_agent_model: str | None = (_env_str("CURSOR_AGENT_MODEL", "").strip() or None)
    cursor_agent_stream_partial_output: bool = _env_bool("CURSOR_AGENT_STREAM_PARTIAL_OUTPUT", True)

    claude_bin: str = os.environ.get("CLAUDE_BIN", "claude")
    claude_model: str | None = (_env_str("CLAUDE_MODEL", "").strip() or None)

    gemini_bin: str = os.environ.get("GEMINI_BIN", "gemini")
    gemini_model: str | None = (_env_str("GEMINI_MODEL", "").strip() or None)

    # Hard safety caps.
    max_prompt_chars: int = _env_int("CODEX_MAX_PROMPT_CHARS", 200_000)
    timeout_seconds: int = _env_int("CODEX_TIMEOUT_SECONDS", 600)
    max_concurrency: int = _env_int("CODEX_MAX_CONCURRENCY", 2)
    # asyncio StreamReader limit for the Codex subprocess pipes. The default (64KiB)
    # is often too small for NDJSON events that can contain large assistant/tool text.
    subprocess_stream_limit: int = _env_int("CODEX_SUBPROCESS_STREAM_LIMIT", 16 * 1024 * 1024)
    # SSE keep-alive interval. Some clients (or proxies) enforce read timeouts on
    # streaming responses; sending periodic SSE comments prevents idle disconnects.
    sse_keepalive_seconds: int = _env_int("CODEX_SSE_KEEPALIVE_SECONDS", 2)

    # Image input (OpenAI-style `content: [{"type":"image_url", ...}]`).
    enable_image_input: bool = _env_bool("CODEX_ENABLE_IMAGE_INPUT", True)
    max_image_count: int = _env_int("CODEX_MAX_IMAGE_COUNT", 4)
    max_image_bytes: int = _env_int("CODEX_MAX_IMAGE_BYTES", 8 * 1024 * 1024)

    # CORS (comma-separated origins). Empty disables CORS.
    cors_origins: str = os.environ.get("CODEX_CORS_ORIGINS", "")

    # Compatibility: strip `</answer>` from model output for clients that parse
    # do(...)/finish(...) calls (e.g. Open-AutoGLM).
    strip_answer_tags: bool = _env_bool("CODEX_STRIP_ANSWER_TAGS", True)

    # Logging / observability (prints prompts, events, and outputs to server logs).
    debug_log: bool = _env_bool("CODEX_DEBUG_LOG", False)
    log_max_chars: int = _env_int("CODEX_LOG_MAX_CHARS", 4000)


settings = Settings()
