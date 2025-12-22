from __future__ import annotations

import json
import os
import shlex
import tempfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Literal

SandboxMode = Literal["read-only", "workspace-write", "danger-full-access"]
ApprovalPolicy = Literal["untrusted", "on-failure", "on-request", "never"]
GatewayProvider = Literal["auto", "codex", "cursor-agent", "claude", "gemini"]

_GATEWAY_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), os.pardir))
_DEFAULT_CODEX_CLI_HOME = os.path.join(_GATEWAY_ROOT, ".codex-gateway-home")


def _maybe_load_dotenv(path: Path) -> None:
    """
    Minimal .env loader (no dependency) so `uvicorn main:app` works out of the box.
    - Existing process env always wins.
    - Disable by setting `CODEX_NO_DOTENV=1`.
    """
    if os.environ.get("CODEX_NO_DOTENV"):
        return
    if not path.exists() or not path.is_file():
        return
    for raw_line in path.read_text(encoding="utf-8", errors="ignore").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("export "):
            line = line[len("export ") :].strip()
        key, sep, value = line.partition("=")
        if not sep:
            continue
        key = key.strip()
        value = value.strip()
        if not key:
            continue
        if value and value[0] in {"'", '"'} and value[-1] == value[0]:
            value = value[1:-1]
        os.environ.setdefault(key, value)


def _autoload_dotenv() -> None:
    # Load from CWD first, then repo root (same policy as the CLI entrypoint).
    cwd_env = Path.cwd() / ".env"
    _maybe_load_dotenv(cwd_env)
    repo_env = Path(_GATEWAY_ROOT) / ".env"
    if repo_env != cwd_env:
        _maybe_load_dotenv(repo_env)


_autoload_dotenv()

def _apply_preset() -> None:
    """
    Apply an opinionated preset by setting default env vars (without overriding explicitly-set env).
    This keeps the "happy path" config tiny, while still allowing full tuning via env overrides.
    """

    preset = (os.environ.get("CODEX_PRESET") or "").strip().lower().replace("_", "-")
    if not preset:
        return

    presets: dict[str, dict[str, str]] = {
        # Best defaults for local OpenAI-compatible API usage (fast + safe).
        "codex-fast": {
            "CODEX_PROVIDER": "codex",
            "CODEX_MODEL": "gpt-5.2",
            "CODEX_MODEL_REASONING_EFFORT": "low",
            "CODEX_USE_CODEX_RESPONSES_API": "1",
            "CODEX_SANDBOX": "read-only",
            "CODEX_APPROVAL_POLICY": "never",
            "CODEX_SKIP_GIT_REPO_CHECK": "1",
            "CODEX_DISABLE_SHELL_TOOL": "1",
            "CODEX_DISABLE_VIEW_IMAGE_TOOL": "1",
            "CODEX_SSE_KEEPALIVE_SECONDS": "2",
            "CODEX_MAX_CONCURRENCY": "100",  # HTTP API, maximize throughput
            "CODEX_LOG_MODE": "qa",
            "CODEX_LOG_MAX_CHARS": "4000",
            "CODEX_LOG_EVENTS": "0",
            "CODEX_ALLOW_CLIENT_PROVIDER_OVERRIDE": "0",
            "CODEX_ALLOW_CLIENT_MODEL_OVERRIDE": "0",
        },
        # Allow request-side provider prefixes (cursor:/claude:/gemini:) in `model`.
        "multi-fast": {
            "CODEX_PROVIDER": "auto",
            "CODEX_MODEL": "gpt-5.2",
            "CODEX_MODEL_REASONING_EFFORT": "low",
            "CODEX_USE_CODEX_RESPONSES_API": "1",
            "CODEX_SANDBOX": "read-only",
            "CODEX_APPROVAL_POLICY": "never",
            "CODEX_SKIP_GIT_REPO_CHECK": "1",
            "CODEX_DISABLE_SHELL_TOOL": "1",
            "CODEX_DISABLE_VIEW_IMAGE_TOOL": "1",
            "CODEX_SSE_KEEPALIVE_SECONDS": "2",
            "CODEX_LOG_MODE": "qa",
            "CODEX_LOG_MAX_CHARS": "4000",
            "CODEX_LOG_EVENTS": "0",
            # Explicitly allow provider prefixes even if CODEX_PROVIDER changes later.
            "CODEX_ALLOW_CLIENT_PROVIDER_OVERRIDE": "1",
            "CODEX_ALLOW_CLIENT_MODEL_OVERRIDE": "1",
        },
        # Open-AutoGLM / phone automation focused.
        "autoglm-phone": {
            "CODEX_PROVIDER": "codex",
            "CODEX_MODEL": "gpt-5.2",
            "CODEX_MODEL_REASONING_EFFORT": "low",
            "CODEX_USE_CODEX_RESPONSES_API": "1",
            "CODEX_SANDBOX": "read-only",
            "CODEX_APPROVAL_POLICY": "never",
            "CODEX_SKIP_GIT_REPO_CHECK": "1",
            "CODEX_DISABLE_SHELL_TOOL": "1",
            "CODEX_DISABLE_VIEW_IMAGE_TOOL": "1",
            "CODEX_STRIP_ANSWER_TAGS": "1",
            "CODEX_SSE_KEEPALIVE_SECONDS": "2",
            "CODEX_LOG_MODE": "qa",
            "CODEX_LOG_MAX_CHARS": "8000",
            "CODEX_LOG_EVENTS": "0",
            "CODEX_ALLOW_CLIENT_PROVIDER_OVERRIDE": "0",
            "CODEX_ALLOW_CLIENT_MODEL_OVERRIDE": "0",
        },
        # Force cursor-agent provider, keep it "API-like" by disabling indexing by default.
        "cursor-fast": {
            "CODEX_PROVIDER": "cursor-agent",
            "CURSOR_AGENT_MODEL": "gpt-5.1-codex",
            "CURSOR_AGENT_DISABLE_INDEXING": "1",
            "CODEX_LOG_MODE": "qa",
            "CODEX_LOG_MAX_CHARS": "4000",
            "CODEX_LOG_EVENTS": "0",
        },
        "cursor-auto": {
            "CODEX_PROVIDER": "cursor-agent",
            "CURSOR_AGENT_MODEL": "composer-1",
            "CURSOR_AGENT_DISABLE_INDEXING": "1",
            "CURSOR_AGENT_WORKSPACE": "/tmp/cursor-empty-workspace",
            "CODEX_MAX_CONCURRENCY": "100",  # subprocess-based but still parallelizable
            "CODEX_LOG_MODE": "qa",
            "CODEX_LOG_MAX_CHARS": "4000",
            "CODEX_LOG_EVENTS": "0",
        },
        # Claude direct OAuth (no subprocess).
        "claude-oauth": {
            "CODEX_PROVIDER": "claude",
            "CLAUDE_USE_OAUTH_API": "1",
            "CODEX_MAX_CONCURRENCY": "100",  # HTTP API, maximize throughput
            "CODEX_LOG_MODE": "qa",
            "CODEX_LOG_MAX_CHARS": "4000",
            "CODEX_LOG_EVENTS": "0",
        },
        # Gemini Cloud Code Assist backend (no subprocess).
        "gemini-cloudcode": {
            "CODEX_PROVIDER": "gemini",
            "GEMINI_USE_CLOUDCODE_API": "1",
            "GEMINI_MODEL": "gemini-3-flash-preview",
            "CODEX_MAX_CONCURRENCY": "100",  # HTTP API, maximize throughput
            "CODEX_LOG_MODE": "qa",
            "CODEX_LOG_MAX_CHARS": "4000",
            "CODEX_LOG_EVENTS": "0",
        },
    }

    conf = presets.get(preset)
    if conf is None:
        return

    for key, value in conf.items():
        os.environ.setdefault(key, value)


_apply_preset()


def _apply_preset_env() -> None:
    """
    Optional opinionated presets to reduce env surface area.

    Set `CODEX_PRESET` to one of the supported values; this will set a small set of
    environment variables via `os.environ.setdefault` (explicit env always wins).
    """
    preset = (os.environ.get("CODEX_PRESET") or "").strip().lower()
    if not preset:
        return

    presets: dict[str, dict[str, str]] = {
        # Default for local OpenAI-compatible usage with real SSE streaming.
        "codex-fast": {
            "CODEX_PROVIDER": "codex",
            "CODEX_USE_CODEX_RESPONSES_API": "1",
            "CODEX_MODEL_REASONING_EFFORT": "low",
            "CODEX_DISABLE_SHELL_TOOL": "1",
            "CODEX_DISABLE_VIEW_IMAGE_TOOL": "1",
            "CODEX_SSE_KEEPALIVE_SECONDS": "2",
            "CODEX_MAX_CONCURRENCY": "20",
            "CODEX_LOG_MODE": "qa",
        },
        # Open-AutoGLM style phone UI automation (action parsing + screenshots).
        "autoglm-phone": {
            "CODEX_PROVIDER": "codex",
            "CODEX_MODEL": "gpt-5.2",
            "CODEX_USE_CODEX_RESPONSES_API": "1",
            "CODEX_MODEL_REASONING_EFFORT": "low",
            "CODEX_DISABLE_SHELL_TOOL": "1",
            "CODEX_DISABLE_VIEW_IMAGE_TOOL": "1",
            "CODEX_STRIP_ANSWER_TAGS": "1",
            "CODEX_SSE_KEEPALIVE_SECONDS": "2",
            "CODEX_LOG_MODE": "qa",
        },
        # Cursor Agent via CLI (avoid indexing by default).
        "cursor-fast": {
            "CODEX_PROVIDER": "cursor-agent",
            "CURSOR_AGENT_MODEL": "gpt-5.1-codex",
            "CURSOR_AGENT_DISABLE_INDEXING": "1",
            "CODEX_LOG_MODE": "qa",
        },
        "cursor-auto": {
            "CODEX_PROVIDER": "cursor-agent",
            "CURSOR_AGENT_MODEL": "composer-1",
            "CURSOR_AGENT_DISABLE_INDEXING": "1",
            "CURSOR_AGENT_WORKSPACE": "/tmp/cursor-empty-workspace",
            "CODEX_MAX_CONCURRENCY": "10",
            "CODEX_LOG_MODE": "qa",
        },
        # Claude direct HTTP + SSE (requires OAuth creds file).
        "claude-oauth": {
            "CODEX_PROVIDER": "claude",
            "CLAUDE_USE_OAUTH_API": "1",
            "CLAUDE_MODEL": "sonnet",
            "CODEX_MAX_CONCURRENCY": "100",  # HTTP API, maximize throughput
            "CODEX_LOG_MODE": "qa",
        },
        # Gemini direct HTTP + SSE (CloudCode; requires Gemini CLI login state).
        "gemini-cloudcode": {
            "CODEX_PROVIDER": "gemini",
            "GEMINI_USE_CLOUDCODE_API": "1",
            "GEMINI_MODEL": "gemini-3-flash-preview",
            "CODEX_MAX_CONCURRENCY": "20",
            "CODEX_LOG_MODE": "qa",
        },
    }

    chosen = presets.get(preset)
    if not chosen:
        return
    for k, v in chosen.items():
        os.environ.setdefault(k, v)


_apply_preset_env()


def _default_tmp_root() -> str:
    # Prefer /tmp for predictability (many tools and docs assume it), fall back to the
    # platform temp dir when /tmp is unavailable.
    for candidate in (os.environ.get("CODEX_TMP_ROOT") or "", "/tmp"):
        p = candidate.strip()
        if p and Path(p).is_dir():
            return p
    return tempfile.gettempdir()


def _resolve_workspace() -> str:
    raw = (os.environ.get("CODEX_WORKSPACE") or "").strip()
    if raw:
        return os.path.abspath(os.path.expanduser(raw))
    # Default to an empty temp workspace so users don't need to configure CODEX_WORKSPACE.
    return tempfile.mkdtemp(prefix="agent-cli-to-api-workspace-", dir=_default_tmp_root())


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
    workspace: str = _resolve_workspace()

    # Optional HOME override for the Codex CLI subprocess. Use this to point at a minimal
    # `~/.codex/config.toml` (e.g. without MCP servers) for much lower latency. When unset,
    # the system `~/.codex` is used.
    codex_cli_home: str | None = (
        None
        if _env_bool("CODEX_USE_SYSTEM_CODEX_HOME", False)
        else (_env_str("CODEX_CLI_HOME", "").strip() or None)
    )

    # Codex CLI options.
    default_model: str = os.environ.get("CODEX_MODEL", "gpt-5.2")
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
    # Cursor Agent may index the workspace; disabling indexing can reduce startup work for automation use-cases.
    cursor_agent_disable_indexing: bool = _env_bool("CURSOR_AGENT_DISABLE_INDEXING", True)
    # Extra args passed to `cursor-agent` (operator-controlled). Example:
    #   CURSOR_AGENT_EXTRA_ARGS="--endpoint https://api2.cursor.sh --http-version 2"
    cursor_agent_extra_args: list[str] = field(
        default_factory=lambda: shlex.split(os.environ.get("CURSOR_AGENT_EXTRA_ARGS", "") or "")
    )

    claude_bin: str = os.environ.get("CLAUDE_BIN", "claude")
    claude_model: str | None = (_env_str("CLAUDE_MODEL", "").strip() or None)
    # Claude direct OAuth mode (CLIProxyAPI-style). When enabled, the gateway calls the
    # upstream Anthropic HTTP API directly, using a locally cached OAuth access token.
    # This avoids subprocess overhead and supports true SSE streaming.
    claude_use_oauth_api: bool = _env_bool("CLAUDE_USE_OAUTH_API", False)
    claude_oauth_creds_path: str = os.path.expanduser(
        _env_str("CLAUDE_OAUTH_CREDS_PATH", "~/.claude/oauth_creds.json").strip() or "~/.claude/oauth_creds.json"
    )
    # OAuth refresh endpoint is hosted on the Anthropic Console domain.
    claude_oauth_base_url: str = _env_str("CLAUDE_OAUTH_BASE_URL", "https://console.anthropic.com").strip()
    claude_oauth_client_id: str = _env_str("CLAUDE_OAUTH_CLIENT_ID", "").strip()
    # Inference endpoint base URL.
    claude_api_base_url: str = _env_str("CLAUDE_API_BASE_URL", "https://api.anthropic.com").strip()

    gemini_bin: str = os.environ.get("GEMINI_BIN", "gemini")
    gemini_model: str | None = (_env_str("GEMINI_MODEL", "").strip() or None)
    # Gemini "CLI" direct upstream (Cloud Code Assist) mode (CLIProxyAPI-style).
    # Uses the local Gemini CLI OAuth cache by default, so no API key is needed.
    gemini_use_cloudcode_api: bool = _env_bool("GEMINI_USE_CLOUDCODE_API", False)
    gemini_oauth_creds_path: str = os.path.expanduser(
        _env_str("GEMINI_OAUTH_CREDS_PATH", "~/.gemini/oauth_creds.json").strip() or "~/.gemini/oauth_creds.json"
    )
    # OAuth client credentials are intentionally not embedded in the repo (push-protection).
    # If unset, the gateway will try to auto-detect them from the installed `gemini` CLI binary
    # when it needs to refresh access tokens.
    gemini_oauth_client_id: str = _env_str("GEMINI_OAUTH_CLIENT_ID", "").strip()
    gemini_oauth_client_secret: str = _env_str("GEMINI_OAUTH_CLIENT_SECRET", "").strip()
    gemini_cloudcode_base_url: str = _env_str("GEMINI_CLOUDCODE_BASE_URL", "https://cloudcode-pa.googleapis.com").strip()
    gemini_project_id: str = _env_str("GEMINI_PROJECT_ID", "").strip()

    # Hard safety caps.
    max_prompt_chars: int = _env_int("CODEX_MAX_PROMPT_CHARS", 200_000)
    timeout_seconds: int = _env_int("CODEX_TIMEOUT_SECONDS", 600)
    max_concurrency: int = _env_int("CODEX_MAX_CONCURRENCY", 100)
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

    # Logging / observability.
    # - summary: one line per request/response
    # - qa: include last USER message + assistant output
    # - full: include full prompt text + full assistant output
    log_mode: str = _env_str("CODEX_LOG_MODE", "").strip().lower()
    debug_log: bool = _env_bool("CODEX_DEBUG_LOG", False)
    log_events: bool = _env_bool("CODEX_LOG_EVENTS", False)
    log_max_chars: int = _env_int("CODEX_LOG_MAX_CHARS", 4000)
    rich_logs: bool = _env_bool("CODEX_RICH_LOGS", False)
    log_render_markdown: bool = _env_bool("CODEX_LOG_RENDER_MARKDOWN", False)
    log_request_curl: bool = _env_bool("CODEX_LOG_REQUEST_CURL", False)
    log_stream_deltas: bool = _env_bool("CODEX_LOG_STREAM_DELTAS", False)
    log_stream_inline: bool = _env_bool("CODEX_LOG_STREAM_INLINE", False)
    log_stream_inline_suppress_final: bool = _env_bool("CODEX_LOG_STREAM_INLINE_SUPPRESS_FINAL", True)

    def effective_log_mode(self) -> str:
        mode = (self.log_mode or "").strip().lower()
        if mode:
            return mode
        return "qa" if self.debug_log else "summary"


settings = Settings()
