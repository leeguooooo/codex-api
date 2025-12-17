import argparse
import os
from pathlib import Path

import uvicorn


def _normalize_provider(raw: str | None) -> str | None:
    if not raw:
        return None
    v = raw.strip().lower()
    if not v:
        return None
    if v in {"auto", "codex", "claude", "gemini"}:
        return v
    if v in {"cursor-agent", "cursor_agent", "cursoragent", "cursor"}:
        return "cursor-agent"
    return None


def _maybe_load_dotenv(path: Path) -> None:
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


def _default_env_candidates() -> list[Path]:
    candidates: list[Path] = []
    cwd_env = Path.cwd() / ".env"
    if cwd_env.exists() and cwd_env.is_file():
        candidates.append(cwd_env)
    return candidates


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="agent-cli-to-api",
        description="Expose agent CLIs as an OpenAI-compatible /v1 API gateway.",
    )
    parser.add_argument(
        "provider",
        nargs="?",
        default=None,
        help="Provider to use: codex|gemini|claude|cursor-agent (default: auto).",
    )
    parser.add_argument(
        "--host",
        default=os.environ.get("CODEX_HOST", "127.0.0.1"),
        help="Bind host (default: 127.0.0.1).",
    )
    parser.add_argument(
        "--port",
        default=int(os.environ.get("CODEX_PORT", "8000")),
        type=int,
        help="Bind port (default: 8000).",
    )
    parser.add_argument(
        "--reload",
        action="store_true",
        help="Enable uvicorn reload (dev only).",
    )
    parser.add_argument(
        "--log-level",
        default=os.environ.get("CODEX_LOG_LEVEL", "info"),
        help="Uvicorn log level (default: info).",
    )
    parser.add_argument(
        "--env-file",
        default=os.environ.get("CODEX_ENV_FILE") or os.environ.get("CODEX_GATEWAY_ENV_FILE"),
        help="Optionally load environment variables from this .env file.",
    )
    parser.add_argument(
        "--preset",
        default=os.environ.get("CODEX_PRESET"),
        help="Optional config preset (sets recommended env defaults).",
    )
    parser.add_argument(
        "--auto-env",
        action="store_true",
        help="Auto-load .env from the current directory (default: off).",
    )
    return parser


def main(argv: list[str] | None = None) -> None:
    parser = build_parser()
    args = parser.parse_args(argv)

    normalized_provider = _normalize_provider(args.provider)
    if args.provider and not normalized_provider:
        raise SystemExit(f"Unknown provider: {args.provider}")

    if args.env_file:
        path = Path(args.env_file)
        _maybe_load_dotenv(path)
        if path.exists():
            print(f"[agent-cli-to-api] loaded env: {path}")
    elif args.auto_env:
        # Opt-in legacy behavior: load .env from CWD if present.
        for candidate in _default_env_candidates():
            _maybe_load_dotenv(candidate)
            print(f"[agent-cli-to-api] loaded env: {candidate}")
            break
    else:
        # Default: do not load any .env implicitly.
        os.environ.setdefault("CODEX_NO_DOTENV", "1")

    if normalized_provider:
        os.environ["CODEX_PROVIDER"] = normalized_provider

    if args.preset:
        os.environ["CODEX_PRESET"] = str(args.preset)
    elif normalized_provider and not os.environ.get("CODEX_PRESET"):
        # Convenience: if the user calls `agent-cli-to-api <provider>`, apply a sensible preset
        # when it is safe to do so (no hard requirement for a custom .env).
        if normalized_provider == "codex":
            os.environ.setdefault("CODEX_PRESET", "codex-fast")
        elif normalized_provider == "cursor-agent":
            os.environ.setdefault("CODEX_PRESET", "cursor-auto")
        elif normalized_provider == "gemini":
            creds = Path(os.environ.get("GEMINI_OAUTH_CREDS_PATH", "~/.gemini/oauth_creds.json")).expanduser()
            if creds.exists():
                os.environ.setdefault("CODEX_PRESET", "gemini-cloudcode")
        elif normalized_provider == "claude":
            creds = Path(os.environ.get("CLAUDE_OAUTH_CREDS_PATH", "~/.claude/oauth_creds.json")).expanduser()
            if creds.exists():
                os.environ.setdefault("CODEX_PRESET", "claude-oauth")

    uvicorn.run(
        "codex_gateway.server:app",
        host=args.host,
        port=args.port,
        reload=args.reload,
        log_level=args.log_level,
    )


__all__ = ["main"]
