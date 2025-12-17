from __future__ import annotations

import asyncio
import json
import os
import shutil
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .claude_oauth import maybe_refresh_claude_oauth
from .codex_responses import load_codex_auth
from .gemini_cloudcode import load_gemini_creds


@dataclass(frozen=True)
class CheckResult:
    name: str
    ok: bool
    details: str


def _fmt_bool(ok: bool) -> str:
    return "OK" if ok else "FAIL"


def _which(name: str) -> str | None:
    return shutil.which(name)


def _read_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def _check_binary(label: str, bin_name: str) -> CheckResult:
    p = _which(bin_name)
    return CheckResult(f"{label} binary", bool(p), p or f"not found on PATH: {bin_name}")


def _check_file(label: str, path: Path) -> CheckResult:
    if path.exists() and path.is_file():
        return CheckResult(label, True, str(path))
    return CheckResult(label, False, f"missing: {path}")


def _check_codex_auth() -> CheckResult:
    auth = load_codex_auth(codex_cli_home=os.environ.get("CODEX_CLI_HOME"))
    ok = bool(auth.access_token or auth.api_key)
    detail = "auth ok" if ok else "missing ~/.codex/auth.json tokens (run `codex login`)"
    return CheckResult("Codex auth", ok, detail)


def _check_gemini_creds() -> CheckResult:
    path = Path(os.environ.get("GEMINI_OAUTH_CREDS_PATH", "~/.gemini/oauth_creds.json")).expanduser()
    if not path.exists():
        return CheckResult("Gemini OAuth cache", False, f"missing: {path} (run `gemini auth login`)")
    creds = load_gemini_creds(path)
    ok = bool(creds.access_token or creds.refresh_token)
    return CheckResult("Gemini OAuth cache", ok, f"{path} (access={bool(creds.access_token)} refresh={bool(creds.refresh_token)})")


async def _check_claude_oauth_refreshable() -> CheckResult:
    path = Path(os.environ.get("CLAUDE_OAUTH_CREDS_PATH", "~/.claude/oauth_creds.json")).expanduser()
    if not path.exists():
        return CheckResult(
            "Claude OAuth cache",
            False,
            f"missing: {path} (run `python -m codex_gateway.claude_oauth_login`)",
        )
    try:
        creds = await maybe_refresh_claude_oauth(str(path))
    except Exception as e:
        return CheckResult("Claude OAuth cache", False, f"{path} (refresh failed: {e})")
    ok = bool(creds.access_token or creds.refresh_token)
    return CheckResult(
        "Claude OAuth cache",
        ok,
        f"{path} (access={bool(creds.access_token)} refresh={bool(creds.refresh_token)})",
    )


async def run_doctor() -> int:
    checks: list[CheckResult] = []

    checks.append(_check_binary("codex", "codex"))
    checks.append(_check_binary("gemini", "gemini"))
    checks.append(_check_binary("claude", "claude"))
    checks.append(_check_binary("cursor-agent", "cursor-agent"))

    checks.append(_check_codex_auth())
    checks.append(_check_gemini_creds())
    checks.append(await _check_claude_oauth_refreshable())

    workspace = os.environ.get("CODEX_WORKSPACE")
    if workspace:
        checks.append(_check_file("CODEX_WORKSPACE", Path(workspace).expanduser()))

    width = max(len(c.name) for c in checks) if checks else 10
    print("agent-cli-to-api doctor\n")
    for c in checks:
        print(f"- {c.name.ljust(width)} : {_fmt_bool(c.ok)}  {c.details}")

    ok_all = all(c.ok for c in checks)
    print(f"\nResult: {'OK' if ok_all else 'FAIL'}")
    return 0 if ok_all else 1


def main(argv: list[str] | None = None) -> None:
    _ = argv
    code = asyncio.run(run_doctor())
    raise SystemExit(code)


if __name__ == "__main__":
    main(sys.argv[1:])

