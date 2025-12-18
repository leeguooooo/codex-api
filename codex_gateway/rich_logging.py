from __future__ import annotations

from typing import Any


def build_rich_log_config(*, level: str = "info") -> dict[str, Any]:
    """
    Return a uvicorn-compatible `log_config` dict that uses RichHandler.
    Kept optional to avoid changing defaults for users who want plain logs.
    """
    lvl = (level or "info").upper()
    if lvl not in {"CRITICAL", "ERROR", "WARNING", "INFO", "DEBUG", "TRACE"}:
        lvl = "INFO"

    # NOTE: RichHandler does its own formatting; keep format minimal.
    return {
        "version": 1,
        "disable_existing_loggers": False,
        "formatters": {
            "default": {"format": "%(message)s"},
            # Uvicorn's access logger already formats a readable message; avoid relying on
            # version-specific LogRecord fields like `client_addr`.
            "access": {"format": "%(message)s"},
        },
        "handlers": {
            "rich": {
                "class": "rich.logging.RichHandler",
                "level": lvl,
                "formatter": "default",
                "rich_tracebacks": True,
                "markup": False,
                "show_time": True,
                "show_level": True,
                "show_path": False,
            },
            "access_rich": {
                "class": "rich.logging.RichHandler",
                "level": lvl,
                "formatter": "access",
                "rich_tracebacks": False,
                "markup": False,
                "show_time": True,
                "show_level": False,
                "show_path": False,
            },
        },
        "loggers": {
            "uvicorn": {"handlers": ["rich"], "level": lvl, "propagate": False},
            "uvicorn.error": {"handlers": ["rich"], "level": lvl, "propagate": False},
            "uvicorn.access": {"handlers": ["access_rich"], "level": lvl, "propagate": False},
        },
    }
