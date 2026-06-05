"""
File-based token store for container deployments.

Activated when SYNACK_TOKEN_FILE env var is set (the Containerfile sets it to
/data/tokens.json automatically).  On the host (CLI) the env var is not set,
so auth.py falls through to the OS keychain instead.
"""
from __future__ import annotations

import json
import os
from pathlib import Path


def _path() -> Path | None:
    env = os.getenv("SYNACK_TOKEN_FILE")
    return Path(env) if env else None


def is_configured() -> bool:
    """True when SYNACK_TOKEN_FILE is set (i.e. running in a container)."""
    return _path() is not None


def get_token(platform: str) -> str:
    p = _path()
    if p is None or not p.exists():
        return ""
    try:
        return json.loads(p.read_text()).get(platform, "")
    except (json.JSONDecodeError, OSError):
        return ""


def set_token(platform: str, token: str) -> None:
    p = _path()
    if p is None:
        raise RuntimeError(
            "SYNACK_TOKEN_FILE is not set. "
            "Ensure the /data volume is mounted and the env var is configured."
        )
    p.parent.mkdir(parents=True, exist_ok=True)
    data: dict = {}
    if p.exists():
        try:
            data = json.loads(p.read_text())
        except (json.JSONDecodeError, OSError):
            pass
    data[platform] = token
    p.write_text(json.dumps(data, indent=2))
    p.chmod(0o600)


def delete_token(platform: str) -> None:
    p = _path()
    if p is None or not p.exists():
        return
    try:
        data = json.loads(p.read_text())
        data.pop(platform, None)
        p.write_text(json.dumps(data, indent=2))
    except (json.JSONDecodeError, OSError):
        pass
