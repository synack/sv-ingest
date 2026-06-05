"""
Platform selection and token management.

Token lookup order for a given platform:
  1. OS keychain via `keyring`      (CLI on host — set via: python ingest.py token set)
  2. File store via SYNACK_TOKEN_FILE (container deployments — set via web UI)
  3. Platform-specific env var      (SYNACK_TOKEN or SYNACK_FEDRAMP_TOKEN)
  4. Generic fallback env var       (SYNACK_TOKEN)
  5. config.yaml  synack.token      (deprecated — prefer keyring or file store)

set_token / delete_token route to whichever backend is active:
  - SYNACK_TOKEN_FILE set → file store  (container)
  - otherwise             → OS keychain (host/CLI)
"""
from __future__ import annotations

import os

import keyring

from scanner_ingest import token_store

PLATFORMS: dict[str, str] = {
    "commercial": "https://api.synack.com",
    "fedramp":    "https://api.synack.us",
}

_KEYRING_SERVICE = "synack-scanner-ingest"

_ENV_VARS: dict[str, str] = {
    "commercial": "SYNACK_TOKEN",
    "fedramp":    "SYNACK_FEDRAMP_TOKEN",
}


def platform_url(platform: str) -> str:
    try:
        return PLATFORMS[platform]
    except KeyError:
        raise ValueError(f"Unknown platform {platform!r}. Valid: {list(PLATFORMS)}") from None


def get_token(platform: str, config: dict | None = None) -> str:
    """Return the best available token for the given platform."""
    # 1. OS keychain (host/CLI)
    try:
        stored = keyring.get_password(_KEYRING_SERVICE, platform)
        if stored:
            return stored
    except Exception:
        pass

    # 2. File store (container)
    file_token = token_store.get_token(platform)
    if file_token:
        return file_token

    # 3. Platform-specific env var
    env_var = _ENV_VARS.get(platform, "SYNACK_TOKEN")
    token = os.getenv(env_var, "")
    if token:
        return token

    # 4. Generic env var fallback
    if platform != "commercial":
        token = os.getenv("SYNACK_TOKEN", "")
        if token:
            return token

    # 5. config.yaml fallback
    if config:
        token = config.get("synack", {}).get("token", "")
        if token:
            return token

    return ""


def set_token(platform: str, token: str) -> None:
    """Store token in the active backend (file store in containers, keychain on host)."""
    if token_store.is_configured():
        token_store.set_token(platform, token)
    else:
        keyring.set_password(_KEYRING_SERVICE, platform, token)


def delete_token(platform: str) -> None:
    """Remove token from the active backend."""
    if token_store.is_configured():
        token_store.delete_token(platform)
    else:
        try:
            keyring.delete_password(_KEYRING_SERVICE, platform)
        except keyring.errors.PasswordDeleteError:
            pass


def token_source(platform: str, config: dict | None = None) -> str:
    """Return a human-readable description of where the token comes from."""
    try:
        if keyring.get_password(_KEYRING_SERVICE, platform):
            return "keyring"
    except Exception:
        pass
    if token_store.get_token(platform):
        return "file store"
    env_var = _ENV_VARS.get(platform, "SYNACK_TOKEN")
    if os.getenv(env_var):
        return f"env:{env_var}"
    if platform != "commercial" and os.getenv("SYNACK_TOKEN"):
        return "env:SYNACK_TOKEN"
    if config and config.get("synack", {}).get("token"):
        return "config.yaml"
    return "not set"


def mask_token(token: str) -> str:
    """Return a fixed masked display without revealing any token characters."""
    if not token:
        return "(none)"
    return "••••••••••••"
