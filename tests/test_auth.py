"""
Tests for scanner_ingest.auth and scanner_ingest.token_store.

keyring is patched throughout so tests never touch the OS keychain.
SYNACK_TOKEN_FILE and platform env vars are managed via monkeypatch.
"""
import json
from unittest.mock import patch

import pytest

from scanner_ingest import auth, token_store


# ---------------------------------------------------------------------------
# token_store
# ---------------------------------------------------------------------------

class TestTokenStoreIsConfigured:
    def test_false_when_env_not_set(self, monkeypatch):
        monkeypatch.delenv("SYNACK_TOKEN_FILE", raising=False)
        assert not token_store.is_configured()

    def test_true_when_env_set(self, monkeypatch, tmp_path):
        monkeypatch.setenv("SYNACK_TOKEN_FILE", str(tmp_path / "tokens.json"))
        assert token_store.is_configured()


class TestTokenStoreGetToken:
    def test_returns_empty_when_not_configured(self, monkeypatch):
        monkeypatch.delenv("SYNACK_TOKEN_FILE", raising=False)
        assert token_store.get_token("commercial") == ""

    def test_returns_token_from_file(self, monkeypatch, tmp_path):
        f = tmp_path / "tokens.json"
        f.write_text('{"commercial": "my-token"}')
        monkeypatch.setenv("SYNACK_TOKEN_FILE", str(f))
        assert token_store.get_token("commercial") == "my-token"

    def test_returns_empty_for_missing_platform(self, monkeypatch, tmp_path):
        f = tmp_path / "tokens.json"
        f.write_text('{"commercial": "my-token"}')
        monkeypatch.setenv("SYNACK_TOKEN_FILE", str(f))
        assert token_store.get_token("fedramp") == ""

    def test_returns_empty_when_file_missing(self, monkeypatch, tmp_path):
        monkeypatch.setenv("SYNACK_TOKEN_FILE", str(tmp_path / "nonexistent.json"))
        assert token_store.get_token("commercial") == ""

    def test_returns_empty_on_malformed_json(self, monkeypatch, tmp_path):
        f = tmp_path / "tokens.json"
        f.write_text("not-json{{")
        monkeypatch.setenv("SYNACK_TOKEN_FILE", str(f))
        assert token_store.get_token("commercial") == ""


class TestTokenStoreSetToken:
    def test_creates_file_with_token(self, monkeypatch, tmp_path):
        f = tmp_path / "tokens.json"
        monkeypatch.setenv("SYNACK_TOKEN_FILE", str(f))
        token_store.set_token("commercial", "new-token")
        assert json.loads(f.read_text())["commercial"] == "new-token"

    def test_merges_with_existing_tokens(self, monkeypatch, tmp_path):
        f = tmp_path / "tokens.json"
        f.write_text('{"fedramp": "fr-token"}')
        monkeypatch.setenv("SYNACK_TOKEN_FILE", str(f))
        token_store.set_token("commercial", "comm-token")
        data = json.loads(f.read_text())
        assert data["commercial"] == "comm-token"
        assert data["fedramp"] == "fr-token"

    def test_overwrites_existing_platform_token(self, monkeypatch, tmp_path):
        f = tmp_path / "tokens.json"
        f.write_text('{"commercial": "old-token"}')
        monkeypatch.setenv("SYNACK_TOKEN_FILE", str(f))
        token_store.set_token("commercial", "new-token")
        assert json.loads(f.read_text())["commercial"] == "new-token"

    def test_raises_when_not_configured(self, monkeypatch):
        monkeypatch.delenv("SYNACK_TOKEN_FILE", raising=False)
        with pytest.raises(RuntimeError, match="SYNACK_TOKEN_FILE"):
            token_store.set_token("commercial", "tok")

    def test_sets_file_permissions_to_600(self, monkeypatch, tmp_path):
        f = tmp_path / "tokens.json"
        monkeypatch.setenv("SYNACK_TOKEN_FILE", str(f))
        token_store.set_token("commercial", "tok")
        assert oct(f.stat().st_mode)[-3:] == "600"


class TestTokenStoreDeleteToken:
    def test_removes_token_from_file(self, monkeypatch, tmp_path):
        f = tmp_path / "tokens.json"
        f.write_text('{"commercial": "tok", "fedramp": "fr"}')
        monkeypatch.setenv("SYNACK_TOKEN_FILE", str(f))
        token_store.delete_token("commercial")
        data = json.loads(f.read_text())
        assert "commercial" not in data
        assert data["fedramp"] == "fr"

    def test_noop_when_not_configured(self, monkeypatch):
        monkeypatch.delenv("SYNACK_TOKEN_FILE", raising=False)
        token_store.delete_token("commercial")  # must not raise

    def test_noop_when_file_missing(self, monkeypatch, tmp_path):
        monkeypatch.setenv("SYNACK_TOKEN_FILE", str(tmp_path / "nonexistent.json"))
        token_store.delete_token("commercial")  # must not raise


# ---------------------------------------------------------------------------
# auth.get_token — priority order
# ---------------------------------------------------------------------------

@pytest.fixture(autouse=True)
def _clean_env(monkeypatch):
    for var in ("SYNACK_TOKEN", "SYNACK_FEDRAMP_TOKEN", "SYNACK_TOKEN_FILE"):
        monkeypatch.delenv(var, raising=False)


class TestGetTokenPriority:
    def test_config_yaml_is_lowest_priority(self):
        with patch("keyring.get_password", return_value=None):
            tok = auth.get_token("commercial", {"synack": {"token": "from-config"}})
        assert tok == "from-config"

    def test_env_var_beats_config(self, monkeypatch):
        monkeypatch.setenv("SYNACK_TOKEN", "from-env")
        with patch("keyring.get_password", return_value=None):
            tok = auth.get_token("commercial", {"synack": {"token": "from-config"}})
        assert tok == "from-env"

    def test_file_store_beats_env_var(self, monkeypatch, tmp_path):
        f = tmp_path / "tokens.json"
        f.write_text('{"commercial": "from-file"}')
        monkeypatch.setenv("SYNACK_TOKEN_FILE", str(f))
        monkeypatch.setenv("SYNACK_TOKEN", "from-env")
        with patch("keyring.get_password", return_value=None):
            tok = auth.get_token("commercial")
        assert tok == "from-file"

    def test_keychain_beats_file_store(self, monkeypatch, tmp_path):
        f = tmp_path / "tokens.json"
        f.write_text('{"commercial": "from-file"}')
        monkeypatch.setenv("SYNACK_TOKEN_FILE", str(f))
        with patch("keyring.get_password", return_value="from-keychain"):
            tok = auth.get_token("commercial")
        assert tok == "from-keychain"

    def test_returns_empty_when_nothing_set(self):
        with patch("keyring.get_password", return_value=None):
            assert auth.get_token("commercial", {}) == ""

    def test_fedramp_uses_platform_specific_env_var(self, monkeypatch):
        monkeypatch.setenv("SYNACK_FEDRAMP_TOKEN", "fedramp-env")
        with patch("keyring.get_password", return_value=None):
            assert auth.get_token("fedramp") == "fedramp-env"

    def test_fedramp_falls_back_to_generic_env_var(self, monkeypatch):
        monkeypatch.setenv("SYNACK_TOKEN", "generic-env")
        with patch("keyring.get_password", return_value=None):
            assert auth.get_token("fedramp") == "generic-env"

    def test_commercial_does_not_use_generic_env_var_as_fallback(self, monkeypatch):
        # SYNACK_TOKEN *is* the platform env var for commercial, not a fallback
        monkeypatch.setenv("SYNACK_TOKEN", "env-val")
        with patch("keyring.get_password", return_value=None):
            assert auth.get_token("commercial") == "env-val"

    def test_keychain_exception_falls_through(self):
        with patch("keyring.get_password", side_effect=Exception("no keyring")):
            tok = auth.get_token("commercial", {"synack": {"token": "fallback"}})
        assert tok == "fallback"


# ---------------------------------------------------------------------------
# auth.mask_token
# ---------------------------------------------------------------------------

class TestMaskToken:
    def test_set_token_shows_bullets(self):
        assert auth.mask_token("eyJhbGciOi...") == "••••••••••••"

    def test_empty_token_shows_none(self):
        assert auth.mask_token("") == "(none)"


# ---------------------------------------------------------------------------
# auth.token_source
# ---------------------------------------------------------------------------

class TestTokenSource:
    def test_not_set(self, monkeypatch):
        monkeypatch.delenv("SYNACK_TOKEN", raising=False)
        with patch("keyring.get_password", return_value=None):
            with patch("scanner_ingest.token_store.get_token", return_value=""):
                assert auth.token_source("commercial") == "not set"

    def test_env_var_source(self, monkeypatch):
        monkeypatch.setenv("SYNACK_TOKEN", "tok")
        with patch("keyring.get_password", return_value=None):
            with patch("scanner_ingest.token_store.get_token", return_value=""):
                assert auth.token_source("commercial") == "env:SYNACK_TOKEN"

    def test_file_store_source(self, monkeypatch, tmp_path):
        f = tmp_path / "tokens.json"
        f.write_text('{"commercial": "tok"}')
        monkeypatch.setenv("SYNACK_TOKEN_FILE", str(f))
        with patch("keyring.get_password", return_value=None):
            assert auth.token_source("commercial") == "file store"

    def test_config_source(self, monkeypatch):
        monkeypatch.delenv("SYNACK_TOKEN", raising=False)
        with patch("keyring.get_password", return_value=None):
            with patch("scanner_ingest.token_store.get_token", return_value=""):
                src = auth.token_source("commercial", {"synack": {"token": "tok"}})
        assert src == "config.yaml"

    def test_keyring_source(self):
        with patch("keyring.get_password", return_value="tok"):
            assert auth.token_source("commercial") == "keyring"
