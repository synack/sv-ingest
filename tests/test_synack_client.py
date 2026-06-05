"""
Unit tests for SynackClient and resolve_org_uid.

HTTP calls are intercepted by patching requests.Session so no real network
traffic is generated.  auth.get_token is patched to return a fake token so
tests are independent of the OS keychain and any env vars.
"""
import json
from unittest.mock import MagicMock, call, patch

import pytest
import requests

from scanner_ingest.models import VulnerabilityRecord
from scanner_ingest.synack_client import SynackClient, resolve_org_uid


FAKE_TOKEN = "test-bearer-token"
CONFIG = {"synack": {"token": FAKE_TOKEN}}
ORG_UID = "org-test-123"
VULN_URL = f"https://client.synack.com/api/vulnerability/v1/organizations/{ORG_UID}/suspected-vulnerabilities"


def _rec(name="Test Vuln", location="10.0.0.1", cvss_score=5.0, **kwargs):
    return VulnerabilityRecord(name=name, location=location, cvss_score=cvss_score, source="test", **kwargs)


def _resp(status=201, body=None):
    r = MagicMock(spec=requests.Response)
    r.status_code = status
    r.json.return_value = body if body is not None else []
    r.headers = {}
    r.text = json.dumps(body) if body is not None else ""
    return r


# Patch auth so tests never touch the OS keychain
@pytest.fixture(autouse=True)
def _no_keychain(monkeypatch):
    monkeypatch.setattr("scanner_ingest.synack_client.auth.get_token", lambda p, c: c.get("synack", {}).get("token", ""))


# ---------------------------------------------------------------------------
# SynackClient initialisation
# ---------------------------------------------------------------------------

class TestSynackClientInit:
    def test_raises_without_token(self):
        with pytest.raises(ValueError, match="No Synack token"):
            SynackClient({}, platform="commercial")

    def test_default_batch_and_retry(self):
        c = SynackClient(CONFIG)
        assert c._batch == 100
        assert c._retry == 3

    def test_custom_batch_size(self):
        c = SynackClient({"synack": {"token": "tok", "batch_size": 25}})
        assert c._batch == 25

    def test_custom_retry_attempts(self):
        c = SynackClient({"synack": {"token": "tok", "retry_attempts": 5}})
        assert c._retry == 5

    def test_fedramp_platform_uses_correct_base(self):
        c = SynackClient({"synack": {"token": "tok"}}, platform="fedramp")
        assert "synack.us" in c._base


# ---------------------------------------------------------------------------
# submit()
# ---------------------------------------------------------------------------

class TestSubmit:
    def test_dry_run_makes_no_http_calls(self):
        c = SynackClient(CONFIG)
        with patch.object(c._session, "post") as mock_post:
            ids, skipped = c.submit(ORG_UID, [_rec()], dry_run=True)
        mock_post.assert_not_called()
        assert ids == []
        assert skipped == 0

    def test_happy_path_returns_ids(self):
        c = SynackClient(CONFIG)
        with patch.object(c._session, "post", return_value=_resp(201, [101, 102])):
            ids, skipped = c.submit(ORG_UID, [_rec("A"), _rec("B")])
        assert ids == [101, 102]
        assert skipped == 0

    def test_batching_splits_into_correct_number_of_posts(self):
        c = SynackClient({"synack": {"token": "tok", "batch_size": 2}})
        records = [_rec(f"V{i}") for i in range(5)]
        with patch.object(c._session, "post", return_value=_resp(201, [1])) as mock_post:
            c.submit(ORG_UID, records)
        assert mock_post.call_count == 3  # ceil(5/2)

    def test_batch_payload_is_serialized(self):
        c = SynackClient(CONFIG)
        rec = _rec("SQL Injection", "10.0.0.1", cvss_score=9.8, severity="high")
        with patch.object(c._session, "post", return_value=_resp(201, [7])) as mock_post:
            c.submit(ORG_UID, [rec])
        posted_payload = mock_post.call_args.kwargs["json"]
        assert len(posted_payload) == 1
        assert posted_payload[0]["name"] == "SQL Injection"
        assert posted_payload[0]["cvssScore"] == 9.8
        assert posted_payload[0]["severity"] == "high"

    def test_progress_callback_receives_running_totals(self):
        c = SynackClient({"synack": {"token": "tok", "batch_size": 2}})
        records = [_rec(f"V{i}") for i in range(4)]
        cb_calls = []
        with patch.object(c._session, "post", return_value=_resp(201, [])):
            c.submit(ORG_UID, records, progress_cb=lambda s, t: cb_calls.append((s, t)))
        assert cb_calls == [(2, 4), (4, 4)]

    def test_raises_without_org_uid(self):
        c = SynackClient(CONFIG)
        with pytest.raises(ValueError, match="organization_uid"):
            c.submit("", [_rec()])

    def test_all_batch_ids_aggregated(self):
        c = SynackClient({"synack": {"token": "tok", "batch_size": 1}})
        side_effects = [_resp(201, [10]), _resp(201, [20]), _resp(201, [30])]
        with patch.object(c._session, "post", side_effect=side_effects):
            ids, skipped = c.submit(ORG_UID, [_rec(f"V{i}") for i in range(3)])
        assert ids == [10, 20, 30]
        assert skipped == 0


# ---------------------------------------------------------------------------
# _post_with_retry()
# ---------------------------------------------------------------------------

class TestPostWithRetry:
    def test_201_returns_ids_immediately(self):
        c = SynackClient(CONFIG)
        with patch.object(c._session, "post", return_value=_resp(201, [42])):
            assert c._post_with_retry(VULN_URL, [{}]) == [42]

    def test_retryable_status_then_success(self):
        c = SynackClient(CONFIG)
        responses = [_resp(500), _resp(503), _resp(201, [99])]
        with patch.object(c._session, "post", side_effect=responses):
            with patch("scanner_ingest.synack_client.time.sleep"):
                ids = c._post_with_retry(VULN_URL, [{}])
        assert ids == [99]

    def test_non_retryable_error_raises_immediately(self):
        c = SynackClient(CONFIG)
        for status in (400, 401, 403, 404):
            with patch.object(c._session, "post", return_value=_resp(status)):
                with pytest.raises(RuntimeError, match=f"HTTP {status}"):
                    c._post_with_retry(VULN_URL, [{}])

    def test_exhausts_retries_raises_with_attempt_count(self):
        c = SynackClient({"synack": {"token": "tok", "retry_attempts": 2}})
        with patch.object(c._session, "post", return_value=_resp(500)):
            with patch("scanner_ingest.synack_client.time.sleep"):
                with pytest.raises(RuntimeError, match="2 attempts"):
                    c._post_with_retry(VULN_URL, [{}])

    def test_connection_error_retries_then_raises(self):
        c = SynackClient({"synack": {"token": "tok", "retry_attempts": 2}})
        with patch.object(c._session, "post", side_effect=requests.ConnectionError("down")):
            with patch("scanner_ingest.synack_client.time.sleep"):
                with pytest.raises(RuntimeError, match="Connection error"):
                    c._post_with_retry(VULN_URL, [{}])

    def test_retry_after_header_respected(self):
        c = SynackClient(CONFIG)
        rate_limited = _resp(429)
        rate_limited.headers = {"Retry-After": "7"}
        sleep_args = []
        with patch.object(c._session, "post", side_effect=[rate_limited, _resp(201, [])]):
            with patch("scanner_ingest.synack_client.time.sleep", side_effect=lambda s: sleep_args.append(s)):
                c._post_with_retry(VULN_URL, [{}])
        assert sleep_args[0] == 7.0

    def test_delay_doubles_on_each_retry(self):
        c = SynackClient({"synack": {"token": "tok", "retry_attempts": 3}})
        sleep_args = []
        with patch.object(c._session, "post", side_effect=[_resp(500), _resp(500), _resp(201, [])]):
            with patch("scanner_ingest.synack_client.time.sleep", side_effect=lambda s: sleep_args.append(s)):
                c._post_with_retry(VULN_URL, [{}])
        assert sleep_args[1] == sleep_args[0] * 2


# ---------------------------------------------------------------------------
# resolve_org_uid()
# ---------------------------------------------------------------------------

class TestResolveOrgUid:
    def test_resolves_uid_from_first_asset(self):
        data = {"assets": [{"organizationUid": "org-abc123"}]}
        with patch("requests.get", return_value=_resp(200, data)):
            uid = resolve_org_uid("commercial", CONFIG)
        assert uid == "org-abc123"

    def test_handles_flat_list_response(self):
        data = [{"organizationUid": "org-flat"}]
        with patch("requests.get", return_value=_resp(200, data)):
            uid = resolve_org_uid("commercial", CONFIG)
        assert uid == "org-flat"

    def test_raises_without_token(self):
        with pytest.raises(ValueError, match="No token"):
            resolve_org_uid("commercial", {})

    def test_raises_when_asset_list_empty(self):
        with patch("requests.get", return_value=_resp(200, {"assets": []})):
            with pytest.raises(ValueError, match="No assets"):
                resolve_org_uid("commercial", CONFIG)

    def test_raises_when_org_uid_absent_from_asset(self):
        data = {"assets": [{"id": "x", "name": "asset-without-org-uid"}]}
        with patch("requests.get", return_value=_resp(200, data)):
            with pytest.raises(ValueError, match="organizationUid"):
                resolve_org_uid("commercial", CONFIG)

    def test_request_includes_bearer_token(self):
        data = {"assets": [{"organizationUid": "org-xyz"}]}
        with patch("requests.get", return_value=_resp(200, data)) as mock_get:
            resolve_org_uid("commercial", CONFIG)
        headers = mock_get.call_args.kwargs["headers"]
        assert headers["Authorization"] == f"Bearer {FAKE_TOKEN}"
