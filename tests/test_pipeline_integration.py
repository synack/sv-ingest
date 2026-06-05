"""
Pipeline integration tests: real adapters + real SynackClient, HTTP mocked.

These tests exercise the full file → adapter → SynackClient → HTTP stack.
Only the outbound requests.Session.post call is replaced with a mock, so
all parsing, batching, retry, and serialisation logic runs for real.
"""
import json
import textwrap
from unittest.mock import MagicMock, patch

import pytest
import requests

from scanner_ingest import pipeline


CONFIG = {"synack": {"token": "integration-test-token"}}

_TENABLE_CSV = textwrap.dedent("""\
    Name,Risk,Host,Port,Protocol,CVSS v3.0 Base Score,CVE
    Log4Shell,Critical,10.0.0.1,443,https,10.0,CVE-2021-44228
    Heartbleed,High,10.0.0.2,443,https,7.5,CVE-2014-0160
    Info Finding,Info,10.0.0.3,80,http,0.0,
""")

_CISA_KEV_CSV = textwrap.dedent("""\
    cveID,vendorProject,product,vulnerabilityName,dateAdded,shortDescription,requiredAction,dueDate
    CVE-2021-44228,Apache,Log4j,Log4Shell,2021-12-10,RCE via JNDI,Patch now,2021-12-24
    CVE-2014-0160,OpenSSL,OpenSSL,Heartbleed,2022-01-01,Memory leak,Upgrade,2022-01-15
""")


def _mock_post(status=201, ids=None):
    r = MagicMock(spec=requests.Response)
    r.status_code = status
    r.json.return_value = ids if ids is not None else []
    r.headers = {}
    r.text = json.dumps(ids) if ids is not None else ""
    return r


@pytest.fixture(autouse=True)
def _no_keychain(monkeypatch):
    monkeypatch.setattr("scanner_ingest.synack_client.auth.get_token", lambda p, c: c.get("synack", {}).get("token", ""))


@pytest.fixture
def tenable_csv(tmp_path):
    p = tmp_path / "scan.csv"
    p.write_text(_TENABLE_CSV)
    return p


@pytest.fixture
def kev_csv(tmp_path):
    p = tmp_path / "kev.csv"
    p.write_text(_CISA_KEV_CSV)
    return p


# ---------------------------------------------------------------------------
# End-to-end: file → adapter → SynackClient → mocked HTTP
# ---------------------------------------------------------------------------

class TestPipelineEndToEnd:
    def test_tenable_csv_happy_path(self, tenable_csv):
        with patch("scanner_ingest.synack_client.requests.Session") as MockSession:
            session = MagicMock()
            session.post.return_value = _mock_post(201, [101, 102, 103])
            MockSession.return_value = session

            result = pipeline.run(
                file_path=tenable_csv,
                source_type="tenable_sc",
                org_uid="org-abc",
                config=CONFIG,
            )

        assert result.success
        assert result.parsed == 3
        assert result.submitted == 3
        assert result.created_ids == [101, 102, 103]
        session.post.assert_called_once()

    def test_cisa_kev_csv_happy_path(self, kev_csv):
        with patch("scanner_ingest.synack_client.requests.Session") as MockSession:
            session = MagicMock()
            session.post.return_value = _mock_post(201, [201, 202])
            MockSession.return_value = session

            result = pipeline.run(
                file_path=kev_csv,
                source_type="cisa",
                org_uid="org-abc",
                config=CONFIG,
            )

        assert result.success
        assert result.parsed == 2
        assert result.created_ids == [201, 202]

    def test_dry_run_parses_but_does_not_post(self, tenable_csv):
        with patch("scanner_ingest.synack_client.requests.Session") as MockSession:
            session = MagicMock()
            MockSession.return_value = session

            result = pipeline.run(
                file_path=tenable_csv,
                source_type="tenable_sc",
                org_uid="org-abc",
                config=CONFIG,
                dry_run=True,
            )

        assert result.success
        assert result.parsed == 3
        session.post.assert_not_called()

    def test_post_url_contains_org_uid(self, tenable_csv):
        with patch("scanner_ingest.synack_client.requests.Session") as MockSession:
            session = MagicMock()
            session.post.return_value = _mock_post(201, [1])
            MockSession.return_value = session

            pipeline.run(
                file_path=tenable_csv,
                source_type="tenable_sc",
                org_uid="org-specific-uid",
                config=CONFIG,
            )

        url = session.post.call_args.args[0]
        assert "org-specific-uid" in url

    def test_payload_records_are_correctly_serialized(self, tenable_csv):
        with patch("scanner_ingest.synack_client.requests.Session") as MockSession:
            session = MagicMock()
            session.post.return_value = _mock_post(201, [1])
            MockSession.return_value = session

            pipeline.run(
                file_path=tenable_csv,
                source_type="tenable_sc",
                org_uid="org-abc",
                config=CONFIG,
            )

        payload = session.post.call_args.kwargs["json"]
        log4shell = next(r for r in payload if r["name"] == "Log4Shell")
        assert log4shell["cvssScore"] == 10.0
        assert log4shell["location"] == "https://10.0.0.1:443"
        assert log4shell["severity"] == "critical"
        assert "CVE-2021-44228" in log4shell["cves"]

    def test_bearer_token_in_request_headers(self, tenable_csv):
        with patch("scanner_ingest.synack_client.requests.Session") as MockSession:
            session = MagicMock()
            session.post.return_value = _mock_post(201, [1])
            MockSession.return_value = session

            pipeline.run(
                file_path=tenable_csv,
                source_type="tenable_sc",
                org_uid="org-abc",
                config=CONFIG,
            )

        # Session headers are set via headers.update() in __init__
        update_call = session.headers.update.call_args
        headers = update_call.args[0]
        assert headers["Authorization"] == "Bearer integration-test-token"


# ---------------------------------------------------------------------------
# Batching
# ---------------------------------------------------------------------------

class TestPipelineBatching:
    def test_records_split_into_correct_batches(self, tenable_csv):
        cfg = {**CONFIG, "synack": {"token": "integration-test-token", "batch_size": 1}}
        with patch("scanner_ingest.synack_client.requests.Session") as MockSession:
            session = MagicMock()
            session.post.return_value = _mock_post(201, [1])
            MockSession.return_value = session

            result = pipeline.run(
                file_path=tenable_csv,
                source_type="tenable_sc",
                org_uid="org-abc",
                config=cfg,
            )

        assert session.post.call_count == 3  # 3 records, batch_size=1

    def test_each_batch_payload_has_correct_size(self, tenable_csv):
        cfg = {**CONFIG, "synack": {"token": "integration-test-token", "batch_size": 2}}
        with patch("scanner_ingest.synack_client.requests.Session") as MockSession:
            session = MagicMock()
            session.post.return_value = _mock_post(201, [1])
            MockSession.return_value = session

            pipeline.run(
                file_path=tenable_csv,
                source_type="tenable_sc",
                org_uid="org-abc",
                config=cfg,
            )

        batch_sizes = [len(call.kwargs["json"]) for call in session.post.call_args_list]
        assert batch_sizes == [2, 1]  # 3 records: first batch=2, second batch=1


# ---------------------------------------------------------------------------
# Retry behaviour
# ---------------------------------------------------------------------------

class TestPipelineRetry:
    def test_pipeline_succeeds_after_transient_500(self, tenable_csv):
        with patch("scanner_ingest.synack_client.requests.Session") as MockSession:
            session = MagicMock()
            session.post.side_effect = [_mock_post(500), _mock_post(201, [1, 2, 3])]
            MockSession.return_value = session

            with patch("scanner_ingest.synack_client.time.sleep"):
                result = pipeline.run(
                    file_path=tenable_csv,
                    source_type="tenable_sc",
                    org_uid="org-abc",
                    config=CONFIG,
                )

        assert result.success
        assert session.post.call_count == 2

    def test_pipeline_fails_after_exhausted_retries(self, tenable_csv):
        cfg = {**CONFIG, "synack": {"token": "integration-test-token", "retry_attempts": 2}}
        with patch("scanner_ingest.synack_client.requests.Session") as MockSession:
            session = MagicMock()
            session.post.return_value = _mock_post(500)
            MockSession.return_value = session

            with patch("scanner_ingest.synack_client.time.sleep"):
                result = pipeline.run(
                    file_path=tenable_csv,
                    source_type="tenable_sc",
                    org_uid="org-abc",
                    config=cfg,
                )

        assert not result.success
        assert any("Submit error" in e for e in result.errors)

    def test_non_retryable_error_fails_immediately(self, tenable_csv):
        with patch("scanner_ingest.synack_client.requests.Session") as MockSession:
            session = MagicMock()
            session.post.return_value = _mock_post(401)
            MockSession.return_value = session

            result = pipeline.run(
                file_path=tenable_csv,
                source_type="tenable_sc",
                org_uid="org-abc",
                config=CONFIG,
            )

        # Should fail on first attempt, not retry
        assert not result.success
        assert session.post.call_count == 1
