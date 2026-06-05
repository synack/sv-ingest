"""
Web API endpoint tests using FastAPI's TestClient (backed by httpx).

auth functions are patched to avoid keychain access.
pipeline.run is patched so ingest tests don't make real API calls.
Background threads are replaced with a synchronous inline runner so tests
don't need to sleep or poll.
"""
import textwrap
from unittest.mock import MagicMock, patch

import pytest
from fastapi.testclient import TestClient

from scanner_ingest import pipeline as _pipeline_module
from scanner_ingest.pipeline import IngestResult
from web.ingest_ui import _jobs, _Job, app


@pytest.fixture
def client():
    return TestClient(app)


@pytest.fixture(autouse=True)
def _clear_jobs():
    _jobs.clear()
    yield
    _jobs.clear()


@pytest.fixture(autouse=True)
def _mock_auth(monkeypatch):
    """Prevent all keychain and env-var token lookups during web tests."""
    monkeypatch.setattr("scanner_ingest.auth.get_token",
                        lambda p, c=None: "test-token" if p == "commercial" else "")
    monkeypatch.setattr("scanner_ingest.auth.set_token", lambda p, t: None)
    monkeypatch.setattr("scanner_ingest.auth.delete_token", lambda p: None)
    monkeypatch.setattr("scanner_ingest.auth.token_source",
                        lambda p, c=None: "keyring" if p == "commercial" else "not set")
    monkeypatch.setattr("scanner_ingest.auth.mask_token",
                        lambda t: "••••••••••••" if t else "(none)")


class _InlineThread:
    """Replaces threading.Thread; runs the target synchronously on .start()."""
    def __init__(self, target=None, args=(), daemon=False, **_):
        self._target = target
        self._args = args

    def start(self):
        if self._target:
            self._target(*self._args)


# ---------------------------------------------------------------------------
# Index page
# ---------------------------------------------------------------------------

class TestIndex:
    def test_returns_200(self, client):
        assert client.get("/").status_code == 200

    def test_response_is_html(self, client):
        resp = client.get("/")
        assert "text/html" in resp.headers["content-type"]


# ---------------------------------------------------------------------------
# Token endpoints
# ---------------------------------------------------------------------------

class TestGetTokens:
    def test_returns_200(self, client):
        assert client.get("/api/tokens").status_code == 200

    def test_response_is_html(self, client):
        resp = client.get("/api/tokens")
        assert "text/html" in resp.headers["content-type"]


class TestSetToken:
    def test_valid_platform_returns_200(self, client, monkeypatch):
        calls = []
        monkeypatch.setattr("scanner_ingest.auth.set_token",
                            lambda p, t: calls.append((p, t)))
        resp = client.post("/api/tokens/commercial", data={"token": "eyJtest"})
        assert resp.status_code == 200
        assert calls == [("commercial", "eyJtest")]

    def test_unknown_platform_returns_400(self, client):
        resp = client.post("/api/tokens/invalid", data={"token": "tok"})
        assert resp.status_code == 400

    def test_empty_token_not_stored(self, client, monkeypatch):
        calls = []
        monkeypatch.setattr("scanner_ingest.auth.set_token",
                            lambda p, t: calls.append((p, t)))
        client.post("/api/tokens/commercial", data={"token": "   "})
        assert calls == []


class TestDeleteToken:
    def test_valid_platform_returns_200(self, client, monkeypatch):
        calls = []
        monkeypatch.setattr("scanner_ingest.auth.delete_token",
                            lambda p: calls.append(p))
        resp = client.delete("/api/tokens/commercial")
        assert resp.status_code == 200
        assert "commercial" in calls

    def test_unknown_platform_returns_400(self, client):
        resp = client.delete("/api/tokens/invalid")
        assert resp.status_code == 400


# ---------------------------------------------------------------------------
# Org UID resolution
# ---------------------------------------------------------------------------

class TestGetOrgUid:
    def test_returns_uid_on_success(self, client):
        with patch("web.ingest_ui.resolve_org_uid", return_value="org-abc123"):
            resp = client.get("/api/org-uid/commercial")
        assert resp.status_code == 200
        assert resp.text == "org-abc123"

    def test_unknown_platform_returns_400(self, client):
        resp = client.get("/api/org-uid/invalid")
        assert resp.status_code == 400

    def test_resolution_error_returns_422(self, client):
        with patch("web.ingest_ui.resolve_org_uid", side_effect=ValueError("No token")):
            resp = client.get("/api/org-uid/fedramp")
        assert resp.status_code == 422
        assert "Error" in resp.text


# ---------------------------------------------------------------------------
# Ingest — job lifecycle
# ---------------------------------------------------------------------------

_TENABLE_CSV = textwrap.dedent("""\
    Name,Risk,Host,Port,Protocol,CVSS v3.0 Base Score,CVE
    Log4Shell,Critical,10.0.0.1,443,https,10.0,CVE-2021-44228
""")


def _fake_result(tmp_path, parsed=1, success=True):
    from pathlib import Path
    r = IngestResult(file=Path("scan.csv"), source_type="tenable_sc", org_uid="org-abc")
    r.parsed = parsed
    r.submitted = parsed if success else 0
    r.created_ids = list(range(parsed)) if success else []
    if not success:
        r.errors.append("Submit error: API unavailable")
    return r


class TestIngestStart:
    def test_returns_job_id(self, client, tmp_path):
        csv = tmp_path / "scan.csv"
        csv.write_text(_TENABLE_CSV)

        with patch("web.ingest_ui.threading.Thread", _InlineThread):
            with patch("web.ingest_ui.pipeline.run", return_value=_fake_result(tmp_path)):
                resp = client.post("/api/ingest", data={
                    "source_type": "tenable_sc",
                    "platform": "commercial",
                    "org_uid": "org-abc",
                }, files={"file": ("scan.csv", csv.read_bytes(), "text/csv")})

        assert resp.status_code == 200
        assert "job_id" in resp.json()

    def test_dry_run_flag_passed_to_pipeline(self, client, tmp_path):
        csv = tmp_path / "scan.csv"
        csv.write_text(_TENABLE_CSV)
        captured = {}

        def fake_run(**kwargs):
            captured.update(kwargs)
            return _fake_result(tmp_path)

        with patch("web.ingest_ui.threading.Thread", _InlineThread):
            with patch("web.ingest_ui.pipeline.run", side_effect=fake_run):
                client.post("/api/ingest", data={
                    "source_type": "tenable_sc",
                    "platform": "commercial",
                    "org_uid": "org-abc",
                    "dry_run": "1",
                }, files={"file": ("scan.csv", csv.read_bytes(), "text/csv")})

        assert captured.get("dry_run") is True

    def test_source_override_passed_to_config(self, client, tmp_path):
        csv = tmp_path / "scan.csv"
        csv.write_text(_TENABLE_CSV)
        captured = {}

        def fake_run(**kwargs):
            captured.update(kwargs)
            return _fake_result(tmp_path)

        with patch("web.ingest_ui.threading.Thread", _InlineThread):
            with patch("web.ingest_ui.pipeline.run", side_effect=fake_run):
                client.post("/api/ingest", data={
                    "source_type": "tenable_sc",
                    "platform": "commercial",
                    "org_uid": "org-abc",
                    "source_override": "my-scanner",
                }, files={"file": ("scan.csv", csv.read_bytes(), "text/csv")})

        source_id = captured["config"]["sources"]["tenable_sc"]["source_id"]
        assert source_id == "my-scanner"

    def test_listing_uid_passed_to_pipeline(self, client, tmp_path):
        csv = tmp_path / "scan.csv"
        csv.write_text(_TENABLE_CSV)
        captured = {}

        def fake_run(**kwargs):
            captured.update(kwargs)
            return _fake_result(tmp_path)

        with patch("web.ingest_ui.threading.Thread", _InlineThread):
            with patch("web.ingest_ui.pipeline.run", side_effect=fake_run):
                client.post("/api/ingest", data={
                    "source_type": "tenable_sc",
                    "platform": "commercial",
                    "org_uid": "org-abc",
                    "listing_uid": "listing-xyz",
                }, files={"file": ("scan.csv", csv.read_bytes(), "text/csv")})

        assert captured.get("listing_uid") == "listing-xyz"


# ---------------------------------------------------------------------------
# Ingest progress polling
# ---------------------------------------------------------------------------

class TestIngestProgress:
    def test_unknown_job_returns_404(self, client):
        assert client.get("/api/ingest/progress/nonexistent").status_code == 404

    def test_parsing_phase(self, client):
        _jobs["job1"] = _Job(phase="parsing", total=0, submitted=0)
        resp = client.get("/api/ingest/progress/job1")
        assert resp.status_code == 200
        data = resp.json()
        assert data["phase"] == "parsing"
        assert data["pct"] is None

    def test_submitting_phase_with_percentage(self, client):
        _jobs["job2"] = _Job(phase="submitting", total=100, submitted=42)
        resp = client.get("/api/ingest/progress/job2")
        data = resp.json()
        assert data["phase"] == "submitting"
        assert data["pct"] == 42
        assert data["submitted"] == 42
        assert data["total"] == 100

    def test_done_phase(self, client):
        _jobs["job3"] = _Job(phase="done")
        data = client.get("/api/ingest/progress/job3").json()
        assert data["phase"] == "done"
        assert data["pct"] is None

    def test_pct_capped_at_99_during_submission(self, client):
        _jobs["job4"] = _Job(phase="submitting", total=100, submitted=100)
        data = client.get("/api/ingest/progress/job4").json()
        assert data["pct"] == 99


# ---------------------------------------------------------------------------
# Ingest result fetching
# ---------------------------------------------------------------------------

class TestIngestResult:
    def test_202_when_job_not_done(self, client):
        _jobs["job5"] = _Job(phase="parsing")
        assert client.get("/api/ingest/result/job5").status_code == 202

    def test_202_for_unknown_job(self, client):
        assert client.get("/api/ingest/result/nonexistent").status_code == 202

    def test_200_with_html_when_done(self, client):
        _jobs["job6"] = _Job(phase="done", result_html="<p>Done</p>")
        resp = client.get("/api/ingest/result/job6")
        assert resp.status_code == 200
        assert "Done" in resp.text

    def test_job_removed_after_result_fetched(self, client):
        _jobs["job7"] = _Job(phase="done", result_html="<p>Done</p>")
        client.get("/api/ingest/result/job7")
        assert "job7" not in _jobs
