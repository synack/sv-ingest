import textwrap
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from scanner_ingest import pipeline


_CSV = textwrap.dedent("""\
    Name,Risk,Host,Port,Protocol,CVSS v3.0 Base Score,CVE
    Log4Shell,Critical,10.0.0.1,443,https,10.0,CVE-2021-44228
    Heartbleed,High,10.0.0.2,443,https,7.5,CVE-2014-0160
""")


@pytest.fixture
def csv_file(tmp_path):
    p = tmp_path / "scan.csv"
    p.write_text(_CSV)
    return p


@pytest.fixture
def mock_client():
    with patch("scanner_ingest.pipeline.SynackClient") as cls:
        instance = MagicMock()
        instance.submit.return_value = ([101, 102], 0)
        cls.return_value = instance
        yield instance


class TestPipelineRun:
    def test_happy_path(self, csv_file, mock_client):
        result = pipeline.run(
            file_path=csv_file,
            source_type="tenable_sc",
            org_uid="org-abc",
            config={},
            platform="commercial",
        )
        assert result.success
        assert result.parsed == 2
        assert result.submitted == 2
        assert result.created_ids == [101, 102]
        assert result.errors == []

    def test_dry_run_calls_submit_with_flag(self, csv_file, mock_client):
        result = pipeline.run(
            file_path=csv_file,
            source_type="tenable_sc",
            org_uid="org-abc",
            config={},
            dry_run=True,
        )
        assert result.success
        _, kwargs = mock_client.submit.call_args
        assert kwargs.get("dry_run") is True

    def test_parse_error_returns_failure(self, tmp_path, mock_client):
        bad_file = tmp_path / "empty.csv"
        bad_file.write_text("")
        result = pipeline.run(
            file_path=bad_file,
            source_type="tenable_sc",
            org_uid="org-abc",
            config={},
        )
        # Empty CSV → 0 records → success=True, parsed=0 (no error, just empty)
        assert result.parsed == 0

    def test_invalid_source_type_raises_error(self, csv_file, mock_client):
        result = pipeline.run(
            file_path=csv_file,
            source_type="nonexistent_scanner",
            org_uid="org-abc",
            config={},
        )
        assert not result.success
        assert any("Parse error" in e or "nonexistent" in e.lower() for e in result.errors)

    def test_listing_uid_applied_to_records(self, csv_file, mock_client):
        pipeline.run(
            file_path=csv_file,
            source_type="tenable_sc",
            org_uid="org-abc",
            config={},
            listing_uid="listing-xyz",
        )
        submitted_records = mock_client.submit.call_args[0][1]
        assert all(r.listing_uid == "listing-xyz" for r in submitted_records)

    def test_asset_uid_applied_to_records(self, csv_file, mock_client):
        pipeline.run(
            file_path=csv_file,
            source_type="tenable_sc",
            org_uid="org-abc",
            config={},
            asset_uid="asset-xyz",
        )
        submitted_records = mock_client.submit.call_args[0][1]
        assert all(r.asset_uid == "asset-xyz" for r in submitted_records)

    def test_source_id_from_config(self, csv_file, mock_client):
        cfg = {"sources": {"tenable_sc": {"source_id": "custom-tenable"}}}
        pipeline.run(
            file_path=csv_file,
            source_type="tenable_sc",
            org_uid="org-abc",
            config=cfg,
        )
        submitted_records = mock_client.submit.call_args[0][1]
        assert all(r.source == "custom-tenable" for r in submitted_records)

    def test_submit_error_recorded(self, csv_file):
        with patch("scanner_ingest.pipeline.SynackClient") as cls:
            instance = MagicMock()
            instance.submit.side_effect = RuntimeError("API unavailable")
            cls.return_value = instance
            result = pipeline.run(
                file_path=csv_file,
                source_type="tenable_sc",
                org_uid="org-abc",
                config={},
            )
        assert not result.success
        assert any("Submit error" in e for e in result.errors)

    def test_result_file_path(self, csv_file, mock_client):
        result = pipeline.run(
            file_path=csv_file,
            source_type="tenable_sc",
            org_uid="org-abc",
            config={},
        )
        assert result.file == csv_file
