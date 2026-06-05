from datetime import datetime, timezone
from pathlib import Path

import pytest

from scanner_ingest.adapters.base import BaseAdapter
from scanner_ingest.models import VulnerabilityRecord


class _Adapter(BaseAdapter):
    def parse(self, file_path):
        return []


@pytest.fixture
def adapter():
    return _Adapter(source_id="test")


class TestDetectFormat:
    def test_csv(self, tmp_path, adapter):
        f = tmp_path / "scan.csv"
        f.touch()
        assert adapter._detect_format(f) == "csv"

    def test_xlsx(self, tmp_path, adapter):
        f = tmp_path / "scan.xlsx"
        f.touch()
        assert adapter._detect_format(f) == "excel"

    def test_xls(self, tmp_path, adapter):
        f = tmp_path / "scan.xls"
        f.touch()
        assert adapter._detect_format(f) == "excel"

    def test_json(self, tmp_path, adapter):
        f = tmp_path / "scan.json"
        f.touch()
        assert adapter._detect_format(f) == "json"

    def test_unsupported_raises(self, tmp_path, adapter):
        f = tmp_path / "scan.xml"
        f.touch()
        with pytest.raises(ValueError, match="Unsupported file format"):
            adapter._detect_format(f)


class TestParseDate:
    def test_iso_utc(self):
        dt = BaseAdapter._parse_date("2021-12-10T00:00:00Z")
        assert dt == datetime(2021, 12, 10, tzinfo=timezone.utc)

    def test_iso_no_tz(self):
        dt = BaseAdapter._parse_date("2021-12-10T00:00:00")
        assert dt.tzinfo == timezone.utc

    def test_date_only(self):
        dt = BaseAdapter._parse_date("2021-12-10")
        assert dt.year == 2021 and dt.month == 12 and dt.day == 10

    def test_us_format(self):
        dt = BaseAdapter._parse_date("12/10/2021")
        assert dt.month == 12 and dt.day == 10

    def test_empty_string_returns_none(self):
        assert BaseAdapter._parse_date("") is None
        assert BaseAdapter._parse_date("   ") is None

    def test_nan_string_returns_none(self):
        assert BaseAdapter._parse_date("nan") is None
        assert BaseAdapter._parse_date("None") is None

    def test_none_returns_none(self):
        assert BaseAdapter._parse_date(None) is None

    def test_unparseable_returns_none(self):
        assert BaseAdapter._parse_date("not-a-date") is None


class TestSafeFloat:
    def test_integer(self):
        assert BaseAdapter._safe_float(5) == 5.0

    def test_string_float(self):
        assert BaseAdapter._safe_float("7.5") == 7.5

    def test_none_returns_default(self):
        assert BaseAdapter._safe_float(None) == 0.0
        assert BaseAdapter._safe_float(None, default=1.0) == 1.0

    def test_invalid_string_returns_default(self):
        assert BaseAdapter._safe_float("n/a") == 0.0

    def test_zero(self):
        assert BaseAdapter._safe_float(0) == 0.0


class TestSplitIds:
    def test_comma_separated(self):
        assert BaseAdapter._split_ids("CVE-2021-1234, CVE-2021-5678") == ["CVE-2021-1234", "CVE-2021-5678"]

    def test_semicolon_separated(self):
        assert BaseAdapter._split_ids("CVE-2021-1234;CVE-2021-5678") == ["CVE-2021-1234", "CVE-2021-5678"]

    def test_list_passthrough(self):
        assert BaseAdapter._split_ids(["CVE-2021-1234", "CVE-2021-5678"]) == ["CVE-2021-1234", "CVE-2021-5678"]

    def test_empty_string_returns_empty(self):
        assert BaseAdapter._split_ids("") == []
        assert BaseAdapter._split_ids("nan") == []
        assert BaseAdapter._split_ids(None) == []

    def test_strips_whitespace(self):
        result = BaseAdapter._split_ids("  CWE-79  ,  CWE-89  ")
        assert result == ["CWE-79", "CWE-89"]
