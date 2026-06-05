import textwrap

import pytest

from scanner_ingest.adapters.qualys import QualysAdapter, _split_cwes, _parse_qualys_date


@pytest.fixture
def adapter():
    return QualysAdapter(source_id="qualys-was")


def write_csv(tmp_path, content, name="report.csv"):
    p = tmp_path / name
    p.write_text(content)
    return p


_QUALYS_CSV = textwrap.dedent("""\
    VULN_ID,NAME,QID,SEVERITY,BASE CVSS,CWE,CVE,FIRST DETECTION,LAST DETECTION,GROUP,WEB APPLICATION,URL,PAYLOAD REQUEST,PAYLOAD RESPONSE,DESCRIPTION,IMPACT,SOLUTION,VULN TYPE
    1,SQL Injection,12345,5,9.8,CWE-89,CVE-2021-1234,2022-01-01T00:00:00Z,2022-01-15T00:00:00Z,Injection,MyApp,https://example.com/login,,,SQL injection found,Data loss,Use prepared statements,Confirmed
    2,XSS,12346,4,6.5,CWE-79CWE-20,CVE-2021-5678,2022-02-01T00:00:00Z,2022-02-20T00:00:00Z,XSS,MyApp,https://example.com/search,,,XSS found,Session hijack,Escape output,Potential
    3,Info Finding,12347,1,0.0,,,2022-03-01T00:00:00Z,2022-03-15T00:00:00Z,Info,MyApp,https://example.com/info,,,Informational,,Review,
    4,No URL Row,12348,3,5.0,,,2022-04-01T00:00:00Z,2022-04-15T00:00:00Z,Net,MyApp,,,,Missing URL,,Fix,Confirmed
""")

_MISSING_COLS_CSV = textwrap.dedent("""\
    Name,Severity,Score
    Some vuln,High,7.5
""")


class TestSplitCwes:
    def test_single_cwe(self):
        assert _split_cwes("CWE-89") == ["CWE-89"]

    def test_comma_separated(self):
        assert _split_cwes("CWE-89,CWE-79") == ["CWE-89", "CWE-79"]

    def test_semicolon_separated(self):
        assert _split_cwes("CWE-89;CWE-79") == ["CWE-89", "CWE-79"]

    def test_concatenated_no_delimiter(self):
        assert _split_cwes("CWE-20CWE-918") == ["CWE-20", "CWE-918"]

    def test_empty_returns_empty(self):
        assert _split_cwes("") == []
        assert _split_cwes(None) == []
        assert _split_cwes("nan") == []

    def test_ignores_non_cwe(self):
        assert _split_cwes("OWASP-A1,CWE-89") == ["CWE-89"]


class TestParseQualysDate:
    def test_iso_format(self):
        dt = _parse_qualys_date("2022-01-01T00:00:00Z")
        assert dt is not None
        assert dt.year == 2022

    def test_date_only(self):
        dt = _parse_qualys_date("2022-01-01")
        assert dt is not None

    def test_none_returns_none(self):
        assert _parse_qualys_date(None) is None

    def test_empty_returns_none(self):
        assert _parse_qualys_date("") is None


class TestQualysAdapter:
    def test_parses_valid_rows(self, tmp_path, adapter):
        # Row with no URL (row 4) is skipped; Info (row 3) is kept but severity=None
        records = adapter.parse(write_csv(tmp_path, _QUALYS_CSV))
        assert len(records) == 3

    def test_sql_injection_record(self, tmp_path, adapter):
        r = adapter.parse(write_csv(tmp_path, _QUALYS_CSV))[0]
        assert r.name == "SQL Injection"
        assert r.location == "https://example.com/login"
        assert r.cvss_score == 9.8
        assert r.severity == "critical"
        assert "CVE-2021-1234" in r.cves
        assert "CWE-89" in r.cwes
        assert r.confidence == "certain"
        assert r.source == "qualys-was"

    def test_xss_record_concatenated_cwes(self, tmp_path, adapter):
        r = adapter.parse(write_csv(tmp_path, _QUALYS_CSV))[1]
        assert "CWE-79" in r.cwes
        assert "CWE-20" in r.cwes
        assert r.confidence == "tentative"

    def test_info_severity_maps_to_none(self, tmp_path, adapter):
        r = adapter.parse(write_csv(tmp_path, _QUALYS_CSV))[2]
        assert r.severity is None

    def test_no_url_row_skipped(self, tmp_path, adapter):
        names = [r.name for r in adapter.parse(write_csv(tmp_path, _QUALYS_CSV))]
        assert "No URL Row" not in names

    def test_description_plus_impact_combined(self, tmp_path, adapter):
        r = adapter.parse(write_csv(tmp_path, _QUALYS_CSV))[0]
        assert "SQL injection found" in r.description
        assert "Data loss" in r.description

    def test_missing_columns_raises(self, tmp_path, adapter):
        with pytest.raises(ValueError, match="Missing columns"):
            adapter.parse(write_csv(tmp_path, _MISSING_COLS_CSV))

    def test_severity_mapping(self, tmp_path, adapter):
        records = adapter.parse(write_csv(tmp_path, _QUALYS_CSV))
        assert records[0].severity == "critical"  # SEVERITY=5
        assert records[1].severity == "high"       # SEVERITY=4

    def test_dates_parsed(self, tmp_path, adapter):
        r = adapter.parse(write_csv(tmp_path, _QUALYS_CSV))[0]
        assert r.first_found_at is not None
        assert r.first_found_at.year == 2022
