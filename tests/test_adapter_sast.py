import json
import textwrap

import pytest

from scanner_ingest.adapters.sast import SASTAdapter, _split_cwes, _parse_owasp_ids


# ---------------------------------------------------------------------------
# _split_cwes
# ---------------------------------------------------------------------------

class TestSplitCwes:
    def test_single(self):
        assert _split_cwes("CWE-209") == ["CWE-209"]

    def test_comma_separated(self):
        assert _split_cwes("CWE-209, CWE-532") == ["CWE-209", "CWE-532"]

    def test_concatenated_no_delimiter(self):
        assert _split_cwes("CWE-20CWE-918") == ["CWE-20", "CWE-918"]

    def test_empty_returns_empty(self):
        assert _split_cwes("") == []

    def test_nan_returns_empty(self):
        assert _split_cwes("nan") == []


# ---------------------------------------------------------------------------
# _parse_owasp_ids
# ---------------------------------------------------------------------------

class TestParseOwaspIds:
    def test_single(self):
        assert _parse_owasp_ids("A02:2021-Cryptographic Failures") == ["A02:2021"]

    def test_multiple_comma_separated(self):
        assert _parse_owasp_ids("A01:2021-Broken Access Control, A03:2021-Injection") == ["A01:2021", "A03:2021"]

    def test_empty_returns_empty(self):
        assert _parse_owasp_ids("") == []

    def test_non_owasp_string_returns_empty(self):
        assert _parse_owasp_ids("N/A") == []


# ---------------------------------------------------------------------------
# CSV/Excel parsing
# ---------------------------------------------------------------------------

_CSV = textwrap.dedent("""\
    Title,Severity,Confidence,CWE,OWASP,Finding Category,File,Line,Description,Impact,Remediation
    Secret key leak,Critical,High,"CWE-209, CWE-532",A02:2021-Cryptographic Failures,secrets,src/main/Interceptor.java,135,Secret in exception,Attacker can read secret,Never log secrets
    Exposed API key,High,High,CWE-200,A01:2021-Broken Access Control,secrets,src/main/RestController.java,60,API key exposed,Unauth access,Remove endpoint
    Open redirect,High,Medium,CWE-601,A01:2021-Broken Access Control,xss,src/main/ErrorAdvice.java,29,Redirect not validated,Phishing risk,Use allowlist
    Hard-coded cred,Medium,Low,CWE-798,,auth,src/config/Secrets.java,42,Password in code,Credential leak,Use secrets manager
    Info finding,Info,High,CWE-200,,info,src/log/Logger.java,10,Verbose log,,Reduce log level
    ,High,High,CWE-200,,secrets,src/main/Foo.java,1,No title row,,
""")


@pytest.fixture
def adapter():
    return SASTAdapter(source_id="sast-test")


def write_csv(tmp_path, content, name="findings.csv"):
    p = tmp_path / name
    p.write_text(content)
    return p


class TestSASTCsv:
    def test_parses_expected_record_count(self, tmp_path, adapter):
        # Info row is kept with severity=None; no-title row is skipped; 5 records
        records = adapter.parse(write_csv(tmp_path, _CSV))
        assert len(records) == 5

    def test_first_record_fields(self, tmp_path, adapter):
        r = adapter.parse(write_csv(tmp_path, _CSV))[0]
        assert r.name == "Secret key leak"
        assert r.location == "src/main/Interceptor.java:135"
        assert r.severity == "critical"
        assert r.confidence == "certain"
        assert r.cvss_score == 9.0
        assert r.cwes == ["CWE-209", "CWE-532"]
        assert r.owasp_ids == ["A02:2021"]
        assert r.category == "secrets"
        assert r.solution == "Never log secrets"
        assert r.source == "sast-test"

    def test_description_plus_impact_combined(self, tmp_path, adapter):
        r = adapter.parse(write_csv(tmp_path, _CSV))[0]
        assert "Secret in exception" in r.description
        assert "Attacker can read secret" in r.description

    def test_severity_info_maps_to_none(self, tmp_path, adapter):
        records = adapter.parse(write_csv(tmp_path, _CSV))
        info = next(r for r in records if r.name == "Info finding")
        assert info.severity is None
        assert info.cvss_score == 0.0

    def test_confidence_mapping(self, tmp_path, adapter):
        records = adapter.parse(write_csv(tmp_path, _CSV))
        assert records[0].confidence == "certain"   # High
        assert records[2].confidence == "firm"       # Medium
        assert records[3].confidence == "tentative"  # Low

    def test_cvss_derived_from_severity(self, tmp_path, adapter):
        csv = textwrap.dedent("""\
            Title,Severity,Confidence,CWE,OWASP,Finding Category,File,Line,Description,Impact,Remediation
            Critical finding,Critical,High,CWE-200,,a,f.java,1,d,i,r
            High finding,High,High,CWE-200,,a,f.java,2,d,i,r
            Medium finding,Medium,High,CWE-200,,a,f.java,3,d,i,r
            Low finding,Low,High,CWE-200,,a,f.java,4,d,i,r
        """)
        records = adapter.parse(write_csv(tmp_path, csv, "cvss.csv"))
        by_sev = {r.severity: r.cvss_score for r in records}
        assert by_sev["critical"] == 9.0
        assert by_sev["high"] == 7.5
        assert by_sev["medium"] == 5.0
        assert by_sev["low"] == 2.5

    def test_missing_required_columns_raises(self, tmp_path, adapter):
        csv = "Name,Risk\nFoo,High\n"
        with pytest.raises(ValueError, match="SAST export"):
            adapter.parse(write_csv(tmp_path, csv))

    def test_no_title_row_skipped(self, tmp_path, adapter):
        names = [r.name for r in adapter.parse(write_csv(tmp_path, _CSV))]
        assert all(n for n in names)

    def test_source_id_on_records(self, tmp_path, adapter):
        for r in adapter.parse(write_csv(tmp_path, _CSV)):
            assert r.source == "sast-test"

    def test_owasp_absent_gives_empty_list(self, tmp_path, adapter):
        records = adapter.parse(write_csv(tmp_path, _CSV))
        hard_coded = next(r for r in records if r.name == "Hard-coded cred")
        assert hard_coded.owasp_ids == []
