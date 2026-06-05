import json
import textwrap

import pytest

from scanner_ingest.adapters.generic import GenericAdapter


def write_file(tmp_path, content, name):
    p = tmp_path / name
    p.write_text(content)
    return p


# ---------------------------------------------------------------------------
# CSV with default field mapping (column names match internal names)
# ---------------------------------------------------------------------------

_DEFAULT_CSV = textwrap.dedent("""\
    name,location,cvss_score,severity,description,solution,cves,cwes,confidence,first_found_at,last_found_at
    SQL Injection,https://example.com/login,9.8,high,SQL injection found,Use prepared statements,CVE-2021-1234,CWE-89,certain,2022-01-01,2022-01-15
    XSS,https://example.com/search,6.5,medium,XSS found,Escape output,,CWE-79,firm,2022-02-01,2022-02-20
    ,https://example.com/info,0.0,low,No name row,,,,,,
""")

# Custom field mapping: source file uses different column names
_CUSTOM_CSV = textwrap.dedent("""\
    vuln_title,target_url,score,risk_level,vuln_desc,remediation
    SQL Injection,https://example.com/login,9.8,high,SQL injection,Use prepared statements
    XSS,https://example.com/search,6.5,medium,XSS found,Escape output
""")

_JSON_DATA = [
    {
        "name": "SQL Injection",
        "location": "https://example.com/login",
        "cvss_score": 9.8,
        "severity": "high",
        "cves": "CVE-2021-1234",
        "confidence": "certain",
    },
    {
        "name": "XSS",
        "location": "https://example.com/search",
        "cvss_score": 6.5,
        "severity": "medium",
    },
]


def _mapped_adapter(**extra_mapping):
    """GenericAdapter with name+location mapped; extra_mapping adds more fields."""
    mapping = {"name": "name", "location": "location", **extra_mapping}
    return GenericAdapter(source_id="scanner", config={"field_mapping": mapping})


class TestGenericCsvWithMapping:
    def test_record_count(self, tmp_path):
        adapter = _mapped_adapter()
        records = adapter.parse(write_file(tmp_path, _DEFAULT_CSV, "out.csv"))
        assert len(records) == 2  # no-name row skipped

    def test_first_record(self, tmp_path):
        adapter = _mapped_adapter()
        r = adapter.parse(write_file(tmp_path, _DEFAULT_CSV, "out.csv"))[0]
        assert r.name == "SQL Injection"
        assert r.location == "https://example.com/login"
        assert r.cvss_score == 9.8
        assert r.severity == "high"
        assert r.description == "SQL injection found"
        assert r.solution == "Use prepared statements"
        assert "CVE-2021-1234" in r.cves
        assert "CWE-89" in r.cwes
        assert r.confidence == "certain"
        assert r.source == "scanner"

    def test_dates_parsed(self, tmp_path):
        adapter = _mapped_adapter()
        r = adapter.parse(write_file(tmp_path, _DEFAULT_CSV, "out.csv"))[0]
        assert r.first_found_at is not None
        assert r.first_found_at.year == 2022
        assert r.last_found_at is not None

    def test_no_name_row_skipped(self, tmp_path):
        adapter = _mapped_adapter()
        records = adapter.parse(write_file(tmp_path, _DEFAULT_CSV, "out.csv"))
        assert all(r.name for r in records)

    def test_name_field_required_for_record_inclusion(self, tmp_path):
        # Without mapping name, no records are produced even with valid data
        adapter = GenericAdapter(source_id="scanner")
        records = adapter.parse(write_file(tmp_path, _DEFAULT_CSV, "out.csv"))
        assert records == []


class TestGenericCsvCustomMapping:
    def test_custom_field_mapping(self, tmp_path):
        adapter = GenericAdapter(
            source_id="scanner",
            config={
                "field_mapping": {
                    "name": "vuln_title",
                    "location": "target_url",
                    "cvss_score": "score",
                    "severity": "risk_level",
                    "description": "vuln_desc",
                    "solution": "remediation",
                }
            },
        )
        records = adapter.parse(write_file(tmp_path, _CUSTOM_CSV, "out.csv"))
        assert len(records) == 2
        assert records[0].name == "SQL Injection"
        assert records[0].location == "https://example.com/login"
        assert records[0].severity == "high"
        assert records[0].cvss_score == 9.8


class TestGenericJson:
    def test_json_list(self, tmp_path):
        adapter = _mapped_adapter()
        f = write_file(tmp_path, json.dumps(_JSON_DATA), "out.json")
        records = adapter.parse(f)
        assert len(records) == 2
        assert records[0].name == "SQL Injection"
        assert records[0].cvss_score == 9.8
        assert records[0].confidence == "certain"

    def test_json_single_object_wrapped(self, tmp_path):
        adapter = _mapped_adapter()
        f = write_file(tmp_path, json.dumps(_JSON_DATA[0]), "out.json")
        records = adapter.parse(f)
        assert len(records) == 1

    def test_json_cves_split(self, tmp_path):
        adapter = _mapped_adapter()
        f = write_file(tmp_path, json.dumps(_JSON_DATA), "out.json")
        assert "CVE-2021-1234" in adapter.parse(f)[0].cves


class TestGenericLocationFallback:
    def test_falls_back_to_host_port(self, tmp_path):
        csv = textwrap.dedent("""\
            name,host,port,protocol,cvss_score
            MyVuln,10.0.0.1,443,https,5.0
        """)
        adapter = GenericAdapter(source_id="scanner", config={"field_mapping": {"name": "name"}})
        records = adapter.parse(write_file(tmp_path, csv, "out.csv"))
        assert len(records) == 1
        assert records[0].location == "https://10.0.0.1:443"

    def test_falls_back_to_ip_column(self, tmp_path):
        csv = textwrap.dedent("""\
            name,ip,cvss_score
            MyVuln,192.168.1.1,5.0
        """)
        adapter = GenericAdapter(source_id="scanner", config={"field_mapping": {"name": "name"}})
        records = adapter.parse(write_file(tmp_path, csv, "out.csv"))
        assert records[0].location == "192.168.1.1"
