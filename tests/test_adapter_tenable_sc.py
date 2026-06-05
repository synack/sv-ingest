import json
import textwrap

import pytest

from scanner_ingest.adapters.tenable_sc import TenableSCAdapter, _build_location


# ---------------------------------------------------------------------------
# _build_location unit tests
# ---------------------------------------------------------------------------

class TestBuildLocation:
    def test_bare_ip_no_port(self):
        assert _build_location("192.168.1.1", None, None) == "192.168.1.1"

    def test_ip_with_port_defaults_to_tcp(self):
        # Port present but no protocol → tcp is assumed (API requires a scheme with a port)
        assert _build_location("192.168.1.1", "443", None) == "tcp://192.168.1.1:443"

    def test_protocol_and_port(self):
        assert _build_location("192.168.1.1", "443", "https") == "https://192.168.1.1:443"

    def test_protocol_without_port_uses_protocol_and_host(self):
        # Non-port protocol with no port → protocol://host (e.g. https://192.168.1.1)
        assert _build_location("192.168.1.1", None, "https") == "https://192.168.1.1"

    def test_port_zero_treated_as_absent(self):
        assert _build_location("192.168.1.1", "0", "tcp") == "192.168.1.1"

    def test_float_port_normalized(self):
        # Pandas reads integer columns as floats
        assert _build_location("10.0.0.1", "80.0", "http") == "http://10.0.0.1:80"

    def test_port_zero_float(self):
        assert _build_location("10.0.0.1", "0.0", "tcp") == "10.0.0.1"

    def test_protocol_uppercased_is_lowercased(self):
        assert _build_location("10.0.0.1", "445", "TCP") == "tcp://10.0.0.1:445"


# ---------------------------------------------------------------------------
# CSV parsing
# ---------------------------------------------------------------------------

_CSV = textwrap.dedent("""\
    Name,Risk,Host,Port,Protocol,CVSS v3.0 Base Score,CVE,First Seen,Last Seen,Description,Solution
    Apache Log4j RCE,Critical,192.168.1.10,443,https,10.0,"CVE-2021-44228,CVE-2021-45046",2021-12-10,2021-12-15,Log4j exploit,Upgrade Log4j
    OpenSSL Heartbleed,High,10.0.0.5,0,tcp,7.5,,2014-04-07,2014-04-08,OpenSSL vuln,Upgrade OpenSSL
    Info Finding,Info,192.168.1.1,80,http,0.0,,,,Informational,N/A
    ,High,192.168.1.2,443,https,5.0,,,,No-name row,
""")

_CSV_ALIASES = textwrap.dedent("""\
    Plugin Name,Severity,IP Address,Port,Protocol,CVSS v3.0 Base Score,CVE,First Seen,Last Seen
    Plugin with alias columns,high,10.1.2.3,8080,http,6.5,,2023-01-01,2023-06-01
""")

# Matches the SARA Triage Scope export format (capital V, Steps to Remediate, TCP protocol)
_CSV_SARA_FORMAT = textwrap.dedent("""\
    Name,Risk,Host,Port,Protocol,CVSS V3 Base Score,CVE,First Seen,Last Seen,Steps to Remediate
    SMB Signing Disabled,Medium,10.215.60.32,445,TCP,5.3,CVE-2023-1234,2024-01-01,2024-06-01,Enable SMB signing
""")


@pytest.fixture
def adapter():
    return TenableSCAdapter(source_id="tenable-sc")


def write_csv(tmp_path, content, name="scan.csv"):
    p = tmp_path / name
    p.write_text(content)
    return p


class TestTenableSCCsv:
    def test_parses_expected_record_count(self, tmp_path, adapter):
        # No-name row is skipped; Info row is kept with severity=None; 3 records remain
        records = adapter.parse(write_csv(tmp_path, _CSV))
        assert len(records) == 3

    def test_first_record_fields(self, tmp_path, adapter):
        r = adapter.parse(write_csv(tmp_path, _CSV))[0]
        assert r.name == "Apache Log4j RCE"
        assert r.location == "https://192.168.1.10:443"
        assert r.cvss_score == 10.0
        assert r.severity == "critical"
        assert "CVE-2021-44228" in r.cves
        assert "CVE-2021-45046" in r.cves
        assert r.source == "tenable-sc"

    def test_second_record_port_zero_gives_bare_ip(self, tmp_path, adapter):
        r = adapter.parse(write_csv(tmp_path, _CSV))[1]
        assert r.location == "10.0.0.5"
        assert r.severity == "high"

    def test_info_severity_is_none(self, tmp_path, adapter):
        records = adapter.parse(write_csv(tmp_path, _CSV))
        info = next(r for r in records if r.name == "Info Finding")
        assert info.severity is None

    def test_no_name_row_skipped(self, tmp_path, adapter):
        names = [r.name for r in adapter.parse(write_csv(tmp_path, _CSV))]
        assert all(n for n in names)

    def test_column_aliases_resolved(self, tmp_path, adapter):
        records = adapter.parse(write_csv(tmp_path, _CSV_ALIASES))
        assert len(records) == 1
        assert records[0].name == "Plugin with alias columns"
        assert records[0].location == "http://10.1.2.3:8080"

    def test_source_id_on_record(self, tmp_path, adapter):
        for r in adapter.parse(write_csv(tmp_path, _CSV)):
            assert r.source == "tenable-sc"

    def test_first_found_at_parsed(self, tmp_path, adapter):
        r = adapter.parse(write_csv(tmp_path, _CSV))[0]
        assert r.first_found_at is not None
        assert r.first_found_at.year == 2021

    def test_sara_format_cvss_capital_v(self, tmp_path, adapter):
        records = adapter.parse(write_csv(tmp_path, _CSV_SARA_FORMAT))
        assert len(records) == 1
        assert records[0].cvss_score == 5.3

    def test_sara_format_steps_to_remediate(self, tmp_path, adapter):
        records = adapter.parse(write_csv(tmp_path, _CSV_SARA_FORMAT))
        assert records[0].solution == "Enable SMB signing"

    def test_sara_format_protocol_lowercased(self, tmp_path, adapter):
        records = adapter.parse(write_csv(tmp_path, _CSV_SARA_FORMAT))
        assert records[0].location == "tcp://10.215.60.32:445"

    def test_column_map_override(self, tmp_path):
        csv = textwrap.dedent("""\
            VulnTitle,CustomRisk,TargetIP,Port,Proto,Score,CVEList,Detected
            Custom vuln,High,172.16.0.1,22,tcp,7.2,CVE-2023-1234,2023-03-01
        """)
        adapter = TenableSCAdapter(
            source_id="tenable-sc",
            config={"column_map": {"name": "VulnTitle", "host": "TargetIP", "cvss3": "Score"}},
        )
        records = adapter.parse(write_csv(tmp_path, csv))
        assert len(records) == 1
        assert records[0].name == "Custom vuln"


# ---------------------------------------------------------------------------
# JSON parsing
# ---------------------------------------------------------------------------

_JSON_LIST = [
    {
        "name": "Log4Shell",
        "ip": "10.0.0.1",
        "port": 443,
        "protocol": "https",
        "cvssV3BaseScore": 10.0,
        "severity": {"name": "Critical"},
        "cve": "CVE-2021-44228",
        "firstSeen": "2021-12-10",
        "lastSeen": "2021-12-15",
    },
    {
        "name": "Info Finding",
        "ip": "10.0.0.2",
        "port": 0,
        "protocol": "tcp",
        "cvssV3BaseScore": 0.0,
        "severity": {"name": "Info"},
    },
]

_JSON_ENVELOPE = {"response": {"results": _JSON_LIST}}


class TestTenableSCJson:
    def test_flat_list(self, tmp_path, adapter):
        f = tmp_path / "scan.json"
        f.write_text(json.dumps(_JSON_LIST))
        records = adapter.parse(f)
        assert len(records) == 2
        assert records[0].name == "Log4Shell"
        assert records[0].location == "https://10.0.0.1:443"
        assert records[0].severity == "critical"
        assert "CVE-2021-44228" in records[0].cves

    def test_envelope_format(self, tmp_path, adapter):
        f = tmp_path / "scan.json"
        f.write_text(json.dumps(_JSON_ENVELOPE))
        records = adapter.parse(f)
        assert len(records) == 2
        assert records[0].name == "Log4Shell"

    def test_info_severity_in_json(self, tmp_path, adapter):
        f = tmp_path / "scan.json"
        f.write_text(json.dumps(_JSON_LIST))
        records = adapter.parse(f)
        info = next((r for r in records if r.name == "Info Finding"), None)
        assert info is not None
        assert info.severity is None

    def test_port_zero_in_json_gives_bare_ip(self, tmp_path, adapter):
        f = tmp_path / "scan.json"
        f.write_text(json.dumps(_JSON_LIST))
        info = next(r for r in adapter.parse(f) if r.name == "Info Finding")
        assert info.location == "10.0.0.2"
