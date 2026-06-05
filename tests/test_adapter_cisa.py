import json
import textwrap

import pytest

from scanner_ingest.adapters.cisa import CISAAdapter


@pytest.fixture
def adapter():
    return CISAAdapter(source_id="cisa")


def write_csv(tmp_path, content, name="report.csv"):
    p = tmp_path / name
    p.write_text(content)
    return p


# ---------------------------------------------------------------------------
# KEV catalog
# ---------------------------------------------------------------------------

_KEV_CSV = textwrap.dedent("""\
    cveID,vendorProject,product,vulnerabilityName,dateAdded,shortDescription,requiredAction,dueDate
    CVE-2021-44228,Apache,Log4j,Apache Log4j2 RCE,2021-12-10,RCE via JNDI,Patch immediately,2021-12-24
    CVE-2014-0160,OpenSSL,OpenSSL,Heartbleed,2022-01-01,Memory disclosure,Upgrade to 1.0.1g,2022-01-15
    ,,,No CVE row,2022-01-01,Missing CVE ID is OK,
""")


class TestCISAKev:
    def test_detects_kev_format(self, tmp_path, adapter):
        records = adapter.parse(write_csv(tmp_path, _KEV_CSV))
        assert len(records) == 3

    def test_kev_record_fields(self, tmp_path, adapter):
        r = adapter.parse(write_csv(tmp_path, _KEV_CSV))[0]
        assert r.name == "Apache Log4j2 RCE"
        assert "CVE-2021-44228" in r.location or r.location == "Apache/Log4j"
        assert r.cves == ["CVE-2021-44228"]
        assert r.description == "RCE via JNDI"
        assert r.solution == "Patch immediately"

    def test_kev_location_is_vendor_product(self, tmp_path, adapter):
        r = adapter.parse(write_csv(tmp_path, _KEV_CSV))[0]
        assert r.location == "Apache/Log4j"

    def test_kev_date_parsed(self, tmp_path, adapter):
        r = adapter.parse(write_csv(tmp_path, _KEV_CSV))[0]
        assert r.first_found_at is not None
        assert r.first_found_at.year == 2021

    def test_kev_no_cve_id_row_skips_cves(self, tmp_path, adapter):
        r = adapter.parse(write_csv(tmp_path, _KEV_CSV))[2]
        assert r.cves == []

    def test_kev_json_envelope(self, tmp_path, adapter):
        data = {
            "vulnerabilities": [
                {
                    "cveID": "CVE-2021-44228",
                    "vendorProject": "Apache",
                    "product": "Log4j",
                    "vulnerabilityName": "Log4Shell",
                    "dateAdded": "2021-12-10",
                    "shortDescription": "RCE",
                    "requiredAction": "Patch",
                    "dueDate": "2021-12-24",
                }
            ]
        }
        f = tmp_path / "kev.json"
        f.write_text(json.dumps(data))
        records = adapter.parse(f)
        assert len(records) == 1
        assert records[0].name == "Log4Shell"


# ---------------------------------------------------------------------------
# CyHy v2 scan report
# ---------------------------------------------------------------------------

_CYHY_CSV = textwrap.dedent("""\
    owner,ip,port,protocol,dns,severity,cvss_base_score,cvss_version,cve,name,Description,Solution,initial_detection,latest_detection,vpr_score
    AGENCY,192.168.1.10,443,https,host.example.com,4,9.8,3,CVE-2021-44228,Log4Shell,Log4j exploit,Upgrade Log4j,2021-12-10,2021-12-15,9.0
    AGENCY,10.0.0.5,80,http,,2,5.0,2,CVE-2014-0160,Heartbleed,Memory disclosure,Upgrade OpenSSL,2014-04-07,2014-04-08,
    AGENCY,172.16.0.1,0,tcp,,,0.0,3,,CVE-2023-0001,,,2023-01-01,2023-01-02,
""")


class TestCISACyHy:
    def test_detects_cyhy_format(self, tmp_path, adapter):
        records = adapter.parse(write_csv(tmp_path, _CYHY_CSV))
        assert len(records) == 3

    def test_cyhy_record_fields(self, tmp_path, adapter):
        r = adapter.parse(write_csv(tmp_path, _CYHY_CSV))[0]
        assert r.name == "Log4Shell"
        assert r.location == "https://192.168.1.10:443"
        assert r.cvss_score == 9.8
        assert r.cvss_version == 3.1
        assert r.severity == "critical"
        assert "CVE-2021-44228" in r.cves
        assert r.vendor_risk_score == 9.0

    def test_cyhy_severity_integer_mapping(self, tmp_path, adapter):
        records = adapter.parse(write_csv(tmp_path, _CYHY_CSV))
        assert records[0].severity == "critical"  # 4
        assert records[1].severity == "medium"    # 2
        assert records[2].severity is None         # missing

    def test_cyhy_cvss_version_mapping(self, tmp_path, adapter):
        records = adapter.parse(write_csv(tmp_path, _CYHY_CSV))
        assert records[0].cvss_version == 3.1  # cvss_version=3
        assert records[1].cvss_version == 2.0  # cvss_version=2

    def test_cyhy_port_zero_bare_ip(self, tmp_path, adapter):
        records = adapter.parse(write_csv(tmp_path, _CYHY_CSV))
        assert records[2].location == "172.16.0.1"

    def test_cyhy_vpr_none_when_empty(self, tmp_path, adapter):
        records = adapter.parse(write_csv(tmp_path, _CYHY_CSV))
        assert records[1].vendor_risk_score is None


# ---------------------------------------------------------------------------
# Fallback to Tenable SC layout
# ---------------------------------------------------------------------------

_FALLBACK_CSV = textwrap.dedent("""\
    Name,Risk,Host,Port,Protocol,CVSS v3.0 Base Score,CVE
    OpenSSL Heartbleed,High,10.0.0.5,443,https,7.5,CVE-2014-0160
""")


class TestCISAFallback:
    def test_falls_back_to_tenable_sc_parser(self, tmp_path, adapter):
        records = adapter.parse(write_csv(tmp_path, _FALLBACK_CSV))
        assert len(records) == 1
        assert records[0].name == "OpenSSL Heartbleed"
        assert records[0].severity == "high"
