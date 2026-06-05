import textwrap

import pytest

from scanner_ingest.adapters.sca import SCAAdapter, _split_cwes


# ---------------------------------------------------------------------------
# _split_cwes
# ---------------------------------------------------------------------------

class TestSplitCwes:
    def test_single(self):
        assert _split_cwes("CWE-502") == ["CWE-502"]

    def test_comma_separated(self):
        assert _split_cwes("CWE-502, CWE-611") == ["CWE-502", "CWE-611"]

    def test_empty_returns_empty(self):
        assert _split_cwes("") == []


# ---------------------------------------------------------------------------
# Full layout (SCA CVE Report sheet) via CSV fixture
# ---------------------------------------------------------------------------

_FULL_CSV = textwrap.dedent("""\
    Category,Folder,Project,Finding ID,CVE,Severity,CVSS Score,EPSS,Confidence,Kenna Score,Package,Version,Ecosystem,Dependency Type,CWE,Affected Range,Fixed Versions,Reachability,Exploitability,Exposure,Summary
    External,MSR01,proj-a,VULN-001,CVE-2022-1471,high,8.3,0.0148,high,,org.yaml:snakeyaml,2.0,java,direct,CWE-502,<=2.0,2.1,likely_reachable,confirmed,internet,SnakeYAML deserialization RCE.
    External,MSR01,proj-a,VULN-002,CVE-2021-28168,medium,5.5,0.0005,high,,org.glassfish.jersey.core:jersey-server,2.22.2,java,direct,CWE-378,<2.34,2.34,likely_reachable,possible,limited,Jersey insecure temp files.
    External,MSR01,proj-a,VULN-003,,medium,,0.001,medium,,org.springdoc:springdoc-openapi,2.8.8,java,direct,,,,unknown,unconfirmed,internal,Version mismatch risk.
    External,MSR01,proj-a,VULN-004,CVE-2024-9823,critical,9.8,0.976,high,,vuln-pkg,1.0,python,transitive,CWE-94,,3.0,reachable,likely,internet,Critical RCE.
""")


@pytest.fixture
def adapter():
    return SCAAdapter(source_id="sca-test")


def write_csv(tmp_path, content, name="findings.csv"):
    p = tmp_path / name
    p.write_text(content)
    return p


class TestSCAFullLayout:
    def test_parses_expected_count(self, tmp_path, adapter):
        records = adapter.parse(write_csv(tmp_path, _FULL_CSV))
        assert len(records) == 4

    def test_cve_record_name_includes_package(self, tmp_path, adapter):
        r = adapter.parse(write_csv(tmp_path, _FULL_CSV))[0]
        assert r.name == "CVE-2022-1471 — org.yaml:snakeyaml:2.0"

    def test_location_is_package_version(self, tmp_path, adapter):
        r = adapter.parse(write_csv(tmp_path, _FULL_CSV))[0]
        assert r.location == "org.yaml:snakeyaml:2.0"

    def test_cvss_from_score_column(self, tmp_path, adapter):
        r = adapter.parse(write_csv(tmp_path, _FULL_CSV))[0]
        assert r.cvss_score == 8.3

    def test_cvss_falls_back_to_severity_when_missing(self, tmp_path, adapter):
        # VULN-003 has no CVSS Score
        records = adapter.parse(write_csv(tmp_path, _FULL_CSV))
        no_cvss = next(r for r in records if "springdoc" in r.location)
        assert no_cvss.cvss_score == 5.0  # medium → 5.0

    def test_severity_and_confidence_mapped(self, tmp_path, adapter):
        r = adapter.parse(write_csv(tmp_path, _FULL_CSV))[0]
        assert r.severity == "high"
        assert r.confidence == "certain"

    def test_confidence_mapping_medium_to_firm(self, tmp_path, adapter):
        records = adapter.parse(write_csv(tmp_path, _FULL_CSV))
        r = next(r for r in records if "springdoc" in r.location)
        assert r.confidence == "firm"

    def test_cve_in_cves_list(self, tmp_path, adapter):
        r = adapter.parse(write_csv(tmp_path, _FULL_CSV))[0]
        assert r.cves == ["CVE-2022-1471"]

    def test_no_cve_row_has_empty_cves(self, tmp_path, adapter):
        records = adapter.parse(write_csv(tmp_path, _FULL_CSV))
        no_cve = next(r for r in records if "springdoc" in r.location)
        assert no_cve.cves == []

    def test_no_cve_row_name_is_package_version(self, tmp_path, adapter):
        records = adapter.parse(write_csv(tmp_path, _FULL_CSV))
        no_cve = next(r for r in records if "springdoc" in r.location)
        assert no_cve.name == "org.springdoc:springdoc-openapi:2.8.8"

    def test_cwes_parsed(self, tmp_path, adapter):
        r = adapter.parse(write_csv(tmp_path, _FULL_CSV))[0]
        assert r.cwes == ["CWE-502"]

    def test_solution_from_fixed_versions(self, tmp_path, adapter):
        r = adapter.parse(write_csv(tmp_path, _FULL_CSV))[0]
        assert r.solution == "Upgrade to 2.1"

    def test_no_fixed_versions_solution_is_none(self, tmp_path, adapter):
        records = adapter.parse(write_csv(tmp_path, _FULL_CSV))
        no_fix = next(r for r in records if "springdoc" in r.location)
        assert no_fix.solution is None

    def test_description_includes_summary_and_context(self, tmp_path, adapter):
        r = adapter.parse(write_csv(tmp_path, _FULL_CSV))[0]
        assert "SnakeYAML" in r.description
        assert "Reachability" in r.description
        assert "Exploitability" in r.description

    def test_source_id_on_records(self, tmp_path, adapter):
        for r in adapter.parse(write_csv(tmp_path, _FULL_CSV)):
            assert r.source == "sca-test"


# ---------------------------------------------------------------------------
# Brief layout (CVEs sheet only)
# ---------------------------------------------------------------------------

_BRIEF_CSV = textwrap.dedent("""\
    CVE,Severity,Confidence
    CVE-2022-1471,high,high
    CVE-2021-28168,medium,high
    ,medium,medium
""")


class TestSCABriefLayout:
    def test_parses_valid_rows(self, tmp_path, adapter):
        records = adapter.parse(write_csv(tmp_path, _BRIEF_CSV, "brief.csv"))
        assert len(records) == 2

    def test_null_cve_row_skipped(self, tmp_path, adapter):
        records = adapter.parse(write_csv(tmp_path, _BRIEF_CSV, "brief.csv"))
        assert all(r.cves for r in records)

    def test_name_and_location_are_cve_id(self, tmp_path, adapter):
        r = adapter.parse(write_csv(tmp_path, _BRIEF_CSV, "brief.csv"))[0]
        assert r.name == "CVE-2022-1471"
        assert r.location == "CVE-2022-1471"

    def test_cvss_derived_from_severity(self, tmp_path, adapter):
        records = adapter.parse(write_csv(tmp_path, _BRIEF_CSV, "brief.csv"))
        assert records[0].cvss_score == 7.5   # high
        assert records[1].cvss_score == 5.0   # medium
