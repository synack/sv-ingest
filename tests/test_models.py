from datetime import datetime, timezone

import pytest
from pydantic import ValidationError

from scanner_ingest.models import VulnerabilityRecord


def _rec(**kwargs):
    defaults = dict(name="Test Vuln", location="192.168.1.1", cvss_score=5.0, source="test")
    return VulnerabilityRecord(**{**defaults, **kwargs})


class TestVulnerabilityRecord:
    def test_minimal_fields(self):
        r = _rec()
        assert r.name == "Test Vuln"
        assert r.cvss_score == 5.0
        assert r.cves == []
        assert r.cwes == []
        assert r.owasp_ids == []
        assert r.severity is None

    def test_severity_lowercased(self):
        assert _rec(severity="HIGH").severity == "high"
        assert _rec(severity="Critical").severity == "critical"

    def test_invalid_severity_silently_none(self):
        assert _rec(severity="informational").severity is None
        assert _rec(severity="info").severity is None
        assert _rec(severity="bogus").severity is None

    def test_all_valid_severities(self):
        for s in ("critical", "high", "medium", "low"):
            assert _rec(severity=s).severity == s

    def test_confidence_lowercased(self):
        assert _rec(confidence="CERTAIN").confidence == "certain"

    def test_invalid_confidence_silently_none(self):
        assert _rec(confidence="unknown").confidence is None
        assert _rec(confidence="maybe").confidence is None

    def test_all_valid_confidences(self):
        for c in ("certain", "firm", "tentative"):
            assert _rec(confidence=c).confidence == c

    def test_cvss_above_10_raises(self):
        with pytest.raises(ValidationError):
            _rec(cvss_score=10.1)

    def test_cvss_below_0_raises(self):
        with pytest.raises(ValidationError):
            _rec(cvss_score=-0.1)

    def test_cvss_boundary_values_ok(self):
        assert _rec(cvss_score=0.0).cvss_score == 0.0
        assert _rec(cvss_score=10.0).cvss_score == 10.0

    def test_last_found_at_defaults_to_now(self):
        r = _rec()
        assert r.last_found_at.tzinfo is not None

    def test_first_found_at_defaults_none(self):
        assert _rec().first_found_at is None


class TestToSynack:
    def test_minimal_payload_keys(self):
        payload = _rec().to_synack()
        assert set(payload.keys()) == {"name", "location", "cvssScore", "cvssVersion", "lastFoundAt", "source"}

    def test_camelcase_mapping(self):
        dt = datetime(2024, 1, 1, tzinfo=timezone.utc)
        r = _rec(
            severity="high",
            confidence="certain",
            description="desc",
            solution="fix",
            category="Injection",
            cves=["CVE-2021-44228"],
            cwes=["CWE-89"],
            owasp_ids=["A1"],
            first_found_at=dt,
            last_found_at=dt,
            vendor_risk_score=9.5,
            asset_uid="asset-1",
            listing_uid="listing-2",
        )
        p = r.to_synack()
        assert p["cvssScore"] == 5.0
        assert p["cvssVersion"] == 3.1
        assert p["lastFoundAt"] == dt.isoformat()
        assert p["firstFoundAt"] == dt.isoformat()
        assert p["owaspIds"] == ["A1"]
        assert p["vendorRiskScore"] == 9.5
        assert p["assetUid"] == "asset-1"
        assert p["listingUid"] == "listing-2"

    def test_none_optional_fields_omitted(self):
        p = _rec().to_synack()
        for absent in ("description", "solution", "severity", "confidence", "category",
                       "firstFoundAt", "vendorRiskScore", "assetUid", "listingUid"):
            assert absent not in p

    def test_empty_lists_omitted(self):
        p = _rec(cves=[], cwes=[], owasp_ids=[]).to_synack()
        assert "cves" not in p
        assert "cwes" not in p
        assert "owaspIds" not in p

    def test_non_empty_lists_included(self):
        p = _rec(cves=["CVE-2021-1234"], cwes=["CWE-79"]).to_synack()
        assert p["cves"] == ["CVE-2021-1234"]
        assert p["cwes"] == ["CWE-79"]
