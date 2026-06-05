"""
CISA adapter — handles three report formats:

1. CISA Known Exploited Vulnerabilities (KEV) catalog CSV
   Columns: cveID, vendorProject, product, vulnerabilityName, dateAdded,
            shortDescription, requiredAction, dueDate

2. CISA Cyber Hygiene (CyHy) v2 scan report
   Columns: owner, ip, port, protocol, dns, severity (int), cvss_base_score,
            cvss_version (int), cve, name, Description, Solution,
            initial_detection, latest_detection, vpr_score, ...

3. CyHy legacy / Tenable SC-style export
   Detected by fallback when neither of the above column sets are found.
"""
from __future__ import annotations

import json
import logging
from datetime import datetime, timezone
from pathlib import Path

import pandas as pd

from scanner_ingest.models import VulnerabilityRecord
from .base import BaseAdapter
from .tenable_sc import TenableSCAdapter, _build_location

logger = logging.getLogger(__name__)

_KEV_COLUMNS  = {"cveID", "vulnerabilityName", "vendorProject", "shortDescription"}
_CYHY_COLUMNS = {"ip", "cvss_base_score", "initial_detection", "latest_detection"}

_KEV_DEFAULT_CVSS = 0.0

# CyHy integer severity → Synack string
_CYHY_SEVERITY: dict[int, str | None] = {
    4: "critical",
    3: "high",
    2: "medium",
    1: "low",
    0: None,
}

# CyHy cvss_version integer → float used by Synack
_CVSS_VERSION_MAP = {2: 2.0, 3: 3.1}


class CISAAdapter(BaseAdapter):

    def parse(self, file_path: Path) -> list[VulnerabilityRecord]:
        fmt = self._detect_format(file_path)

        if fmt == "json":
            return self._parse_json(file_path)

        df = pd.read_excel(file_path) if fmt == "excel" else pd.read_csv(file_path, low_memory=False)
        df.columns = df.columns.str.strip()
        cols = set(df.columns)

        if _KEV_COLUMNS.issubset(cols):
            return self._parse_kev(df)

        if _CYHY_COLUMNS.issubset(cols):
            logger.debug("CISA: detected CyHy v2 format")
            return self._parse_cyhy(df)

        logger.debug("CISA: falling back to Tenable SC column layout")
        return TenableSCAdapter(source_id=self.source_id, config=self.config)._parse_dataframe(df)

    # ------------------------------------------------------------------
    # CyHy v2 scan report
    # ------------------------------------------------------------------

    def _parse_cyhy(self, df: pd.DataFrame) -> list[VulnerabilityRecord]:
        records: list[VulnerabilityRecord] = []

        for _, row in df.iterrows():
            def get(col: str, default=None):
                v = row.get(col)
                if v is None or (isinstance(v, float) and pd.isna(v)):
                    return default
                s = str(v).strip()
                return s if s not in ("", "nan", "None") else default

            # Name: prefer the name column, fall back to CVE ID, then description
            name = get("name") or get("cve") or get("Description") or get("description")
            if not name:
                continue

            ip       = get("ip", "unknown")
            port     = get("port")
            protocol = get("protocol")
            location = _build_location(ip, str(port) if port else None, str(protocol) if protocol else None)

            cvss     = min(max(self._safe_float(get("cvss_base_score"), 0.0), 0.0), 10.0)
            cvss_ver = _CVSS_VERSION_MAP.get(int(self._safe_float(get("cvss_version"), 3)), 3.1)

            sev_raw  = get("severity")
            severity = _CYHY_SEVERITY.get(int(self._safe_float(sev_raw, -1)), None) if sev_raw else None

            cve_raw  = get("cve", "")
            cves     = [c.strip() for c in cve_raw.replace(";", ",").split(",")
                        if c.strip().upper().startswith("CVE")]

            # Prefer capitalised columns first (CyHy uses both cases)
            description = get("Description") or get("description")
            solution    = get("Solution")    or get("solution")

            vpr = self._safe_float(get("vpr_score")) if get("vpr_score") else None

            first_at = self._parse_date(get("initial_detection"))
            last_at  = self._parse_date(get("latest_detection")) or datetime.now(timezone.utc)

            cwe_raw = get("CWE ID", "")
            cwes    = [c.strip() for c in cwe_raw.replace(";", ",").split(",")
                       if c.strip().upper().startswith("CWE")] if cwe_raw else []

            try:
                records.append(VulnerabilityRecord(
                    name=name,
                    location=location,
                    cvss_score=cvss,
                    cvss_version=cvss_ver,
                    severity=severity,
                    description=description,
                    solution=solution,
                    cves=cves,
                    cwes=cwes,
                    vendor_risk_score=vpr,
                    first_found_at=first_at,
                    last_found_at=last_at,
                    source=self.source_id,
                ))
            except Exception as exc:
                logger.debug("Skipping CyHy row — %s", exc)

        logger.info("CISA CyHy: parsed %d records", len(records))
        return records

    # ------------------------------------------------------------------
    # KEV catalog
    # ------------------------------------------------------------------

    def _parse_kev(self, df: pd.DataFrame) -> list[VulnerabilityRecord]:
        default_cvss = self.config.get("default_cvss_score", _KEV_DEFAULT_CVSS)
        default_ver  = self.config.get("default_cvss_version", 3.1)

        records: list[VulnerabilityRecord] = []
        for _, row in df.iterrows():
            def get(col: str, default=None):
                v = row.get(col)
                if pd.isna(v):
                    return default
                return str(v).strip() or default

            cve_id   = get("cveID", "")
            name     = get("vulnerabilityName") or cve_id
            if not name:
                continue

            vendor   = get("vendorProject", "")
            product  = get("product", "")
            location = f"{vendor}/{product}" if (vendor or product) else "unknown"

            cvss_raw = get("cvssScore") or get("baseScore")
            cvss     = min(max(self._safe_float(cvss_raw, default_cvss), 0.0), 10.0)

            date_added = self._parse_date(get("dateAdded"))
            due_date   = self._parse_date(get("dueDate"))
            cves       = [cve_id] if cve_id.upper().startswith("CVE") else []

            try:
                records.append(VulnerabilityRecord(
                    name=name,
                    location=location,
                    cvss_score=cvss,
                    cvss_version=default_ver,
                    description=get("shortDescription"),
                    solution=get("requiredAction"),
                    cves=cves,
                    first_found_at=date_added,
                    last_found_at=due_date or date_added or datetime.now(timezone.utc),
                    source=self.source_id,
                ))
            except Exception as exc:
                logger.debug("Skipping KEV row — %s", exc)

        logger.info("CISA KEV: parsed %d records", len(records))
        return records

    # ------------------------------------------------------------------
    # JSON
    # ------------------------------------------------------------------

    def _parse_json(self, file_path: Path) -> list[VulnerabilityRecord]:
        with open(file_path) as fh:
            data = json.load(fh)

        if isinstance(data, dict) and "vulnerabilities" in data:
            return self._parse_kev(pd.DataFrame(data["vulnerabilities"]))

        return TenableSCAdapter(source_id=self.source_id, config=self.config)._parse_json(file_path)
