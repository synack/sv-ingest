"""
Opus SCA (Software Composition Analysis) adapter.

Primary format: CSV with record.* columns (Opus pipeline output).
Legacy format:  Excel with "SCA CVE Report" / "CVEs" sheets.
"""
from __future__ import annotations

import json
import logging
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

import pandas as pd

from scanner_ingest.models import VulnerabilityRecord
from .base import BaseAdapter

logger = logging.getLogger(__name__)

_SEVERITY_TO_CVSS: dict[str, float] = {
    "critical": 9.0,
    "high":     7.5,
    "medium":   5.0,
    "low":      2.5,
}

_CONFIDENCE_MAP: dict[str, str] = {
    "high":   "certain",
    "medium": "firm",
    "low":    "tentative",
}

_FULL_SHEET  = "SCA CVE Report"
_BRIEF_SHEET = "CVEs"


def _parse_json_list(value: object) -> list[str]:
    if not value or str(value).strip() in ("", "nan", "None", "[]"):
        return []
    try:
        parsed = json.loads(str(value))
        return [str(s).strip() for s in parsed if str(s).strip()]
    except (json.JSONDecodeError, TypeError):
        return []


def _split_cwes(value: object) -> list[str]:
    items = _parse_json_list(value)
    if items:
        return [s for s in items if s.upper().startswith("CWE-")]
    s = str(value).strip() if value else ""
    if not s or s in ("nan", "None"):
        return []
    parts: list[str] = []
    for chunk in re.split(r"[,;]", s):
        chunk = chunk.strip()
        sub = re.split(r"(?<=\d)(?=CWE-)", chunk)
        parts.extend(p.strip() for p in sub if p.strip().upper().startswith("CWE-"))
    return parts


class SCAAdapter(BaseAdapter):

    def parse(self, file_path: Path) -> list[VulnerabilityRecord]:
        fmt = self._detect_format(file_path)
        if fmt == "excel":
            xl = pd.ExcelFile(file_path)
            if _FULL_SHEET in xl.sheet_names:
                return self._parse_legacy_full(xl.parse(_FULL_SHEET))
            if _BRIEF_SHEET in xl.sheet_names:
                return self._parse_legacy_brief(xl.parse(_BRIEF_SHEET))
            return self._parse_legacy_full(xl.parse(xl.sheet_names[0]))

        df = pd.read_csv(file_path, low_memory=False)
        df.columns = df.columns.str.strip()
        if "record.package" in df.columns:
            return self._parse_opus(df)
        if "Package" in df.columns:
            return self._parse_legacy_full(df)
        return self._parse_legacy_brief(df)

    # ------------------------------------------------------------------
    # Opus pipeline format — record.* columns
    # ------------------------------------------------------------------

    def _parse_opus(self, df: pd.DataFrame) -> list[VulnerabilityRecord]:
        records: list[VulnerabilityRecord] = []

        for _, row in df.iterrows():
            def get(col: str, default=None):
                v = row.get(col)
                if v is None or (isinstance(v, float) and pd.isna(v)):
                    return default
                s = str(v).strip()
                return s if s not in ("", "nan", "None") else default

            package = get("record.package")
            version = get("record.version")
            if not package:
                continue

            pkg_ver = f"{package}:{version}" if version else package
            cves    = [c for c in _parse_json_list(get("record.cves")) if c.upper().startswith("CVE-")]
            name    = f"{cves[0]} — {pkg_ver}" if cves else pkg_ver
            location = pkg_ver

            cvss     = min(max(self._safe_float(get("record.severity.cvss_score"), 0.0), 0.0), 10.0)
            cvss_ver = self._safe_float(get("record.severity.cvss_version"), 3.1)
            sev_raw  = (get("record.severity.label") or "").lower()
            severity = sev_raw if sev_raw in {"critical", "high", "medium", "low"} else None
            if cvss == 0.0 and severity:
                cvss = _SEVERITY_TO_CVSS.get(sev_raw, 0.0)

            conf_raw   = (get("record.confidence") or "").lower()
            confidence = _CONFIDENCE_MAP.get(conf_raw)

            cwes = _split_cwes(get("record.cwe"))

            summary        = get("record.summary", "")
            reachability   = get("record.reachability")
            exploitability = get("record.exploitability")
            exposure       = get("record.exposure")
            ecosystem      = get("record.ecosystem") or get("record.ecosystems")
            dep_type       = get("record.dependency_type")
            epss           = get("record.severity.epss")

            context_parts = []
            if reachability:
                context_parts.append(f"Reachability: {reachability}")
            if exploitability:
                context_parts.append(f"Exploitability: {exploitability}")
            if exposure:
                context_parts.append(f"Exposure: {exposure}")
            if ecosystem:
                context_parts.append(f"Ecosystem: {ecosystem}")
            if dep_type:
                context_parts.append(f"Dependency: {dep_type}")
            if epss:
                context_parts.append(f"EPSS: {epss}")

            description = summary
            if context_parts and description:
                description = description + "\n\n" + " | ".join(context_parts)
            elif context_parts:
                description = " | ".join(context_parts)

            fixed    = get("record.remediation.preferred_fix_version")
            solution = f"Upgrade to {fixed}" if fixed else None

            try:
                records.append(VulnerabilityRecord(
                    name=name,
                    location=location,
                    cvss_score=cvss,
                    cvss_version=cvss_ver,
                    severity=severity,
                    confidence=confidence,
                    description=description or None,
                    solution=solution,
                    cves=cves,
                    cwes=cwes,
                    last_found_at=datetime.now(timezone.utc),
                    source=self.source_id,
                ))
            except Exception as exc:
                logger.debug("Skipping SCA row — %s", exc)

        logger.info("Opus SCA: parsed %d records", len(records))
        return records

    # ------------------------------------------------------------------
    # Legacy triage Excel — "SCA CVE Report" sheet
    # ------------------------------------------------------------------

    def _parse_legacy_full(self, df: pd.DataFrame) -> list[VulnerabilityRecord]:
        df.columns = df.columns.str.strip()
        records: list[VulnerabilityRecord] = []

        for _, row in df.iterrows():
            def get(col: str, default=None):
                v = row.get(col)
                if v is None or (isinstance(v, float) and pd.isna(v)):
                    return default
                s = str(v).strip()
                return s if s not in ("", "nan", "None") else default

            package = get("Package")
            version = get("Version")
            cve     = get("CVE")
            if not package and not cve:
                continue

            pkg_ver  = f"{package}:{version}" if version else (package or "unknown")
            name     = f"{cve} — {pkg_ver}" if cve else pkg_ver
            location = pkg_ver

            cvss_raw = row.get("CVSS Score")
            if cvss_raw is not None and not (isinstance(cvss_raw, float) and pd.isna(cvss_raw)):
                cvss = min(max(self._safe_float(cvss_raw), 0.0), 10.0)
            else:
                cvss = _SEVERITY_TO_CVSS.get((get("Severity") or "").lower(), 0.0)

            sev_raw    = (get("Severity") or "").lower()
            severity   = sev_raw if sev_raw in {"critical", "high", "medium", "low"} else None
            conf_raw   = (get("Confidence") or "").lower()
            confidence = _CONFIDENCE_MAP.get(conf_raw)
            cwes       = _split_cwes(get("CWE"))
            cves       = [cve] if cve else []

            summary        = get("Summary", "")
            reachability   = get("Reachability")
            exploitability = get("Exploitability")
            exposure       = get("Exposure")
            ecosystem      = get("Ecosystem")
            dep_type       = get("Dependency Type")
            epss           = get("EPSS")

            context_parts = []
            for label, val in [("Reachability", reachability), ("Exploitability", exploitability),
                                ("Exposure", exposure), ("Ecosystem", ecosystem),
                                ("Dependency", dep_type), ("EPSS", epss)]:
                if val:
                    context_parts.append(f"{label}: {val}")

            description = summary
            if context_parts and description:
                description = description + "\n\n" + " | ".join(context_parts)
            elif context_parts:
                description = " | ".join(context_parts)

            fixed    = get("Fixed Versions")
            solution = f"Upgrade to {fixed}" if fixed else None

            try:
                records.append(VulnerabilityRecord(
                    name=name,
                    location=location,
                    cvss_score=cvss,
                    severity=severity,
                    confidence=confidence,
                    description=description or None,
                    solution=solution,
                    cves=cves,
                    cwes=cwes,
                    last_found_at=datetime.now(timezone.utc),
                    source=self.source_id,
                ))
            except Exception as exc:
                logger.debug("Skipping SCA legacy row — %s", exc)

        logger.info("Opus SCA (legacy): parsed %d records", len(records))
        return records

    # ------------------------------------------------------------------
    # Legacy triage Excel — "CVEs" sheet
    # ------------------------------------------------------------------

    def _parse_legacy_brief(self, df: pd.DataFrame) -> list[VulnerabilityRecord]:
        df.columns = df.columns.str.strip()
        records: list[VulnerabilityRecord] = []

        for _, row in df.iterrows():
            def get(col: str, default=None):
                v = row.get(col)
                if v is None or (isinstance(v, float) and pd.isna(v)):
                    return default
                s = str(v).strip()
                return s if s not in ("", "nan", "None") else default

            cve = get("CVE")
            if not cve:
                continue

            sev_raw    = (get("Severity") or "").lower()
            severity   = sev_raw if sev_raw in {"critical", "high", "medium", "low"} else None
            cvss       = _SEVERITY_TO_CVSS.get(sev_raw, 0.0)
            conf_raw   = (get("Confidence") or "").lower()
            confidence = _CONFIDENCE_MAP.get(conf_raw)

            try:
                records.append(VulnerabilityRecord(
                    name=cve,
                    location=cve,
                    cvss_score=cvss,
                    severity=severity,
                    confidence=confidence,
                    cves=[cve],
                    last_found_at=datetime.now(timezone.utc),
                    source=self.source_id,
                ))
            except Exception as exc:
                logger.debug("Skipping SCA brief row — %s", exc)

        logger.info("Opus SCA (legacy brief): parsed %d records", len(records))
        return records
