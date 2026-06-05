"""
Qualys WAS (Web Application Scanner) adapter.


Expected columns:
  VULN_ID, NAME, QID, SEVERITY, BASE CVSS, CWE, CVE,
  FIRST DETECTION, LAST DETECTION, GROUP, WEB APPLICATION,
  URL, PAYLOAD REQUEST, PAYLOAD RESPONSE, DESCRIPTION,
  IMPACT, SOLUTION, VULN TYPE
"""
from __future__ import annotations

import logging
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

import pandas as pd

from scanner_ingest.models import VulnerabilityRecord
from .base import BaseAdapter

logger = logging.getLogger(__name__)

# Qualys WAS severity (1-5) → Synack string
_SEVERITY_MAP: dict[int, Optional[str]] = {
    5: "critical",
    4: "high",
    3: "medium",
    2: "low",
    1: None,   # informational
}

# Qualys VULN TYPE → Synack confidence
_CONFIDENCE_MAP: dict[str, str] = {
    "confirmed": "certain",
    "potential": "tentative",
    "sensitive":  "firm",
}

# Date formats Qualys WAS uses: "10 May 2020 01:00AM GMT"
_DATE_FORMATS = (
    "%d %b %Y %I:%M%p %Z",
    "%d %b %Y %I:%M %p %Z",
    "%Y-%m-%dT%H:%M:%SZ",
    "%Y-%m-%dT%H:%M:%S",
    "%Y-%m-%d",
)

_QUALYS_COLUMNS = {"NAME", "QID", "SEVERITY", "BASE CVSS", "FIRST DETECTION", "LAST DETECTION", "URL"}


def _split_cwes(value: object) -> list[str]:
    """Split CWE IDs handling both delimiters and concatenated forms like 'CWE-20CWE-918'."""
    if not value or str(value).strip() in ("", "nan", "None"):
        return []
    s = str(value).strip()
    # Split on commas/semicolons first, then re-split on embedded CWE- prefixes
    parts: list[str] = []
    for chunk in re.split(r"[,;]", s):
        chunk = chunk.strip()
        if not chunk:
            continue
        # Split concatenated CWEs: "CWE-20CWE-918" → ["CWE-20", "CWE-918"]
        sub = re.split(r"(?<=\d)(?=CWE-)", chunk)
        parts.extend(p.strip() for p in sub if p.strip().upper().startswith("CWE-"))
    return parts


def _parse_qualys_date(value: object) -> Optional[datetime]:
    if not value or str(value).strip() in ("", "nan", "None"):
        return None
    s = str(value).strip()
    for fmt in _DATE_FORMATS:
        try:
            dt = datetime.strptime(s, fmt)
            return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)
        except ValueError:
            continue
    return None


class QualysAdapter(BaseAdapter):

    def parse(self, file_path: Path) -> list[VulnerabilityRecord]:
        fmt = self._detect_format(file_path)
        df = pd.read_excel(file_path) if fmt == "excel" else pd.read_csv(file_path, low_memory=False)
        df.columns = df.columns.str.strip()

        if not _QUALYS_COLUMNS.issubset(set(df.columns)):
            missing = _QUALYS_COLUMNS - set(df.columns)
            raise ValueError(f"File does not appear to be a Qualys WAS export. Missing columns: {missing}")

        return self._parse_dataframe(df)

    def _parse_dataframe(self, df: pd.DataFrame) -> list[VulnerabilityRecord]:
        records: list[VulnerabilityRecord] = []

        for _, row in df.iterrows():
            def get(col: str, default=None):
                v = row.get(col)
                if v is None or (isinstance(v, float) and pd.isna(v)):
                    return default
                s = str(v).strip()
                return s if s not in ("", "nan", "None") else default

            name = get("NAME")
            if not name:
                continue

            location = get("URL")
            if not location:
                logger.debug("Skipping row '%s' — no URL", name[:60])
                continue

            cvss    = min(max(self._safe_float(get("BASE CVSS"), 0.0), 0.0), 10.0)
            cvss_ver = self.config.get("default_cvss_version", 3.1)

            sev_raw  = get("SEVERITY")
            severity = _SEVERITY_MAP.get(int(self._safe_float(sev_raw, 0)), None) if sev_raw else None

            cves = [c for c in self._split_ids(get("CVE", "")) if c.upper().startswith("CVE")]
            cwes = _split_cwes(get("CWE", ""))

            vuln_type  = get("VULN TYPE", "")
            confidence = _CONFIDENCE_MAP.get(vuln_type.lower(), None) if vuln_type else None

            description = get("DESCRIPTION")
            impact      = get("IMPACT")
            if impact and description:
                description = f"{description}\n\nImpact: {impact}"
            elif impact:
                description = impact

            first_at = _parse_qualys_date(get("FIRST DETECTION"))
            last_at  = _parse_qualys_date(get("LAST DETECTION")) or datetime.now(timezone.utc)

            try:
                records.append(VulnerabilityRecord(
                    name=name,
                    location=location,
                    cvss_score=cvss,
                    cvss_version=cvss_ver,
                    severity=severity,
                    description=description,
                    solution=get("SOLUTION"),
                    cves=cves,
                    cwes=cwes,
                    confidence=confidence,
                    first_found_at=first_at,
                    last_found_at=last_at,
                    source=self.source_id,
                ))
            except Exception as exc:
                logger.debug("Skipping Qualys row — %s", exc)

        logger.info("Qualys WAS: parsed %d records", len(records))
        return records
