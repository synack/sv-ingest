"""
Opus SAST (Static Application Security Testing) adapter.

Primary format: CSV with record.* columns (Opus pipeline output).
Legacy format:  Excel with Title/Severity/File/Line columns.
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
    "info":     0.0,
}

_CONFIDENCE_MAP: dict[str, str] = {
    "high":   "certain",
    "medium": "firm",
    "low":    "tentative",
}


def _parse_json_list(value: object) -> list[str]:
    """Parse a JSON array string into a list of strings, or return []."""
    if not value or str(value).strip() in ("", "nan", "None", "[]"):
        return []
    try:
        parsed = json.loads(str(value))
        return [str(s).strip() for s in parsed if str(s).strip()]
    except (json.JSONDecodeError, TypeError):
        return []


def _split_cwes(value: object) -> list[str]:
    """Split CWE IDs from a JSON array string or comma-separated string."""
    items = _parse_json_list(value)
    if items:
        return [s for s in items if s.upper().startswith("CWE-")]
    # Fallback: plain comma/semicolon separated
    s = str(value).strip() if value else ""
    if not s or s in ("nan", "None"):
        return []
    parts: list[str] = []
    for chunk in re.split(r"[,;]", s):
        chunk = chunk.strip()
        sub = re.split(r"(?<=\d)(?=CWE-)", chunk)
        parts.extend(p.strip() for p in sub if p.strip().upper().startswith("CWE-"))
    return parts


def _parse_owasp_ids(value: object) -> list[str]:
    """Extract OWASP Top-10 codes (e.g. 'A02:2021') from a JSON array or plain string."""
    items = _parse_json_list(value)
    if not items:
        raw = str(value).strip() if value else ""
        if raw and raw not in ("nan", "None"):
            items = [p.strip() for p in re.split(r"[,;]", raw) if p.strip()]
    ids = []
    for item in items:
        m = re.search(r"(A\d{2}:\d{4})", item)
        if m:
            ids.append(m.group(1))
    return ids


class SASTAdapter(BaseAdapter):

    def parse(self, file_path: Path) -> list[VulnerabilityRecord]:
        fmt = self._detect_format(file_path)
        df = pd.read_excel(file_path) if fmt == "excel" else pd.read_csv(file_path, low_memory=False)
        df.columns = df.columns.str.strip()

        if "record.title" in df.columns:
            return self._parse_opus(df)
        return self._parse_legacy(df)

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

            name = get("record.title")
            if not name:
                continue

            file_str = get("record.location.file", "unknown")
            line     = get("record.location.line")
            location = f"{file_str}:{int(float(line))}" if line else file_str

            sev_raw    = (get("record.severity") or "").lower()
            severity   = sev_raw if sev_raw in {"critical", "high", "medium", "low"} else None
            cvss       = _SEVERITY_TO_CVSS.get(sev_raw, 0.0)
            conf_raw   = (get("record.confidence") or "").lower()
            confidence = _CONFIDENCE_MAP.get(conf_raw)

            cwes      = _split_cwes(get("record.cwe"))
            owasp_ids = _parse_owasp_ids(get("record.owasp"))

            description = get("record.description")
            impact      = get("record.impact")
            if impact and description:
                description = f"{description}\n\nImpact: {impact}"
            elif impact:
                description = impact

            try:
                records.append(VulnerabilityRecord(
                    name=name,
                    location=location,
                    cvss_score=cvss,
                    severity=severity,
                    confidence=confidence,
                    description=description,
                    solution=get("record.remediation.summary"),
                    category=get("record.category"),
                    cwes=cwes,
                    owasp_ids=owasp_ids,
                    last_found_at=datetime.now(timezone.utc),
                    source=self.source_id,
                ))
            except Exception as exc:
                logger.debug("Skipping SAST row — %s", exc)

        logger.info("Opus SAST: parsed %d records", len(records))
        return records

    # ------------------------------------------------------------------
    # Legacy triage Excel format — Title/Severity/File/Line columns
    # ------------------------------------------------------------------

    def _parse_legacy(self, df: pd.DataFrame) -> list[VulnerabilityRecord]:
        missing = {"Title", "Severity", "File", "Line"} - set(df.columns)
        if missing:
            raise ValueError(f"File does not appear to be a SAST export. Missing columns: {missing}")

        records: list[VulnerabilityRecord] = []

        for _, row in df.iterrows():
            def get(col: str, default=None):
                v = row.get(col)
                if v is None or (isinstance(v, float) and pd.isna(v)):
                    return default
                s = str(v).strip()
                return s if s not in ("", "nan", "None") else default

            name = get("Title")
            if not name:
                continue

            file_str = get("File", "unknown")
            line     = get("Line")
            location = f"{file_str}:{int(float(line))}" if line else file_str

            sev_raw    = (get("Severity") or "").lower()
            severity   = sev_raw if sev_raw in {"critical", "high", "medium", "low"} else None
            cvss       = _SEVERITY_TO_CVSS.get(sev_raw, 0.0)
            conf_raw   = (get("Confidence") or "").lower()
            confidence = _CONFIDENCE_MAP.get(conf_raw)

            cwes      = _split_cwes(get("CWE"))
            owasp_ids = _parse_owasp_ids(get("OWASP"))

            description = get("Description")
            impact      = get("Impact")
            if impact and description:
                description = f"{description}\n\nImpact: {impact}"
            elif impact:
                description = impact

            try:
                records.append(VulnerabilityRecord(
                    name=name,
                    location=location,
                    cvss_score=cvss,
                    severity=severity,
                    confidence=confidence,
                    description=description,
                    solution=get("Remediation"),
                    category=get("Finding Category"),
                    cwes=cwes,
                    owasp_ids=owasp_ids,
                    last_found_at=datetime.now(timezone.utc),
                    source=self.source_id,
                ))
            except Exception as exc:
                logger.debug("Skipping SAST legacy row — %s", exc)

        logger.info("Opus SAST (legacy): parsed %d records", len(records))
        return records
