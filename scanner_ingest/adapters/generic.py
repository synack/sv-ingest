"""
Generic adapter — handles arbitrary CSV/JSON/Excel files via a configurable
field_mapping in config.yaml.  Used for custom scanner outputs.

field_mapping keys are internal VulnerabilityRecord field names; values are
the corresponding column/key names in the source file.
"""
from __future__ import annotations

import json
import logging
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import pandas as pd

from scanner_ingest.models import VulnerabilityRecord
from .base import BaseAdapter

logger = logging.getLogger(__name__)

_DEFAULTS: dict[str, Any] = {
    "name":          None,
    "location":      None,
    "cvss_score":    "cvss_score",
    "cvss_version":  "cvss_version",
    "severity":      "severity",
    "description":   "description",
    "solution":      "solution",
    "category":      "category",
    "cves":          "cves",
    "cwes":          "cwes",
    "owasp_ids":     "owasp_ids",
    "confidence":    "confidence",
    "first_found_at":"first_found_at",
    "last_found_at": "last_found_at",
    "vendor_risk_score": "vendor_risk_score",
    "asset_uid":     "asset_uid",
    "listing_uid":   "listing_uid",
}


class GenericAdapter(BaseAdapter):

    def __init__(self, source_id: str, config: dict = None):
        super().__init__(source_id, config)
        # Merge user-supplied field_mapping over defaults
        self._mapping: dict[str, Any] = {**_DEFAULTS, **(self.config.get("field_mapping") or {})}

    def parse(self, file_path: Path) -> list[VulnerabilityRecord]:
        fmt = self._detect_format(file_path)
        if fmt == "json":
            return self._parse_json(file_path)
        df = pd.read_excel(file_path) if fmt == "excel" else pd.read_csv(file_path)
        df.columns = df.columns.str.strip()
        return self._parse_dataframe(df)

    # ------------------------------------------------------------------
    # CSV / Excel
    # ------------------------------------------------------------------

    def _parse_dataframe(self, df: pd.DataFrame) -> list[VulnerabilityRecord]:
        records: list[VulnerabilityRecord] = []

        for _, row in df.iterrows():
            item = {k: (None if pd.isna(v) else v) for k, v in row.items()}
            rec = self._build_record(item)
            if rec:
                records.append(rec)

        logger.info("Generic: parsed %d records", len(records))
        return records

    # ------------------------------------------------------------------
    # JSON
    # ------------------------------------------------------------------

    def _parse_json(self, file_path: Path) -> list[VulnerabilityRecord]:
        with open(file_path) as fh:
            data = json.load(fh)

        items = data if isinstance(data, list) else [data]
        records: list[VulnerabilityRecord] = []

        for item in items:
            if not isinstance(item, dict):
                continue
            rec = self._build_record(item)
            if rec:
                records.append(rec)

        logger.info("Generic (JSON): parsed %d records", len(records))
        return records

    # ------------------------------------------------------------------
    # Shared builder
    # ------------------------------------------------------------------

    def _build_record(self, item: dict) -> VulnerabilityRecord | None:
        def get(field: str, default=None):
            src_key = self._mapping.get(field)
            if src_key is None:
                return default
            v = item.get(src_key, default)
            return v if v not in (None, "", "nan", "None") else default

        # Location: use explicit mapping, or combine host + port if available
        location = get("location")
        if not location:
            host     = str(item.get("host") or item.get("ip") or item.get("target") or "unknown")
            port     = item.get("port")
            protocol = item.get("protocol")
            location = _build_location(host, str(port) if port else None, str(protocol) if protocol else None)

        name = get("name")
        if not name:
            logger.debug("Skipping record — no name field found (mapping: %s)", self._mapping.get("name"))
            return None

        cvss      = min(max(self._safe_float(get("cvss_score"), 0.0), 0.0), 10.0)
        cvss_ver  = self._safe_float(get("cvss_version"), self.config.get("default_cvss_version", 3.1))

        cves      = self._split_ids(get("cves"))
        cwes      = self._split_ids(get("cwes"))
        owasp_ids = self._split_ids(get("owasp_ids"))

        vrs_raw   = get("vendor_risk_score")
        vrs       = self._safe_float(vrs_raw) if vrs_raw is not None else None

        first_at  = self._parse_date(get("first_found_at"))
        last_at   = self._parse_date(get("last_found_at")) or datetime.now(timezone.utc)

        try:
            return VulnerabilityRecord(
                name=str(name),
                location=location,
                cvss_score=cvss,
                cvss_version=cvss_ver,
                severity=get("severity"),
                description=get("description"),
                solution=get("solution"),
                category=get("category"),
                cves=cves,
                cwes=cwes,
                owasp_ids=owasp_ids,
                confidence=get("confidence"),
                first_found_at=first_at,
                last_found_at=last_at,
                vendor_risk_score=vrs,
                asset_uid=get("asset_uid"),
                listing_uid=get("listing_uid"),
                source=self.source_id,
            )
        except Exception as exc:
            logger.debug("Skipping record — %s", exc)
            return None


def _build_location(host: str, port: str | None, protocol: str | None) -> str:
    if port:
        try:
            port_int = int(float(port))
            port = None if port_int == 0 else str(port_int)
        except (ValueError, TypeError):
            port = None
    has_port = bool(port)
    if protocol and has_port:
        return f"{protocol}://{host}:{port}"
    if has_port:
        return f"{host}:{port}"
    return host
