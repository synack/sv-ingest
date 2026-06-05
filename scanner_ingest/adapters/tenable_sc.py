"""
Tenable SC adapter — handles both CSV exports and JSON (API response format).

CSV column names vary by Tenable SC version and export template, so this adapter
uses an alias table to find the right column regardless of exact naming.
"""
from __future__ import annotations

import ipaddress
import json
import logging
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

import pandas as pd

from scanner_ingest.models import VulnerabilityRecord
from .base import BaseAdapter

logger = logging.getLogger(__name__)

# Maps internal field names to possible CSV column name variants
_COL_ALIASES: dict[str, list[str]] = {
    "name":       ["Name", "Plugin Name", "pluginName", "Vulnerability"],
    "cvss3":      ["CVSS v3.0 Base Score", "CVSS v3 Base Score", "CVSS V3 Base Score", "cvssV3BaseScore", "CVSS3"],
    "cvss2":      ["CVSS v2.0 Base Score", "CVSS v2 Base Score", "CVSS V2 Base Score", "cvssV2BaseScore", "CVSS2", "CVSS"],
    "severity":   ["Risk", "Severity", "severity"],
    "host":       ["Host", "IP Address", "ip", "Asset", "DNS Name", "NetBIOS Name"],
    "port":       ["Port", "port"],
    "protocol":   ["Protocol", "protocol"],
    "description":["Description", "description", "Synopsis", "synopsis"],
    "solution":   ["Solution", "solution", "Steps to Remediate", "Remediation"],
    "cve":        ["CVE", "CVE ID", "cve", "CVEs"],
    "first_seen": ["First Seen", "First Discovered", "firstSeen", "firstDiscovered"],
    "last_seen":  ["Last Seen", "Last Observed", "lastSeen", "lastObserved"],
}

_RISK_MAP: dict[str, Optional[str]] = {
    "critical": "critical",
    "high":     "high",
    "medium":   "medium",
    "low":      "low",
    "info":     None,
    "none":     None,
    "informational": None,
}


class TenableSCAdapter(BaseAdapter):

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

    def _resolve_col(self, df: pd.DataFrame, field: str) -> Optional[str]:
        override = self.config.get("column_map", {}).get(field)
        if override:
            return override if override in df.columns else None
        for alias in _COL_ALIASES.get(field, []):
            if alias in df.columns:
                return alias
        return None

    def _parse_dataframe(self, df: pd.DataFrame) -> list[VulnerabilityRecord]:
        col = {f: self._resolve_col(df, f) for f in _COL_ALIASES}

        cvss_version = 3.1
        if col["cvss3"]:
            cvss_col, cvss_version = col["cvss3"], 3.1
        elif col["cvss2"]:
            cvss_col, cvss_version = col["cvss2"], 2.0
        else:
            cvss_col = None

        default_cvss_version = self.config.get("default_cvss_version", cvss_version)

        records: list[VulnerabilityRecord] = []
        for _, row in df.iterrows():
            def get(field: str, default=None):
                c = col.get(field)
                if not c:
                    return default
                v = row.get(c)
                if pd.isna(v):
                    return default
                return str(v).strip() or default

            name = get("name")
            if not name:
                continue

            host     = get("host", "unknown")
            port     = get("port")
            protocol = get("protocol")
            location = _build_location(host, port, protocol)

            cvss_raw = row.get(cvss_col) if cvss_col else None
            cvss     = min(max(self._safe_float(cvss_raw), 0.0), 10.0)

            sev_raw  = get("severity", "")
            severity = _RISK_MAP.get(sev_raw.lower()) if sev_raw else None

            cves = [c for c in self._split_ids(get("cve", "")) if c.upper().startswith("CVE")]

            try:
                records.append(VulnerabilityRecord(
                    name=name,
                    location=location,
                    cvss_score=cvss,
                    cvss_version=default_cvss_version,
                    severity=severity,
                    description=get("description"),
                    solution=get("solution"),
                    cves=cves,
                    first_found_at=self._parse_date(get("first_seen")),
                    last_found_at=self._parse_date(get("last_seen")) or datetime.now(timezone.utc),
                    source=self.source_id,
                ))
            except Exception as exc:
                logger.debug("Skipping row — %s", exc)

        logger.info("Tenable SC: parsed %d records", len(records))
        return records

    # ------------------------------------------------------------------
    # JSON (Tenable SC REST API response envelope)
    # ------------------------------------------------------------------

    def _parse_json(self, file_path: Path) -> list[VulnerabilityRecord]:
        with open(file_path) as fh:
            data = json.load(fh)

        if isinstance(data, dict):
            response = data.get("response", data)
            items = response.get("results", response) if isinstance(response, dict) else response
        elif isinstance(data, list):
            items = data
        else:
            return []

        records: list[VulnerabilityRecord] = []
        for item in items:
            if not isinstance(item, dict):
                continue

            host     = item.get("ip") or item.get("host") or (item.get("asset") or {}).get("ipv4", "unknown")
            port     = item.get("port", "")
            protocol = item.get("protocol", "")
            location = _build_location(str(host), str(port) if port else None, str(protocol) if protocol else None)

            if item.get("cvssV3BaseScore"):
                cvss, cvss_version = self._safe_float(item["cvssV3BaseScore"]), 3.1
            elif item.get("cvssV2BaseScore"):
                cvss, cvss_version = self._safe_float(item["cvssV2BaseScore"]), 2.0
            else:
                cvss, cvss_version = 0.0, 3.1

            sev_obj  = item.get("severity", {})
            sev_name = sev_obj.get("name", "") if isinstance(sev_obj, dict) else str(sev_obj)
            severity = _RISK_MAP.get(sev_name.lower())

            cves = [c for c in self._split_ids(item.get("cve", "")) if str(c).upper().startswith("CVE")]

            name = item.get("name") or item.get("pluginName", "")
            if not name:
                continue

            try:
                records.append(VulnerabilityRecord(
                    name=name,
                    location=location,
                    cvss_score=min(max(cvss, 0.0), 10.0),
                    cvss_version=cvss_version,
                    severity=severity,
                    description=item.get("description") or item.get("synopsis"),
                    solution=item.get("solution"),
                    cves=cves,
                    first_found_at=self._parse_date(item.get("firstSeen") or item.get("firstDiscovered")),
                    last_found_at=self._parse_date(item.get("lastSeen") or item.get("lastObserved")) or datetime.now(timezone.utc),
                    source=self.source_id,
                ))
            except Exception as exc:
                logger.debug("Skipping JSON item — %s", exc)

        logger.info("Tenable SC (JSON): parsed %d records", len(records))
        return records


def _is_ip(host: str) -> bool:
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        return False


def _build_location(host: str, port: Optional[str], protocol: Optional[str]) -> str:
    """Build a location string matching the Synack API spec.

    For IP hosts: bare IP, protocol://IP, or protocol://IP:port.
    For hostnames: https://host or https://host:port (API requires URL format for non-IPs).
    Port 0 is treated as absent (Tenable uses 0 for protocol-level findings).
    Pandas often reads integer columns as floats ("80.0"); we normalize those.
    """
    if port:
        try:
            port_int = int(float(port))
            port = None if port_int == 0 else str(port_int)
        except (ValueError, TypeError):
            port = None
    has_port = bool(port)
    proto = protocol.lower() if protocol else None

    _PORT_REQUIRED = {"tcp", "udp"}

    if _is_ip(host):
        if proto and has_port:
            return f"{proto}://{host}:{port}"
        if proto and proto not in _PORT_REQUIRED:
            # e.g. icmp://192.168.1.1 — protocols that don't use ports
            return f"{proto}://{host}"
        if has_port:
            return f"tcp://{host}:{port}"
        return host
    else:
        # Hostname — API only accepts URL format (scheme + host) for non-IPs
        if has_port:
            return f"https://{host}:{port}"
        return f"https://{host}"
