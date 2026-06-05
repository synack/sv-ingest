"""
Orchestrates: file → adapter → validate → Synack API.
"""
from __future__ import annotations

import logging
import os
import re
from dataclasses import dataclass, field
from pathlib import Path

from scanner_ingest.adapters import get_adapter
from scanner_ingest.models import VulnerabilityRecord
from scanner_ingest.synack_client import SynackClient, resolve_org_uid

logger = logging.getLogger(__name__)

# Matches bare IPs or anything with a URL scheme (https://, tcp://, etc.)
_NETWORK_LOC_RE = re.compile(r'^(?:\w[\w.+-]*://|(?:\d{1,3}\.){3}\d{1,3})')


def _is_network_loc(loc: str) -> bool:
    return bool(_NETWORK_LOC_RE.match(loc))


@dataclass
class IngestResult:
    file: Path
    source_type: str
    org_uid: str
    parsed: int = 0
    submitted: int = 0
    skipped: int = 0
    created_ids: list[int] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)

    @property
    def success(self) -> bool:
        return not self.errors


def run(
    file_path: Path,
    source_type: str,
    org_uid: str,
    config: dict,
    platform: str = "commercial",
    dry_run: bool = False,
    listing_uid: str | None = None,
    asset_uid: str | None = None,
    default_location: str | None = None,
    progress_cb=None,
) -> IngestResult:
    result = IngestResult(file=file_path, source_type=source_type, org_uid=org_uid)

    src_config = config.get("sources", {}).get(source_type, {})
    source_id  = src_config.get("source_id", source_type.replace("_", "-"))

    # default_location: explicit arg takes priority, then per-source config
    if not default_location:
        default_location = src_config.get("default_location") or None

    # Resolve org_uid: explicit arg > env var > config > assets API
    if not org_uid:
        org_uid = os.getenv("SYNACK_ORG_UID") or config.get("synack", {}).get("organization_uid", "")
    if not org_uid:
        try:
            org_uid = resolve_org_uid(platform, config)
            logger.info("Auto-resolved organizationUid: %s", org_uid)
        except Exception as exc:
            result.errors.append(f"Could not resolve organization UID: {exc}")
            return result
    result.org_uid = org_uid

    try:
        adapter = get_adapter(source_type, source_id=source_id, config=src_config)
        records: list[VulnerabilityRecord] = adapter.parse(file_path)
        result.parsed = len(records)
        logger.info("Parsed %d records from %s", result.parsed, file_path.name)
    except Exception as exc:
        result.errors.append(f"Parse error: {exc}")
        logger.error("Parse error for %s: %s", file_path, exc)
        return result

    if not records:
        logger.warning("No records found in %s", file_path)
        return result

    # Apply optional overrides for asset/listing UID
    if listing_uid or asset_uid:
        for rec in records:
            if listing_uid and not rec.listing_uid:
                rec.listing_uid = listing_uid
            if asset_uid and not rec.asset_uid:
                rec.asset_uid = asset_uid

    # Apply default_location to any record whose location isn't a valid network address/URL
    if default_location:
        replaced = 0
        for rec in records:
            if not _is_network_loc(rec.location or ""):
                rec.location = default_location
                replaced += 1
        if replaced:
            logger.info("Applied default_location to %d record(s) with non-network locations", replaced)

    try:
        client = SynackClient(config, platform=platform)
        ids, skipped       = client.submit(org_uid, records, dry_run=dry_run, progress_cb=progress_cb)
        result.submitted   = len(records)
        result.skipped     = skipped
        result.created_ids = ids
    except Exception as exc:
        result.errors.append(f"Submit error: {exc}")
        logger.error("Submit error: %s", exc)

    return result
