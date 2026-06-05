"""
Synack API client.

Auth: Synack uses OAuth2 implicit flow (browser-based).  For programmatic use,
supply a pre-obtained Bearer token via `python cli.py token set` (stored in the
OS keychain) or the SYNACK_TOKEN / SYNACK_FEDRAMP_TOKEN env vars.
"""
from __future__ import annotations

import logging
import time
from typing import Iterator

import requests

from scanner_ingest import auth
from scanner_ingest.models import VulnerabilityRecord

logger = logging.getLogger(__name__)

_DEFAULT_BATCH   = 100
_DEFAULT_RETRIES = 3
_RETRY_STATUS    = {429, 500, 502, 503, 504}

# Vulnerability ingest API base URLs
_VULN_API_BASE = {
    "commercial": "https://client.synack.com/api/vulnerability",
    "fedramp":    "https://client.synack.us/api/vulnerability",
}

# Asset API base URLs (used only for org UID resolution)
_ASSET_API_BASE = {
    "commercial": "https://client.synack.com/api/asset",
    "fedramp":    "https://client.synack.us/api/asset",
}


def resolve_org_uid(platform: str, config: dict) -> str:
    """Resolve the organization UID by fetching one asset from the assets API."""
    token = auth.get_token(platform, config)
    if not token:
        raise ValueError(
            f"No token set for platform '{platform}'. "
            f"Run: python ingest.py token set --platform {platform}"
        )
    base = _ASSET_API_BASE[platform]
    resp = requests.get(
        f"{base}/v2/assets",
        params={"perPage": 1},
        headers={"Authorization": f"Bearer {token}", "Accept": "application/json"},
        timeout=10,
    )
    resp.raise_for_status()
    data = resp.json()
    assets = data if isinstance(data, list) else data.get("assets", data.get("data", []))
    if not assets:
        raise ValueError("No assets returned — cannot determine organization UID.")
    org_uid = assets[0].get("organizationUid", "")
    if not org_uid:
        raise ValueError("Asset response did not include 'organizationUid'.")
    logger.info("Resolved organizationUid: %s", org_uid)
    return org_uid


class SynackClient:

    def __init__(self, config: dict, platform: str = "commercial"):
        synack_cfg   = config.get("synack", {})
        self._platform = platform
        self._base   = _VULN_API_BASE[platform].rstrip("/")
        self._token  = auth.get_token(platform, config)
        self._batch  = int(synack_cfg.get("batch_size") or _DEFAULT_BATCH)
        self._retry  = int(synack_cfg.get("retry_attempts") or _DEFAULT_RETRIES)

        if not self._token:
            raise ValueError(
                f"No Synack token found for platform '{platform}'. "
                f"Run: python cli.py token set --platform {platform}"
            )

        self._session = requests.Session()
        self._session.headers.update({
            "Authorization": f"Bearer {self._token}",
            "Content-Type":  "application/json",
            "Accept":        "application/json",
        })

    def submit(
        self,
        org_uid: str,
        records: list[VulnerabilityRecord],
        dry_run: bool = False,
        progress_cb=None,
    ) -> tuple[list[int], int]:
        """Submit all records in batches.

        Returns (created_ids, skipped) where skipped is the count of
        individual records the API rejected with HTTP 403.
        """
        if not org_uid:
            raise ValueError("organization_uid is required")

        url         = f"{self._base}/v1/organizations/{org_uid}/suspected-vulnerabilities"
        all_ids:    list[int] = []
        skipped_count = 0
        submitted   = 0

        for batch in _chunks(records, self._batch):
            logger.info("Submitting batch of %d to %s (dry_run=%s)", len(batch), url, dry_run)

            if dry_run:
                payload = [r.to_synack() for r in batch]
                logger.info("[DRY RUN] Payload sample: %s", payload[0] if payload else {})
            else:
                ids, skipped = self._submit_batch(url, batch)
                all_ids.extend(ids)
                skipped_count += skipped
                if ids:
                    logger.info("  → created IDs: %s", ids)

            submitted += len(batch)
            if progress_cb:
                progress_cb(submitted, len(records))

        return all_ids, skipped_count

    def _submit_batch(
        self,
        url: str,
        batch: list[VulnerabilityRecord],
    ) -> tuple[list[int], int]:
        """Submit a batch, splitting recursively on HTTP 403.

        On a 403, the batch is halved and each half retried so a single
        rejected record does not block the rest. Records that are still
        rejected when submitted alone are logged and skipped.

        Returns (created_ids, skipped_count).
        """
        payload = [r.to_synack() for r in batch]
        try:
            ids = self._post_with_retry(url, payload)
            return ids, 0
        except RuntimeError as exc:
            if "HTTP 403" not in str(exc):
                raise
            if len(batch) == 1:
                logger.warning("Record rejected (HTTP 403), skipping: %r", batch[0].name[:80])
                return [], 1
            mid = len(batch) // 2
            ids1, skip1 = self._submit_batch(url, batch[:mid])
            ids2, skip2 = self._submit_batch(url, batch[mid:])
            return ids1 + ids2, skip1 + skip2

    def _post_with_retry(self, url: str, payload: list[dict]) -> list[int]:
        delay      = 2.0
        last_exc:  Exception | None = None
        last_resp: requests.Response | None = None

        for attempt in range(1, self._retry + 1):
            try:
                resp = self._session.post(url, json=payload, timeout=30)

                if resp.status_code == 201:
                    return resp.json()

                if resp.status_code in _RETRY_STATUS:
                    last_resp = resp
                    body = _safe_body(resp)
                    wait = float(resp.headers.get("Retry-After", delay))
                    logger.warning(
                        "HTTP %d on attempt %d/%d — retrying in %.0fs: %s",
                        resp.status_code, attempt, self._retry, wait, body,
                    )
                    time.sleep(wait)
                    delay *= 2
                    continue

                # Non-retryable HTTP error — fail immediately with full details
                body = _safe_body(resp)
                logger.error("HTTP %d from %s: %s", resp.status_code, url, body)
                raise RuntimeError(f"HTTP {resp.status_code}: {body}")

            except RuntimeError:
                raise
            except requests.RequestException as exc:
                last_exc = exc
                logger.warning("Request error on attempt %d/%d: %s — retrying", attempt, self._retry, exc)
                if attempt < self._retry:
                    time.sleep(delay)
                    delay *= 2

        if last_resp is not None:
            raise RuntimeError(f"HTTP {last_resp.status_code} after {self._retry} attempts: {_safe_body(last_resp)}")
        raise RuntimeError(f"Connection error after {self._retry} attempts: {last_exc}") from last_exc


def _safe_body(resp: requests.Response) -> str:
    try:
        body = resp.json()
        return str(body)
    except Exception:
        return resp.text[:400] or "(empty)"


def _chunks(lst: list, n: int) -> Iterator[list]:
    for i in range(0, len(lst), n):
        yield lst[i : i + n]
