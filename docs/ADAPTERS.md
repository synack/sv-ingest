# Writing a New Adapter

Adapters are the source-specific parsers that translate scanner exports into
`VulnerabilityRecord` objects. Adding a new scanner format requires one new
file and two lines of registration code.

---

## Quick start

```
scanner_ingest/adapters/
  base.py           ← abstract base, helpers
  tenable_sc.py     ← example: CSV with column variance
  cisa.py           ← example: multi-format (KEV + CyHy)
  qualys.py         ← example: custom date parsing, CWE splitting
  generic.py        ← example: config-driven field mapping
  myformat.py       ← your new adapter goes here
  __init__.py       ← register here
```

---

## Step 1 — Create the adapter file

```python
# scanner_ingest/adapters/myformat.py
from __future__ import annotations

import logging
from datetime import datetime, timezone
from pathlib import Path

import pandas as pd

from scanner_ingest.models import VulnerabilityRecord
from .base import BaseAdapter

logger = logging.getLogger(__name__)


class MyFormatAdapter(BaseAdapter):

    def parse(self, file_path: Path) -> list[VulnerabilityRecord]:
        fmt = self._detect_format(file_path)
        df = pd.read_excel(file_path) if fmt == "excel" else pd.read_csv(file_path)
        df.columns = df.columns.str.strip()
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

            name = get("Vulnerability Name")
            if not name:
                continue

            try:
                records.append(VulnerabilityRecord(
                    name=name,
                    location=get("Host") or "unknown",
                    cvss_score=min(max(self._safe_float(get("CVSS Score"), 0.0), 0.0), 10.0),
                    cvss_version=self.config.get("default_cvss_version", 3.1),
                    severity=get("Severity"),
                    description=get("Description"),
                    solution=get("Solution"),
                    cves=self._split_ids(get("CVEs", "")),
                    cwes=self._split_ids(get("CWEs", "")),
                    first_found_at=self._parse_date(get("First Seen")),
                    last_found_at=self._parse_date(get("Last Seen")) or datetime.now(timezone.utc),
                    source=self.source_id,
                ))
            except Exception as exc:
                logger.debug("Skipping row — %s", exc)

        logger.info("MyFormat: parsed %d records", len(records))
        return records
```

---

## Step 2 — Register the adapter

```python
# scanner_ingest/adapters/__init__.py
from .myformat import MyFormatAdapter          # add this import

ADAPTER_REGISTRY: dict[str, type] = {
    "tenable_sc": TenableSCAdapter,
    "cisa":       CISAAdapter,
    "qualys":     QualysAdapter,
    "generic":    GenericAdapter,
    "myformat":   MyFormatAdapter,             # add this entry
}
```

That's it. The new source type is immediately available in the CLI and web UI.

---

## BaseAdapter reference

All adapters inherit from `BaseAdapter` (`scanner_ingest/adapters/base.py`).

### Constructor

```python
BaseAdapter.__init__(self, source_id: str, config: dict = None)
```

- `self.source_id` — string identifier sent to the Synack API as the `source` field
- `self.config` — the source-specific config dict from `config.yaml` (e.g. `sources.myformat`)

### Abstract method

```python
def parse(self, file_path: Path) -> list[VulnerabilityRecord]:
    ...
```

The only method you must implement. Return an empty list if no records are found;
raise `ValueError` if the file is not a recognized format for this adapter.

### Helper methods

| Method | Description |
|--------|-------------|
| `_detect_format(file_path)` | Returns `"csv"`, `"excel"`, or `"json"` from the file extension. Raises `ValueError` for unsupported extensions. |
| `_parse_date(value)` | Parses common date strings to a UTC-aware `datetime`. Returns `None` if unparseable. Handles ISO 8601, `%Y-%m-%d`, `%m/%d/%Y`, `%d/%m/%Y`. |
| `_safe_float(value, default=0.0)` | Converts `value` to `float`, returning `default` on failure. |
| `_split_ids(value)` | Splits a comma/semicolon-delimited string (or passes through a list) into a `list[str]`. Handles pandas `nan` and `None` gracefully. |

---

## VulnerabilityRecord fields

Defined in `scanner_ingest/models.py`.

| Field | Type | Required | Notes |
|-------|------|----------|-------|
| `name` | `str` | yes | Vulnerability title |
| `location` | `str` | yes | IP, `host:port`, or `protocol://host:port` — see below |
| `cvss_score` | `float` | yes | 0.0–10.0 |
| `cvss_version` | `float` | no | Default `3.1` |
| `severity` | `str` | no | `critical`, `high`, `medium`, `low` — invalid values silently become `None` |
| `confidence` | `str` | no | `certain`, `firm`, `tentative` — invalid values silently become `None` |
| `description` | `str` | no | |
| `solution` | `str` | no | |
| `category` | `str` | no | |
| `cves` | `list[str]` | no | e.g. `["CVE-2024-1234"]` |
| `cwes` | `list[str]` | no | e.g. `["CWE-79"]` |
| `owasp_ids` | `list[str]` | no | |
| `first_found_at` | `datetime` | no | UTC-aware |
| `last_found_at` | `datetime` | no | Defaults to now |
| `vendor_risk_score` | `float` | no | |
| `asset_uid` | `str` | no | Synack asset UID |
| `listing_uid` | `str` | no | Synack listing UID |
| `source` | `str` | yes | Set to `self.source_id` |

### Location format

The Synack API accepts three location formats:

```
192.168.1.1               # bare IP (host-level finding)
192.168.1.1:443           # IP + port
https://192.168.1.1:443   # protocol + IP + port
```

Protocol without a port is **rejected**. Port `0` should be treated as absent
(yields a bare IP). Use the `_build_location()` helper in `generic.py` as a reference.

---

## Config access

Your adapter can read source-specific settings from `self.config`:

```yaml
# config.yaml
sources:
  myformat:
    source_id: "my-scanner"
    default_cvss_version: 3.1
    custom_setting: "value"
```

```python
self.config.get("custom_setting")          # "value"
self.config.get("default_cvss_version", 3.1)
```
