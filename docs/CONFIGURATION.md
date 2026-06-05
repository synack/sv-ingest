# Configuration Reference

Configuration is provided via `config.yaml`. All settings are optional —
the application works with environment variables alone for simple use cases.

Copy the annotated example to get started:

```bash
cp config.yaml.example config.yaml
```

---

## `synack` — API settings

```yaml
synack:
  platform: "commercial"
  organization_uid: ""
  batch_size: 100
  retry_attempts: 3
```

| Key | Default | Description |
|-----|---------|-------------|
| `platform` | `commercial` | Default platform: `commercial` (api.synack.com) or `fedramp` (api.synack.us) |
| `organization_uid` | `""` | Org UID to submit vulnerabilities against. Can also be set via `SYNACK_ORG_UID` env var or `--org` CLI flag. If omitted, the client attempts to auto-detect via the assets API. |
| `batch_size` | `100` | Number of vulnerabilities per API request. Reduce if hitting payload size limits. |
| `retry_attempts` | `3` | Number of retries on transient API errors (5xx, timeouts). |

---

## `sources` — per-adapter settings

Each key matches a source type registered in `ADAPTER_REGISTRY`.

### `tenable_sc`

```yaml
sources:
  tenable_sc:
    source_id: "tenable-sc"
    default_cvss_version: 3.1
    column_map:
      name: "Plugin Name"
      cvss_score: "CVSS v3.0 Base Score"
```

| Key | Default | Description |
|-----|---------|-------------|
| `source_id` | `"tenable-sc"` | String sent to the Synack API as the `source` field. |
| `default_cvss_version` | `3.1` | CVSS version to use when the file does not specify one. |
| `column_map` | `{}` | Override detected column names. Keys are internal field names; values are the column headers in your export. Useful when your Tenable export uses non-standard column names. |

### `cisa`

```yaml
sources:
  cisa:
    source_id: "cisa-hygiene"
    default_cvss_version: 3.1
```

| Key | Default | Description |
|-----|---------|-------------|
| `source_id` | `"cisa-hygiene"` | Source identifier sent to the API. |
| `default_cvss_version` | `3.1` | CVSS version fallback. |

Supports three CISA report formats auto-detected from column headers:
KEV catalog, Cyber Hygiene (CyHy) vulnerability report, and CyHy port/service report.

### `qualys`

```yaml
sources:
  qualys:
    source_id: "qualys-was"
    default_cvss_version: 3.1
```

| Key | Default | Description |
|-----|---------|-------------|
| `source_id` | `"qualys-was"` | Source identifier sent to the API. |
| `default_cvss_version` | `3.1` | CVSS version fallback. |

### `generic`

```yaml
sources:
  generic:
    source_id: "custom-scanner"
    default_cvss_version: 3.1
    field_mapping:
      name: "vulnerability_name"
      location: "target_host"
      cvss_score: "cvss_score"
      severity: "severity"
      description: "description"
      solution: "solution"
      cves: "cve_ids"
      cwes: "cwe_ids"
      first_found_at: "first_seen"
      last_found_at: "last_seen"
      asset_uid: "asset_uid"
      listing_uid: "listing_uid"
```

| Key | Default | Description |
|-----|---------|-------------|
| `source_id` | `"custom-scanner"` | Overridable at runtime with `--source` CLI flag. |
| `default_cvss_version` | `3.1` | CVSS version fallback. |
| `field_mapping` | see below | Maps internal field names to your file's column/key names. |

**`field_mapping` keys** (all optional — unmapped fields are skipped):

| Internal field | Notes |
|----------------|-------|
| `name` | Vulnerability title — required for a record to be created |
| `location` | Target host/URL. If absent, the adapter falls back to `host`/`ip`/`target` columns combined with `port` and `protocol`. |
| `cvss_score` | |
| `cvss_version` | |
| `severity` | Must resolve to `critical`, `high`, `medium`, or `low` |
| `confidence` | Must resolve to `certain`, `firm`, or `tentative` |
| `description` | |
| `solution` | |
| `category` | |
| `cves` | Comma-separated string or JSON array |
| `cwes` | Comma-separated string or JSON array |
| `owasp_ids` | Comma-separated string or JSON array |
| `first_found_at` | Parsed via common date formats |
| `last_found_at` | Defaults to now if absent |
| `vendor_risk_score` | Float |
| `asset_uid` | Synack asset UID |
| `listing_uid` | Synack listing UID |

---

## `scheduler` — service mode

Used only when running `python ingest.py serve`.

```yaml
scheduler:
  poll_interval_seconds: 60
  processed_log: "./processed_files.log"
  watch_dirs:
    - path: "./incoming/tenable"
      source_type: "tenable_sc"
      org_uid: "your-org-uid"
      platform: "commercial"
    - path: "./incoming/fedramp"
      source_type: "tenable_sc"
      org_uid: "your-fedramp-org-uid"
      platform: "fedramp"
```

| Key | Default | Description |
|-----|---------|-------------|
| `poll_interval_seconds` | `60` | How often each watch directory is scanned for new files. |
| `processed_log` | `./processed_files.log` | Path to the log file tracking already-processed files. Files listed here are skipped on subsequent polls. |

### `watch_dirs` entries

| Key | Required | Description |
|-----|----------|-------------|
| `path` | yes | Directory to watch. Relative paths are resolved from the working directory. |
| `source_type` | yes | Adapter to use: `tenable_sc`, `cisa`, `qualys`, or `generic`. |
| `org_uid` | no | Org UID for this directory. Falls back to `SYNACK_ORG_UID` env var. |
| `platform` | no | `commercial` or `fedramp`. Defaults to `synack.platform`. |

---

## Environment variables

Environment variables take effect when the corresponding config.yaml key is
absent. `.env` files are loaded automatically if present.

| Variable | Equivalent config key | Description |
|----------|----------------------|-------------|
| `SYNACK_TOKEN` | — | Commercial platform Bearer token |
| `SYNACK_FEDRAMP_TOKEN` | — | FedRAMP platform Bearer token |
| `SYNACK_ORG_UID` | `synack.organization_uid` | Default org UID |
| `SYNACK_TOKEN_FILE` | — | Path to a JSON token store (used in containers) |

---

## Validation

To verify your configuration without running an ingest:

```bash
python ingest.py validate-config --config config.yaml
```

This prints all resolved settings with tokens masked, platform status, and
all configured watch directories.
