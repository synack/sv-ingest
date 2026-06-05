# Scanner Ingest

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

**Bring your existing vulnerability scan results into Synack.**

Scanner Ingest reads exports from the security scanners you already run, normalizes
them into a single common format, and submits them to the Synack platform as
Suspected Vulnerabilities (SVs). Use it from the command line for one-off uploads,
through a simple web interface, or as a background service that watches a folder and
ingests new scan files automatically.

---

## Why use it

- **Works with the tools you have** — Tenable, CISA KEV/Cyber Hygiene, Qualys, and any
  generic CSV/JSON scanner via configurable field mapping.
- **Three ways to run it** — CLI, web UI, or an unattended directory-watching service.
- **Safe to try** — `--dry-run` parses and validates a file without submitting anything.
- **Commercial and FedRAMP** — point it at either Synack environment.

---

## Supported scanners

| Source type | Format | Description |
|-------------|--------|-------------|
| `tenable_sc` | CSV / Excel | Tenable Security Center vulnerability export |
| `cisa` | CSV | CISA Known Exploited Vulnerabilities (KEV) catalog or Cyber Hygiene (CyHy) report |
| `qualys` | CSV / Excel | Qualys WAS export |
| `generic` | CSV / JSON | Any scanner — map its columns to the common model in `config.yaml` |
| `opus-sast` | CSV / Excel | Static analysis (SAST) export — set a **Default Location** (see [SAST/SCA notes](#sastsca-notes)) |
| `opus-sca` | CSV / Excel | Software composition analysis (SCA) export — set a **Default Location** (see [SAST/SCA notes](#sastsca-notes)) |

Don't see your scanner? Use the `generic` adapter, or [add a new one](#adding-a-new-scanner) — it's a small Python file.

---

## Quick start

```bash
# 1. Install (Python 3.12+)
pip install -r requirements.txt

# 2. Store your Synack API token (saved to your OS keychain)
python ingest.py token set --platform commercial

# 3. Validate a file without submitting anything
python ingest.py ingest tenable_sc --file scan.csv --org <ORG_UID> --dry-run

# 4. Submit for real
python ingest.py ingest tenable_sc --file scan.csv --org <ORG_UID>
```

Prefer a container? See [Running in a container](#running-in-a-container).

---

## Authentication

Store an API token once per Synack environment — it's saved to your OS keychain:

```bash
python ingest.py token set --platform commercial   # https://api.synack.com
python ingest.py token set --platform fedramp      # https://api.synack.us
```

For CI or container use, supply tokens via environment variables instead:

```bash
export SYNACK_TOKEN=your_commercial_bearer_token
export SYNACK_FEDRAMP_TOKEN=your_fedramp_bearer_token
export SYNACK_ORG_UID=your_org_uid
```

Or copy `.env.example` to `.env` and fill in your values.

Tokens are resolved in this order: **keychain → file store (`SYNACK_TOKEN_FILE`) → environment variable → `config.yaml`**.

---

## Usage

### Command line

```bash
# Tenable Security Center
python ingest.py ingest tenable_sc --file scan.csv --org <ORG_UID>

# CISA KEV / Cyber Hygiene
python ingest.py ingest cisa --file kev.csv --org <ORG_UID>

# Qualys WAS
python ingest.py ingest qualys --file report.csv --org <ORG_UID>

# Generic / custom scanner
python ingest.py ingest generic --file out.json --org <ORG_UID> --source my-scanner

# Target the FedRAMP environment
python ingest.py ingest tenable_sc --file scan.csv --org <ORG_UID> --platform fedramp

# Dry run — parse and validate without submitting
python ingest.py ingest tenable_sc --file scan.csv --org <ORG_UID> --dry-run
```

See all options with `python ingest.py ingest --help`.

### Web interface

```bash
pip install -r requirements.txt
uvicorn web.ingest_ui:app --port 8080
```

Then open <http://localhost:8080>. The web UI lets you upload a file, manage tokens,
resolve your organization UID, and watch real-time progress. Press `Ctrl+C` to stop the server.

### Service mode — watch a folder

Configure one or more `watch_dirs` in `config.yaml` (see `config.yaml.example`), then:

```bash
python ingest.py serve --config config.yaml
```

The service polls each watched directory on an interval (default 60s) and ingests any new
files it finds. Already-processed files are tracked so they aren't submitted twice.

---

## SAST/SCA notes

SAST findings use file paths (`src/auth/login.py:42`) and SCA findings use package
coordinates (`org.example:library:1.2.3`) as their location. The Synack API expects a
network address (IP or URL), so supply a fallback **Default Location**:

**Web UI** — expand **Optional fields** and set **Default Location** before uploading.

**Command line:**
```bash
python ingest.py ingest opus-sast --file sast.csv --org <ORG_UID> \
  --default-location https://app.example.com
```

**config.yaml** (applied automatically):
```yaml
sources:
  opus-sast:
    default_location: https://app.example.com
  opus-sca:
    default_location: 10.0.0.1
```

The fallback is applied only to records that don't already carry a valid IP or URL;
findings with a real network location are left unchanged.

---

## Configuration

`config.yaml` is optional — every setting has a default or an environment-variable
equivalent. To customize, copy the example and edit:

```bash
cp config.yaml.example config.yaml
```

Common settings:

| Setting | Default | Description |
|---------|---------|-------------|
| `synack.platform` | `commercial` | Default Synack environment |
| `synack.organization_uid` | `""` | Org UID (or set `SYNACK_ORG_UID`) |
| `synack.batch_size` | `100` | Vulnerabilities submitted per API request |
| `synack.retry_attempts` | `3` | Retries on transient API errors |
| `scheduler.poll_interval_seconds` | `60` | Directory watch interval (service mode) |

See [docs/CONFIGURATION.md](docs/CONFIGURATION.md) for the complete reference.

---

## Running in a container

```bash
# With Compose
docker compose up --build

# Or directly
docker build -t scanner-ingest .
docker run -d --name scanner-ingest \
  -p 8080:8080 \
  -v ./data:/data \
  -e SYNACK_TOKEN_FILE=/data/tokens.json \
  scanner-ingest
```

The `/data` volume persists your token store and the processed-files log.
See [docs/DEPLOYMENT.md](docs/DEPLOYMENT.md) for the full deployment guide.

---

## Documentation

| Document | Description |
|----------|-------------|
| [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) | High-level system map: data flow and key modules |
| [docs/CONFIGURATION.md](docs/CONFIGURATION.md) | Full `config.yaml` reference |
| [docs/DEPLOYMENT.md](docs/DEPLOYMENT.md) | Container setup, volumes, env vars, updates |
| [docs/ADAPTERS.md](docs/ADAPTERS.md) | Guide to writing and registering new adapters |
| [docs/API.md](docs/API.md) | Web API endpoint reference |

---

## Adding a new scanner

Each scanner is a small adapter — one Python file:

1. Create `scanner_ingest/adapters/myformat.py` subclassing `BaseAdapter`.
2. Implement `parse(file_path) -> list[VulnerabilityRecord]`.
3. Register it in `scanner_ingest/adapters/__init__.py`:

   ```python
   from .myformat import MyFormatAdapter

   ADAPTER_REGISTRY = {
       ...
       "myformat": MyFormatAdapter,
   }
   ```

The new source type then appears automatically in both the CLI and the web UI.
See [docs/ADAPTERS.md](docs/ADAPTERS.md) for the full guide.

---

## Project layout

```
scanner_ingest/
  adapters/         # Source-specific parsers (one file per scanner)
  auth.py           # Token storage and lookup
  models.py         # VulnerabilityRecord — the common data model
  pipeline.py       # Orchestrates: file → adapter → validate → API
  scheduler.py      # Directory watcher (service mode)
  synack_client.py  # Synack API client
web/
  ingest_ui.py      # FastAPI web UI
  templates/        # HTML templates
ingest.py           # CLI entry point
```

---

## License

Released under the [MIT License](LICENSE).
