# Web API Reference

The web UI is served by a FastAPI application (`web/ingest_ui.py`) on port `8080`.
All API endpoints are under `/api/`. The full-page UI is at `/`.

> **Note:** OpenAPI/Swagger docs are disabled in the app (`docs_url=None`).
> This document is the authoritative API reference.

---

## Token Management

### `GET /api/tokens`

Returns the current token status for all platforms as an HTML partial.

**Response:** `text/html` — rendered `_tokens.html` partial showing each
platform's masked token and source (keychain, env var, etc.)

---

### `POST /api/tokens/{platform}`

Stores a Bearer token for the given platform.

**Path parameters:**

| Parameter | Values |
|-----------|--------|
| `platform` | `commercial`, `fedramp` |

**Form body:**

| Field | Required | Description |
|-------|----------|-------------|
| `token` | yes | Bearer token string |

**Response:** `text/html` — updated `_tokens.html` partial

**Errors:**

| Status | Condition |
|--------|-----------|
| `400` | Unknown platform |

**Example:**
```bash
curl -X POST http://localhost:8080/api/tokens/commercial \
  -F "token=eyJhbGciOiJSUzI1NiJ9..."
```

---

### `DELETE /api/tokens/{platform}`

Removes the stored token for the given platform.

**Path parameters:**

| Parameter | Values |
|-----------|--------|
| `platform` | `commercial`, `fedramp` |

**Response:** `text/html` — updated `_tokens.html` partial

**Errors:**

| Status | Condition |
|--------|-----------|
| `400` | Unknown platform |

**Example:**
```bash
curl -X DELETE http://localhost:8080/api/tokens/commercial
```

---

## Org UID Resolution

### `GET /api/org-uid/{platform}`

Resolves the organization UID for the given platform by calling the Synack
assets API. Requires a token to be set for that platform.

**Path parameters:**

| Parameter | Values |
|-----------|--------|
| `platform` | `commercial`, `fedramp` |

**Response:** `text/html` — the org UID string (plain text body, HTML content type)

**Errors:**

| Status | Condition |
|--------|-----------|
| `400` | Unknown platform |
| `422` | Token not set, API error, or org cannot be resolved |

**Example:**
```bash
curl http://localhost:8080/api/org-uid/commercial
# abc123def456
```

---

## Ingest

The ingest flow is asynchronous. `POST /api/ingest` starts a background job
and returns a `job_id`. Poll `GET /api/ingest/progress/{job_id}` until
`phase == "done"`, then fetch the result from `GET /api/ingest/result/{job_id}`.

### `POST /api/ingest`

Uploads a vulnerability file and starts an ingest job.

**Form body (multipart/form-data):**

| Field | Required | Description |
|-------|----------|-------------|
| `file` | yes | The vulnerability export file (`.csv`, `.xlsx`, `.json`) |
| `source_type` | yes | Adapter: `tenable_sc`, `cisa`, `qualys`, `generic` |
| `platform` | yes | `commercial` or `fedramp` |
| `org_uid` | yes | Target organization UID |
| `source_override` | no | Override the `source` identifier sent to the Synack API |
| `listing_uid` | no | Associate all records with a specific Synack listing UID |
| `asset_uid` | no | Associate all records with a specific Synack asset UID |
| `dry_run` | no | Any non-null value enables dry-run mode (parse only, no API calls) |

**Response:** `application/json`

```json
{ "job_id": "a3f9c1b2d4e6" }
```

**Errors:**

| Status | Condition |
|--------|-----------|
| `500` | Failed to save uploaded file to temp storage |

**Example:**
```bash
curl -X POST http://localhost:8080/api/ingest \
  -F "file=@scan.csv" \
  -F "source_type=tenable_sc" \
  -F "platform=commercial" \
  -F "org_uid=abc123"
```

---

### `GET /api/ingest/progress/{job_id}`

Polls the progress of a running ingest job.

**Path parameters:**

| Parameter | Description |
|-----------|-------------|
| `job_id` | Job ID returned by `POST /api/ingest` |

**Response:** `application/json`

```json
{
  "phase": "submitting",
  "pct": 42,
  "submitted": 420,
  "total": 1000
}
```

| Field | Description |
|-------|-------------|
| `phase` | `"parsing"` — file is being parsed; `"submitting"` — sending to API; `"done"` — finished |
| `pct` | Integer 0–99 during `submitting` phase, `null` otherwise |
| `submitted` | Number of records submitted so far |
| `total` | Total records to submit (0 during `parsing` phase) |

**Errors:**

| Status | Condition |
|--------|-----------|
| `404` | Unknown `job_id` |

---

### `GET /api/ingest/result/{job_id}`

Fetches the final result HTML for a completed job. The job is removed from
memory after this call.

**Path parameters:**

| Parameter | Description |
|-----------|-------------|
| `job_id` | Job ID returned by `POST /api/ingest` |

**Response:**
- `text/html` with status `200` — rendered result partial (on success or error)
- Empty body with status `202` — job not yet complete

---

## Full ingest flow (example)

```bash
# 1. Start the job
JOB=$(curl -s -X POST http://localhost:8080/api/ingest \
  -F "file=@scan.csv" \
  -F "source_type=tenable_sc" \
  -F "platform=commercial" \
  -F "org_uid=abc123" | python3 -c "import sys,json; print(json.load(sys.stdin)['job_id'])")

# 2. Poll until done
while true; do
  RESP=$(curl -s "http://localhost:8080/api/ingest/progress/$JOB")
  PHASE=$(echo $RESP | python3 -c "import sys,json; print(json.load(sys.stdin)['phase'])")
  echo $RESP
  [ "$PHASE" = "done" ] && break
  sleep 1
done

# 3. Fetch result
curl -s "http://localhost:8080/api/ingest/result/$JOB"
```

---

## Dry-run mode

Pass any value for `dry_run` to parse and validate the file without submitting
to the Synack API. Useful for verifying file format and record count before
a live ingest.

```bash
curl -X POST http://localhost:8080/api/ingest \
  -F "file=@scan.csv" \
  -F "source_type=tenable_sc" \
  -F "platform=commercial" \
  -F "org_uid=abc123" \
  -F "dry_run=1"
```
