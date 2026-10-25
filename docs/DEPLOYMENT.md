# Deployment Guide

## Container (recommended)

The application is packaged as a container image using the `Containerfile` at
the repo root. It exposes port `8080` and expects a `/data` volume for
persistent state.

### Prerequisites

- Docker, Podman, or compatible container runtime
- `docker compose` or `podman compose` (optional, for Compose-based deployment)

### Quick start with Compose

```bash
# Clone the repo
git clone https://github.com/synack/sv-ingest.git
cd sv-ingest

# Set tokens (see Token Setup below)
cp .env.example .env
# Edit .env with your tokens

# Build and start
docker compose up --build -d
# or
podman compose up --build -d
```

The web UI is available at http://localhost:8080.

### Quick start without Compose

```bash
# Build
podman build -t scanner-ingest .

# Create data directory
mkdir -p ./data

# Run
podman run -d \
  --name scanner-ingest \
  -p 8080:8080 \
  -v ./data:/data:Z \
  -e SYNACK_TOKEN_FILE=/data/tokens.json \
  scanner-ingest
```

### Stopping and restarting

```bash
podman stop scanner-ingest
podman start scanner-ingest
```

---

## Volumes

| Mount point | Purpose |
|-------------|---------|
| `/data` | Persists `tokens.json` (API tokens) and optionally `processed_files.log` |
| `/incoming` | Optional: drop files here for service-mode auto-ingest |

The `/data` directory must be writable by the container process. On SELinux
systems (RHEL, Fedora), the `:Z` flag is required for Podman volume mounts.

---

## Environment variables

| Variable | Description | Example |
|----------|-------------|---------|
| `SYNACK_TOKEN` | Commercial platform Bearer token | `eyJ...` |
| `SYNACK_FEDRAMP_TOKEN` | FedRAMP platform Bearer token | `eyJ...` |
| `SYNACK_ORG_UID` | Default organization UID | `abc123` |
| `SYNACK_TOKEN_FILE` | Path to JSON token store (container use) | `/data/tokens.json` |

`SYNACK_TOKEN_FILE` points to a JSON file of the form:
```json
{
  "commercial": "your_commercial_token",
  "fedramp": "your_fedramp_token"
}
```

Token lookup priority: **OS keychain → `SYNACK_TOKEN_FILE` → platform env var (`SYNACK_TOKEN` / `SYNACK_FEDRAMP_TOKEN`) → generic `SYNACK_TOKEN` fallback → config.yaml**.

---

## Token setup

### Via the web UI

Open http://localhost:8080, go to the **Tokens** section, and paste your
Bearer token for each platform.

### Via the CLI (inside the container)

```bash
podman exec -it scanner-ingest python ingest.py token set --platform commercial
```

### Via environment variables

Set `SYNACK_TOKEN` and/or `SYNACK_FEDRAMP_TOKEN` in the environment or `.env`
file before starting the container.

---

## Service mode (directory watching)

To enable automatic ingestion when files are dropped into a directory:

1. Configure `watch_dirs` in `config.yaml` (see `config.yaml.example`)
2. Mount the watch directory into the container
3. Start with the `serve` command:

```yaml
# compose.yaml — add to the service definition
command: ["python", "ingest.py", "serve", "--config", "/app/config.yaml"]
volumes:
  - ./data:/data:Z
  - ./incoming:/incoming:Z
  - ./config.yaml:/app/config.yaml:ro
```

---

## Updating

```bash
git pull
podman build -t scanner-ingest .
podman stop scanner-ingest
podman rm scanner-ingest
podman run -d --name scanner-ingest -p 8080:8080 -v ./data:/data:Z \
  -e SYNACK_TOKEN_FILE=/data/tokens.json scanner-ingest
```

Tokens stored in `/data/tokens.json` are preserved across updates.

---

## Ports

| Port | Protocol | Description |
|------|----------|-------------|
| 8080 | HTTP | Web UI |

The application does not support TLS termination directly. Run behind a
reverse proxy (nginx, Caddy) for HTTPS in production.
