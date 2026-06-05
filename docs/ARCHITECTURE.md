# Architecture

A high-level map of how Scanner Ingest is put together. For component-level
detail on writing a scanner adapter, see [ADAPTERS.md](ADAPTERS.md).

## Data flow

```
file → Adapter.parse() → list[VulnerabilityRecord] → SynackClient.submit() → Synack API
```

`pipeline.run()` owns this flow end to end: it loads the adapter for the source
type, parses the file into records, submits them, and returns a result summary.
The web UI runs `pipeline.run()` in a background thread and polls for progress;
the CLI calls it directly.

## Key modules

| File | Role |
|------|------|
| `ingest.py` | CLI entry point (Click). Commands: `token`, `ingest`, `serve`, `validate-config` |
| `scanner_ingest/pipeline.py` | Single `run()` function: loads adapter → parses → submits → returns result |
| `scanner_ingest/adapters/` | One file per source type; all subclass `BaseAdapter` |
| `scanner_ingest/models.py` | `VulnerabilityRecord` Pydantic model — the canonical internal representation |
| `scanner_ingest/synack_client.py` | `SynackClient` — batched API submission, org UID resolution |
| `scanner_ingest/auth.py` | Token lookup across keychain, file store, env vars, and config |
| `scanner_ingest/scheduler.py` | `IngestScheduler` — directory watcher for service mode |
| `web/ingest_ui.py` | FastAPI app — file upload, token management, background ingest jobs, progress polling |

## The data model

Every adapter converts its source format into a list of `VulnerabilityRecord`
objects (`scanner_ingest/models.py`). This unified model is what the rest of the
pipeline operates on, so the Synack client and submission logic never need to know
which scanner the data came from. See the field reference in
[ADAPTERS.md](ADAPTERS.md#vulnerabilityrecord-fields).

## Adding a scanner

Adapters are self-contained: subclass `BaseAdapter`, implement `parse()`, and
register the class in `scanner_ingest/adapters/__init__.py`. The new source type
then becomes available in both the CLI and the web UI automatically. Full
walkthrough in [ADAPTERS.md](ADAPTERS.md).
