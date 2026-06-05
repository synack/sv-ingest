"""
Scanner Ingest — Web UI (FastAPI)

Run locally:  uvicorn web.app:app --reload --port 8080
In container: started automatically via CMD in Containerfile
"""
from __future__ import annotations

import logging
import shutil
import tempfile
import threading
import uuid
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

logging.getLogger("scanner_ingest").setLevel(logging.WARNING)

from fastapi import FastAPI, Form, Request, UploadFile
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.templating import Jinja2Templates

from scanner_ingest import auth, pipeline
from scanner_ingest.adapters import ADAPTER_REGISTRY
from scanner_ingest.synack_client import resolve_org_uid

app = FastAPI(title="Scanner Ingest", docs_url=None, redoc_url=None)

_TEMPLATES = Jinja2Templates(directory=str(Path(__file__).parent / "templates"))

_SOURCE_LABELS = {
    "tenable_sc": "Tenable SC",
    "cisa":       "CISA (KEV / CyHy)",
    "qualys":     "Qualys WAS",
    "generic":    "Generic / Custom Scanner",
    "opus-sast":  "Opus 4.7 SAST",
    "opus-sca":   "Opus 4.7 SCA",
}

# Minimal runtime config — tokens come from keyring/file store, not config.yaml
_API_CONFIG = {"synack": {"batch_size": 100, "retry_attempts": 3}}


@dataclass
class _Job:
    filename: str = ""
    phase: str = "parsing"    # parsing | submitting | done
    total: int = 0
    submitted: int = 0
    result_html: str = ""


_jobs: dict[str, _Job] = {}


def _token_rows() -> list[dict]:
    return [
        {
            "platform": p,
            "url":      url,
            "token":    auth.get_token(p),
            "masked":   auth.mask_token(auth.get_token(p)),
            "source":   auth.token_source(p),
            "is_set":   bool(auth.get_token(p)),
        }
        for p, url in auth.PLATFORMS.items()
    ]


def _render_result(context: dict) -> str:
    return _TEMPLATES.env.get_template("_result.html").render(context)


def _bg_ingest(job: _Job, tmp_path: Path, run_kwargs: dict, result_ctx: dict) -> None:
    try:
        def progress_cb(done: int, total: int) -> None:
            job.phase     = "submitting"
            job.total     = total
            job.submitted = done

        result = pipeline.run(**run_kwargs, progress_cb=progress_cb)
        job.result_html = _render_result({**result_ctx, "result": result})
    except Exception as exc:
        job.result_html = _render_result({"error": str(exc), "filename": job.filename})
    finally:
        job.phase = "done"
        tmp_path.unlink(missing_ok=True)


# ---------------------------------------------------------------------------
# Full page
# ---------------------------------------------------------------------------

@app.get("/", response_class=HTMLResponse)
async def index(request: Request):
    return _TEMPLATES.TemplateResponse(request, "index.html", {
        "platforms":     list(auth.PLATFORMS.items()),
        "source_types":  list(ADAPTER_REGISTRY.keys()),
        "source_labels": _SOURCE_LABELS,
    })


# ---------------------------------------------------------------------------
# Token management (returns _tokens.html partial)
# ---------------------------------------------------------------------------

@app.get("/api/tokens", response_class=HTMLResponse)
async def get_tokens(request: Request):
    return _TEMPLATES.TemplateResponse(request, "_tokens.html", {
        "tokens": _token_rows(),
    })


@app.post("/api/tokens/{platform}", response_class=HTMLResponse)
async def set_token(request: Request, platform: str, token: str = Form(...)):
    if platform not in auth.PLATFORMS:
        return HTMLResponse(f"<p class='msg error'>Unknown platform: {platform}</p>", status_code=400)
    if token.strip():
        auth.set_token(platform, token.strip())
    return _TEMPLATES.TemplateResponse(request, "_tokens.html", {
        "tokens": _token_rows(),
        "saved":  platform,
    })


@app.delete("/api/tokens/{platform}", response_class=HTMLResponse)
async def clear_token(request: Request, platform: str):
    if platform not in auth.PLATFORMS:
        return HTMLResponse(f"<p class='msg error'>Unknown platform: {platform}</p>", status_code=400)
    auth.delete_token(platform)
    return _TEMPLATES.TemplateResponse(request, "_tokens.html", {
        "tokens":  _token_rows(),
        "cleared": platform,
    })


# ---------------------------------------------------------------------------
# Org UID resolution
# ---------------------------------------------------------------------------

@app.get("/api/org-uid/{platform}", response_class=HTMLResponse)
async def get_org_uid(platform: str):
    if platform not in auth.PLATFORMS:
        return HTMLResponse(f"Unknown platform: {platform}", status_code=400)
    try:
        uid = resolve_org_uid(platform, _API_CONFIG)
        return HTMLResponse(uid)
    except Exception as exc:
        return HTMLResponse(f"Error: {exc}", status_code=422)


# ---------------------------------------------------------------------------
# Ingest — starts background job, returns job_id
# ---------------------------------------------------------------------------

@app.post("/api/ingest")
async def ingest_start(
    file:             UploadFile,
    source_type:      str           = Form(...),
    platform:         str           = Form(...),
    org_uid:          str           = Form(...),
    source_override:  str           = Form(""),
    listing_uid:      str           = Form(""),
    asset_uid:        str           = Form(""),
    default_location: str           = Form(""),
    dry_run:          Optional[str] = Form(None),
):
    cfg = dict(_API_CONFIG)
    if source_override.strip():
        cfg.setdefault("sources", {}).setdefault(source_type, {})["source_id"] = source_override.strip()

    suffix   = Path(file.filename or "upload").suffix or ".csv"
    tmp_path: Path | None = None

    try:
        with tempfile.NamedTemporaryFile(suffix=suffix, delete=False) as tmp:
            shutil.copyfileobj(file.file, tmp)
            tmp_path = Path(tmp.name)
    except Exception as exc:
        return JSONResponse({"error": str(exc)}, status_code=500)

    job_id = uuid.uuid4().hex[:12]
    job    = _Job(filename=file.filename or "upload")
    _jobs[job_id] = job

    run_kwargs = dict(
        file_path=tmp_path,
        source_type=source_type,
        org_uid=org_uid.strip(),
        config=cfg,
        platform=platform,
        dry_run=dry_run is not None,
        listing_uid=listing_uid.strip() or None,
        asset_uid=asset_uid.strip() or None,
        default_location=default_location.strip() or None,
    )
    result_ctx = dict(
        filename=file.filename,
        dry_run=dry_run is not None,
        platform=platform,
        platform_url=auth.PLATFORMS.get(platform, ""),
    )

    threading.Thread(
        target=_bg_ingest,
        args=(job, tmp_path, run_kwargs, result_ctx),
        daemon=True,
    ).start()

    return JSONResponse({"job_id": job_id})


@app.get("/api/ingest/progress/{job_id}")
async def ingest_progress(job_id: str):
    job = _jobs.get(job_id)
    if not job:
        return JSONResponse({"error": "not found"}, status_code=404)
    pct = (
        min(99, int(job.submitted / job.total * 100))
        if job.phase == "submitting" and job.total > 0
        else None
    )
    return JSONResponse({"phase": job.phase, "pct": pct, "submitted": job.submitted, "total": job.total})


@app.get("/api/ingest/result/{job_id}", response_class=HTMLResponse)
async def ingest_result(job_id: str):
    job = _jobs.get(job_id)
    if not job or job.phase != "done":
        return HTMLResponse("", status_code=202)
    _jobs.pop(job_id, None)
    return HTMLResponse(job.result_html)
