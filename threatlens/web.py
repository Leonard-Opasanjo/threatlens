"""The dashboard: import indicators, browse and filter them, read enrichment, set status, export reports."""

from __future__ import annotations

import os
from pathlib import Path
from urllib.parse import urlsplit

from fastapi import FastAPI, File, Form, HTTPException, Request, UploadFile
from fastapi.middleware.trustedhost import TrustedHostMiddleware
from fastapi.responses import HTMLResponse, JSONResponse, PlainTextResponse, RedirectResponse, Response
from fastapi.templating import Jinja2Templates
from jinja2 import Environment, PackageLoader, select_autoescape

from . import REPO_URL, __version__
from .db import STATUSES, Store
from .enrich import SEVERITIES, VERDICTS, Dns, Enricher, Structural, load_feeds
from .ioc import TYPES, defang, defang_text, parse_csv, parse_json, parse_text
from .report import investigation_report, to_json

env = Environment(loader=PackageLoader("threatlens", "templates"), autoescape=select_autoescape(["html"]))
env.globals.update(version=__version__, repo_url=REPO_URL, severities=SEVERITIES, verdicts=VERDICTS, types=TYPES,
                   statuses=STATUSES)
env.filters["defang"] = defang
env.filters["defang_text"] = defang_text
templates = Jinja2Templates(env=env)
# no Swagger UI: it loads third-party scripts, which the dashboard's content policy rightly refuses
app = FastAPI(title="ThreatLens", docs_url=None, redoc_url=None, openapi_url="/api/openapi.json")
# host names the dashboard answers to; a DNS-rebinding page arrives under its own name and gets 400
ALLOWED_HOSTS = [h.strip() for h in os.environ.get("THREATLENS_ALLOWED_HOSTS", "127.0.0.1,localhost").split(",")
                 if h.strip()]
SECURITY_HEADERS = {
    "content-security-policy": "default-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; "
                               "form-action 'self'; frame-ancestors 'none'; base-uri 'self'",
    "x-content-type-options": "nosniff", "x-frame-options": "DENY",
    "referrer-policy": "strict-origin-when-cross-origin",
    "permissions-policy": "camera=(), microphone=(), geolocation=()", "cache-control": "no-store",
}
MAX_UPLOAD = 5 * 1024 * 1024
LIST_LIMIT = 500


def store() -> Store:
    if not hasattr(app.state, "store"):
        app.state.store = Store(os.environ.get("THREATLENS_DB", "threatlens.db"))
    return app.state.store


def enricher(online: bool) -> Enricher:
    sources = [Structural(), *load_feeds(online=online)]
    if online:
        sources.append(Dns())
    return Enricher(sources)


def _same_origin(request: Request) -> bool:
    """A browser names the page that sent a form in Origin (or Referer); curl and scripts send neither."""
    origin = request.headers.get("origin") or request.headers.get("referer")
    return not origin or urlsplit(origin).netloc == request.headers.get("host")


@app.middleware("http")
async def security_headers(request: Request, call_next):
    length = request.headers.get("content-length", "")
    if request.method not in ("GET", "HEAD", "OPTIONS") and not _same_origin(request):
        response = PlainTextResponse("Cross-site request refused.", status_code=403)
    elif length.isdigit() and int(length) > MAX_UPLOAD + 1024 * 1024:  # the file plus room for the form fields
        response = PlainTextResponse("Request too large: uploads are limited to 5 MB.", status_code=413)
    else:
        response = await call_next(request)
    for k, v in SECURITY_HEADERS.items():
        response.headers.setdefault(k, v)
    return response


app.add_middleware(TrustedHostMiddleware, allowed_hosts=ALLOWED_HOSTS)


def _page(request: Request, name: str, status_code: int = 200, **ctx) -> HTMLResponse:
    return templates.TemplateResponse(request, name, ctx, status_code=status_code)


def _first(rows: list[dict]) -> dict:
    """At most LIST_LIMIT rows for a page, and whether more matched (callers ask for one extra row)."""
    return {"rows": rows[:LIST_LIMIT], "more": len(rows) > LIST_LIMIT}


@app.get("/", response_class=HTMLResponse)
def index(request: Request):
    return _page(request, "index.html", stats=store().stats(), imports=store().list_imports()[:20])


@app.post("/import")  # a plain def runs in the thread pool, so a long import or DNS run does not stall the server
def do_import(request: Request, text: str = Form(""), source: str = Form(""), fmt: str = Form("auto"),
              online: str | None = Form(None), file: UploadFile | None = File(None)):  # noqa: B008
    name = source.strip() or "pasted"
    if file is not None and file.filename:
        data = file.file.read(MAX_UPLOAD + 1)
        if len(data) > MAX_UPLOAD:
            return _page(request, "error.html", status_code=413, title="File too large",
                         message="Uploads are limited to 5 MB.")
        text = data.decode("utf-8", "replace")
        name = source.strip() or file.filename
        if fmt == "auto":
            lower = file.filename.lower()
            fmt = "csv" if lower.endswith(".csv") else "json" if lower.endswith(".json") else "text"
    if not text.strip():
        return _page(request, "error.html", status_code=400, title="Nothing to import",
                     message="Paste indicators or upload a CSV, JSON or text file.")
    try:
        if fmt == "csv":
            indicators = parse_csv(text, name)
        elif fmt == "json":
            indicators = parse_json(text, name)
        else:
            indicators = parse_text(text, name)
    except (ValueError, KeyError) as e:
        return _page(request, "error.html", status_code=400, title="Could not parse the input", message=str(e))
    if not indicators:
        return _page(request, "error.html", status_code=400, title="No indicators found",
                     message="Nothing in the input looked like an IP address, domain, URL or hash "
                             f"({indicators.skipped} values skipped).")
    try:
        counts = store().ingest(indicators, enricher(online == "yes"), name, name, online == "yes")
    except OSError as e:
        return _page(request, "error.html", status_code=502, title="Online source failed", message=str(e))
    return RedirectResponse(f"/imports/{counts['import_id']}", status_code=303)


@app.get("/indicators", response_class=HTMLResponse)
def indicators(request: Request, type: str | None = None, verdict: str | None = None, severity: str | None = None,
               status: str | None = None, q: str | None = None):
    rows = store().list(type=type or None, verdict=verdict or None, severity=severity or None, status=status or None,
                        q=(q or "").strip() or None, limit=LIST_LIMIT + 1)
    return _page(request, "indicators.html", **_first(rows), filters={"type": type or "", "verdict": verdict or "",
                                                                       "severity": severity or "",
                                                                       "status": status or "", "q": q or ""})


@app.get("/indicators/{ind_id}", response_class=HTMLResponse)
def indicator(request: Request, ind_id: int):
    row = store().get(ind_id)
    if row is None:
        raise HTTPException(404, "indicator not found")
    return _page(request, "indicator.html", row=row)


@app.post("/indicators/{ind_id}/status")
def set_status(ind_id: int, status: str = Form(...), note: str = Form("")):
    try:
        store().set_status(ind_id, status, note)
    except KeyError as e:
        raise HTTPException(404, "indicator not found") from e
    except ValueError as e:
        raise HTTPException(400, str(e)) from e
    return RedirectResponse(f"/indicators/{ind_id}", status_code=303)


@app.get("/imports/{import_id}", response_class=HTMLResponse)
def import_page(request: Request, import_id: int):
    imp = store().get_import(import_id)
    if imp is None:
        raise HTTPException(404, "import not found")
    return _page(request, "import.html", imp=imp, **_first(store().list(import_id=import_id, limit=LIST_LIMIT + 1)))


def _report_rows(import_id: int | None):
    return store().with_signals(store().list(import_id=import_id, limit=None))


@app.get("/imports/{import_id}/report.md")
def import_report(import_id: int):
    imp = store().get_import(import_id)
    if imp is None:
        raise HTTPException(404, "import not found")
    text = investigation_report(_report_rows(import_id), f"Investigation report: {imp['name']}",
                                context=f"import {import_id} of {imp['at'][:16].replace('T', ' ')}")
    return Response(text, media_type="text/markdown",
                    headers={"content-disposition": f'attachment; filename="threatlens-import-{import_id}.md"'})


@app.get("/report.md")
def full_report():
    return Response(investigation_report(_report_rows(None)), media_type="text/markdown",
                    headers={"content-disposition": 'attachment; filename="threatlens-report.md"'})


@app.get("/report.json")
def full_json():
    return Response(to_json(_report_rows(None)), media_type="application/json")


@app.get("/api/indicators")
def api_indicators(type: str | None = None, verdict: str | None = None, severity: str | None = None,
                   q: str | None = None, limit: int = LIST_LIMIT):
    return JSONResponse(content=store().list(type=type, verdict=verdict, severity=severity, q=q, limit=limit))


@app.get("/api/indicators/{ind_id}")
def api_indicator(ind_id: int):
    row = store().get(ind_id)
    if row is None:
        raise HTTPException(404, "indicator not found")
    return JSONResponse(content=row)


@app.get("/api/stats")
def api_stats():
    return store().stats()


@app.get("/healthz")
def healthz():
    return {"ok": True}


def serve(host: str = "127.0.0.1", port: int = 8000, db: str | None = None) -> None:
    import uvicorn

    if db:
        os.environ["THREATLENS_DB"] = str(Path(db))
    uvicorn.run(app, host=host, port=port, log_level="info")
