#!/usr/bin/env python3
"""
webui.py — minimal Flask front-end for domain_scraper.

Form on / submits a domain list. The scrape runs in a background thread;
the page polls /jobs/<id> until done, then renders the results table.

Run:
    python3 webui.py            # http://127.0.0.1:5000
    PORT=8080 python3 webui.py  # custom port
"""
import csv
import io
import os
import secrets
import threading
import time
import traceback
from dataclasses import dataclass, field
from typing import Optional

from flask import Flask, jsonify, render_template, request, abort, Response

import domain_scraper as ds
import tools

MAX_DOMAINS = 50
JOBS: dict[str, "Job"] = {}
JOBS_LOCK = threading.Lock()

app = Flask(__name__)


@dataclass
class Job:
    id: str
    domains: list
    render: bool
    no_subdomains: bool
    workers: int
    render_wait: int
    proxy: Optional[str]
    status: str = "queued"  # queued | running | done | error
    rows: list = field(default_factory=list)
    error: Optional[str] = None
    started_at: float = 0.0
    finished_at: float = 0.0
    log: list = field(default_factory=list)


def run_job(job: Job):
    job.status = "running"
    job.started_at = time.time()
    try:
        if job.render:
            def log(msg, file=None):
                job.log.append(str(msg))
            job.rows = ds.audit_all_browser(
                job.domains,
                do_subdomains=not job.no_subdomains,
                log=log,
                proxy=job.proxy,
                wait_ms=job.render_wait,
            )
        else:
            from concurrent.futures import ThreadPoolExecutor, as_completed
            with ThreadPoolExecutor(max_workers=job.workers) as ex:
                futs = {
                    ex.submit(ds.audit_domain_requests, d, not job.no_subdomains): d
                    for d in job.domains
                }
                for fut in as_completed(futs):
                    d = futs[fut]
                    try:
                        rows = fut.result()
                        job.rows.extend(rows)
                        job.log.append(f"[+] {d} done ({len(rows)} rows)")
                    except Exception as e:
                        job.log.append(f"[!] {d}: {e}")
        job.status = "done"
    except Exception as e:
        job.status = "error"
        job.error = f"{type(e).__name__}: {e}\n{traceback.format_exc()}"
    finally:
        job.finished_at = time.time()


@app.route("/")
def index():
    return render_template("index.html", max_domains=MAX_DOMAINS)


@app.post("/scan")
def scan():
    raw = request.form.get("domains", "").strip()
    domains = [
        line.strip() for line in raw.splitlines()
        if line.strip() and not line.lstrip().startswith("#")
    ]
    if not domains:
        return jsonify(error="no domains given"), 400
    if len(domains) > MAX_DOMAINS:
        return jsonify(error=f"max {MAX_DOMAINS} domains per job"), 400

    job = Job(
        id=secrets.token_urlsafe(8),
        domains=domains,
        render=request.form.get("render") == "on",
        no_subdomains=request.form.get("no_subdomains") == "on",
        workers=max(1, min(20, int(request.form.get("workers") or 5))),
        render_wait=max(1000, min(60000, int(request.form.get("render_wait") or 5000))),
        proxy=(request.form.get("proxy") or "").strip() or None,
    )
    with JOBS_LOCK:
        JOBS[job.id] = job
    threading.Thread(target=run_job, args=(job,), daemon=True).start()
    return jsonify(job_id=job.id)


@app.get("/jobs/<job_id>")
def job_status(job_id):
    job = JOBS.get(job_id)
    if not job:
        abort(404)
    return jsonify(
        id=job.id,
        status=job.status,
        rows=job.rows,
        error=job.error,
        log=job.log[-50:],
        elapsed=round((job.finished_at or time.time()) - job.started_at, 1)
                if job.started_at else 0,
        domain_count=len(job.domains),
        row_count=len(job.rows),
    )


@app.get("/jobs/<job_id>/csv")
def job_csv(job_id):
    job = JOBS.get(job_id)
    if not job:
        abort(404)
    if job.status != "done":
        abort(409, "job not finished")
    fields = [
        "input_domain", "target", "final_url", "status", "server",
        "cookie_count", "set_cookies",
        "banner_text", "privacy_links", "clean_text_excerpt", "backend",
    ]
    buf = io.StringIO()
    w = csv.DictWriter(buf, fieldnames=fields, quoting=csv.QUOTE_ALL)
    w.writeheader()
    for row in job.rows:
        w.writerow(row)
    return Response(
        buf.getvalue(),
        mimetype="text/csv",
        headers={"Content-Disposition": f"attachment; filename=scan_{job.id}.csv"},
    )


# ---------- tool tabs ----------

TOOLS = {
    # name: (callable, list of arg names in payload order)
    "whois":          (tools.whois_lookup,        ["target"]),
    "dns":            (tools.dns_records,         ["target"]),
    "ipinfo":         (tools.ip_info,             ["target"]),
    "reverse_ip":     (tools.reverse_ip,          ["target"]),
    "asn":            (tools.asn_info,            ["target"]),
    "bgp_prefixes":   (tools.bgp_prefixes,        ["target"]),
    "headers":        (tools.http_headers,        ["target"]),
    "tls":            (tools.tls_cert,            ["target"]),
    "robots_sitemap": (tools.robots_and_sitemap,  ["target"]),
    "wayback":        (tools.wayback_snapshots,   ["target"]),
    "emails":         (tools.email_harvest,       ["target"]),
    "subdomains":     (tools.subdomain_enum_multi, ["target"]),
    "github":         (tools.github_user,         ["target"]),
    "hibp":           (tools.hibp_email,          ["target"]),
    "shodan":         (tools.shodan_host,         ["target"]),
    "censys":         (tools.censys_host,         ["target"]),
    "greynoise":      (tools.greynoise_ip,        ["target"]),
    "virustotal":     (tools.virustotal,          ["target"]),
    "abuseipdb":      (tools.abuseipdb,           ["target"]),
    "urlscan":        (tools.urlscan_search,      ["target"]),
    "hash":           (tools.hash_text,           ["value"]),
    "json_pretty":    (tools.json_pretty,         ["value"]),
}


@app.post("/tool/<name>")
def run_tool(name):
    spec = TOOLS.get(name)
    if not spec:
        abort(404, f"unknown tool: {name}")
    fn, arg_names = spec
    payload = request.get_json(silent=True) or request.form
    args = [payload.get(a, "") for a in arg_names]
    try:
        return jsonify(fn(*args))
    except Exception as e:
        return jsonify(error=f"{type(e).__name__}: {e}"), 500


@app.post("/tool/codec")
def run_codec():
    """Encode/decode dispatcher. Body: {op, kind, value}."""
    p = request.get_json(silent=True) or request.form
    return jsonify(tools.encode_decode(
        p.get("op", ""), p.get("kind", ""), p.get("value", "")
    ))


if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    # bind to 127.0.0.1 by default — this UI has no auth, do NOT expose publicly
    host = os.environ.get("HOST", "127.0.0.1")
    app.run(host=host, port=port, debug=False)
