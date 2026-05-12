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
import json
import os
import secrets
import sqlite3
import sys
import threading
import time
import traceback
from collections import defaultdict, deque
from dataclasses import dataclass, field
from functools import wraps
from pathlib import Path
from typing import Optional


# ---- .env auto-loader ---------------------------------------------------
# Tiny parser, no python-dotenv dependency. Reads KEY=VALUE per line, skips
# blanks and lines starting with '#'. Existing env vars take precedence so
# `SHODAN_API_KEY=... python3 webui.py` still works.
def _load_dotenv(path: str) -> int:
    if not os.path.isfile(path):
        return 0
    loaded = 0
    with open(path, "r", encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            if line.startswith("export "):
                line = line[7:]
            key, _, val = line.partition("=")
            key = key.strip()
            val = val.strip().strip('"').strip("'")
            if key and key not in os.environ:
                os.environ[key] = val
                loaded += 1
    return loaded


_DOTENV = os.path.join(os.path.dirname(os.path.abspath(__file__)), ".env")
if _load_dotenv(_DOTENV):
    print(f"[webui] loaded env vars from {_DOTENV}", file=sys.stderr)


from flask import (Flask, jsonify, render_template, request, abort,
                   Response, redirect, session, url_for)
from werkzeug.security import check_password_hash, generate_password_hash

import domain_scraper as ds
import tools
import tools_username
import tools_social
import tools_email_phone
import tools_cyber
import tools_local
import tools_blockchain
import tools_graph
import tools_js_intel

MAX_DOMAINS = 50
JOBS: dict[str, "Job"] = {}
JOBS_LOCK = threading.Lock()

# ---------- job persistence (Phase 0 Track C) ----------
# Finished jobs are mirrored to a tiny SQLite DB so they survive process
# restarts. In-flight jobs stay only in JOBS dict — recovering an
# interrupted scan would need worker resumption logic that lives in the
# Phase 1 Celery / arq migration. For now: don't lose investigations
# you already completed.
_JOBS_DB_PATH = Path(
    os.environ.get("SAFENEST_JOBS_DB")
    or (Path.home() / ".local" / "share" / "safenest" / "jobs.db")
)


def _jobs_db_conn():
    _JOBS_DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(_JOBS_DB_PATH, timeout=5)
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA synchronous=NORMAL")
    return conn


def _jobs_db_init():
    try:
        with _jobs_db_conn() as c:
            c.executescript("""
                CREATE TABLE IF NOT EXISTS jobs (
                    id              TEXT PRIMARY KEY,
                    status          TEXT NOT NULL,
                    domains_json    TEXT,
                    rows_json       TEXT,
                    log_json        TEXT,
                    error           TEXT,
                    render          INTEGER,
                    no_subdomains   INTEGER,
                    workers         INTEGER,
                    render_wait     INTEGER,
                    proxy           TEXT,
                    started_at      REAL,
                    finished_at     REAL,
                    created_ts      INTEGER
                );
                CREATE INDEX IF NOT EXISTS idx_jobs_finished
                    ON jobs(finished_at);
            """)
    except Exception as e:
        print(f"[webui] job DB init failed: {e}", file=sys.stderr)


def _save_job(job: "Job"):
    try:
        with _jobs_db_conn() as c:
            c.execute(
                "INSERT OR REPLACE INTO jobs "
                "(id,status,domains_json,rows_json,log_json,error,"
                " render,no_subdomains,workers,render_wait,proxy,"
                " started_at,finished_at,created_ts) "
                "VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                (
                    job.id, job.status,
                    json.dumps(job.domains),
                    json.dumps(job.rows),
                    json.dumps(job.log),
                    job.error,
                    int(bool(job.render)),
                    int(bool(job.no_subdomains)),
                    int(job.workers or 5),
                    int(job.render_wait or 5000),
                    job.proxy,
                    float(job.started_at or 0.0),
                    float(job.finished_at or 0.0),
                    int(time.time()),
                ),
            )
    except Exception as e:
        print(f"[webui] job save failed: {e}", file=sys.stderr)


def _load_finished_jobs(limit: int = 200) -> dict:
    out: dict = {}
    try:
        with _jobs_db_conn() as c:
            cur = c.execute(
                "SELECT id,status,domains_json,rows_json,log_json,error,"
                " render,no_subdomains,workers,render_wait,proxy,"
                " started_at,finished_at FROM jobs "
                "ORDER BY finished_at DESC LIMIT ?", (limit,)
            )
            for row in cur.fetchall():
                (jid, status, dj, rj, lj, err, rndr, nosub,
                 workers, rwait, proxy, started, finished) = row
                j = Job(
                    id=jid,
                    domains=json.loads(dj) if dj else [],
                    render=bool(rndr),
                    no_subdomains=bool(nosub),
                    workers=int(workers or 5),
                    render_wait=int(rwait or 5000),
                    proxy=proxy,
                    status=status,
                    rows=json.loads(rj) if rj else [],
                    error=err,
                    started_at=float(started or 0.0),
                    finished_at=float(finished or 0.0),
                    log=json.loads(lj) if lj else [],
                )
                out[jid] = j
    except Exception as e:
        print(f"[webui] job load failed: {e}", file=sys.stderr)
    return out


def _list_jobs(limit: int = 50) -> list:
    """Lightweight listing for /jobs (no rows / log payloads)."""
    out = []
    try:
        with _jobs_db_conn() as c:
            cur = c.execute(
                "SELECT id,status,domains_json,started_at,finished_at,error "
                "FROM jobs ORDER BY finished_at DESC LIMIT ?", (limit,)
            )
            for row in cur.fetchall():
                jid, status, dj, started, finished, err = row
                domains = json.loads(dj) if dj else []
                out.append({
                    "id": jid,
                    "status": status,
                    "domain_count": len(domains),
                    "domains_preview": domains[:3],
                    "started_at": started or 0.0,
                    "finished_at": finished or 0.0,
                    "elapsed": round((finished or 0.0) - (started or 0.0), 1)
                                if started and finished else 0,
                    "error": err,
                })
    except Exception as e:
        print(f"[webui] job list failed: {e}", file=sys.stderr)
    return out

# ---------- auth ----------
# Auth is OPT-IN. If neither WEBUI_USERNAME nor WEBUI_PASSWORD_HASH is set,
# the dashboard is open (same behavior as before — fine for 127.0.0.1).
# If both are set, every route except /login + /static is gated by login.
AUTH_USER = os.environ.get("WEBUI_USERNAME") or ""
AUTH_HASH = os.environ.get("WEBUI_PASSWORD_HASH") or ""
AUTH_ENABLED = bool(AUTH_USER and AUTH_HASH)

LOGIN_FAILS: dict[str, deque] = defaultdict(deque)
LOGIN_FAILS_LOCK = threading.Lock()
LOGIN_WINDOW_S = 60
LOGIN_MAX_FAILS = 5

app = Flask(__name__)
app.secret_key = (os.environ.get("WEBUI_SECRET_KEY")
                  or secrets.token_hex(32))
if not os.environ.get("WEBUI_SECRET_KEY"):
    print("[webui] WARNING: WEBUI_SECRET_KEY not set — using a random "
          "one for this run. All sessions invalidate on restart. Set "
          "WEBUI_SECRET_KEY in your env to keep sessions stable.",
          file=sys.stderr)
app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    # SESSION_COOKIE_SECURE only set when running behind HTTPS — see README
    SESSION_COOKIE_SECURE=os.environ.get("WEBUI_HTTPS") == "1",
    PERMANENT_SESSION_LIFETIME=60 * 60 * 8,  # 8 hours
)


def _client_ip() -> str:
    return request.headers.get("X-Forwarded-For", request.remote_addr or "?")\
        .split(",")[0].strip()


def _record_fail(ip: str):
    with LOGIN_FAILS_LOCK:
        q = LOGIN_FAILS[ip]
        now = time.time()
        while q and now - q[0] > LOGIN_WINDOW_S:
            q.popleft()
        q.append(now)


def _too_many_fails(ip: str) -> bool:
    with LOGIN_FAILS_LOCK:
        q = LOGIN_FAILS[ip]
        now = time.time()
        while q and now - q[0] > LOGIN_WINDOW_S:
            q.popleft()
        return len(q) >= LOGIN_MAX_FAILS


def login_required(view):
    @wraps(view)
    def wrapper(*a, **kw):
        if not AUTH_ENABLED:
            return view(*a, **kw)
        if session.get("user") == AUTH_USER:
            return view(*a, **kw)
        if request.path.startswith("/jobs/") or \
           request.path.startswith("/tool/") or \
           request.path == "/scan":
            return jsonify(error="not authenticated"), 401
        return redirect(url_for("login", next=request.path))
    return wrapper


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


# Bootstrap the jobs DB and rehydrate finished jobs from disk so /jobs and
# /jobs/<id> work seamlessly across webui restarts.
_jobs_db_init()
try:
    _rehydrated = _load_finished_jobs(limit=200)
    JOBS.update(_rehydrated)
    if _rehydrated:
        print(f"[webui] rehydrated {len(_rehydrated)} job(s) from "
              f"{_JOBS_DB_PATH}", file=sys.stderr)
except Exception as _e:
    print(f"[webui] job rehydrate failed: {_e}", file=sys.stderr)


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
        # persist the terminal state so the job survives a webui restart
        _save_job(job)


# ---------- login / logout ----------

@app.route("/login", methods=["GET", "POST"])
def login():
    if not AUTH_ENABLED:
        return redirect(url_for("index"))
    if request.method == "GET":
        return render_template("login.html",
                                error=request.args.get("error"))
    ip = _client_ip()
    if _too_many_fails(ip):
        return render_template("login.html",
                                error="too many failed attempts — "
                                      "wait a minute and try again"), 429
    user = (request.form.get("username") or "").strip()
    pw = request.form.get("password") or ""
    user_ok = secrets.compare_digest(user, AUTH_USER)
    pw_ok = check_password_hash(AUTH_HASH, pw) if AUTH_HASH else False
    if user_ok and pw_ok:
        session.clear()
        session["user"] = AUTH_USER
        session.permanent = True
        # clear fail counter for this IP on success
        with LOGIN_FAILS_LOCK:
            LOGIN_FAILS.pop(ip, None)
        nxt = request.args.get("next") or url_for("index")
        if not nxt.startswith("/"):
            nxt = url_for("index")
        return redirect(nxt)
    _record_fail(ip)
    return render_template("login.html",
                            error="invalid credentials"), 401


@app.post("/logout")
def logout():
    session.clear()
    return redirect(url_for("login") if AUTH_ENABLED else url_for("index"))


@app.route("/")
@login_required
def index():
    return render_template("index.html",
                            max_domains=MAX_DOMAINS,
                            auth_enabled=AUTH_ENABLED,
                            current_user=session.get("user"))


@app.post("/scan")
@login_required
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


@app.get("/jobs")
@login_required
def jobs_list():
    """Recent finished jobs (lightweight — no rows / no logs)."""
    return jsonify(jobs=_list_jobs(limit=100))


@app.get("/jobs/<job_id>")
@login_required
def job_status(job_id):
    job = JOBS.get(job_id)
    if not job:
        # cold cache — try SQLite for a previously-finished job
        loaded = _load_finished_jobs(limit=1000).get(job_id)
        if not loaded:
            abort(404)
        JOBS[job_id] = loaded
        job = loaded
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
@login_required
def job_csv(job_id):
    job = JOBS.get(job_id)
    if not job:
        loaded = _load_finished_jobs(limit=1000).get(job_id)
        if not loaded:
            abort(404)
        JOBS[job_id] = loaded
        job = loaded
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
    # ---- existing core ----
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

    # ---- people / username ----
    "username_sweep":     (tools_username.username_sweep,
                            ["username", "categories"]),
    "username_categories":(tools_username.list_username_categories, []),

    # ---- social-platform deep-dives ----
    "reddit_user":        (tools_social.reddit_user,        ["target"]),
    "hn_user":            (tools_social.hn_user,            ["target"]),
    "github_emails":      (tools_social.github_emails,      ["target"]),
    "github_pubkeys":     (tools_social.github_pubkeys,     ["target"]),
    "mastodon":           (tools_social.mastodon_lookup,    ["target"]),
    "telegram":           (tools_social.telegram_user,      ["target"]),
    "steam":              (tools_social.steam_profile,      ["target"]),
    "keybase":            (tools_social.keybase_user,       ["target"]),
    "npm":                (tools_social.npm_user,           ["target"]),
    "pgp":                (tools_social.pgp_lookup,         ["target"]),
    "discord_invite":     (tools_social.discord_invite,     ["target"]),
    "youtube":            (tools_social.youtube_channel,    ["target"]),
    "roblox":             (tools_social.roblox_user,        ["target"]),
    "lichess":            (tools_social.lichess_user,       ["target"]),
    "chesscom":           (tools_social.chesscom_user,      ["target"]),
    "tiktok":             (tools_social.tiktok_public,      ["target"]),

    # ---- email / phone ----
    "gravatar":           (tools_email_phone.gravatar_lookup,    ["target"]),
    "mx":                 (tools_email_phone.mx_lookup,          ["target"]),
    "email_auth":         (tools_email_phone.email_auth_records, ["target"]),
    "email_pattern":      (tools_email_phone.email_pattern_guess,
                            ["name", "domain"]),
    "pwned_password":     (tools_email_phone.hibp_password,      ["value"]),
    "emailrep":           (tools_email_phone.emailrep,           ["target"]),
    "email_account_check":(tools_email_phone.email_account_check,["target"]),
    "phone":              (tools_email_phone.phone_parse,
                            ["target", "region"]),

    # ---- cyber / threat intel ----
    "cve":                (tools_cyber.cve_lookup,         ["target"]),
    "cve_search":         (tools_cyber.cve_search,         ["target", "limit"]),
    "otx":                (tools_cyber.otx_indicators,     ["target"]),
    "urlhaus":            (tools_cyber.urlhaus_lookup,     ["target"]),
    "threatfox":          (tools_cyber.threatfox_query,    ["target"]),
    "tor_exit":           (tools_cyber.tor_exit_check,     ["target"]),
    "dnsbl":              (tools_cyber.dnsbl_check,        ["target"]),
    "ssl_labs":           (tools_cyber.ssl_labs,           ["target"]),
    "observatory":        (tools_cyber.mozilla_observatory,["target"]),
    "favicon_hash":       (tools_cyber.favicon_hash,       ["target"]),
    "tech_detect":        (tools_cyber.tech_detect,        ["target"]),
    "cms_detect":         (tools_cyber.cms_detect,         ["target"]),
    "port_scan":          (tools_cyber.port_scan_quick,    ["target", "ports"]),
    "cors_check":         (tools_cyber.cors_check,         ["target"]),
    "cookie_audit":       (tools_cyber.cookie_audit,       ["target"]),
    "subdomain_takeover": (tools_cyber.subdomain_takeover, ["target"]),
    "tls_fingerprint":    (tools_cyber.tls_fingerprint,    ["target"]),
    "mitre_attack":       (tools_cyber.mitre_attack,       ["target"]),
    "wayback_urls":       (tools_cyber.wayback_urls,       ["target"]),

    # ---- local / Kali shell-outs ----
    "nmap":               (tools_local.nmap_scan,          ["target", "profile"]),
    "theharvester":       (tools_local.theharvester,
                            ["target", "source", "limit"]),
    "sublist3r":          (tools_local.sublist3r_scan,     ["target"]),
    "amass":              (tools_local.amass_passive,      ["target"]),
    "subfinder":          (tools_local.subfinder_scan,     ["target"]),
    "assetfinder":        (tools_local.assetfinder_scan,   ["target"]),
    "dnstwist":           (tools_local.dnstwist_scan,      ["target"]),
    "whatweb":            (tools_local.whatweb_scan,       ["target"]),
    "wafw00f":            (tools_local.wafw00f_scan,       ["target"]),
    "dnsenum":            (tools_local.dnsenum_scan,       ["target"]),
    "nikto":              (tools_local.nikto_scan,         ["target"]),
    "wpscan":             (tools_local.wpscan_scan,        ["target"]),
    "dig":                (tools_local.dig_query,          ["target", "rtype"]),
    "traceroute":         (tools_local.traceroute,         ["target"]),
    "gobuster":           (tools_local.gobuster_dir,       ["target", "wordlist"]),
    "exiftool":           (tools_local.exiftool_url,       ["target"]),
    "installed_tools":    (tools_local.installed_tools,    []),

    # ---- blockchain / wallet intelligence ----
    "chain_detect":       (tools_blockchain.detect_chain,        ["target"]),
    "eth_info":           (tools_blockchain.eth_address_info,    ["target"]),
    "eth_txs":            (tools_blockchain.eth_address_txs,     ["target", "limit"]),
    "eth_token_txs":      (tools_blockchain.eth_address_token_txs,
                            ["target", "limit"]),
    "btc_info":           (tools_blockchain.btc_address_info,    ["target"]),
    "btc_txs":            (tools_blockchain.btc_address_txs,     ["target", "limit"]),
    "tron_info":          (tools_blockchain.tron_address_info,   ["target"]),
    "tron_txs":           (tools_blockchain.tron_address_txs,    ["target", "limit"]),
    "blockchair":         (tools_blockchain.blockchair_address,  ["target", "chain"]),
    "btccom":             (tools_blockchain.btccom_address,      ["target"]),
    "tx_lookup":          (tools_blockchain.tx_lookup,           ["target", "chain"]),
    "multi_chain":        (tools_blockchain.multi_chain_lookup,  ["target"]),
    "wallet_risk":        (tools_blockchain.wallet_risk,
                            ["target", "chain", "limit"]),

    # ---- graph intelligence ----
    "graph_add_entity":   (tools_graph.add_entity,
                            ["id", "type", "label"]),
    "graph_add_edge":     (tools_graph.add_edge,
                            ["src", "dst", "kind"]),
    "graph_remove":       (tools_graph.remove_entity,    ["id"]),
    "graph_get":          (tools_graph.get_entity,       ["id"]),
    "graph_search":       (tools_graph.search,
                            ["query", "type", "tag", "limit"]),
    "graph_neighbors":    (tools_graph.neighbors,        ["id", "depth", "limit"]),
    "graph_stats":        (tools_graph.stats,            []),
    "graph_clear":        (tools_graph.clear_graph,      ["confirm"]),
    "graph_export_json":  (tools_graph.export_json,      []),

    # ---- javascript intelligence ----
    "js_intel":           (tools_js_intel.js_analyze,
                            ["target", "fetch_external", "max_scripts",
                             "persist_to_graph", "enrich_wallets"]),
    "js_correlate":       (tools_graph.find_correlations,
                            ["host"]),
}


@app.post("/tool/<name>")
@login_required
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


@app.get("/graph/export.graphml")
@login_required
def graph_export_graphml():
    xml = tools_graph.export_graphml()
    return Response(
        xml, mimetype="application/graphml+xml",
        headers={"Content-Disposition":
                  "attachment; filename=safenest_graph.graphml"},
    )


@app.get("/graph/export.json")
@login_required
def graph_export_json_file():
    body = tools_graph.export_json()
    import json as _json
    return Response(
        _json.dumps(body, indent=2, ensure_ascii=False),
        mimetype="application/json",
        headers={"Content-Disposition":
                  "attachment; filename=safenest_graph.json"},
    )


@app.get("/graph/export.csv")
@login_required
def graph_export_csv_files():
    """Returns a tiny ZIP with nodes.csv + edges.csv."""
    import io as _io
    import zipfile as _zip
    payload = tools_graph.export_csv()
    buf = _io.BytesIO()
    with _zip.ZipFile(buf, "w", _zip.ZIP_DEFLATED) as zf:
        zf.writestr("nodes.csv", payload["nodes_csv"])
        zf.writestr("edges.csv", payload["edges_csv"])
    return Response(
        buf.getvalue(), mimetype="application/zip",
        headers={"Content-Disposition":
                  "attachment; filename=safenest_graph_csv.zip"},
    )


@app.post("/tool/codec")
@login_required
def run_codec():
    """Encode/decode dispatcher. Body: {op, kind, value}."""
    p = request.get_json(silent=True) or request.form
    return jsonify(tools.encode_decode(
        p.get("op", ""), p.get("kind", ""), p.get("value", "")
    ))


if __name__ == "__main__":
    # Helper: generate a password hash to put in $WEBUI_PASSWORD_HASH.
    if len(sys.argv) > 1 and sys.argv[1] == "--hash-password":
        import getpass
        pw1 = getpass.getpass("New password: ")
        pw2 = getpass.getpass("Confirm:      ")
        if pw1 != pw2:
            print("passwords don't match", file=sys.stderr)
            sys.exit(1)
        if len(pw1) < 8:
            print("password too short (min 8 chars)", file=sys.stderr)
            sys.exit(1)
        print(generate_password_hash(pw1))
        sys.exit(0)

    port = int(os.environ.get("PORT", 5000))
    host = os.environ.get("HOST", "127.0.0.1")
    if AUTH_ENABLED:
        print(f"[webui] auth ENABLED (user={AUTH_USER!r})", file=sys.stderr)
    else:
        print(f"[webui] auth DISABLED — bound to {host}. Set "
              f"WEBUI_USERNAME and WEBUI_PASSWORD_HASH to enable auth.",
              file=sys.stderr)
    app.run(host=host, port=port, debug=False)
