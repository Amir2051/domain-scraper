#!/usr/bin/env python3
"""
tools.py — backend functions for the web UI's tool tabs.

All functions are sync, return JSON-serializable dicts/lists, and never
raise to the caller — failures come back as {"error": "..."} so the
HTTP layer can render them uniformly.
"""
from __future__ import annotations

import base64
import binascii
import hashlib
import json
import os
import re
import socket
import ssl
import subprocess
from datetime import datetime, timezone
from urllib.parse import quote, unquote, urljoin, urlparse

import dns.resolver
import dns.exception
import requests
from bs4 import BeautifulSoup

from safenest.http import DEFAULT_HEADERS as HEADERS, DEFAULT_UA as UA, make_client


def _need_key(env_name: str):
    """Return the env var value or a structured error dict."""
    key = os.environ.get(env_name)
    if not key:
        return None, {"error": f"missing API key — set ${env_name} in your shell "
                                f"environment before launching webui.py"}
    return key, None

HTTP_TIMEOUT = 12
_safe_request, _ = make_client(timeout=HTTP_TIMEOUT)

# ---------- helpers ----------

def _domain_only(s: str) -> str:
    """Accept either a bare domain or a full URL; return just the host."""
    s = (s or "").strip()
    if not s:
        return ""
    if "://" in s:
        s = urlparse(s).hostname or s
    return s.strip().lstrip(".").rstrip("/").lower()


# ============== RECON ==============

def whois_lookup(target: str) -> dict:
    """Shell out to the system `whois` binary. Trim banner/comment lines."""
    target = _domain_only(target)
    if not target:
        return {"error": "empty domain"}
    try:
        out = subprocess.run(
            ["whois", target], capture_output=True, text=True, timeout=20
        )
    except subprocess.TimeoutExpired:
        return {"error": "whois timed out"}
    except FileNotFoundError:
        return {"error": "whois CLI not installed"}
    text = out.stdout or out.stderr
    # strip comment / disclaimer lines
    cleaned = "\n".join(
        ln for ln in text.splitlines()
        if ln.strip() and not ln.lstrip().startswith(("%", "#", ">>>"))
    )
    fields = {}
    for ln in cleaned.splitlines():
        if ":" in ln:
            k, _, v = ln.partition(":")
            k = k.strip().lower()
            v = v.strip()
            if k and v and k in (
                "domain name", "registrar", "creation date", "updated date",
                "registry expiry date", "registrar abuse contact email",
                "name server", "registrant country", "registrant organization",
                "domain status", "dnssec",
            ):
                fields.setdefault(k, []).append(v)
    return {"target": target, "fields": fields, "raw": cleaned[:8000]}


def dns_records(target: str) -> dict:
    """Resolve common record types via dnspython."""
    target = _domain_only(target)
    if not target:
        return {"error": "empty domain"}
    out = {"target": target, "records": {}}
    resolver = dns.resolver.Resolver()
    resolver.lifetime = 8
    for rtype in ("A", "AAAA", "MX", "NS", "TXT", "CNAME", "SOA", "CAA"):
        try:
            answers = resolver.resolve(target, rtype)
            out["records"][rtype] = [r.to_text() for r in answers]
        except dns.resolver.NoAnswer:
            out["records"][rtype] = []
        except dns.resolver.NXDOMAIN:
            return {"target": target, "error": "NXDOMAIN"}
        except dns.exception.DNSException as e:
            out["records"][rtype] = [f"<error: {e.__class__.__name__}>"]
    return out


def ip_info(target: str) -> dict:
    """If `target` is a hostname, resolve to IP first; then geolocate."""
    target = (target or "").strip()
    if not target:
        return {"error": "empty input"}
    ip = target
    if not re.match(r"^[\d.:a-fA-F]+$", target):
        try:
            ip = socket.gethostbyname(_domain_only(target))
        except Exception as e:
            return {"error": f"resolve failed: {e}"}
    r = _safe_request(f"http://ip-api.com/json/{ip}")
    if isinstance(r, Exception):
        return {"ip": ip, "error": str(r)}
    try:
        return {"ip": ip, "info": r.json()}
    except Exception:
        return {"ip": ip, "error": "non-json response"}


def reverse_ip(target: str) -> dict:
    """Find other domains hosted on same IP via HackerTarget free API."""
    target = (target or "").strip()
    if not target:
        return {"error": "empty input"}
    ip = target
    if not re.match(r"^[\d.:a-fA-F]+$", target):
        try:
            ip = socket.gethostbyname(_domain_only(target))
        except Exception as e:
            return {"error": f"resolve failed: {e}"}
    r = _safe_request(f"https://api.hackertarget.com/reverseiplookup/?q={ip}")
    if isinstance(r, Exception):
        return {"ip": ip, "error": str(r)}
    body = r.text.strip()
    if "error" in body.lower() or "api count exceeded" in body.lower():
        return {"ip": ip, "error": body[:200]}
    domains = [d.strip() for d in body.splitlines() if d.strip()]
    return {"ip": ip, "count": len(domains), "domains": domains[:200]}


# ============== HTTP / TLS ==============

SECURITY_HEADERS = {
    "strict-transport-security": "HSTS",
    "content-security-policy": "CSP",
    "x-frame-options": "X-Frame-Options",
    "x-content-type-options": "X-Content-Type-Options",
    "referrer-policy": "Referrer-Policy",
    "permissions-policy": "Permissions-Policy",
    "cross-origin-opener-policy": "COOP",
    "cross-origin-embedder-policy": "COEP",
    "cross-origin-resource-policy": "CORP",
}


def _normalize_url(s: str) -> str:
    s = (s or "").strip()
    if not s:
        return ""
    if "://" not in s:
        s = "https://" + s
    return s


def http_headers(target: str) -> dict:
    url = _normalize_url(target)
    if not url:
        return {"error": "empty input"}
    r = _safe_request(url)
    if isinstance(r, Exception):
        return {"url": url, "error": str(r)}
    all_headers = dict(r.headers)
    sec = {}
    missing = []
    for h, label in SECURITY_HEADERS.items():
        present = next((v for k, v in r.headers.items() if k.lower() == h), None)
        if present:
            sec[label] = present
        else:
            missing.append(label)
    return {
        "url": url,
        "final_url": r.url,
        "status": r.status_code,
        "all_headers": all_headers,
        "security_headers": sec,
        "missing_security_headers": missing,
        "score": f"{len(sec)}/{len(SECURITY_HEADERS)}",
    }


def tls_cert(target: str) -> dict:
    """Open a TLS connection on 443 and dump the peer certificate."""
    host = _domain_only(target) or target.strip()
    if not host:
        return {"error": "empty input"}
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((host, 443), timeout=10) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                cert = ssock.getpeercert()
                version = ssock.version()
                cipher = ssock.cipher()
    except Exception as e:
        return {"host": host, "error": str(e)}

    def _flatten_pairs(seq):
        out = {}
        for grp in seq or ():
            for k, v in grp:
                out[k] = v
        return out

    subject = _flatten_pairs(cert.get("subject"))
    issuer = _flatten_pairs(cert.get("issuer"))
    not_before = cert.get("notBefore")
    not_after = cert.get("notAfter")
    sans = [v for k, v in cert.get("subjectAltName", []) if k == "DNS"]

    def _parse(d):
        if not d:
            return None
        try:
            return datetime.strptime(d, "%b %d %H:%M:%S %Y %Z").replace(
                tzinfo=timezone.utc).isoformat()
        except Exception:
            return d

    return {
        "host": host,
        "tls_version": version,
        "cipher": cipher[0] if cipher else None,
        "subject": subject,
        "issuer": issuer,
        "not_before": _parse(not_before),
        "not_after": _parse(not_after),
        "san_count": len(sans),
        "sans": sans[:60],
        "serial": cert.get("serialNumber"),
    }


def robots_and_sitemap(target: str) -> dict:
    base = _normalize_url(target)
    if not base:
        return {"error": "empty input"}
    parsed = urlparse(base)
    root = f"{parsed.scheme}://{parsed.netloc}"
    out = {"root": root}
    for name in ("robots.txt", "sitemap.xml"):
        url = f"{root}/{name}"
        r = _safe_request(url)
        if isinstance(r, Exception):
            out[name] = {"url": url, "error": str(r)}
        else:
            text = r.text or ""
            out[name] = {
                "url": url,
                "status": r.status_code,
                "content_type": r.headers.get("Content-Type", ""),
                "size": len(text),
                "body": text[:8000],
            }
    return out


# ============== OSINT ==============

def wayback_snapshots(target: str, limit: int = 50) -> dict:
    target = _domain_only(target)
    if not target:
        return {"error": "empty domain"}
    url = (f"https://web.archive.org/cdx/search/cdx"
           f"?url={quote(target)}/*&output=json&limit={limit}"
           f"&fl=timestamp,original,statuscode&filter=statuscode:200"
           f"&collapse=urlkey")
    last_err = None
    for attempt in range(2):
        r = _safe_request(url, timeout=45)
        if not isinstance(r, Exception):
            try:
                rows = r.json()
            except Exception:
                return {"error": "wayback returned non-json"}
            if not rows:
                return {"target": target, "count": 0, "snapshots": []}
            header, *data = rows
            snaps = [
                {
                    "timestamp": d[0],
                    "original": d[1],
                    "status": d[2],
                    "wayback_url": f"https://web.archive.org/web/{d[0]}/{d[1]}",
                }
                for d in data
            ]
            return {"target": target, "count": len(snaps), "snapshots": snaps}
        last_err = r
    return {"error": f"wayback unreachable after 2 tries: {last_err}"}


EMAIL_RE = re.compile(
    r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}",
)


def email_harvest(target: str, depth: int = 1) -> dict:
    """Fetch homepage + common contact pages and pull email addresses.
    Capped + deduped."""
    base = _normalize_url(target)
    if not base:
        return {"error": "empty input"}
    base_host = urlparse(base).netloc
    visited = set()
    found = set()
    pages_left = 12  # bumped from 6

    def crawl(url, current_depth):
        nonlocal pages_left
        if pages_left <= 0 or url in visited:
            return
        visited.add(url)
        pages_left -= 1
        r = _safe_request(url)
        if isinstance(r, Exception) or r.status_code >= 400:
            return
        text = r.text or ""
        for m in EMAIL_RE.findall(text):
            if any(m.lower().endswith(x) for x in
                   (".png", ".jpg", ".gif", ".svg", ".css", ".js",
                    ".webp", ".woff", ".woff2", ".ico")):
                continue
            # filter obvious noise (sentry DSNs, example domains, hash@2x)
            if any(x in m.lower() for x in
                   ("@example.", "sentry.io", "@2x.", ".ingest.")):
                continue
            found.add(m.lower())
        if current_depth < depth:
            soup = BeautifulSoup(text, "html.parser")
            for a in soup.find_all("a", href=True)[:30]:
                href = urljoin(url, a["href"])
                if urlparse(href).netloc == base_host and href.startswith(
                        ("http://", "https://")):
                    crawl(href, current_depth + 1)

    # try homepage + common contact paths up front
    crawl(base, 0)
    parsed = urlparse(base)
    root = f"{parsed.scheme}://{parsed.netloc}"
    for path in ("/contact", "/contact-us", "/about", "/about-us",
                 "/team", "/staff", "/people", "/imprint", "/legal",
                 "/privacy", "/support"):
        crawl(root + path, 0)

    return {
        "target": base,
        "pages_visited": len(visited),
        "count": len(found),
        "emails": sorted(found),
    }


def subdomain_enum_multi(target: str) -> dict:
    """Combined enum: crt.sh + HackerTarget + Wayback. Reports per-source
    status so failures don't disappear silently."""
    target = _domain_only(target)
    if not target:
        return {"error": "empty domain"}

    seen = set()
    sources = {}

    # ---- crt.sh
    try:
        r = requests.get(f"https://crt.sh/?q=%25.{target}&output=json",
                         timeout=30, headers=HEADERS)
        if r.status_code == 200 and r.text.strip():
            before = len(seen)
            for entry in r.json():
                for name in entry.get("name_value", "").splitlines():
                    name = name.strip().lower().lstrip("*.")
                    if name.endswith(target) and "@" not in name:
                        seen.add(name)
            sources["crt.sh"] = {"ok": True, "added": len(seen) - before}
        else:
            sources["crt.sh"] = {"ok": False,
                                  "error": f"HTTP {r.status_code}"}
    except Exception as e:
        sources["crt.sh"] = {"ok": False, "error": str(e)[:120]}

    # ---- HackerTarget
    try:
        r = requests.get(f"https://api.hackertarget.com/hostsearch/?q={target}",
                         timeout=20, headers=HEADERS)
        body = r.text or ""
        if r.status_code == 200 and "error" not in body.lower() \
                and "api count exceeded" not in body.lower():
            before = len(seen)
            for ln in body.splitlines():
                host = ln.split(",")[0].strip().lower()
                if host.endswith(target):
                    seen.add(host)
            sources["hackertarget"] = {"ok": True, "added": len(seen) - before}
        else:
            sources["hackertarget"] = {"ok": False, "error": body[:120]}
    except Exception as e:
        sources["hackertarget"] = {"ok": False, "error": str(e)[:120]}

    # ---- Wayback CDX
    try:
        r = requests.get(
            f"https://web.archive.org/cdx/search/cdx?url=*.{target}/*"
            f"&output=json&fl=original&collapse=urlkey&limit=5000",
            timeout=45, headers=HEADERS,
        )
        if r.status_code == 200 and r.text.strip():
            rows = r.json()
            before = len(seen)
            for row in rows[1:]:
                u = row[0] if row else ""
                host = urlparse(u).netloc.lower()
                if host and host.endswith(target):
                    seen.add(host)
            sources["wayback"] = {"ok": True, "added": len(seen) - before}
        else:
            sources["wayback"] = {"ok": False,
                                   "error": f"HTTP {r.status_code}"}
    except Exception as e:
        sources["wayback"] = {"ok": False, "error": str(e)[:120]}

    subs = sorted(seen)
    return {
        "target": target,
        "sources": sources,
        "sources_used": [s for s, v in sources.items() if v.get("ok")],
        "count": len(subs),
        "subdomains": subs,
    }


# ============== ENCODERS ==============

def _b64_decode(s: str) -> str:
    """Try urlsafe and standard, with padding fix."""
    s = s.strip()
    pad = "=" * (-len(s) % 4)
    for fn in (base64.urlsafe_b64decode, base64.b64decode):
        try:
            return fn(s + pad).decode("utf-8", errors="replace")
        except Exception:
            continue
    return ""


def encode_decode(op: str, kind: str, value: str) -> dict:
    """op = encode | decode; kind = base64 | url | jwt; value = input string."""
    if not value:
        return {"error": "empty input"}
    try:
        if kind == "base64":
            if op == "encode":
                return {"result": base64.b64encode(value.encode("utf-8")).decode()}
            else:
                return {"result": _b64_decode(value)}
        if kind == "url":
            if op == "encode":
                return {"result": quote(value, safe="")}
            else:
                return {"result": unquote(value)}
        if kind == "jwt":
            # decode-only: split on dots, base64-decode header + payload
            parts = value.strip().split(".")
            if len(parts) < 2:
                return {"error": "not a JWT (need 2-3 dot-separated parts)"}
            try:
                header = json.loads(_b64_decode(parts[0]))
            except Exception as e:
                return {"error": f"header decode failed: {e}"}
            try:
                payload = json.loads(_b64_decode(parts[1]))
            except Exception as e:
                return {"error": f"payload decode failed: {e}"}
            return {
                "header": header,
                "payload": payload,
                "signature_present": len(parts) >= 3 and bool(parts[2]),
                "note": "signature NOT verified",
            }
        return {"error": f"unknown kind: {kind}"}
    except (binascii.Error, ValueError) as e:
        return {"error": f"{type(e).__name__}: {e}"}


def hash_text(value: str) -> dict:
    if not value:
        return {"error": "empty input"}
    b = value.encode("utf-8")
    return {
        "md5": hashlib.md5(b).hexdigest(),
        "sha1": hashlib.sha1(b).hexdigest(),
        "sha256": hashlib.sha256(b).hexdigest(),
        "sha512": hashlib.sha512(b).hexdigest(),
        "bytes": len(b),
    }


def json_pretty(value: str) -> dict:
    if not value:
        return {"error": "empty input"}
    try:
        return {"result": json.dumps(json.loads(value), indent=2, sort_keys=False)}
    except Exception as e:
        return {"error": f"invalid JSON: {e}"}


# ============== ASN / BGP (no key) ==============

def asn_info(target: str) -> dict:
    """ASN + prefix info for an IP or ASN, via RIPEstat (no key)."""
    target = (target or "").strip()
    if not target:
        return {"error": "empty input"}
    try:
        if target.upper().startswith("AS") or target.isdigit():
            asn = target.upper().lstrip("AS")
            r = _safe_request(
                f"https://stat.ripe.net/data/as-overview/data.json"
                f"?resource=AS{asn}",
            )
            if isinstance(r, Exception):
                return {"error": str(r)}
            d = r.json().get("data", {})
            holder = d.get("holder", "")
            return {
                "kind": "asn",
                "asn": asn,
                "holder": holder,
                "announced": d.get("announced"),
                "type": d.get("type"),
                "block": (d.get("block") or {}).get("resource"),
            }
        # else: IP path
        ip = target
        if not re.match(r"^[\d.:a-fA-F]+$", target):
            ip = socket.gethostbyname(_domain_only(target))
        r = _safe_request(
            f"https://stat.ripe.net/data/network-info/data.json"
            f"?resource={ip}",
        )
        if isinstance(r, Exception):
            return {"error": str(r)}
        d = r.json().get("data", {})
        asns = d.get("asns") or []
        out = {"kind": "ip", "ip": ip, "prefix": d.get("prefix"),
               "asns": asns, "asn_details": []}
        # enrich with holder names for each ASN
        for asn in asns[:5]:
            r2 = _safe_request(
                f"https://stat.ripe.net/data/as-overview/data.json"
                f"?resource=AS{asn}", timeout=8,
            )
            if not isinstance(r2, Exception):
                dd = r2.json().get("data", {})
                out["asn_details"].append({
                    "asn": asn, "holder": dd.get("holder"),
                    "type": dd.get("type"),
                })
        return out
    except Exception as e:
        return {"error": str(e)}


def bgp_prefixes(asn: str) -> dict:
    """List prefixes announced by an ASN. RIPEstat."""
    asn = (asn or "").strip().upper().lstrip("AS")
    if not asn or not asn.isdigit():
        return {"error": "ASN must be a number (e.g. 13335 or AS13335)"}
    r = _safe_request(
        f"https://stat.ripe.net/data/announced-prefixes/data.json"
        f"?resource=AS{asn}", timeout=20,
    )
    if isinstance(r, Exception):
        return {"error": str(r)}
    prefixes = r.json().get("data", {}).get("prefixes") or []
    v4 = [p["prefix"] for p in prefixes if ":" not in p.get("prefix", "")]
    v6 = [p["prefix"] for p in prefixes if ":" in p.get("prefix", "")]
    return {
        "asn": asn,
        "ipv4_count": len(v4),
        "ipv6_count": len(v6),
        "ipv4": v4[:200],
        "ipv6": v6[:200],
    }


# ============== GITHUB OSINT (no key needed for basic) ==============

def github_user(username: str) -> dict:
    username = (username or "").strip().lstrip("@")
    if not username:
        return {"error": "empty username"}
    headers = dict(HEADERS)
    if os.environ.get("GITHUB_TOKEN"):
        headers["Authorization"] = f"Bearer {os.environ['GITHUB_TOKEN']}"
    out = {"username": username}
    # profile
    r = _safe_request(f"https://api.github.com/users/{username}",
                      headers=headers)
    if isinstance(r, Exception):
        return {"error": str(r)}
    if r.status_code == 404:
        return {"error": f"user '{username}' not found"}
    if r.status_code == 403:
        return {"error": f"rate-limited (set $GITHUB_TOKEN to raise the cap)"}
    p = r.json()
    out["profile"] = {
        k: p.get(k) for k in (
            "id", "login", "name", "company", "blog", "location",
            "email", "bio", "twitter_username", "created_at", "updated_at",
            "public_repos", "public_gists", "followers", "following",
        )
    }
    # top repos
    r2 = _safe_request(
        f"https://api.github.com/users/{username}/repos"
        f"?sort=updated&per_page=20", headers=headers,
    )
    if not isinstance(r2, Exception) and r2.status_code == 200:
        out["recent_repos"] = [
            {
                "name": rp["name"],
                "fork": rp.get("fork"),
                "stars": rp.get("stargazers_count"),
                "language": rp.get("language"),
                "pushed_at": rp.get("pushed_at"),
                "url": rp.get("html_url"),
                "description": (rp.get("description") or "")[:200],
            }
            for rp in r2.json()
        ]
    return out


# ============== HIBP (paid key) ==============

def hibp_email(email: str) -> dict:
    email = (email or "").strip()
    if not email or "@" not in email:
        return {"error": "give a valid email address"}
    key, err = _need_key("HIBP_API_KEY")
    if err:
        return err
    r = _safe_request(
        f"https://haveibeenpwned.com/api/v3/breachedaccount/{quote(email)}"
        f"?truncateResponse=false",
        headers={"hibp-api-key": key, "User-Agent": "domain-scraper-toolkit"},
    )
    if isinstance(r, Exception):
        return {"error": str(r)}
    if r.status_code == 404:
        return {"email": email, "breaches": [], "count": 0,
                "note": "no breaches found for this address"}
    if r.status_code == 401:
        return {"error": "HIBP key invalid or expired"}
    if r.status_code == 429:
        return {"error": "HIBP rate limited — wait a few seconds and retry"}
    if r.status_code != 200:
        return {"error": f"HIBP returned {r.status_code}: {r.text[:200]}"}
    breaches = r.json()
    return {
        "email": email,
        "count": len(breaches),
        "breaches": [
            {
                "Name": b.get("Name"), "Title": b.get("Title"),
                "Domain": b.get("Domain"), "BreachDate": b.get("BreachDate"),
                "PwnCount": b.get("PwnCount"),
                "DataClasses": b.get("DataClasses"),
                "IsVerified": b.get("IsVerified"),
            }
            for b in breaches
        ],
    }


# ============== SHODAN ==============

def shodan_host(ip: str) -> dict:
    ip = (ip or "").strip()
    if not ip:
        return {"error": "empty input"}
    if not re.match(r"^[\d.:a-fA-F]+$", ip):
        try:
            ip = socket.gethostbyname(_domain_only(ip))
        except Exception as e:
            return {"error": f"resolve failed: {e}"}
    key, err = _need_key("SHODAN_API_KEY")
    if err:
        return err
    r = _safe_request(f"https://api.shodan.io/shodan/host/{ip}?key={key}")
    if isinstance(r, Exception):
        return {"error": str(r)}
    if r.status_code == 404:
        return {"ip": ip, "error": "no Shodan data for this IP"}
    if r.status_code == 401:
        return {"error": "Shodan key invalid"}
    if r.status_code != 200:
        return {"error": f"Shodan returned {r.status_code}: {r.text[:200]}"}
    d = r.json()
    services = []
    for svc in d.get("data", []):
        services.append({
            "port": svc.get("port"),
            "transport": svc.get("transport"),
            "product": svc.get("product"),
            "version": svc.get("version"),
            "banner": (svc.get("data") or "").splitlines()[0][:160],
            "ssl_subject": (svc.get("ssl") or {}).get("cert", {}).get("subject"),
            "timestamp": svc.get("timestamp"),
        })
    return {
        "ip": ip,
        "country": d.get("country_name"),
        "city": d.get("city"),
        "isp": d.get("isp"),
        "org": d.get("org"),
        "asn": d.get("asn"),
        "hostnames": d.get("hostnames", []),
        "ports": d.get("ports", []),
        "tags": d.get("tags", []),
        "vulns": list(d.get("vulns", []) or []),
        "services": services,
        "last_update": d.get("last_update"),
    }


# ============== CENSYS ==============

def censys_host(ip: str) -> dict:
    ip = (ip or "").strip()
    if not ip:
        return {"error": "empty input"}
    if not re.match(r"^[\d.:a-fA-F]+$", ip):
        try:
            ip = socket.gethostbyname(_domain_only(ip))
        except Exception as e:
            return {"error": f"resolve failed: {e}"}
    api_id = os.environ.get("CENSYS_API_ID")
    api_secret = os.environ.get("CENSYS_API_SECRET")
    if not api_id or not api_secret:
        return {"error": "missing API creds — set $CENSYS_API_ID and "
                         "$CENSYS_API_SECRET"}
    try:
        r = requests.get(f"https://search.censys.io/api/v2/hosts/{ip}",
                         auth=(api_id, api_secret), timeout=15,
                         headers={"User-Agent": UA})
    except Exception as e:
        return {"error": str(e)}
    if r.status_code == 401:
        return {"error": "Censys creds invalid"}
    if r.status_code == 404:
        return {"ip": ip, "error": "no Censys data for this IP"}
    if r.status_code != 200:
        return {"error": f"Censys returned {r.status_code}: {r.text[:200]}"}
    d = r.json().get("result", {})
    services = [
        {
            "port": s.get("port"),
            "service_name": s.get("service_name"),
            "transport_protocol": s.get("transport_protocol"),
            "extended_service_name": s.get("extended_service_name"),
            "software": s.get("software"),
            "tls": (s.get("tls") or {}).get("certificates", {}).get(
                "leaf_data", {}).get("subject_dn") if s.get("tls") else None,
        }
        for s in d.get("services", [])
    ]
    return {
        "ip": ip,
        "location": d.get("location"),
        "autonomous_system": d.get("autonomous_system"),
        "operating_system": d.get("operating_system"),
        "service_count": len(services),
        "services": services,
        "last_updated_at": d.get("last_updated_at"),
    }


# ============== GREYNOISE (community endpoint, no key) ==============

def greynoise_ip(ip: str) -> dict:
    ip = (ip or "").strip()
    if not ip:
        return {"error": "empty input"}
    if not re.match(r"^[\d.:a-fA-F]+$", ip):
        try:
            ip = socket.gethostbyname(_domain_only(ip))
        except Exception as e:
            return {"error": f"resolve failed: {e}"}
    headers = dict(HEADERS)
    if os.environ.get("GREYNOISE_API_KEY"):
        headers["key"] = os.environ["GREYNOISE_API_KEY"]
    r = _safe_request(
        f"https://api.greynoise.io/v3/community/{ip}", headers=headers,
    )
    if isinstance(r, Exception):
        return {"error": str(r)}
    if r.status_code == 404:
        return {"ip": ip, "classification": "unknown",
                "note": "IP not in GreyNoise dataset (i.e. not seen mass-scanning)"}
    if r.status_code == 429:
        return {"error": "GreyNoise rate limited — set $GREYNOISE_API_KEY to raise"}
    if r.status_code != 200:
        return {"error": f"GreyNoise {r.status_code}: {r.text[:200]}"}
    return r.json()


# ============== VIRUSTOTAL ==============

def virustotal(target: str) -> dict:
    target = (target or "").strip()
    if not target:
        return {"error": "empty input"}
    key, err = _need_key("VT_API_KEY")
    if err:
        return err

    # detect kind: ip / domain
    kind = "ip" if re.match(r"^[\d.:a-fA-F]+$", target) else "domain"
    target_norm = target if kind == "ip" else _domain_only(target)
    path = "ip_addresses" if kind == "ip" else "domains"

    r = _safe_request(
        f"https://www.virustotal.com/api/v3/{path}/{target_norm}",
        headers={"x-apikey": key, "User-Agent": UA},
    )
    if isinstance(r, Exception):
        return {"error": str(r)}
    if r.status_code == 401:
        return {"error": "VT key invalid"}
    if r.status_code == 404:
        return {"target": target, "error": "VT has no record for this target"}
    if r.status_code != 200:
        return {"error": f"VT {r.status_code}: {r.text[:200]}"}
    a = r.json().get("data", {}).get("attributes", {})
    stats = a.get("last_analysis_stats", {})
    return {
        "target": target_norm,
        "kind": kind,
        "reputation": a.get("reputation"),
        "harmless": stats.get("harmless"),
        "malicious": stats.get("malicious"),
        "suspicious": stats.get("suspicious"),
        "undetected": stats.get("undetected"),
        "timeout": stats.get("timeout"),
        "categories": a.get("categories"),
        "registrar": a.get("registrar"),
        "creation_date": a.get("creation_date"),
        "last_modification_date": a.get("last_modification_date"),
        "tags": a.get("tags"),
    }


# ============== ABUSEIPDB ==============

def abuseipdb(ip: str) -> dict:
    ip = (ip or "").strip()
    if not ip:
        return {"error": "empty input"}
    if not re.match(r"^[\d.:a-fA-F]+$", ip):
        try:
            ip = socket.gethostbyname(_domain_only(ip))
        except Exception as e:
            return {"error": f"resolve failed: {e}"}
    key, err = _need_key("ABUSEIPDB_API_KEY")
    if err:
        return err
    r = _safe_request(
        "https://api.abuseipdb.com/api/v2/check",
        headers={"Key": key, "Accept": "application/json"},
        params={"ipAddress": ip, "maxAgeInDays": 90, "verbose": ""},
    )
    if isinstance(r, Exception):
        return {"error": str(r)}
    if r.status_code == 401:
        return {"error": "AbuseIPDB key invalid"}
    if r.status_code != 200:
        return {"error": f"AbuseIPDB {r.status_code}: {r.text[:200]}"}
    d = r.json().get("data", {})
    return {
        "ip": d.get("ipAddress"),
        "abuse_score": d.get("abuseConfidenceScore"),
        "is_public": d.get("isPublic"),
        "is_whitelisted": d.get("isWhitelisted"),
        "country": d.get("countryCode"),
        "usage_type": d.get("usageType"),
        "isp": d.get("isp"),
        "domain": d.get("domain"),
        "total_reports": d.get("totalReports"),
        "last_reported_at": d.get("lastReportedAt"),
        "recent_reports": [
            {
                "reported_at": rep.get("reportedAt"),
                "categories": rep.get("categories"),
                "comment": (rep.get("comment") or "")[:200],
            }
            for rep in (d.get("reports") or [])[:10]
        ],
    }


# ============== URLSCAN.IO ==============

def urlscan_search(target: str) -> dict:
    """Search public urlscan.io results for a domain. No key needed."""
    target = _domain_only(target) or target.strip()
    if not target:
        return {"error": "empty input"}
    headers = dict(HEADERS)
    if os.environ.get("URLSCAN_API_KEY"):
        headers["API-Key"] = os.environ["URLSCAN_API_KEY"]
    r = _safe_request(
        f"https://urlscan.io/api/v1/search/?q=domain:{quote(target)}&size=25",
        headers=headers,
    )
    if isinstance(r, Exception):
        return {"error": str(r)}
    if r.status_code != 200:
        return {"error": f"urlscan {r.status_code}: {r.text[:200]}"}
    res = r.json().get("results", [])
    return {
        "target": target,
        "count": len(res),
        "scans": [
            {
                "url": s.get("page", {}).get("url"),
                "domain": s.get("page", {}).get("domain"),
                "ip": s.get("page", {}).get("ip"),
                "country": s.get("page", {}).get("country"),
                "asn": s.get("page", {}).get("asn"),
                "ptr": s.get("page", {}).get("ptr"),
                "scan_time": s.get("task", {}).get("time"),
                "result_url": s.get("result"),
                "screenshot": s.get("screenshot"),
            }
            for s in res
        ],
    }
