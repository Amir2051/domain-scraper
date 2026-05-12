#!/usr/bin/env python3
"""
tools_cyber.py — cyber / threat-intel tools.

Free / no-key first. A handful (ThreatFox v2, AbuseIPDB) require keys —
those return a structured error if the env var isn't set.
"""
from __future__ import annotations

import base64
import os
import re
import socket
import ssl
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import quote, urljoin, urlparse

import dns.resolver
import dns.exception
import requests
from bs4 import BeautifulSoup

from safenest.http import DEFAULT_HEADERS as HEADERS, DEFAULT_UA as UA, make_client

TIMEOUT = 12
_get, _post = make_client(timeout=TIMEOUT)


def _norm_url(s):
    s = (s or "").strip()
    if not s:
        return ""
    if "://" not in s:
        s = "https://" + s
    return s


def _domain_only(s):
    s = (s or "").strip()
    if "://" in s:
        s = urlparse(s).hostname or s
    return s.strip().lstrip(".").rstrip("/").lower()


def _resolve(host):
    try:
        return socket.gethostbyname(host)
    except Exception:
        return None


# ============== CVE / NVD ==============

def cve_lookup(cve_id: str) -> dict:
    """NVD CVE lookup (no key for low rate). Set $NVD_API_KEY for higher
    quota."""
    cve_id = (cve_id or "").strip().upper()
    if not re.match(r"^CVE-\d{4}-\d{4,7}$", cve_id):
        return {"error": "expected CVE-YYYY-NNNN(N+)"}
    h = dict(HEADERS)
    if os.environ.get("NVD_API_KEY"):
        h["apiKey"] = os.environ["NVD_API_KEY"]
    r = _get(f"https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={cve_id}",
             headers=h, timeout=20)
    if isinstance(r, Exception):
        return {"error": str(r)}
    if r.status_code == 404:
        return {"error": f"{cve_id} not found"}
    if r.status_code != 200:
        return {"error": f"NVD returned {r.status_code}: {r.text[:200]}"}
    try:
        items = r.json().get("vulnerabilities", [])
    except Exception:
        return {"error": "non-json"}
    if not items:
        return {"error": f"no record for {cve_id}"}
    v = items[0].get("cve", {})
    metrics = v.get("metrics", {})
    cvss = (metrics.get("cvssMetricV31") or
            metrics.get("cvssMetricV30") or
            metrics.get("cvssMetricV2") or [{}])[0].get("cvssData", {})
    descs = v.get("descriptions", [])
    desc_en = next((d.get("value") for d in descs if d.get("lang") == "en"), "")
    refs = [r.get("url") for r in (v.get("references") or [])][:15]
    weaknesses = []
    for w in (v.get("weaknesses") or []):
        for d in (w.get("description") or []):
            weaknesses.append(d.get("value"))
    return {
        "id": v.get("id"),
        "published": v.get("published"),
        "modified": v.get("lastModified"),
        "status": v.get("vulnStatus"),
        "description": desc_en[:1500],
        "cvss_version": cvss.get("version"),
        "cvss_score": cvss.get("baseScore"),
        "cvss_severity": cvss.get("baseSeverity"),
        "vector": cvss.get("vectorString"),
        "weaknesses": weaknesses,
        "references": refs,
    }


def cve_search(keyword: str, limit=10) -> dict:
    keyword = (keyword or "").strip()
    if not keyword:
        return {"error": "empty keyword"}
    try:
        limit = max(1, min(50, int(limit) if limit else 10))
    except (ValueError, TypeError):
        limit = 10
    h = dict(HEADERS)
    if os.environ.get("NVD_API_KEY"):
        h["apiKey"] = os.environ["NVD_API_KEY"]
    r = _get(
        f"https://services.nvd.nist.gov/rest/json/cves/2.0"
        f"?keywordSearch={quote(keyword)}&resultsPerPage={limit}",
        headers=h, timeout=25,
    )
    if isinstance(r, Exception):
        return {"error": str(r)}
    if r.status_code != 200:
        return {"error": f"NVD returned {r.status_code}"}
    try:
        items = r.json().get("vulnerabilities", [])
    except Exception:
        return {"error": "non-json"}
    out = []
    for it in items[:limit]:
        v = it.get("cve", {})
        metrics = v.get("metrics", {})
        cvss = (metrics.get("cvssMetricV31") or
                metrics.get("cvssMetricV30") or [{}])[0].get("cvssData", {})
        desc_en = next((d.get("value") for d in (v.get("descriptions") or [])
                        if d.get("lang") == "en"), "")
        out.append({
            "id": v.get("id"),
            "published": v.get("published"),
            "score": cvss.get("baseScore"),
            "severity": cvss.get("baseSeverity"),
            "summary": desc_en[:300],
        })
    return {"keyword": keyword, "count": len(out), "results": out}


# ============== AlienVault OTX (no key for basic) ==============

def otx_indicators(target: str) -> dict:
    """AlienVault OTX — pulses + general info for an IP/domain/hash.
    No key needed for these endpoints (rate-limited)."""
    target = (target or "").strip()
    if not target:
        return {"error": "empty input"}
    # decide kind
    if re.match(r"^[\da-fA-F]{32,128}$", target):
        kind = "file"
    elif re.match(r"^[\d.]+$", target):
        kind = "IPv4"
    elif ":" in target:
        kind = "IPv6"
    else:
        kind = "domain"
        target = _domain_only(target)
    base = f"https://otx.alienvault.com/api/v1/indicators/{kind}/{quote(target)}/general"
    r = _get(base)
    if isinstance(r, Exception):
        return {"error": str(r)}
    if r.status_code == 404:
        return {"target": target, "kind": kind, "error": "not in OTX"}
    if r.status_code != 200:
        return {"error": f"OTX returned {r.status_code}: {r.text[:200]}"}
    try:
        d = r.json()
    except Exception:
        return {"error": "non-json"}
    pulses = (d.get("pulse_info") or {}).get("pulses") or []
    return {
        "target": target,
        "kind": kind,
        "reputation": d.get("reputation"),
        "type_title": d.get("type_title"),
        "country": d.get("country_name"),
        "city": d.get("city"),
        "asn": d.get("asn"),
        "pulse_count": len(pulses),
        "tags": list({t for p in pulses for t in (p.get("tags") or [])})[:30],
        "malware_families": list({m.get("display_name") for p in pulses
                                    for m in (p.get("malware_families") or [])
                                    if m.get("display_name")})[:20],
        "pulses": [
            {"name": p.get("name"),
             "tags": p.get("tags"),
             "modified": p.get("modified"),
             "adversary": p.get("adversary"),
             "tlp": p.get("TLP")}
            for p in pulses[:15]
        ],
    }


# ============== abuse.ch URLhaus ==============

def urlhaus_lookup(target: str) -> dict:
    """URLhaus host-or-url lookup. No key required (POST form)."""
    target = (target or "").strip()
    if not target:
        return {"error": "empty input"}
    if "://" in target:
        url = "https://urlhaus-api.abuse.ch/v1/url/"
        data = {"url": target}
    else:
        url = "https://urlhaus-api.abuse.ch/v1/host/"
        data = {"host": _domain_only(target)}
    try:
        r = requests.post(url, data=data, headers=HEADERS, timeout=TIMEOUT)
    except Exception as e:
        return {"error": str(e)}
    if r.status_code != 200:
        return {"error": f"URLhaus returned {r.status_code}"}
    try:
        d = r.json()
    except Exception:
        return {"error": "non-json"}
    if d.get("query_status") == "no_results":
        return {"target": target, "found": False,
                "note": "no URLhaus records"}
    out = {"target": target, "query_status": d.get("query_status")}
    if "host" in d:
        out["host"] = d.get("host")
        out["firstseen"] = d.get("firstseen")
        out["url_count"] = d.get("url_count")
        out["urls"] = [
            {"url": u.get("url"), "url_status": u.get("url_status"),
             "threat": u.get("threat"),
             "tags": u.get("tags"), "date_added": u.get("date_added"),
             "reporter": u.get("reporter")}
            for u in (d.get("urls") or [])[:20]
        ]
    else:
        out.update({
            "url": d.get("url"),
            "url_status": d.get("url_status"),
            "threat": d.get("threat"),
            "date_added": d.get("date_added"),
            "tags": d.get("tags"),
            "payloads": [
                {"file_name": p.get("filename"),
                 "type": p.get("file_type"),
                 "md5": p.get("response_md5"),
                 "sha256": p.get("response_sha256"),
                 "signature": p.get("signature")}
                for p in (d.get("payloads") or [])[:10]
            ],
        })
    return out


# ============== abuse.ch ThreatFox ==============

def threatfox_query(target: str) -> dict:
    """ThreatFox IOC search. Recent versions of the API require an
    Auth-Key — returns a key-needed error if $THREATFOX_API_KEY isn't set."""
    target = (target or "").strip()
    if not target:
        return {"error": "empty input"}
    h = dict(HEADERS)
    key = os.environ.get("THREATFOX_API_KEY")
    if key:
        h["Auth-Key"] = key
    try:
        r = requests.post(
            "https://threatfox-api.abuse.ch/api/v1/",
            json={"query": "search_ioc", "search_term": target},
            headers=h, timeout=TIMEOUT,
        )
    except Exception as e:
        return {"error": str(e)}
    if r.status_code == 401:
        return {"error": "ThreatFox now requires an API key — set "
                "$THREATFOX_API_KEY (free signup at auth.abuse.ch)"}
    if r.status_code != 200:
        return {"error": f"ThreatFox returned {r.status_code}"}
    try:
        d = r.json()
    except Exception:
        return {"error": "non-json"}
    if d.get("query_status") != "ok":
        return {"target": target, "found": False, "status": d.get("query_status")}
    data = d.get("data") or []
    return {
        "target": target,
        "count": len(data),
        "iocs": [
            {"ioc": i.get("ioc"), "type": i.get("ioc_type"),
             "threat_type": i.get("threat_type"),
             "malware": i.get("malware"),
             "confidence": i.get("confidence_level"),
             "first_seen": i.get("first_seen"),
             "tags": i.get("tags")}
            for i in data[:20]
        ],
    }


# ============== Tor exit list ==============

def tor_exit_check(ip: str) -> dict:
    """Is this IP a current Tor exit node? Uses the official exit list."""
    ip = (ip or "").strip()
    if not ip:
        return {"error": "empty input"}
    if not re.match(r"^[\d.:a-fA-F]+$", ip):
        ip = _resolve(_domain_only(ip)) or ip
    r = _get("https://check.torproject.org/torbulkexitlist", timeout=15)
    if isinstance(r, Exception):
        return {"error": str(r)}
    if r.status_code != 200:
        return {"error": f"torproject returned {r.status_code}"}
    exits = set(r.text.splitlines())
    return {
        "ip": ip,
        "is_tor_exit": ip in exits,
        "total_exits_known": len(exits),
    }


# ============== DNSBL ==============

DNSBLS = [
    "zen.spamhaus.org",
    "b.barracudacentral.org",
    "bl.spamcop.net",
    "cbl.abuseat.org",
    "dnsbl.sorbs.net",
    "psbl.surriel.com",
    "ubl.unsubscore.com",
    "dnsbl-1.uceprotect.net",
    "rbl.efnetrbl.org",
    "ix.dnsbl.manitu.net",
]


def dnsbl_check(ip: str) -> dict:
    ip = (ip or "").strip()
    if not ip:
        return {"error": "empty input"}
    if not re.match(r"^[\d.]+$", ip):
        ip = _resolve(_domain_only(ip)) or ip
    if not re.match(r"^[\d.]+$", ip):
        return {"error": "couldn't resolve to IPv4 (DNSBLs only support v4)"}
    octets = ip.split(".")
    if len(octets) != 4:
        return {"error": "not IPv4"}
    rev = ".".join(reversed(octets))
    res = dns.resolver.Resolver()
    res.lifetime = 4
    res.timeout = 4
    listed = []
    clean = []
    errored = []

    def _check(bl):
        try:
            ans = res.resolve(f"{rev}.{bl}", "A")
            return bl, [r.to_text() for r in ans]
        except dns.resolver.NXDOMAIN:
            return bl, None
        except dns.exception.DNSException as e:
            return bl, e.__class__.__name__

    with ThreadPoolExecutor(max_workers=10) as ex:
        for bl, result in ex.map(_check, DNSBLS):
            if result is None:
                clean.append(bl)
            elif isinstance(result, list):
                listed.append({"dnsbl": bl, "answer": result})
            else:
                errored.append({"dnsbl": bl, "error": result})
    return {
        "ip": ip,
        "listed_count": len(listed),
        "listed": listed,
        "clean_count": len(clean),
        "clean": clean,
        "errored": errored,
    }


# ============== SSL Labs ==============

def ssl_labs(host: str) -> dict:
    """Trigger / fetch SSL Labs scan. Slow (~2 min for first scan)."""
    host = _domain_only(host) or (host or "").strip()
    if not host:
        return {"error": "empty host"}
    r = _get(f"https://api.ssllabs.com/api/v3/analyze?host={quote(host)}"
             f"&fromCache=on&maxAge=24",
             timeout=30)
    if isinstance(r, Exception):
        return {"error": str(r)}
    if r.status_code != 200:
        return {"error": f"SSL Labs returned {r.status_code}"}
    try:
        d = r.json()
    except Exception:
        return {"error": "non-json"}
    endpoints = d.get("endpoints") or []
    return {
        "host": d.get("host"),
        "status": d.get("status"),
        "status_message": d.get("statusMessage"),
        "start_time": d.get("startTime"),
        "test_time": d.get("testTime"),
        "engine_version": d.get("engineVersion"),
        "endpoints": [
            {"ip": e.get("ipAddress"),
             "server_name": e.get("serverName"),
             "grade": e.get("grade"),
             "grade_trust_ignored": e.get("gradeTrustIgnored"),
             "has_warnings": e.get("hasWarnings"),
             "is_exceptional": e.get("isExceptional"),
             "progress": e.get("progress"),
             "status_message": e.get("statusMessage")}
            for e in endpoints
        ],
        "note": "If status='IN_PROGRESS', re-run after ~90s.",
    }


# ============== Mozilla HTTP Observatory ==============

def mozilla_observatory(host: str) -> dict:
    host = _domain_only(host) or (host or "").strip()
    if not host:
        return {"error": "empty host"}
    try:
        r = requests.post(
            "https://http-observatory.security.mozilla.org/api/v1/analyze",
            params={"host": host}, headers=HEADERS, timeout=30,
        )
    except Exception as e:
        return {"error": str(e)}
    if r.status_code != 200:
        return {"error": f"observatory returned {r.status_code}"}
    try:
        d = r.json()
    except Exception:
        return {"error": "non-json"}
    return {
        "host": host,
        "scan_id": d.get("scan_id"),
        "state": d.get("state"),
        "grade": d.get("grade"),
        "score": d.get("score"),
        "tests_passed": d.get("tests_passed"),
        "tests_failed": d.get("tests_failed"),
        "start_time": d.get("start_time"),
        "end_time": d.get("end_time"),
        "note": "If state='PENDING' or 'STARTED', re-run after a few seconds.",
    }


# ============== Favicon hash (Shodan-style) ==============

def favicon_hash(target: str) -> dict:
    """Compute mmh3 hash of base64-encoded favicon — used as a Shodan
    pivot ('http.favicon.hash:<n>') to find every host with the same icon."""
    try:
        import mmh3
    except ImportError:
        return {"error": "mmh3 not installed — pip install mmh3"}
    url = _norm_url(target)
    if not url:
        return {"error": "empty input"}
    favicon_url = url
    if not favicon_url.endswith("/favicon.ico"):
        # try /favicon.ico off the host root
        p = urlparse(url)
        favicon_url = f"{p.scheme}://{p.netloc}/favicon.ico"
    r = _get(favicon_url)
    if isinstance(r, Exception):
        return {"error": str(r)}
    if r.status_code != 200:
        return {"error": f"favicon GET returned {r.status_code}"}
    b64 = base64.encodebytes(r.content).decode()
    h = mmh3.hash(b64)
    return {
        "favicon_url": favicon_url,
        "size_bytes": len(r.content),
        "content_type": r.headers.get("Content-Type", ""),
        "mmh3_hash": h,
        "shodan_query": f'http.favicon.hash:{h}',
        "fofa_query": f'icon_hash="{h}"',
    }


# ============== Tech-stack fingerprint ==============

TECH_RULES = [
    # (name, header_name_lc | None, header_value_regex | None, body_regex | None)
    ("WordPress",       None,            None,            r"/wp-(content|includes)/"),
    ("Drupal",          "x-generator",   r"Drupal",       r"/sites/default/files/"),
    ("Joomla",          None,            None,            r'<meta name="generator" content="Joomla'),
    ("Ghost",           "x-powered-by",  r"ghost",        r'content="Ghost'),
    ("Magento",         None,            None,            r"Mage\.|/skin/frontend/"),
    ("Shopify",         "x-shopid",      None,            r"cdn\.shopify\.com"),
    ("Wix",             "x-wix-request-id", None,         r"static\.wixstatic\.com"),
    ("Squarespace",     None,            None,            r"static1\.squarespace\.com|<!-- Squarespace"),
    ("Webflow",         None,            None,            r"webflow\.com|wf-page"),
    ("Cloudflare",      "cf-ray",        None,            None),
    ("Fastly",          "x-served-by",   None,            None),
    ("Fastly",          "x-fastly-request-id", None,      None),
    ("Akamai",          "x-akamai-transformed", None,     None),
    ("AWS CloudFront",  "via",           r"cloudfront",   r"cloudfront\.net"),
    ("nginx",           "server",        r"nginx",        None),
    ("Apache",          "server",        r"^Apache(/|\s|$)", None),
    ("LiteSpeed",       "server",        r"LiteSpeed",    None),
    ("IIS",             "server",        r"Microsoft-IIS",None),
    ("Caddy",           "server",        r"Caddy",        None),
    ("Express",         "x-powered-by",  r"Express",      None),
    ("PHP",             "x-powered-by",  r"PHP/",         None),
    ("Next.js",         "x-powered-by",  r"Next\.js",     r"_next/static"),
    ("Nuxt",            None,            None,            r"__nuxt|_nuxt/"),
    ("React",           None,            None,            r"reactroot|/static/js/main\.[a-f0-9]"),
    ("Vue",             None,            None,            r"data-v-[a-f0-9]"),
    ("Angular",         None,            None,            r"ng-version"),
    ("Svelte",          None,            None,            r"data-svelte|svelte-"),
    ("jQuery",          None,            None,            r"jquery[.-]\d|/jquery\.js"),
    ("Bootstrap",       None,            None,            r"bootstrap[.-]\d|/bootstrap\.css"),
    ("Tailwind",        None,            None,            r"tailwindcss"),
    ("Google Analytics",None,            None,            r"google-analytics\.com|googletagmanager"),
    ("Stripe",          None,            None,            r"js\.stripe\.com"),
    ("Hotjar",          None,            None,            r"static\.hotjar\.com"),
    ("Sentry",          None,            None,            r"sentry-cdn|browser\.sentry-cdn"),
    ("reCAPTCHA",       None,            None,            r"google\.com/recaptcha"),
    ("Cloudflare Turnstile", None,       None,            r"challenges\.cloudflare\.com"),
    ("HubSpot",         None,            None,            r"js\.hs-scripts|hubspot"),
    ("Intercom",        None,            None,            r"widget\.intercom"),
    ("Zendesk",         None,            None,            r"static\.zdassets|zendesk\.com/embeddable"),
    ("OneTrust",        None,            None,            r"cdn\.cookielaw\.org|onetrust"),
    ("Cookiebot",       None,            None,            r"consent\.cookiebot\.com"),
]


def tech_detect(target: str) -> dict:
    url = _norm_url(target)
    if not url:
        return {"error": "empty input"}
    r = _get(url)
    if isinstance(r, Exception):
        return {"error": str(r)}
    headers = {k.lower(): v for k, v in r.headers.items()}
    body = r.text or ""
    matched = []
    for name, hdr_name, hdr_re, body_re in TECH_RULES:
        h_match = b_match = None
        if hdr_name:
            v = headers.get(hdr_name)
            if v is None:
                h_match = False
            elif hdr_re is None:
                h_match = True
            else:
                h_match = bool(re.search(hdr_re, v, re.IGNORECASE))
        if body_re:
            b_match = bool(re.search(body_re, body, re.IGNORECASE))
        if h_match or b_match:
            matched.append(name)
    return {
        "url": r.url,
        "status": r.status_code,
        "server": headers.get("server"),
        "x_powered_by": headers.get("x-powered-by"),
        "tech_detected": sorted(set(matched)),
        "tech_count": len(set(matched)),
    }


# ============== CMS detect (specific to common CMSs) ==============

def cms_detect(target: str) -> dict:
    """Probe for WordPress / Drupal / Joomla / Ghost / Magento markers."""
    url = _norm_url(target)
    if not url:
        return {"error": "empty input"}
    r = _get(url)
    if isinstance(r, Exception):
        return {"error": str(r)}
    text = r.text or ""
    findings = []
    if "/wp-content/" in text or "/wp-includes/" in text:
        findings.append("WordPress")
        # version probe
        m = re.search(r'<meta name="generator" content="WordPress\s+([\d.]+)"', text)
        if m:
            findings.append(f"WP version: {m.group(1)}")
    if "Drupal" in text or "/sites/default/" in text:
        findings.append("Drupal")
    if "Joomla" in text:
        findings.append("Joomla")
    if "Ghost" in (r.headers.get("X-Powered-By") or "") or 'content="Ghost' in text:
        findings.append("Ghost")
    if "Mage." in text or "/skin/frontend/" in text:
        findings.append("Magento")

    # WP specific endpoints
    wp_signals = {}
    for path in ("/wp-login.php", "/wp-json/", "/xmlrpc.php"):
        rr = _get(urljoin(url, path))
        if not isinstance(rr, Exception):
            wp_signals[path] = rr.status_code

    return {
        "url": r.url,
        "findings": findings,
        "wp_endpoint_status": wp_signals,
    }


# ============== Quick TCP port scan ==============

COMMON_PORTS = [21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445,
                465, 587, 993, 995, 1433, 1521, 1723, 2049, 2375, 3306,
                3389, 5432, 5900, 5985, 6379, 8000, 8008, 8080, 8081,
                8443, 8888, 9200, 9300, 11211, 27017]


def port_scan_quick(target: str, ports: str = "") -> dict:
    """Concurrent TCP-connect scan of common ports (or comma-separated list).
    NOT a stealth scan — host sees full connections. ~3s for default list."""
    host = _domain_only(target) or (target or "").strip()
    if not host:
        return {"error": "empty host"}
    if ports:
        try:
            port_list = [int(p) for p in ports.split(",") if p.strip()]
        except ValueError:
            return {"error": "ports must be comma-separated integers"}
    else:
        port_list = COMMON_PORTS
    if len(port_list) > 200:
        return {"error": "max 200 ports per scan"}

    ip = _resolve(host)
    if not ip:
        return {"error": f"could not resolve {host}"}

    def _probe(p):
        try:
            with socket.create_connection((ip, p), timeout=2) as s:
                # try to grab a 1-line banner (cheap)
                try:
                    s.settimeout(0.7)
                    banner = s.recv(120).decode("latin-1", errors="replace").strip()
                except Exception:
                    banner = ""
            return p, True, banner
        except Exception:
            return p, False, ""

    open_ports = []
    with ThreadPoolExecutor(max_workers=50) as ex:
        for p, is_open, banner in ex.map(_probe, port_list):
            if is_open:
                open_ports.append({"port": p, "banner": banner[:160]})
    return {
        "host": host,
        "ip": ip,
        "ports_checked": len(port_list),
        "open_count": len(open_ports),
        "open": sorted(open_ports, key=lambda x: x["port"]),
    }


# ============== CORS check ==============

def cors_check(target: str) -> dict:
    url = _norm_url(target)
    if not url:
        return {"error": "empty input"}
    test_origin = "https://evil.example.com"
    try:
        r = requests.get(url, headers={**HEADERS, "Origin": test_origin},
                          timeout=TIMEOUT, allow_redirects=True)
    except Exception as e:
        return {"error": str(e)}
    aco = r.headers.get("Access-Control-Allow-Origin")
    acc = r.headers.get("Access-Control-Allow-Credentials")
    risk = "low"
    notes = []
    if aco == "*":
        risk = "low" if (acc or "").lower() != "true" else "high"
        if (acc or "").lower() == "true":
            notes.append("ACAO=* with ACAC=true is invalid per spec, rejected by browsers, but indicates misconfig")
    elif aco == test_origin:
        risk = "high"
        notes.append("server reflects arbitrary Origin — full CSRF-via-CORS risk")
    elif aco and aco != "null":
        risk = "info"
        notes.append("ACAO is allow-listed to a specific origin (good)")
    if aco == "null":
        risk = "high"
        notes.append("ACAO='null' is exploitable by any sandboxed iframe")
    return {
        "url": r.url,
        "status": r.status_code,
        "test_origin_sent": test_origin,
        "access_control_allow_origin": aco,
        "access_control_allow_credentials": acc,
        "vary_origin": r.headers.get("Vary"),
        "risk": risk,
        "notes": notes,
    }


# ============== Cookie audit ==============

def cookie_audit(target: str) -> dict:
    url = _norm_url(target)
    if not url:
        return {"error": "empty input"}
    r = _get(url)
    if isinstance(r, Exception):
        return {"error": str(r)}
    raw = r.headers.get("Set-Cookie") or ""
    # requests collapses duplicate Set-Cookie; use raw_headers if available
    raws = r.raw.headers.getlist("Set-Cookie") if hasattr(r.raw, "headers") else [raw]
    cookies = []
    for line in raws:
        if not line:
            continue
        parts = [p.strip() for p in line.split(";")]
        name, _, value = parts[0].partition("=")
        attrs = {p.split("=", 1)[0].lower(): (p.split("=", 1)[1]
                  if "=" in p else True) for p in parts[1:]}
        cookies.append({
            "name": name,
            "value_len": len(value),
            "secure": bool(attrs.get("secure")),
            "httponly": bool(attrs.get("httponly")),
            "samesite": attrs.get("samesite"),
            "expires": attrs.get("expires"),
            "path": attrs.get("path"),
            "domain": attrs.get("domain"),
        })
    issues = []
    for c in cookies:
        if not c["secure"] and url.startswith("https://"):
            issues.append(f"{c['name']}: Secure flag missing")
        if not c["httponly"]:
            issues.append(f"{c['name']}: HttpOnly missing")
        if not c["samesite"]:
            issues.append(f"{c['name']}: SameSite not set (browser default = Lax)")
    return {
        "url": r.url,
        "cookie_count": len(cookies),
        "cookies": cookies,
        "issue_count": len(issues),
        "issues": issues,
    }


# ============== Subdomain takeover heuristic ==============

TAKEOVER_FINGERPRINTS = [
    ("GitHub Pages",  "There isn't a GitHub Pages site here"),
    ("Heroku",        "no such app"),
    ("Heroku",        "herokucdn.com"),
    ("Shopify",       "Sorry, this shop is currently unavailable"),
    ("Tumblr",        "Whatever you were looking for doesn't currently exist"),
    ("WordPress",     "Do you want to register"),
    ("Bitbucket",     "Repository not found"),
    ("Fastly",        "Fastly error: unknown domain"),
    ("Pantheon",      "The gods are wise"),
    ("Tilda",         "Please renew your subscription"),
    ("Surge.sh",      "project not found"),
    ("Unbounce",      "The requested URL was not found"),
    ("Ghost",         "Domain error"),
    ("Cargo",         "404 Not Found"),  # weak — combine with CNAME
    ("AWS S3",        "NoSuchBucket"),
    ("Azure",         "404 Web Site not found"),
]


def subdomain_takeover(target: str) -> dict:
    """Check a hostname for classic takeover fingerprints. Looks up the
    CNAME and inspects the body."""
    target = _domain_only(target)
    if not target:
        return {"error": "empty input"}
    res = dns.resolver.Resolver()
    res.lifetime = 6
    cname = None
    try:
        ans = res.resolve(target, "CNAME")
        cname = str(ans[0].target).rstrip(".")
    except Exception:
        pass
    out = {"target": target, "cname": cname}
    for scheme in ("http://", "https://"):
        try:
            r = requests.get(scheme + target, headers=HEADERS, timeout=10,
                              allow_redirects=False)
            body = (r.text or "")[:8000]
            for prov, sig in TAKEOVER_FINGERPRINTS:
                if sig.lower() in body.lower():
                    out["likely_takeover"] = True
                    out["provider"] = prov
                    out["signature"] = sig
                    out["status"] = r.status_code
                    return out
            out[f"{scheme}status"] = r.status_code
        except Exception as e:
            out[f"{scheme}error"] = str(e)[:100]
    out["likely_takeover"] = False
    return out


# ============== JARM-lite TLS fingerprint ==============

def tls_fingerprint(host: str, port: int = 443) -> dict:
    """Light TLS handshake fingerprint — captures protocol/cipher/cert
    chain length. Not a true JARM (no probe permutations) but useful."""
    host = _domain_only(host) or (host or "").strip()
    if not host:
        return {"error": "empty host"}
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((host, port), timeout=10) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                version = ssock.version()
                cipher = ssock.cipher()
                cert = ssock.getpeercert()
                der_chain = ssock.getpeercert(True)
        chain_size = len(der_chain) if der_chain else 0
    except Exception as e:
        return {"host": host, "error": str(e)}
    return {
        "host": host,
        "port": port,
        "tls_version": version,
        "cipher_suite": cipher[0] if cipher else None,
        "cipher_bits": cipher[2] if cipher else None,
        "cert_size_bytes": chain_size,
        "subject": dict((k, v) for tup in (cert.get("subject") or ())
                         for k, v in tup),
        "issuer": dict((k, v) for tup in (cert.get("issuer") or ())
                        for k, v in tup),
    }


# ============== MITRE ATT&CK ==============

def mitre_attack(technique_id: str) -> dict:
    """Look up an ATT&CK technique by ID (e.g. T1059) via the public
    MITRE STIX feed."""
    tid = (technique_id or "").strip().upper()
    if not re.match(r"^T\d{4}(\.\d{3})?$", tid):
        return {"error": "expected ATT&CK ID like T1059 or T1059.001"}
    # Use the lightweight web API mirror
    r = _get(f"https://attack.mitre.org/techniques/{tid.replace('.', '/')}/")
    if isinstance(r, Exception):
        return {"error": str(r)}
    if r.status_code != 200:
        return {"error": f"MITRE returned {r.status_code}"}
    soup = BeautifulSoup(r.text, "html.parser")
    title = (soup.find("h1") or {}).get_text(strip=True) if soup.find("h1") else None
    desc = (soup.find("div", class_="description-body") or
            soup.find("div", class_="description"))
    desc_text = desc.get_text(" ", strip=True)[:2000] if desc else ""
    cards = {}
    for card in soup.select(".card-data"):
        spans = card.find_all("span")
        if len(spans) >= 2:
            cards[spans[0].get_text(strip=True).rstrip(":").lower()] = \
                spans[-1].get_text(" ", strip=True)
    return {
        "id": tid,
        "url": r.url,
        "title": title,
        "description": desc_text,
        "metadata": cards,
    }


# ============== Wayback URL list (for an OSINT pivot) ==============

def wayback_urls(target: str, limit: int = 200) -> dict:
    """Just URL strings (no timestamps) — for hunting forgotten endpoints."""
    target = _domain_only(target)
    if not target:
        return {"error": "empty domain"}
    r = _get(
        f"https://web.archive.org/cdx/search/cdx?url={quote(target)}/*"
        f"&output=json&fl=original&collapse=urlkey&limit={limit}",
        timeout=45,
    )
    if isinstance(r, Exception):
        return {"error": str(r)}
    if r.status_code != 200:
        return {"error": f"wayback returned {r.status_code}"}
    try:
        rows = r.json()
    except Exception:
        return {"error": "non-json"}
    urls = sorted({row[0] for row in rows[1:] if row})
    return {"target": target, "count": len(urls), "urls": urls[:limit]}
