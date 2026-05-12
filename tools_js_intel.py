#!/usr/bin/env python3
"""
tools_js_intel.py — JavaScript intelligence for a target website.

Fetches the target's homepage, then for each external script (and the
inline scripts on the page itself) extracts:

  * tracking IDs — Google Analytics (UA / GA4 / GTM), Meta Pixel,
    Hotjar, Mixpanel, Segment, AdSense, Stripe public, HubSpot,
    Intercom, reCAPTCHA, Cloudflare beacon
  * wallet references — ETH and TRON aggressively; BTC and SOL only
    when a wallet-context word is in the surrounding text (these
    encodings overlap too much with normal base58 strings otherwise)
  * Web3 integration markers — window.ethereum, walletConnect,
    MetaMask, coinbaseWallet, ethers.js, phantom.solana, …
  * suspicious patterns — eval(), Function() constructor, large
    atob() payloads, document.write, packed `\\xHH` sequences
  * hidden third-party API URLs (absolute http(s) URLs not on the
    target's own host or on a known CDN-noise list)

Result is structured so each per-script record carries a SHA-256 of
its body — Phase-1 graph ingestion will key cross-domain correlation
("the same minified JS lives on these N domains") off that hash.

Module #1 of SAFENESTT 2099. Lawful, passive, read-only — no
deobfuscation, no JS execution, no payload extraction.
"""
from __future__ import annotations

import hashlib
import re
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urljoin, urlparse

from bs4 import BeautifulSoup

from safenest.http import DEFAULT_HEADERS as HEADERS, DEFAULT_UA as UA, make_client
import tools_graph

TIMEOUT = 12
_get, _ = make_client(timeout=TIMEOUT)

MAX_EXTERNAL_SCRIPTS = 40
MAX_SCRIPT_BYTES = 300_000
MAX_INLINE_BYTES = 300_000
FETCH_WORKERS = 10

# ----- tracking-ID regexes ---------------------------------------------
# group(1) is the ID where the regex has a capturing group, otherwise
# the entire match becomes the ID.
TRACKING_PATTERNS: list[tuple[str, re.Pattern]] = [
    ("ga_universal",       re.compile(r"\bUA-\d{4,10}-\d+\b")),
    ("ga4",                re.compile(r"\bG-[A-Z0-9]{8,12}\b")),
    ("gtm",                re.compile(r"\bGTM-[A-Z0-9]{4,10}\b")),
    ("meta_pixel",         re.compile(r"fbq\(\s*['\"]init['\"]\s*,\s*['\"](\d{10,17})['\"]")),
    ("meta_pixel_url",     re.compile(r"facebook\.com/tr\?id=(\d{10,17})")),
    ("hotjar",             re.compile(r"hjid\s*[:=]\s*(\d{4,10})")),
    ("mixpanel",           re.compile(r"mixpanel\.init\(\s*['\"]([a-f0-9]{32})['\"]")),
    ("segment",            re.compile(r"analytics\.load\(\s*['\"]([A-Za-z0-9]{10,32})['\"]")),
    ("adsense",            re.compile(r"\bca-pub-\d{10,20}\b")),
    ("stripe_pk",          re.compile(r"\bpk_(?:live|test)_[A-Za-z0-9]{20,99}\b")),
    ("cloudflare_beacon",  re.compile(r"static\.cloudflareinsights\.com/beacon\.min\.js")),
    ("recaptcha_site_key", re.compile(r"recaptcha/api\.js\?render=([A-Za-z0-9_-]{30,})")),
    ("hubspot",            re.compile(r"//js\.hs-scripts\.com/(\d+)\.js")),
    ("intercom",           re.compile(r"intercomSettings[^;{}]*app_id\s*:\s*['\"]([A-Za-z0-9]{6,12})['\"]")),
    ("crisp",              re.compile(r"CRISP_WEBSITE_ID\s*=\s*['\"]([a-f0-9-]{36})['\"]")),
    ("tawk_to",            re.compile(r"embed\.tawk\.to/([a-f0-9]{24})/")),
]

# ----- wallet refs -----------------------------------------------------
ETH_REF      = re.compile(r"\b(0x[a-fA-F0-9]{40})\b")
TRON_REF     = re.compile(r"\b(T[1-9A-HJ-NP-Za-km-z]{33})\b")
BTC_REF_BARE = re.compile(r"\b((?:bc1[0-9ac-hj-np-z]{8,80})|(?:[13][a-km-zA-HJ-NP-Z1-9]{25,34}))\b")
SOL_REF_BARE = re.compile(r"\b([1-9A-HJ-NP-Za-km-z]{32,44})\b")
CONTEXT_BTC  = re.compile(r"\b(btc|bitcoin|wallet|address)\b", re.IGNORECASE)
CONTEXT_SOL  = re.compile(r"\b(sol|solana|phantom)\b", re.IGNORECASE)

# ----- Web3 markers ----------------------------------------------------
WEB3_MARKERS: list[str] = [
    "window.ethereum", "ethereum.request", "web3.eth",
    "WalletConnect", "walletconnect", "@walletconnect",
    "MetaMask", "metamask", "coinbaseWallet", "trustwallet",
    "phantom.solana", "solflare", "ethers.js", "ethers.providers",
    "wagmi", "viem.createPublicClient",
]

# ----- suspicious patterns ---------------------------------------------
SUSPICIOUS_PATTERNS: list[tuple[str, re.Pattern]] = [
    ("eval_call",            re.compile(r"(?<!['\"])\beval\s*\(")),
    ("function_constructor", re.compile(r"\bnew\s+Function\s*\(\s*['\"]")),
    ("atob_large_payload",   re.compile(r"\batob\s*\(\s*['\"][A-Za-z0-9+/=]{160,}['\"]")),
    ("document_write",       re.compile(r"document\.write\s*\(")),
    ("hex_packed",           re.compile(r"\\x[0-9a-f]{2}\\x[0-9a-f]{2}\\x[0-9a-f]{2}\\x[0-9a-f]{2}", re.IGNORECASE)),
    ("unicode_packed",       re.compile(r"\\u[0-9a-f]{4}\\u[0-9a-f]{4}\\u[0-9a-f]{4}\\u[0-9a-f]{4}", re.IGNORECASE)),
]

# Hosts whose presence in third-party URL lists adds no investigation
# value — purely CDN/font/library traffic.
CDN_NOISE_HOSTS = {
    "cdnjs.cloudflare.com", "cdn.jsdelivr.net", "unpkg.com",
    "ajax.googleapis.com", "fonts.googleapis.com", "fonts.gstatic.com",
    "cdn.tailwindcss.com", "polyfill.io", "esm.sh",
    "code.jquery.com", "stackpath.bootstrapcdn.com",
}

# absolute http(s) URLs in script bodies
URL_RE = re.compile(r"\bhttps?://[A-Za-z0-9._\-~%:/?#\[\]@!$&'()*+,;=]+")


def _hostof(u: str) -> str:
    try:
        return (urlparse(u).hostname or "").lower()
    except Exception:
        return ""


def _norm_url(s: str) -> str:
    s = (s or "").strip()
    if not s:
        return ""
    if "://" not in s:
        s = "https://" + s.lstrip("/")
    return s


def _extract_tracking(text: str) -> list[dict]:
    found, seen = [], set()
    for kind, pat in TRACKING_PATTERNS:
        for m in pat.finditer(text):
            v = m.group(1) if m.lastindex else m.group(0)
            key = (kind, v)
            if key in seen:
                continue
            seen.add(key)
            found.append({"kind": kind, "id": v})
    return found


def _extract_wallets(text: str) -> dict:
    out = {"eth": [], "tron": [], "btc": [], "sol": []}
    seen = set()

    for m in ETH_REF.finditer(text):
        v = m.group(1)
        if v.lower() in seen:
            continue
        seen.add(v.lower())
        out["eth"].append(v)

    for m in TRON_REF.finditer(text):
        v = m.group(1)
        if v in seen:
            continue
        seen.add(v)
        out["tron"].append(v)

    # BTC / SOL: only emit when a context word is within ±50 chars,
    # otherwise the false-positive rate on base58 strings is huge.
    for m in BTC_REF_BARE.finditer(text):
        v = m.group(1)
        if v in seen:
            continue
        s, e = max(0, m.start() - 50), min(len(text), m.end() + 50)
        if CONTEXT_BTC.search(text[s:e]):
            seen.add(v)
            out["btc"].append(v)

    for m in SOL_REF_BARE.finditer(text):
        v = m.group(1)
        if v in seen or len(v) < 32:
            continue
        s, e = max(0, m.start() - 50), min(len(text), m.end() + 50)
        ctx = text[s:e]
        # SOL is the noisiest of the four — require both context AND
        # the absence of an ETH/TRON match in the same window (those
        # are higher-precision encodings of the same byte space).
        if CONTEXT_SOL.search(ctx) and not ETH_REF.search(ctx):
            seen.add(v)
            out["sol"].append(v)

    return out


def _extract_web3(text: str) -> list[str]:
    return [m for m in WEB3_MARKERS if m in text]


def _extract_suspicious(text: str) -> list[str]:
    return [name for name, pat in SUSPICIOUS_PATTERNS if pat.search(text)]


def _extract_api_urls(text: str, base_host: str, limit: int = 30) -> list[str]:
    seen, out = set(), []
    for m in URL_RE.finditer(text):
        u = m.group(0).rstrip(".,;'\"")
        h = _hostof(u)
        if not h or h == base_host or h in CDN_NOISE_HOSTS:
            continue
        if u in seen:
            continue
        seen.add(u)
        out.append(u)
        if len(out) >= limit:
            break
    return out


def _fetch_one_script(src_url: str) -> dict:
    r = _get(src_url)
    if isinstance(r, Exception):
        return {"src": src_url, "error": f"network: {r}"}
    if r.status_code != 200:
        return {"src": src_url, "error": f"HTTP {r.status_code}"}
    body = r.text or ""
    truncated = False
    if len(body.encode("utf-8", errors="ignore")) > MAX_SCRIPT_BYTES:
        body = body[: MAX_SCRIPT_BYTES // 2]
        truncated = True
    sha = hashlib.sha256(body.encode("utf-8", errors="ignore")).hexdigest()
    return {
        "src": src_url,
        "host": _hostof(src_url),
        "size": len(body),
        "sha256": sha,
        "body": body,
        "truncated": truncated,
    }


def js_analyze(target: str, fetch_external: str = "1",
               max_scripts: int = MAX_EXTERNAL_SCRIPTS,
               persist_to_graph: str = "1") -> dict:
    """Main entry-point. Returns a fully aggregated intelligence dict.

    fetch_external: pass "0" / "false" / "" to skip downloading external
    scripts (in which case only the inline scripts on the homepage are
    scanned). Coerced from string because the web UI ships form values
    as strings.

    persist_to_graph: when truthy (default), the extracted artifacts are
    written to the local link-intelligence graph and a correlation query
    is run to surface OTHER domains in the graph that share any tracking
    ID, script SHA-256, or wallet reference with this scan."""
    url = _norm_url(target)
    if not url:
        return {"error": "empty target"}
    base_host = _hostof(url)

    page = _get(url)
    if isinstance(page, Exception):
        return {"error": f"network: {page}"}
    if page.status_code >= 400:
        return {"error": f"page HTTP {page.status_code}"}

    soup = BeautifulSoup(page.text or "", "html.parser")
    page_text = page.text or ""

    fetch_flag = str(fetch_external).lower() not in ("0", "false", "no", "off", "")
    try:
        max_scripts_n = max(1, min(MAX_EXTERNAL_SCRIPTS, int(max_scripts) if max_scripts else MAX_EXTERNAL_SCRIPTS))
    except Exception:
        max_scripts_n = MAX_EXTERNAL_SCRIPTS

    external_urls: list[str] = []
    inline_bodies: list[str] = []
    for tag in soup.find_all("script"):
        src = tag.get("src")
        if src:
            external_urls.append(urljoin(url, src))
        else:
            body = tag.string or ""
            if body.strip():
                if len(body.encode("utf-8", errors="ignore")) > MAX_INLINE_BYTES:
                    body = body[: MAX_INLINE_BYTES // 2]
                inline_bodies.append(body)

    external_urls = list(dict.fromkeys(external_urls))[:max_scripts_n]

    script_records: list[dict] = []
    if fetch_flag and external_urls:
        with ThreadPoolExecutor(max_workers=FETCH_WORKERS) as ex:
            futures = {ex.submit(_fetch_one_script, s): s for s in external_urls}
            for fu in as_completed(futures):
                script_records.append(fu.result())

    # per-script analysis
    per_script: list[dict] = []
    for rec in script_records:
        if "body" not in rec:
            per_script.append({
                "src": rec.get("src"),
                "host": _hostof(rec.get("src", "")),
                "error": rec.get("error"),
            })
            continue
        body = rec["body"]
        per_script.append({
            "src": rec["src"],
            "host": rec["host"],
            "size": rec["size"],
            "sha256": rec["sha256"],
            "truncated": rec.get("truncated", False),
            "tracking_ids": _extract_tracking(body),
            "wallet_refs": _extract_wallets(body),
            "web3_markers": _extract_web3(body),
            "suspicious_markers": _extract_suspicious(body),
            "third_party_urls": _extract_api_urls(body, base_host),
        })

    # The page itself often carries tracking IDs in inline <script> blocks
    # and even in markup data-attrs, so scan the full HTML for them too.
    inline_joined = "\n".join(inline_bodies)
    page_scan_text = page_text + "\n" + inline_joined
    inline_intel = {
        "count": len(inline_bodies),
        "total_size": sum(len(b) for b in inline_bodies),
        "tracking_ids":      _extract_tracking(page_scan_text),
        "wallet_refs":       _extract_wallets(page_scan_text),
        "web3_markers":      _extract_web3(page_scan_text),
        "suspicious_markers": _extract_suspicious(page_scan_text),
        "third_party_urls":  _extract_api_urls(page_scan_text, base_host),
    }

    # aggregate
    agg_tracking: list[dict] = []
    agg_eth: list[str] = []
    agg_tron: list[str] = []
    agg_btc: list[str] = []
    agg_sol: list[str] = []
    agg_web3: list[str] = []
    agg_susp: list[str] = []
    agg_third: list[str] = []
    seen_t, seen_w, seen_w3, seen_s, seen_u = set(), set(), set(), set(), set()

    def _push_tracking(items):
        for it in items:
            key = (it["kind"], it["id"])
            if key in seen_t:
                continue
            seen_t.add(key)
            agg_tracking.append(it)

    def _push_wallets(d):
        for v in d.get("eth", []):
            if v.lower() in seen_w:
                continue
            seen_w.add(v.lower()); agg_eth.append(v)
        for v in d.get("tron", []):
            if v in seen_w:
                continue
            seen_w.add(v); agg_tron.append(v)
        for v in d.get("btc", []):
            if v in seen_w:
                continue
            seen_w.add(v); agg_btc.append(v)
        for v in d.get("sol", []):
            if v in seen_w:
                continue
            seen_w.add(v); agg_sol.append(v)

    def _push_list(values, seen, out):
        for v in values:
            if v in seen:
                continue
            seen.add(v); out.append(v)

    _push_tracking(inline_intel["tracking_ids"])
    _push_wallets(inline_intel["wallet_refs"])
    _push_list(inline_intel["web3_markers"], seen_w3, agg_web3)
    _push_list(inline_intel["suspicious_markers"], seen_s, agg_susp)
    _push_list(inline_intel["third_party_urls"], seen_u, agg_third)

    for ps in per_script:
        _push_tracking(ps.get("tracking_ids", []))
        _push_wallets(ps.get("wallet_refs", {}))
        _push_list(ps.get("web3_markers", []), seen_w3, agg_web3)
        _push_list(ps.get("suspicious_markers", []), seen_s, agg_susp)
        _push_list(ps.get("third_party_urls", []), seen_u, agg_third)

    # third-party host frequency
    host_count: dict[str, int] = {}
    for u in agg_third:
        h = _hostof(u)
        if h:
            host_count[h] = host_count.get(h, 0) + 1
    third_party_hosts = sorted(
        ({"host": h, "url_count": c} for h, c in host_count.items()),
        key=lambda x: -x["url_count"],
    )

    out = {
        "target": url,
        "host": base_host,
        "page_status": page.status_code,
        "external_scripts_total": len(external_urls),
        "external_scripts_fetched": sum(1 for r in script_records if "body" in r),
        "inline_scripts": inline_intel["count"],
        "inline_total_size": inline_intel["total_size"],
        "tracking_ids": agg_tracking,
        "tracking_id_count": len(agg_tracking),
        "wallet_refs": {
            "eth":  agg_eth,
            "tron": agg_tron,
            "btc":  agg_btc,
            "sol":  agg_sol,
        },
        "wallet_ref_count": len(agg_eth) + len(agg_tron) + len(agg_btc) + len(agg_sol),
        "web3_detected": bool(agg_web3),
        "web3_markers": agg_web3,
        "suspicious_markers": agg_susp,
        "third_party_urls": agg_third,
        "third_party_hosts": third_party_hosts,
        "scripts": per_script,
    }

    # Link-intelligence: write to the graph and look up other domains
    # that share any of these signals. Off by default for ad-hoc scans
    # that the analyst doesn't want polluting the investigation corpus.
    persist = str(persist_to_graph).lower() not in ("0", "false", "no", "off", "")
    if persist:
        try:
            ingest_stats = tools_graph.ingest_js_intel(base_host, out)
        except Exception as e:
            ingest_stats = {"error": f"ingest: {type(e).__name__}: {e}"}
        try:
            corr = tools_graph.find_correlations(
                base_host,
                tracking_ids=agg_tracking,
                scripts=[{"sha256": s.get("sha256"), "src": s.get("src"),
                          "host": s.get("host")}
                         for s in per_script if s.get("sha256")],
                wallets=out["wallet_refs"],
            )
        except Exception as e:
            corr = {"error": f"correlate: {type(e).__name__}: {e}"}
        out["graph_ingest"] = ingest_stats
        out["correlations"] = corr
    else:
        out["graph_ingest"] = {"skipped": True}
        out["correlations"] = {"skipped": True}

    return out
