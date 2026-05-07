#!/usr/bin/env python3
"""
domain_scraper.py — multi-purpose domain audit scraper.

For each domain in the input file, collects:
  1. Subdomains  via crt.sh certificate transparency logs
  2. Set-Cookie  headers / browser cookies on the landing page
  3. Cookie / consent banner text found in the HTML
  4. Privacy / cookie policy links + a cleaned text excerpt of the page

Two backends:
  - default:   `requests` with realistic Chrome headers (fast, no JS)
  - --render:  Playwright + full Chromium + playwright-stealth
               (real JS, real TLS, patches navigator.webdriver and ~10
               other detection signals; surfaces JS-injected banners
               like OneTrust). Optional --proxy for IP-based bypass.

Output: a single CSV with one row per (input_domain, target) pair.

Usage:
    python3 domain_scraper.py domains.txt -o results.csv
    python3 domain_scraper.py domains.txt --no-subdomains -w 10
    python3 domain_scraper.py domains.txt --render -o real.csv
    python3 domain_scraper.py domains.txt --render --proxy http://user:pass@host:port
"""

import argparse
import csv
import glob
import json
import os
import re
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from urllib.parse import urljoin, urlparse

import requests
from bs4 import BeautifulSoup

UA = ("Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) "
      "Chrome/124.0.0.0 Safari/537.36")
HEADERS = {
    "User-Agent": UA,
    "Accept": ("text/html,application/xhtml+xml,application/xml;q=0.9,"
               "image/avif,image/webp,image/apng,*/*;q=0.8"),
    "Accept-Language": "en-US,en;q=0.9",
    "Accept-Encoding": "gzip, deflate, br",
    "Sec-Ch-Ua": '"Chromium";v="124", "Google Chrome";v="124", "Not-A.Brand";v="99"',
    "Sec-Ch-Ua-Mobile": "?0",
    "Sec-Ch-Ua-Platform": '"Linux"',
    "Sec-Fetch-Dest": "document",
    "Sec-Fetch-Mode": "navigate",
    "Sec-Fetch-Site": "none",
    "Sec-Fetch-User": "?1",
    "Upgrade-Insecure-Requests": "1",
    "DNT": "1",
}
TIMEOUT = 15
RENDER_TIMEOUT_MS = 30000
RENDER_WAIT_MS = 5000  # post-load settle time for JS-injected banners + CMP iframes
BANNER_RE = re.compile(
    # narrow: real cookie/consent signals + named CMP vendor classes only.
    # Avoid generic terms like "banner", "notice", "tracking" — they
    # produce false positives (marketing heroes, promo strips).
    r"(cookie|consent|gdpr|ccpa|"
    r"onetrust|optanon|cookielaw|"
    r"cookiebot|"
    r"qc-cmp|"
    r"sp_message|sp-message|sourcepoint|"
    r"truste|trustarc|"
    r"usercentrics|uc-banner|"
    r"didomi|osano)",
    re.I,
)
# Frame URL patterns for third-party Consent Management Platforms (CMPs).
# When --render is on, we also scrape banner text from any iframe whose URL
# matches one of these — that's where modern sites put their consent UI.
CMP_FRAME_RE = re.compile(
    r"(privacy-mgmt\.com|sourcepoint|"
    r"cookielaw\.org|onetrust|"
    r"consent\.cookiebot\.com|cookiebot|"
    r"consent\.trustarc\.com|trustarc|"
    r"quantcast\.mgr\.consensu\.org|qc-cmp|"
    r"app\.usercentrics\.eu|usercentrics|"
    r"sdk\.privacy-center\.org|didomi|"
    r"cmp\.osano\.com|osano)",
    re.I,
)
SUBDOMAIN_CAP = 25


# --------- shared HTML parsers ----------

def extract_banner(html):
    soup = BeautifulSoup(html, "html.parser")
    hits = []
    for tag in soup.find_all(["div", "section", "aside", "footer"]):
        cls = tag.get("class") or []
        attrs = " ".join([tag.get("id", ""), " ".join(cls)]).lower()
        if BANNER_RE.search(attrs):
            text = tag.get_text(" ", strip=True)
            if 20 < len(text) < 2000:
                hits.append(text)
                if len(hits) >= 3:
                    break
    return " | ".join(hits)


def extract_privacy_links(base_url, html):
    soup = BeautifulSoup(html, "html.parser")
    found = set()
    for a in soup.find_all("a", href=True):
        text = (a.get_text() or "").lower()
        href = a["href"]
        if any(k in text for k in ("privacy", "cookie", "gdpr")) or \
           any(k in href.lower() for k in ("privacy", "cookie", "gdpr")):
            found.add(urljoin(base_url, href))
    return sorted(found)[:5]


def clean_text(html, max_len=1000):
    soup = BeautifulSoup(html, "html.parser")
    for tag in soup(["script", "style", "noscript"]):
        tag.decompose()
    text = re.sub(r"\s+", " ", soup.get_text(" ", strip=True))
    return text[:max_len]


# --------- subdomain enumeration ----------

def crtsh_subdomains(domain, timeout=30):
    try:
        r = requests.get(
            f"https://crt.sh/?q=%25.{domain}&output=json",
            timeout=timeout,
            headers=HEADERS,
        )
        if r.status_code != 200 or not r.text.strip():
            return []
        seen = set()
        for entry in r.json():
            for name in entry.get("name_value", "").splitlines():
                name = name.strip().lower().lstrip("*.")
                if name.endswith(domain) and "@" not in name:
                    seen.add(name)
        return sorted(seen)
    except Exception:
        return []


# --------- requests backend ----------

def fetch(url, timeout=TIMEOUT):
    try:
        return requests.get(url, timeout=timeout, headers=HEADERS,
                            allow_redirects=True)
    except Exception:
        return None


def collect_cookies_requests(resp):
    return [{
        "name": c.name, "domain": c.domain, "path": c.path,
        "secure": c.secure, "expires": c.expires,
    } for c in resp.cookies]


def audit_target_requests(input_domain, target):
    for scheme in ("https", "http"):
        url = f"{scheme}://{target}"
        r = fetch(url)
        if r is None:
            continue
        html = r.text or ""
        cookies = collect_cookies_requests(r)
        return {
            "input_domain": input_domain,
            "target": target,
            "final_url": r.url,
            "status": r.status_code,
            "server": r.headers.get("Server", ""),
            "cookie_count": len(cookies),
            "set_cookies": json.dumps(cookies, default=str),
            "banner_text": extract_banner(html)[:1500],
            "privacy_links": "; ".join(extract_privacy_links(url, html)),
            "clean_text_excerpt": clean_text(html, max_len=1000),
            "backend": "requests",
        }
    return None


# --------- playwright backend ----------

def extract_banner_from_frames(page):
    """Scan iframes for known Consent Management Platforms and pull
    banner text from any that match. Returns ' | '-joined snippets."""
    hits = []
    for fr in page.frames:
        try:
            url = fr.url or ""
        except Exception:
            continue
        if not url or url == "about:blank":
            continue
        if not CMP_FRAME_RE.search(url):
            continue
        try:
            text = fr.evaluate(
                "() => document.body ? document.body.innerText : ''"
            ) or ""
        except Exception:
            continue
        text = re.sub(r"\s+", " ", text).strip()
        if 20 < len(text) < 2000:
            hits.append(text)
        if len(hits) >= 3:
            break
    return " | ".join(hits)


def audit_target_browser(input_domain, target, context):
    """Use a Playwright browser context to fetch with real JS + TLS."""
    for scheme in ("https", "http"):
        url = f"{scheme}://{target}"
        page = context.new_page()
        try:
            try:
                resp = page.goto(url, timeout=RENDER_TIMEOUT_MS,
                                 wait_until="domcontentloaded")
            except Exception:
                page.close()
                continue
            if resp is None:
                page.close()
                continue
            # let JS-injected banners + CMP iframes settle
            try:
                page.wait_for_timeout(RENDER_WAIT_MS)
            except Exception:
                pass
            html = page.content()
            final_url = page.url
            status = resp.status
            server = ""
            try:
                server = (resp.headers or {}).get("server", "")
            except Exception:
                pass
            cookies_raw = context.cookies()
            cookies = [{
                "name": c.get("name"), "domain": c.get("domain"),
                "path": c.get("path"), "secure": c.get("secure"),
                "expires": c.get("expires"),
            } for c in cookies_raw]

            banner_main = extract_banner(html)
            banner_iframe = extract_banner_from_frames(page)
            banner = " | ".join(b for b in (banner_main, banner_iframe) if b)

            page.close()
            try:
                context.clear_cookies()
            except Exception:
                pass
            return {
                "input_domain": input_domain,
                "target": target,
                "final_url": final_url,
                "status": status,
                "server": server,
                "cookie_count": len(cookies),
                "set_cookies": json.dumps(cookies, default=str),
                "banner_text": banner[:1500],
                "privacy_links": "; ".join(extract_privacy_links(url, html)),
                "clean_text_excerpt": clean_text(html, max_len=1000),
                "backend": "playwright",
            }
        except Exception:
            try:
                page.close()
            except Exception:
                pass
            continue
    return None


# --------- per-domain orchestration ----------

def audit_domain_requests(domain, do_subdomains=True):
    rows = []
    targets = [domain]
    if do_subdomains:
        for s in crtsh_subdomains(domain)[:SUBDOMAIN_CAP]:
            if s != domain and s not in targets:
                targets.append(s)
    for t in targets:
        row = audit_target_requests(domain, t)
        if row:
            rows.append(row)
    return rows


def find_full_chromium():
    """Locate the full Chromium binary (not headless-shell) in the
    Playwright cache. Returns None if only the shell is available."""
    cache = Path.home() / ".cache" / "ms-playwright"
    candidates = sorted(glob.glob(str(cache / "chromium-*" / "chrome-linux64" / "chrome")))
    return candidates[-1] if candidates else None


def parse_proxy(proxy_url):
    """Convert a proxy URL string to Playwright's proxy dict.
    Accepts http://user:pass@host:port, socks5://host:port, etc."""
    if not proxy_url:
        return None
    u = urlparse(proxy_url)
    out = {"server": f"{u.scheme}://{u.hostname}:{u.port}" if u.port else f"{u.scheme}://{u.hostname}"}
    if u.username:
        out["username"] = u.username
    if u.password:
        out["password"] = u.password
    return out


def audit_all_browser(domains, do_subdomains=True, log=print, proxy=None):
    """Sequential Playwright pass over every domain.
    Uses full Chromium (not headless-shell) + playwright-stealth."""
    from playwright.sync_api import sync_playwright
    from playwright_stealth import Stealth

    full_chromium = find_full_chromium()
    launch_kwargs = {"headless": True}
    if full_chromium:
        launch_kwargs["executable_path"] = full_chromium
        launch_kwargs["args"] = ["--headless=new"]
        log(f"[render] using full Chromium at {full_chromium}", file=sys.stderr)
    else:
        log("[render] WARNING: full Chromium not found, falling back to headless-shell "
            "(more detectable). Run: playwright install chromium --no-shell",
            file=sys.stderr)
    px = parse_proxy(proxy)
    if px:
        launch_kwargs["proxy"] = px
        log(f"[render] proxy: {px['server']}", file=sys.stderr)

    rows = []
    stealth = Stealth(navigator_user_agent_override=UA)
    with stealth.use_sync(sync_playwright()) as p:
        browser = p.chromium.launch(**launch_kwargs)
        context = browser.new_context(
            user_agent=UA,
            locale="en-US",
            viewport={"width": 1366, "height": 768},
            extra_http_headers={
                "Accept-Language": "en-US,en;q=0.9",
                "DNT": "1",
            },
        )
        try:
            for domain in domains:
                targets = [domain]
                if do_subdomains:
                    for s in crtsh_subdomains(domain)[:SUBDOMAIN_CAP]:
                        if s != domain and s not in targets:
                            targets.append(s)
                for t in targets:
                    row = audit_target_browser(domain, t, context)
                    if row:
                        rows.append(row)
                log(f"[+] {domain} done ({sum(1 for r in rows if r['input_domain']==domain)} rows)",
                    file=sys.stderr)
        finally:
            context.close()
            browser.close()
    return rows


# --------- main ----------

def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("input", help="text file with one domain per line")
    ap.add_argument("-o", "--output", default="scrape_results.csv")
    ap.add_argument("-w", "--workers", type=int, default=5,
                    help="parallel workers (requests backend only; render runs sequentially)")
    ap.add_argument("--no-subdomains", action="store_true",
                    help="skip crt.sh subdomain enumeration")
    ap.add_argument("--render", action="store_true",
                    help="use Playwright + full Chromium + stealth (real JS, slower, ~3-5s/page)")
    ap.add_argument("--proxy", default=None,
                    help="proxy URL for --render mode, e.g. http://user:pass@host:port "
                         "or socks5://host:port (env PROXY also honored)")
    args = ap.parse_args()
    proxy = args.proxy or os.environ.get("PROXY")

    with open(args.input) as f:
        domains = [line.strip() for line in f
                   if line.strip() and not line.lstrip().startswith("#")]

    fields = [
        "input_domain", "target", "final_url", "status", "server",
        "cookie_count", "set_cookies",
        "banner_text", "privacy_links", "clean_text_excerpt", "backend",
    ]

    rows = []
    if args.render:
        print("[render] using Playwright + Chromium + stealth (sequential)", file=sys.stderr)
        rows = audit_all_browser(domains,
                                 do_subdomains=not args.no_subdomains,
                                 proxy=proxy)
    else:
        with ThreadPoolExecutor(max_workers=args.workers) as ex:
            futs = {
                ex.submit(audit_domain_requests, d, not args.no_subdomains): d
                for d in domains
            }
            for fut in as_completed(futs):
                d = futs[fut]
                try:
                    domain_rows = fut.result()
                    rows.extend(domain_rows)
                    print(f"[+] {d} done ({len(domain_rows)} rows)", file=sys.stderr)
                except Exception as e:
                    print(f"[!] {d}: {e}", file=sys.stderr)

    with open(args.output, "w", newline="", encoding="utf-8") as out:
        writer = csv.DictWriter(out, fieldnames=fields, quoting=csv.QUOTE_ALL)
        writer.writeheader()
        for row in rows:
            writer.writerow(row)

    print(f"\nWrote {len(rows)} rows to {args.output}", file=sys.stderr)


if __name__ == "__main__":
    main()
