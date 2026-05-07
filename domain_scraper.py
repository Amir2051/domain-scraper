#!/usr/bin/env python3
"""
domain_scraper.py — multi-purpose domain audit scraper.

For each domain in the input file, collects:
  1. Subdomains  via crt.sh certificate transparency logs
  2. Set-Cookie  headers returned on the landing page
  3. Cookie / consent banner text found in the HTML
  4. Privacy / cookie policy links + a cleaned text excerpt of the page

Output: a single CSV with one row per (input_domain, target) pair.

Usage:
    python3 domain_scraper.py domains.txt -o results.csv
    python3 domain_scraper.py domains.txt --no-subdomains -w 10
"""

import argparse
import csv
import json
import re
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urljoin

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
BANNER_RE = re.compile(r"(cookie|consent|gdpr|ccpa|privacy|tracking)", re.I)
SUBDOMAIN_CAP = 25  # safety cap per input domain


def crtsh_subdomains(domain, timeout=30):
    """Public certificate-transparency lookup. Returns sorted unique list."""
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


def fetch(url, timeout=TIMEOUT):
    try:
        return requests.get(
            url,
            timeout=timeout,
            headers=HEADERS,
            allow_redirects=True,
        )
    except Exception:
        return None


def collect_cookies(resp):
    out = []
    for c in resp.cookies:
        out.append({
            "name": c.name,
            "domain": c.domain,
            "path": c.path,
            "secure": c.secure,
            "expires": c.expires,
        })
    return out


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


def audit_target(input_domain, target):
    """Returns one CSV row dict, or None if target unreachable."""
    for scheme in ("https", "http"):
        url = f"{scheme}://{target}"
        r = fetch(url)
        if r is None:
            continue
        html = r.text or ""
        cookies = collect_cookies(r)
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
        }
    return None


def audit_domain(domain, do_subdomains=True):
    rows = []
    targets = [domain]
    if do_subdomains:
        for s in crtsh_subdomains(domain)[:SUBDOMAIN_CAP]:
            if s != domain and s not in targets:
                targets.append(s)
    for t in targets:
        row = audit_target(domain, t)
        if row:
            rows.append(row)
    return rows


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("input", help="text file with one domain per line")
    ap.add_argument("-o", "--output", default="scrape_results.csv")
    ap.add_argument("-w", "--workers", type=int, default=5)
    ap.add_argument("--no-subdomains", action="store_true",
                    help="skip crt.sh subdomain enumeration")
    args = ap.parse_args()

    with open(args.input) as f:
        domains = [
            line.strip() for line in f
            if line.strip() and not line.lstrip().startswith("#")
        ]

    fields = [
        "input_domain", "target", "final_url", "status", "server",
        "cookie_count", "set_cookies",
        "banner_text", "privacy_links", "clean_text_excerpt",
    ]

    written = 0
    with open(args.output, "w", newline="", encoding="utf-8") as out:
        writer = csv.DictWriter(out, fieldnames=fields,
                                quoting=csv.QUOTE_ALL)
        writer.writeheader()
        with ThreadPoolExecutor(max_workers=args.workers) as ex:
            futs = {
                ex.submit(audit_domain, d, not args.no_subdomains): d
                for d in domains
            }
            for fut in as_completed(futs):
                d = futs[fut]
                try:
                    for row in fut.result():
                        writer.writerow(row)
                        written += 1
                    print(f"[+] {d} done", file=sys.stderr)
                except Exception as e:
                    print(f"[!] {d}: {e}", file=sys.stderr)

    print(f"\nWrote {written} rows to {args.output}", file=sys.stderr)


if __name__ == "__main__":
    main()
