# domain-scraper

Multi-purpose domain audit scraper. For each domain in a list, collects:

1. Subdomains via [crt.sh](https://crt.sh) certificate transparency
2. Cookies set by the landing page (HTTP `Set-Cookie` or browser cookies)
3. Cookie / consent banner text scraped from the HTML
4. Privacy / cookie policy links + a cleaned text excerpt of the page

Two backends:

- **default (`requests`)** — fast, no JS, realistic Chrome 124 headers + Brotli.
  Beats basic UA-sniffing bot filters.
- **`--render`** — Playwright + full Chromium + `playwright-stealth`.
  Real JS execution, real TLS, patches `navigator.webdriver` and ~10 other
  detection signals. Surfaces JS-injected cookie banners (OneTrust,
  Cookiebot, Mozilla's CCPA banner, etc.) that the `requests` mode misses.

## Install

```bash
pip install -r requirements.txt
# only needed if you want --render mode:
playwright install chromium
```

## Use

```bash
# fast, requests-based
python3 domain_scraper.py domains.txt -o results.csv
python3 domain_scraper.py domains.txt --no-subdomains -w 10

# real-browser rendering (slower, ~3-5s/page, runs sequentially)
python3 domain_scraper.py domains.txt --render -o real.csv

# behind a proxy (HTTP or SOCKS5)
python3 domain_scraper.py domains.txt --render \
    --proxy http://user:pass@proxy.example.com:8080
PROXY=socks5://127.0.0.1:9050 python3 domain_scraper.py domains.txt --render
```

Input: one domain per line, no scheme. Lines starting with `#` are ignored.
Output: a CSV with one row per `(input_domain, target)` pair.

## Output columns

| column | meaning |
|---|---|
| `input_domain` | domain as given in input file |
| `target` | the actual host queried (input domain or a subdomain from crt.sh) |
| `final_url` | URL after redirects |
| `status` | HTTP status code |
| `server` | `Server` response header |
| `cookie_count` | number of cookies the response set |
| `set_cookies` | JSON of cookie `{name, domain, path, secure, expires}` |
| `banner_text` | text scraped from cookie/consent banner-like elements |
| `privacy_links` | `;`-separated list of privacy/cookie policy URLs found on the page |
| `clean_text_excerpt` | up to 1000 chars of cleaned visible text |

## Limits

- **`requests` mode**: no JS execution. JS-injected banners (OneTrust etc.)
  won't show up. Use `--render` for those.
- **`--render` mode**: still won't beat hardened enterprise bot management
  (Akamai Bot Manager, Cloudflare Turnstile interactive challenges) or
  real CAPTCHAs. For those, supply a residential proxy via `--proxy`, or
  use a commercial unblocker service.
- crt.sh subdomains capped at 25 per input domain.
- Default 15s HTTP timeout, 30s for crt.sh, 30s for browser navigation.

## Use responsibly

This tool collects data from publicly reachable URLs and a public CT log.
Bypassing bot protection on sites you don't own and don't have permission
to audit is a legal grey-to-black zone in most jurisdictions. Stick to
your own assets, in-scope bug-bounty targets, or clearly public research.
