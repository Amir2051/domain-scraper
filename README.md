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

# slow proxy / tor — bump the post-load wait so JS-injected CMP iframes finish
python3 domain_scraper.py domains.txt --render \
    --proxy socks5://127.0.0.1:9050 --render-wait 15000
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

## Web UI (`webui.py`)

Optional Flask dashboard wrapping the scraper plus **70+** recon / OSINT
/ threat / cyber / social tools across these tabs:

| Tab | What's in it |
|---|---|
| **Scraper**     | The original cookie/banner/privacy-link audit |
| **Recon**       | WHOIS, DNS, IP geo, reverse IP, ASN/BGP |
| **HTTP / TLS**  | Security-header grade, TLS cert dump, robots.txt + sitemap.xml |
| **OSINT**       | Wayback, multi-source subdomains, email harvest, GitHub user, HIBP |
| **People**      | Sherlock-style username sweep across ~60 sites (parallel, no key) |
| **Social**      | Reddit, HackerNews, GitHub commit-emails + SSH/GPG keys, Mastodon, Telegram, Steam, Keybase, npm, PGP keyserver, Discord invite, YouTube, Roblox, Lichess, Chess.com, TikTok |
| **Email/Phone** | Gravatar, MX, SPF/DMARC/DKIM posture, emailrep.io, holehe-style account check, libphonenumber parse, HIBP pwned-password (k-anonymity), email pattern guesser |
| **Threat**      | Shodan, Censys, GreyNoise, VirusTotal, AbuseIPDB, URLScan |
| **Cyber**       | NVD CVE lookup, AlienVault OTX, URLhaus, ThreatFox, Tor exit, DNSBL (10), tech-stack detect, CMS detect, cookie audit, CORS check, subdomain takeover heuristic, port scan, favicon hash (Shodan/FOFA pivot), TLS fingerprint, SSL Labs, Mozilla Observatory, MITRE ATT&CK, Wayback URL list |
| **Local**       | Wraps Kali CLIs if installed: nmap, theHarvester, sublist3r, amass, subfinder, assetfinder, dnstwist, whatweb, wafw00f, dnsenum, nikto, wpscan, dig, traceroute, gobuster, exiftool. Hit "Probe installed tools" first to see what's present. Strict input validation, hard timeouts, bounded output. |
| **Encoders**    | base64, URL, JWT decode, hash, JSON pretty |

Bound to `127.0.0.1` by default.

```bash
pip install flask
python3 webui.py            # http://127.0.0.1:5000
PORT=8080 python3 webui.py  # custom port
HOST=0.0.0.0 python3 webui.py   # LAN — auth + HTTPS strongly recommended (see below)
```

### Optional auth

Auth is **off by default** (open localhost dashboard). To enable it,
set `WEBUI_USERNAME` and `WEBUI_PASSWORD_HASH` in your environment.

```bash
# 1. Generate a password hash (prompts twice, no echo)
python3 webui.py --hash-password
# scrypt:32768:8:1$abcd...$ef01...

# 2. Export the env vars and launch
export WEBUI_USERNAME=alice
export WEBUI_PASSWORD_HASH='scrypt:32768:8:1$abcd...$ef01...'
export WEBUI_SECRET_KEY=$(openssl rand -hex 32)   # keeps sessions stable across restarts
python3 webui.py
```

Behavior with auth on:
- All routes redirect to `/login` until a valid session cookie is present.
- API routes (`/scan`, `/jobs/*`, `/tool/*`) return JSON `401` instead of
  redirecting, so the JS front-end can intercept and bounce to login.
- Login is rate-limited: 5 failed attempts per IP per minute → `429`.
- Sessions last 8 hours, cookies are `HttpOnly` + `SameSite=Lax`.

### TLS / exposing beyond localhost

Auth alone is **not enough** to safely expose the UI to a network — the
password and session cookie travel in cleartext over plain HTTP. Put a
TLS terminator in front (Caddy, nginx, or a self-signed cert via Flask's
`ssl_context`) and set `WEBUI_HTTPS=1` so the session cookie gets the
`Secure` flag.

### API keys for tool tabs

The bulk of the tools work **without any API keys**. Optional keys raise
rate limits or unlock paid endpoints:

```bash
# paid tools (return structured error if key missing)
export SHODAN_API_KEY=…
export CENSYS_API_ID=…  CENSYS_API_SECRET=…
export VT_API_KEY=…
export ABUSEIPDB_API_KEY=…
export HIBP_API_KEY=…
export THREATFOX_API_KEY=…   # abuse.ch now requires a free auth key
export WPSCAN_API_TOKEN=…    # WP vuln database

# free but rate-limited — key raises the limit
export GREYNOISE_API_KEY=…
export URLSCAN_API_KEY=…
export GITHUB_TOKEN=…        # 60 → 5000/hr (also speeds up GitHub-emails)
export NVD_API_KEY=…         # free at nvd.nist.gov, raises CVE quota
export EMAILREP_API_KEY=…    # raises emailrep.io rate limit
```

Tools that need a key but don't have one return a structured error in
the result panel rather than crashing.

### Optional system binaries (Local tab)

The **Local** tab shells out to Kali / pentest CLIs only if they're
installed. None are required to run the dashboard. Useful ones to
have on `$PATH`:

```
nmap theHarvester sublist3r amass subfinder assetfinder dnstwist
whatweb wafw00f dnsenum nikto wpscan dig traceroute gobuster exiftool
```

On Kali these come with `apt install kali-tools-information-gathering
kali-tools-vulnerability` (already present on the standard Kali image).
Hit **Probe installed tools** in the UI for a complete inventory.
