# domain-scraper

Multi-purpose domain audit scraper. For each domain in a list, collects:

1. Subdomains via [crt.sh](https://crt.sh) certificate transparency
2. `Set-Cookie` headers from the landing page
3. Cookie / consent banner text scraped from the HTML
4. Privacy / cookie policy links + a cleaned text excerpt of the page

Sends realistic Chrome 124 headers (UA, Accept, Sec-Ch-Ua, Sec-Fetch-*, Brotli)
to get past basic UA-sniffing bot filters. Enterprise bot management
(Akamai Bot Manager, Cloudflare) will still block — those need a real browser.

## Install

```bash
pip install -r requirements.txt
```

## Use

```bash
python3 domain_scraper.py domains.txt -o results.csv
python3 domain_scraper.py domains.txt --no-subdomains -w 10
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

- `requests`-based, no JS execution. JS-injected banners (OneTrust etc.) won't show up.
- crt.sh subdomains capped at 25 per input domain.
- Hard-coded 15s HTTP timeout, 30s for crt.sh.
