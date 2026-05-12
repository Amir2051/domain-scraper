#!/usr/bin/env python3
"""
tools_email_phone.py — email + phone OSINT.

All free / no-key endpoints (HIBP-passwords uses k-anonymity, no key).
"""
from __future__ import annotations

import hashlib
import re
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Optional
from urllib.parse import quote

import dns.resolver
import dns.exception
import requests

from safenest.http import DEFAULT_HEADERS as HEADERS, DEFAULT_UA as UA, make_client

TIMEOUT = 10
EMAIL_RE = re.compile(r"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$")

_get, _post = make_client(timeout=TIMEOUT)


# ============== EMAIL ==============

def gravatar_lookup(email: str) -> dict:
    """Md5 of lowercased email → gravatar profile JSON (no key needed)."""
    email = (email or "").strip().lower()
    if "@" not in email:
        return {"error": "give a valid email"}
    h = hashlib.md5(email.encode()).hexdigest()
    image_url = f"https://gravatar.com/avatar/{h}?d=404"
    profile_url = f"https://gravatar.com/{h}.json"
    img = _get(image_url, headers={"Accept": "image/*"})
    has_avatar = (not isinstance(img, Exception) and img.status_code == 200)
    profile = _get(profile_url)
    out: dict = {
        "email": email,
        "md5_hash": h,
        "avatar_url": f"https://gravatar.com/avatar/{h}",
        "has_avatar": has_avatar,
        "profile_url": f"https://gravatar.com/{h}",
    }
    if not isinstance(profile, Exception) and profile.status_code == 200:
        try:
            j = profile.json()
            entries = (j.get("entry") or [])
            if entries:
                e = entries[0]
                out["profile"] = {
                    "preferred_username": e.get("preferredUsername"),
                    "display_name": e.get("displayName"),
                    "name": e.get("name"),
                    "about": e.get("aboutMe"),
                    "location": e.get("currentLocation"),
                    "urls": e.get("urls"),
                    "accounts": [
                        {"shortname": a.get("shortname"),
                         "url": a.get("url"),
                         "verified": a.get("verified")}
                        for a in (e.get("accounts") or [])
                    ],
                }
        except Exception:
            pass
    return out


def mx_lookup(domain: str) -> dict:
    domain = (domain or "").strip().lower()
    if not domain:
        return {"error": "empty domain"}
    if "@" in domain:
        domain = domain.split("@", 1)[1]
    out = {"domain": domain}
    res = dns.resolver.Resolver()
    res.lifetime = 8
    try:
        ans = res.resolve(domain, "MX")
        out["mx_records"] = sorted(
            [{"preference": r.preference,
              "exchange": str(r.exchange).rstrip(".")} for r in ans],
            key=lambda x: x["preference"],
        )
    except dns.resolver.NoAnswer:
        out["mx_records"] = []
    except dns.resolver.NXDOMAIN:
        return {"domain": domain, "error": "NXDOMAIN"}
    except dns.exception.DNSException as e:
        return {"domain": domain, "error": str(e)}
    # provider hint
    mx_str = " ".join(r["exchange"] for r in out.get("mx_records", []))
    hints = {
        "google": ("google.com", "googlemail"),
        "microsoft": ("outlook.com", "protection.outlook"),
        "proton": ("protonmail", "proton.ch"),
        "zoho": ("zoho",),
        "fastmail": ("messagingengine", "fastmail"),
        "yandex": ("yandex",),
        "icloud": ("icloud", "mail.me.com"),
    }
    for prov, needles in hints.items():
        if any(n in mx_str for n in needles):
            out["provider_guess"] = prov
            break
    return out


def email_auth_records(domain: str) -> dict:
    """SPF + DMARC + DKIM (default selector probe). DNS based."""
    domain = (domain or "").strip().lower()
    if not domain:
        return {"error": "empty domain"}
    if "@" in domain:
        domain = domain.split("@", 1)[1]
    res = dns.resolver.Resolver()
    res.lifetime = 8
    out = {"domain": domain}

    def _txt(name):
        try:
            ans = res.resolve(name, "TXT")
            return [b"".join(r.strings).decode("utf-8", errors="replace")
                    for r in ans]
        except dns.resolver.NoAnswer:
            return []
        except dns.resolver.NXDOMAIN:
            return None
        except dns.exception.DNSException as e:
            return [f"<error: {e.__class__.__name__}>"]

    txt = _txt(domain) or []
    out["spf"] = next((t for t in txt if t.lower().startswith("v=spf1")), None)
    out["spf_present"] = out["spf"] is not None

    dmarc = _txt(f"_dmarc.{domain}")
    out["dmarc"] = next((t for t in (dmarc or []) if t.lower().startswith("v=dmarc1")),
                         None)
    out["dmarc_present"] = out["dmarc"] is not None

    # try common DKIM selectors
    found_selectors: dict = {}
    for sel in ("default", "google", "selector1", "selector2", "k1",
                "mail", "dkim", "20161025", "smtpapi", "mxvault",
                "fm1", "fm2", "fm3"):
        rec = _txt(f"{sel}._domainkey.{domain}")
        if rec:
            for r in rec:
                if "v=dkim1" in r.lower() or "p=" in r.lower():
                    found_selectors[sel] = r
                    break
    out["dkim_selectors_found"] = list(found_selectors.keys())
    out["dkim_records"] = found_selectors

    # MTA-STS + TLS-RPT
    for kind, name in (("mta_sts", f"_mta-sts.{domain}"),
                        ("tls_rpt", f"_smtp._tls.{domain}")):
        rec = _txt(name)
        out[kind] = (rec[0] if rec else None)

    score = sum(bool(out[k]) for k in ("spf", "dmarc")) + (1 if found_selectors else 0)
    out["posture_score"] = f"{score}/3"
    return out


def email_pattern_guess(name: str, domain: str) -> dict:
    """Generate the most common corporate email patterns for a name @ domain."""
    name = (name or "").strip()
    domain = (domain or "").strip().lower().lstrip("@")
    if not name or not domain:
        return {"error": "need both name and domain"}
    parts = re.split(r"\s+", name)
    if len(parts) < 2:
        first, last = parts[0].lower(), ""
    else:
        first = parts[0].lower()
        last = parts[-1].lower()
    f = first
    l = last
    fi = first[0] if first else ""
    li = last[0] if last else ""
    patterns = []
    if last:
        patterns += [
            f"{f}.{l}@{domain}", f"{f}{l}@{domain}",
            f"{f}_{l}@{domain}", f"{f}-{l}@{domain}",
            f"{fi}{l}@{domain}", f"{f}{li}@{domain}",
            f"{fi}.{l}@{domain}", f"{l}.{f}@{domain}",
            f"{f}@{domain}", f"{l}@{domain}",
            f"{fi}{li}@{domain}",
        ]
    else:
        patterns += [f"{f}@{domain}"]
    seen = set()
    out = []
    for p in patterns:
        if p not in seen:
            seen.add(p)
            out.append(p)
    return {"name": name, "domain": domain, "candidates": out}


def hibp_password(password: str) -> dict:
    """Check a password against HIBP via k-anonymity (sends only first
    5 hex chars of SHA-1 — full hash never leaves your machine).
    No API key needed."""
    pw = password or ""
    if not pw:
        return {"error": "empty password"}
    sha1 = hashlib.sha1(pw.encode("utf-8")).hexdigest().upper()
    prefix, suffix = sha1[:5], sha1[5:]
    r = _get(f"https://api.pwnedpasswords.com/range/{prefix}",
             headers={"Add-Padding": "true"})
    if isinstance(r, Exception):
        return {"error": str(r)}
    if r.status_code != 200:
        return {"error": f"HIBP returned {r.status_code}"}
    for line in r.text.splitlines():
        h, _, count = line.strip().partition(":")
        if h == suffix:
            n = int(count) if count.isdigit() else 0
            if n == 0:
                return {"pwned": False, "count": 0,
                         "note": "padded (HIBP returns count=0 for padding entries) — likely safe"}
            return {"pwned": True, "count": n,
                     "note": f"this password appears in {n:,} known breaches — DO NOT use it"}
    return {"pwned": False, "count": 0,
             "note": "not found in HIBP database"}


def emailrep(email: str) -> dict:
    """emailrep.io via the official sublime-security/emailrep.io-python client.
    Requires $EMAILREP_API_KEY (the unauthenticated API is disabled)."""
    import os
    email = (email or "").strip().lower()
    if not EMAIL_RE.match(email):
        return {"error": "invalid email"}
    try:
        from emailrep import EmailRep
    except ImportError:
        return {"error": "emailrep client not installed — pip install -e ./emailrep.io-python"}
    key = os.environ.get("EMAILREP_API_KEY")
    try:
        d = EmailRep(key=key).query(email)
    except Exception as e:
        return {"error": str(e)}
    if isinstance(d, dict) and d.get("status") == "fail":
        msg = d.get("reason") or "emailrep failed"
        if not key:
            msg += " (set $EMAILREP_API_KEY)"
        return {"error": msg}
    return {
        "email": d.get("email"),
        "reputation": d.get("reputation"),
        "suspicious": d.get("suspicious"),
        "references": d.get("references"),
        "summary": d.get("summary"),
        "details": d.get("details"),
    }


# ---------- Holehe-style: which sites recognise this email ----------

# Each entry: (name, request_fn). request_fn(email) returns
#   True   — email is registered
#   False  — not registered
#   None   — couldn't tell (rate limit, captcha, etc.)
def _holehe_pinterest(email):
    try:
        r = requests.post(
            "https://www.pinterest.com/_ngjs/resource/EmailExistsResource/get/",
            params={"source_url": "/", "data":
                    f'{{"options":{{"email":"{email}"}}}}'},
            headers=HEADERS, timeout=TIMEOUT,
        )
        if r.status_code == 200:
            j = r.json()
            return bool(((j.get("resource_response") or {}).get("data")))
    except Exception:
        return None
    return None


def _holehe_lastfm(email):
    try:
        r = requests.post(
            "https://www.last.fm/join/partner/email-check",
            data={"email": email},
            headers={**HEADERS, "X-Requested-With": "XMLHttpRequest"},
            timeout=TIMEOUT,
        )
        if r.status_code == 200:
            return "already" in (r.text or "").lower()
    except Exception:
        return None
    return None


def _holehe_spotify(email):
    try:
        r = requests.get(
            "https://spclient.wg.spotify.com/signup/public/v1/account",
            params={"validate": 1, "email": email},
            headers=HEADERS, timeout=TIMEOUT,
        )
        if r.status_code == 200:
            j = r.json()
            return j.get("status") == 20  # 20 = email already in use
    except Exception:
        return None
    return None


def _holehe_adobe(email):
    try:
        r = requests.post(
            "https://auth.services.adobe.com/signin/v2/users/exists",
            json={"username": email},
            headers={**HEADERS, "Content-Type": "application/json",
                     "x-ims-clientid": "adobedotcom2"},
            timeout=TIMEOUT,
        )
        if r.status_code == 200:
            return r.json().get("exists", False)
    except Exception:
        return None
    return None


def _holehe_imgur(email):
    try:
        r = requests.post(
            "https://api.imgur.com/account/v1/emails/check",
            json={"email": email},
            headers={**HEADERS, "X-Mashape-Key": "0",
                     "Authorization": "Client-ID 546c25a59c58ad7"},
            timeout=TIMEOUT,
        )
        if r.status_code in (200, 409):
            return r.status_code == 409 or "registered" in r.text.lower()
    except Exception:
        return None
    return None


def _holehe_github(email):
    # public commits search — finds emails used in open-source contributions
    try:
        r = requests.get(
            f"https://api.github.com/search/users?q={quote(email)}+in:email",
            headers=HEADERS, timeout=TIMEOUT,
        )
        if r.status_code == 200:
            return (r.json().get("total_count") or 0) > 0
    except Exception:
        return None
    return None


def _holehe_gravatar(email):
    h = hashlib.md5(email.lower().encode()).hexdigest()
    try:
        r = requests.get(f"https://gravatar.com/{h}.json",
                          headers=HEADERS, timeout=TIMEOUT)
        return r.status_code == 200
    except Exception:
        return None


HOLEHE_SITES = {
    "pinterest":  _holehe_pinterest,
    "lastfm":     _holehe_lastfm,
    "spotify":    _holehe_spotify,
    "adobe":      _holehe_adobe,
    "imgur":      _holehe_imgur,
    "github":     _holehe_github,
    "gravatar":   _holehe_gravatar,
}


def email_account_check(email: str, workers: int = 6) -> dict:
    """Holehe-style: which of N sites already have this email registered?"""
    email = (email or "").strip().lower()
    if not EMAIL_RE.match(email):
        return {"error": "invalid email"}
    found, not_found, unknown = [], [], []
    with ThreadPoolExecutor(max_workers=workers) as ex:
        futs = {ex.submit(fn, email): name for name, fn in HOLEHE_SITES.items()}
        for fut in as_completed(futs):
            name = futs[fut]
            try:
                res = fut.result()
            except Exception:
                res = None
            if res is True:
                found.append(name)
            elif res is False:
                not_found.append(name)
            else:
                unknown.append(name)
    return {
        "email": email,
        "found_on": sorted(found),
        "not_found_on": sorted(not_found),
        "unknown": sorted(unknown),
        "total_sites": len(HOLEHE_SITES),
    }


# ============== PHONE ==============

def phone_parse(number: str, region: str = "") -> dict:
    """Parse a phone number with libphonenumber. Returns country, type,
    carrier, region. region is the default country if number has no '+'."""
    number = (number or "").strip()
    if not number:
        return {"error": "empty number"}
    try:
        import phonenumbers
        from phonenumbers import (carrier as ph_carrier,
                                    geocoder as ph_geocoder,
                                    timezone as ph_timezone, NumberParseException,
                                    PhoneNumberType)
    except ImportError:
        return {"error": "phonenumbers not installed — pip install phonenumbers"}
    try:
        parsed = phonenumbers.parse(number, (region or None))
    except NumberParseException as e:
        return {"error": f"parse failed: {e}"}
    type_map = {
        PhoneNumberType.FIXED_LINE: "fixed_line",
        PhoneNumberType.MOBILE: "mobile",
        PhoneNumberType.FIXED_LINE_OR_MOBILE: "fixed_line_or_mobile",
        PhoneNumberType.TOLL_FREE: "toll_free",
        PhoneNumberType.PREMIUM_RATE: "premium_rate",
        PhoneNumberType.SHARED_COST: "shared_cost",
        PhoneNumberType.VOIP: "voip",
        PhoneNumberType.PERSONAL_NUMBER: "personal",
        PhoneNumberType.PAGER: "pager",
        PhoneNumberType.UAN: "uan",
        PhoneNumberType.VOICEMAIL: "voicemail",
        PhoneNumberType.UNKNOWN: "unknown",
    }
    return {
        "input": number,
        "valid": phonenumbers.is_valid_number(parsed),
        "possible": phonenumbers.is_possible_number(parsed),
        "country_code": parsed.country_code,
        "national_number": parsed.national_number,
        "region": phonenumbers.region_code_for_number(parsed),
        "type": type_map.get(phonenumbers.number_type(parsed), "unknown"),
        "carrier": ph_carrier.name_for_number(parsed, "en"),
        "location": ph_geocoder.description_for_number(parsed, "en"),
        "timezones": list(ph_timezone.time_zones_for_number(parsed)),
        "e164": phonenumbers.format_number(
            parsed, phonenumbers.PhoneNumberFormat.E164),
        "international": phonenumbers.format_number(
            parsed, phonenumbers.PhoneNumberFormat.INTERNATIONAL),
        "national": phonenumbers.format_number(
            parsed, phonenumbers.PhoneNumberFormat.NATIONAL),
    }
