#!/usr/bin/env python3
"""
tools_local.py — wrappers around Kali / popular OSINT CLIs.

Every wrapper:
  * checks shutil.which() — missing binary returns a structured error
  * sanitises the target to hostname / IP / domain — no shell metachars
  * uses subprocess.run(..., shell=False) and a hard timeout
  * truncates output so a runaway tool can't fill memory
"""
from __future__ import annotations

import re
import shutil
import subprocess
from typing import Optional

# strict patterns — refuse anything that doesn't match
HOSTNAME_RE = re.compile(r"^(?=.{1,253}$)(?:[A-Za-z0-9_](?:[A-Za-z0-9_-]{0,61}[A-Za-z0-9_])?\.)*"
                          r"[A-Za-z0-9_](?:[A-Za-z0-9_-]{0,61}[A-Za-z0-9_])?$")
IP4_RE = re.compile(r"^(\d{1,3}\.){3}\d{1,3}$")
IP6_RE = re.compile(r"^[0-9a-fA-F:]+$")
URL_RE = re.compile(r"^https?://[A-Za-z0-9._\-:/?&=%+@#~,!\[\]]+$")
ASN_RE = re.compile(r"^(AS)?\d{1,10}$")
MAX_OUTPUT = 100_000


def _safe_target(value: str, kinds: tuple = ("host",)) -> Optional[str]:
    """Validate input. Return cleaned target or None.
    kinds: any of "host", "ip", "url", "asn"."""
    v = (value or "").strip()
    if not v:
        return None
    if "host" in kinds and HOSTNAME_RE.match(v):
        return v
    if "ip" in kinds and (IP4_RE.match(v) or IP6_RE.match(v)):
        return v
    if "url" in kinds and URL_RE.match(v):
        return v
    if "asn" in kinds and ASN_RE.match(v):
        return v.upper()
    return None


def _need_bin(name: str) -> Optional[dict]:
    if not shutil.which(name):
        return {"error": f"binary '{name}' not installed or not on $PATH"}
    return None


def _run(cmd: list, timeout: int = 60) -> dict:
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True,
                               timeout=timeout)
    except subprocess.TimeoutExpired as e:
        return {"error": f"{cmd[0]} timed out after {timeout}s",
                "stdout": (e.stdout or "")[-MAX_OUTPUT:] if e.stdout else "",
                "stderr": (e.stderr or "")[-MAX_OUTPUT:] if e.stderr else ""}
    except FileNotFoundError:
        return {"error": f"binary '{cmd[0]}' not found"}
    return {
        "cmd": " ".join(cmd),
        "returncode": proc.returncode,
        "stdout": (proc.stdout or "")[:MAX_OUTPUT],
        "stderr": (proc.stderr or "")[:MAX_OUTPUT],
        "truncated": (len(proc.stdout or "") > MAX_OUTPUT
                       or len(proc.stderr or "") > MAX_OUTPUT),
    }


# ============== nmap ==============

def nmap_scan(target: str, profile: str = "fast") -> dict:
    """profile = fast | service | top1000 | vuln-light. Always -Pn (no
    ICMP probe so VPN'd hosts return)."""
    err = _need_bin("nmap")
    if err:
        return err
    t = _safe_target(target, kinds=("host", "ip"))
    if not t:
        return {"error": "target must be hostname or IPv4/IPv6"}
    profiles = {
        "fast":      ["-Pn", "-F", "-T4"],
        "service":   ["-Pn", "-sV", "-F", "-T4"],
        "top1000":   ["-Pn", "-T4"],
        "vuln-light":["-Pn", "-sV", "-F", "-T4", "--script",
                      "vuln,vulners", "--script-timeout", "30s"],
    }
    flags = profiles.get(profile)
    if flags is None:
        return {"error": f"profile must be one of {list(profiles)}"}
    return _run(["nmap", *flags, t], timeout=180 if profile == "vuln-light" else 90)


# ============== theHarvester ==============

def theharvester(domain: str, source: str = "bing", limit=100) -> dict:
    """Run theHarvester against a domain. source examples: bing, duckduckgo,
    crtsh, hackertarget, otx, threatcrowd, anubis, certspotter, baidu."""
    err = _need_bin("theHarvester")
    if err:
        # also try lowercase variant
        err2 = _need_bin("theharvester")
        if err2:
            return err
    bin_name = "theHarvester" if shutil.which("theHarvester") else "theharvester"
    d = _safe_target(domain, kinds=("host",))
    if not d:
        return {"error": "domain must be a valid hostname"}
    source = source or "bing"
    if not re.match(r"^[a-zA-Z0-9_,]+$", source):
        return {"error": "source contains invalid characters"}
    try:
        limit_n = int(limit) if limit else 100
    except (ValueError, TypeError):
        limit_n = 100
    if not (10 <= limit_n <= 1000):
        limit_n = 100
    return _run([bin_name, "-d", d, "-b", source, "-l", str(limit_n)],
                 timeout=180)


# ============== sublist3r ==============

def sublist3r_scan(domain: str) -> dict:
    err = _need_bin("sublist3r")
    if err:
        return err
    d = _safe_target(domain, kinds=("host",))
    if not d:
        return {"error": "domain must be a valid hostname"}
    return _run(["sublist3r", "-d", d, "-n"], timeout=180)


# ============== amass passive ==============

def amass_passive(domain: str) -> dict:
    err = _need_bin("amass")
    if err:
        return err
    d = _safe_target(domain, kinds=("host",))
    if not d:
        return {"error": "domain must be a valid hostname"}
    return _run(["amass", "enum", "-passive", "-d", d, "-timeout", "2"],
                 timeout=180)


# ============== subfinder ==============

def subfinder_scan(domain: str) -> dict:
    err = _need_bin("subfinder")
    if err:
        return err
    d = _safe_target(domain, kinds=("host",))
    if not d:
        return {"error": "domain must be a valid hostname"}
    return _run(["subfinder", "-d", d, "-silent", "-timeout", "10"],
                 timeout=180)


# ============== assetfinder ==============

def assetfinder_scan(domain: str) -> dict:
    err = _need_bin("assetfinder")
    if err:
        return err
    d = _safe_target(domain, kinds=("host",))
    if not d:
        return {"error": "domain must be a valid hostname"}
    return _run(["assetfinder", "--subs-only", d], timeout=120)


# ============== dnstwist ==============

def dnstwist_scan(domain: str) -> dict:
    """Generate look-alike domains (typo squat detection)."""
    err = _need_bin("dnstwist")
    if err:
        return err
    d = _safe_target(domain, kinds=("host",))
    if not d:
        return {"error": "domain must be a valid hostname"}
    return _run(["dnstwist", "--registered", "-f", "json", d], timeout=120)


# ============== whatweb ==============

def whatweb_scan(target: str) -> dict:
    err = _need_bin("whatweb")
    if err:
        return err
    t = _safe_target(target, kinds=("host", "url"))
    if not t:
        return {"error": "target must be hostname or URL"}
    return _run(["whatweb", "--no-errors", "-a", "3", t], timeout=60)


# ============== wafw00f ==============

def wafw00f_scan(target: str) -> dict:
    err = _need_bin("wafw00f")
    if err:
        return err
    t = _safe_target(target, kinds=("host", "url"))
    if not t:
        return {"error": "target must be hostname or URL"}
    return _run(["wafw00f", "-a", t], timeout=60)


# ============== dnsenum ==============

def dnsenum_scan(domain: str) -> dict:
    err = _need_bin("dnsenum")
    if err:
        return err
    d = _safe_target(domain, kinds=("host",))
    if not d:
        return {"error": "domain must be a valid hostname"}
    return _run(["dnsenum", "--noreverse", "--nocolor", "-t", "10",
                  "--threads", "8", d], timeout=120)


# ============== nikto ==============

def nikto_scan(target: str) -> dict:
    err = _need_bin("nikto")
    if err:
        return err
    t = _safe_target(target, kinds=("host", "url"))
    if not t:
        return {"error": "target must be hostname or URL"}
    return _run(["nikto", "-host", t, "-maxtime", "60s",
                  "-Tuning", "x6", "-nointeractive"],
                 timeout=120)


# ============== wpscan ==============

def wpscan_scan(target: str) -> dict:
    err = _need_bin("wpscan")
    if err:
        return err
    t = _safe_target(target, kinds=("host", "url"))
    if not t:
        return {"error": "target must be hostname or URL"}
    if not t.startswith("http"):
        t = "https://" + t
    cmd = ["wpscan", "--url", t, "--no-banner", "--random-user-agent",
            "--disable-tls-checks", "--no-update", "--detection-mode",
            "passive", "--format", "cli-no-colour"]
    import os
    if os.environ.get("WPSCAN_API_TOKEN"):
        cmd.extend(["--api-token", os.environ["WPSCAN_API_TOKEN"]])
    return _run(cmd, timeout=180)


# ============== dig ==============

def dig_query(target: str, rtype: str = "ANY") -> dict:
    err = _need_bin("dig")
    if err:
        return err
    t = _safe_target(target, kinds=("host",))
    if not t:
        return {"error": "target must be a valid hostname"}
    rtype = (rtype or "ANY").upper()
    if not re.match(r"^[A-Z]{1,10}$", rtype):
        return {"error": "rtype must be 1-10 uppercase letters"}
    return _run(["dig", "+short", "+nocomments", "+noquestion",
                  t, rtype], timeout=15)


# ============== traceroute ==============

def traceroute(target: str) -> dict:
    err = _need_bin("traceroute")
    if err:
        return err
    t = _safe_target(target, kinds=("host", "ip"))
    if not t:
        return {"error": "target must be hostname or IP"}
    return _run(["traceroute", "-n", "-w", "1", "-q", "1", "-m", "20", t],
                 timeout=60)


# ============== gobuster (dir brute) ==============

def gobuster_dir(target: str, wordlist: str = "") -> dict:
    err = _need_bin("gobuster")
    if err:
        return err
    t = _safe_target(target, kinds=("host", "url"))
    if not t:
        return {"error": "target must be hostname or URL"}
    if not t.startswith("http"):
        t = "https://" + t
    # default to a small dirbuster wordlist if available
    import os as _os
    candidate_wordlists = [
        wordlist or "",
        "/usr/share/wordlists/dirb/common.txt",
        "/usr/share/wordlists/dirbuster/directory-list-2.3-small.txt",
        "/usr/share/seclists/Discovery/Web-Content/common.txt",
    ]
    chosen = next((w for w in candidate_wordlists
                    if w and _os.path.isfile(w)), None)
    if not chosen:
        return {"error": "no wordlist found — pass `wordlist` arg pointing "
                "to a real file (e.g. /usr/share/wordlists/dirb/common.txt)"}
    return _run(["gobuster", "dir", "-q", "-t", "20", "-k", "-r",
                  "--no-color", "--timeout", "5s",
                  "-w", chosen, "-u", t], timeout=180)


# ============== exiftool (image metadata) ==============

def exiftool_url(url: str) -> dict:
    """Download an image URL and run exiftool on it. Helpful for image
    OSINT (camera model, GPS, original date)."""
    err = _need_bin("exiftool")
    if err:
        return err
    t = _safe_target(url, kinds=("url",))
    if not t:
        return {"error": "must be a valid http(s) URL"}
    import tempfile, os, requests as rq
    try:
        r = rq.get(t, timeout=15, stream=True,
                    headers={"User-Agent": "domain-scraper-toolkit"})
        if r.status_code != 200:
            return {"error": f"download returned {r.status_code}"}
        with tempfile.NamedTemporaryFile(delete=False, suffix=".bin") as f:
            for chunk in r.iter_content(8192):
                f.write(chunk)
                if f.tell() > 30 * 1024 * 1024:  # 30 MB cap
                    break
            tmp = f.name
        try:
            return _run(["exiftool", "-G", "-j", tmp], timeout=20)
        finally:
            try:
                os.unlink(tmp)
            except OSError:
                pass
    except Exception as e:
        return {"error": str(e)}


# ============== which-tools-are-installed probe ==============

KALI_TOOLS = [
    "nmap", "theHarvester", "sublist3r", "amass", "subfinder",
    "assetfinder", "dnstwist", "whatweb", "wafw00f", "dnsenum",
    "nikto", "wpscan", "dig", "traceroute", "gobuster", "exiftool",
    "ffuf", "feroxbuster", "httpx", "katana", "nuclei",
    "trufflehog", "gitleaks", "masscan", "fierce", "recon-ng",
]


def installed_tools() -> dict:
    found, missing = [], []
    for t in KALI_TOOLS:
        if shutil.which(t):
            found.append({"name": t, "path": shutil.which(t)})
        else:
            missing.append(t)
    return {"found_count": len(found), "found": found,
             "missing_count": len(missing), "missing": missing}
