#!/usr/bin/env python3
"""
tools_screenshot.py — passive screenshot capture + visual-similarity intel.

Drives headless Chromium via Playwright to grab a full-page screenshot
of a target URL, then computes perceptual hashes (pHash, dHash, average,
wavelet) and compares them against the local archive. Used to spot:

  * clones / reskinned scam sites (very low Hamming distance on pHash)
  * impersonation layouts (fake exchange UIs reusing the same chrome)
  * landing-page reuse across campaign domains

Archive layout (under ~/.local/share/safenest/screenshots/):

    <host>__<ts>.png
    <host>__<ts>.png.meta.json    {target, host, ts, phash, dhash,
                                    average_hash, whash}

The archive's only job is to be the corpus we diff against. No DB —
walks the directory each time. Phase 1 will lift this into Postgres
+ MinIO; for now JSON sidecars are enough and easy to inspect.

Lawful, passive, read-only: this only opens pages and captures pixels
you'd see in a normal browser. No interaction beyond page load.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import Optional
from urllib.parse import urlparse

try:
    from PIL import Image
    import imagehash
    HAS_IMAGEHASH = True
except Exception as e:
    HAS_IMAGEHASH = False
    _IMAGEHASH_ERROR = f"{type(e).__name__}: {e}"

try:
    from playwright.sync_api import sync_playwright
    HAS_PLAYWRIGHT = True
except Exception as e:
    HAS_PLAYWRIGHT = False
    _PLAYWRIGHT_ERROR = f"{type(e).__name__}: {e}"

# Storage
ARCHIVE_DIR = Path(
    os.environ.get("SAFENEST_SCREENSHOT_DIR")
    or (Path.home() / ".local" / "share" / "safenest" / "screenshots")
)

# Browser config — defensive defaults
NAV_TIMEOUT_MS = 20_000
RENDER_WAIT_MS = 4_000
VIEWPORT = {"width": 1366, "height": 900}
USER_AGENT = (
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36"
)

# perceptual-hash similarity bands (Hamming distance over a 64-bit hash)
SIMILARITY_BANDS = [
    (0,  4,  "identical"),
    (5,  10, "near-identical"),
    (11, 16, "very similar"),
    (17, 22, "similar"),
]


def _safe_host(s: str) -> str:
    h = (urlparse(s if "://" in s else "https://" + s).hostname or "").lower()
    return re.sub(r"[^a-z0-9._-]", "_", h)[:80] or "unknown"


def _ensure_archive():
    ARCHIVE_DIR.mkdir(parents=True, exist_ok=True)


def _band(distance: int) -> Optional[str]:
    for lo, hi, label in SIMILARITY_BANDS:
        if lo <= distance <= hi:
            return label
    return None


def _hashes_for(img_path: Path) -> dict:
    with Image.open(img_path) as im:
        im = im.convert("RGB")
        return {
            "phash":        str(imagehash.phash(im)),
            "dhash":        str(imagehash.dhash(im)),
            "average_hash": str(imagehash.average_hash(im)),
            "whash":        str(imagehash.whash(im)),
        }


def _hamming(a: str, b: str) -> int:
    """Distance between two hex-encoded imagehash strings."""
    return imagehash.hex_to_hash(a) - imagehash.hex_to_hash(b)


def _read_meta(meta_path: Path) -> Optional[dict]:
    try:
        with open(meta_path, "r", encoding="utf-8") as fh:
            return json.load(fh)
    except Exception:
        return None


def list_archive(limit: int = 200) -> dict:
    """Return everything we have on disk, newest first."""
    _ensure_archive()
    items = []
    for meta_path in sorted(ARCHIVE_DIR.glob("*.png.meta.json"),
                             key=lambda p: p.stat().st_mtime,
                             reverse=True):
        m = _read_meta(meta_path)
        if not m:
            continue
        m["image_path"] = str(meta_path).removesuffix(".meta.json")
        items.append(m)
        if len(items) >= limit:
            break
    return {"count": len(items), "items": items, "archive_dir": str(ARCHIVE_DIR)}


def _find_similar(new_hashes: dict, self_path: str,
                  max_distance: int = 22) -> list:
    """Walk the archive and rank every prior screenshot by pHash distance
    from the new one. Limit to records within `max_distance` Hamming
    distance (≈ 22 covers identical → similar; > 22 is unrelated)."""
    _ensure_archive()
    new_phash = new_hashes.get("phash")
    if not new_phash:
        return []
    out = []
    for meta_path in ARCHIVE_DIR.glob("*.png.meta.json"):
        img_path = str(meta_path).removesuffix(".meta.json")
        if img_path == self_path:
            continue
        m = _read_meta(meta_path)
        if not m or not m.get("phash"):
            continue
        try:
            d_p = _hamming(new_phash, m["phash"])
        except Exception:
            continue
        if d_p > max_distance:
            continue
        try:
            d_d = _hamming(new_hashes.get("dhash", ""), m.get("dhash", "")) \
                  if new_hashes.get("dhash") and m.get("dhash") else None
        except Exception:
            d_d = None
        out.append({
            "host":          m.get("host"),
            "target":        m.get("target"),
            "captured_iso":  m.get("captured_iso"),
            "phash":         m["phash"],
            "phash_distance": d_p,
            "dhash_distance": d_d,
            "band":          _band(d_p),
            "image_path":    img_path,
        })
    out.sort(key=lambda r: r["phash_distance"])
    return out


def screenshot_capture(target: str,
                        wait_ms: int = RENDER_WAIT_MS,
                        full_page: str = "1",
                        proxy: Optional[str] = None) -> dict:
    """Capture a screenshot, hash it, write the sidecar, and return the
    full record (including similar-screenshot matches in the archive)."""
    if not HAS_PLAYWRIGHT:
        return {"error": f"playwright not available: {_PLAYWRIGHT_ERROR}"}
    if not HAS_IMAGEHASH:
        return {"error": f"imagehash not available: {_IMAGEHASH_ERROR}. "
                         f"`pip install imagehash Pillow`"}
    if not (target or "").strip():
        return {"error": "target required"}

    url = target.strip()
    if "://" not in url:
        url = "https://" + url
    host = _safe_host(url)
    _ensure_archive()
    ts = int(time.time())
    img_path = ARCHIVE_DIR / f"{host}__{ts}.png"
    meta_path = Path(str(img_path) + ".meta.json")

    try:
        wait_ms_i = max(0, min(30_000, int(wait_ms) if wait_ms else RENDER_WAIT_MS))
    except Exception:
        wait_ms_i = RENDER_WAIT_MS
    full = str(full_page).lower() not in ("0", "false", "no", "off", "")

    try:
        with sync_playwright() as p:
            browser_kwargs = {}
            if proxy:
                browser_kwargs["proxy"] = {"server": proxy}
            browser = p.chromium.launch(headless=True, **browser_kwargs)
            ctx = browser.new_context(viewport=VIEWPORT, user_agent=USER_AGENT,
                                       java_script_enabled=True)
            page = ctx.new_page()
            try:
                page.goto(url, timeout=NAV_TIMEOUT_MS, wait_until="load")
            except Exception as nav_err:
                # try a softer wait condition before giving up
                try:
                    page.goto(url, timeout=NAV_TIMEOUT_MS,
                              wait_until="domcontentloaded")
                except Exception:
                    browser.close()
                    return {"error": f"navigation failed: {nav_err}"}
            if wait_ms_i:
                page.wait_for_timeout(wait_ms_i)
            page.screenshot(path=str(img_path), full_page=full)
            try:
                title = page.title()
            except Exception:
                title = None
            try:
                final_url = page.url
            except Exception:
                final_url = url
            browser.close()
    except Exception as e:
        return {"error": f"capture: {type(e).__name__}: {e}"}

    # compute hashes
    try:
        hashes = _hashes_for(img_path)
    except Exception as e:
        return {"error": f"hash: {type(e).__name__}: {e}"}

    size = img_path.stat().st_size
    captured_iso = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(ts))
    meta = {
        "target": url,
        "final_url": final_url,
        "host": host,
        "ts": ts,
        "captured_iso": captured_iso,
        "title": title,
        "size_bytes": size,
        **hashes,
    }
    with open(meta_path, "w", encoding="utf-8") as fh:
        json.dump(meta, fh, indent=2)

    similar = _find_similar(hashes, str(img_path))

    return {
        "ok": True,
        "target": url,
        "final_url": final_url,
        "host": host,
        "title": title,
        "captured_iso": captured_iso,
        "ts": ts,
        "image_path": str(img_path),
        "meta_path": str(meta_path),
        "size_bytes": size,
        **hashes,
        "similar_count": len(similar),
        "similar": similar[:20],
    }


def screenshot_compare(target: str = "", max_distance: int = 22) -> dict:
    """Re-run similarity for the most recent capture of `target`.
    Useful when more screenshots have been added since the original
    capture and you want fresh matches."""
    if not HAS_IMAGEHASH:
        return {"error": f"imagehash not available: {_IMAGEHASH_ERROR}"}
    _ensure_archive()
    host = _safe_host(target) if target else None
    candidates = sorted(ARCHIVE_DIR.glob("*.png.meta.json"),
                         key=lambda p: p.stat().st_mtime, reverse=True)
    if host:
        candidates = [p for p in candidates if p.name.startswith(host + "__")]
    if not candidates:
        return {"error": f"no archived screenshots for {host or 'any host'}"}
    meta = _read_meta(candidates[0])
    if not meta:
        return {"error": "failed to read newest meta"}
    img_path = str(candidates[0]).removesuffix(".meta.json")
    try:
        max_d = max(0, min(64, int(max_distance) if max_distance else 22))
    except Exception:
        max_d = 22
    similar = _find_similar({"phash": meta.get("phash"),
                              "dhash": meta.get("dhash")},
                              img_path, max_distance=max_d)
    return {
        "ok": True,
        "host": host or meta.get("host"),
        "captured_iso": meta.get("captured_iso"),
        "image_path": img_path,
        "phash": meta.get("phash"),
        "similar_count": len(similar),
        "similar": similar[:30],
    }


def screenshot_archive_stats() -> dict:
    _ensure_archive()
    total = 0
    by_host: dict = {}
    for p in ARCHIVE_DIR.glob("*.png"):
        total += 1
        host = p.name.split("__", 1)[0]
        by_host[host] = by_host.get(host, 0) + 1
    return {
        "archive_dir": str(ARCHIVE_DIR),
        "total_screenshots": total,
        "distinct_hosts": len(by_host),
        "by_host": dict(sorted(by_host.items(), key=lambda kv: -kv[1])[:25]),
        "playwright_available": HAS_PLAYWRIGHT,
        "imagehash_available": HAS_IMAGEHASH,
    }
