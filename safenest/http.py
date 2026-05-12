"""safenest.http — unified HTTP helper for the OSINT plugin modules.

Replaces the four near-identical ``_get`` definitions (and ``_safe_request``
in tools.py) that lived in every tools_*.py file. One source of truth for:

  * User-Agent + Accept-Language defaults
  * Per-call timeout handling
  * Connection pooling via a shared :class:`requests.Session`
  * The "never raise, return either Response or Exception" contract that
    every caller already relies on

Each plugin module wires its own ``_get`` / ``_post`` once at import time
via :func:`make_client`, which binds the module's preferred default
timeout. Callsites stay exactly as they were:

    from safenest.http import make_client
    _get, _post = make_client(timeout=15)

    r = _get(url)
    r = _get(url, params={"q": "x"}, headers={"Accept": "image/*"})

Future Phase 1 hooks (retry, per-host token-bucket throttle, response
cache, async httpx variant) plug in here without touching callsites.
"""
from __future__ import annotations

from typing import Callable, Tuple

import requests

# Chrome 124 on Linux. Matches what the tools_*.py modules used to hard-code
# locally. Defensive recon only — never used to bypass auth or impersonate.
DEFAULT_UA = (
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36"
)
DEFAULT_HEADERS = {
    "User-Agent": DEFAULT_UA,
    "Accept-Language": "en-US,en;q=0.9",
}
DEFAULT_TIMEOUT = 12

# One Session, reused for every outbound call. Keeps TLS + TCP handshakes
# warm per upstream host. Functionally invisible to callers; cheaper for
# tools that hammer the same API (Etherscan, TronScan, crt.sh, etc.).
_session = requests.Session()
_session.headers.update(DEFAULT_HEADERS)


def _merge_headers(extra) -> dict:
    if not extra:
        return dict(DEFAULT_HEADERS)
    merged = dict(DEFAULT_HEADERS)
    merged.update(extra)
    return merged


def http_get(url: str, *, timeout: float = DEFAULT_TIMEOUT, **kw):
    """GET via the shared session. Returns a :class:`requests.Response`
    on success, or the caught Exception on failure. Never raises."""
    headers = _merge_headers(kw.pop("headers", None))
    try:
        return _session.get(
            url,
            headers=headers,
            timeout=timeout,
            allow_redirects=True,
            **kw,
        )
    except Exception as e:
        return e


def http_post(url: str, *, timeout: float = DEFAULT_TIMEOUT, **kw):
    """POST counterpart. Same return contract as :func:`http_get`."""
    headers = _merge_headers(kw.pop("headers", None))
    try:
        return _session.post(
            url,
            headers=headers,
            timeout=timeout,
            allow_redirects=True,
            **kw,
        )
    except Exception as e:
        return e


def make_client(timeout: float = DEFAULT_TIMEOUT) -> Tuple[Callable, Callable]:
    """Bind ``(get, post)`` helpers to a default timeout.

    Each plugin module calls this once at import time so its existing
    callsites — ``_get(url)``, ``_get(url, params=...)`` etc. — keep
    working without per-call timeout boilerplate.
    """

    def _get(url, **kw):
        t = kw.pop("timeout", timeout)
        return http_get(url, timeout=t, **kw)

    def _post(url, **kw):
        t = kw.pop("timeout", timeout)
        return http_post(url, timeout=t, **kw)

    return _get, _post
