#!/usr/bin/env python3
"""
tools_social.py — per-platform deep-dive OSINT.

These return richer data than `tools_username.username_sweep` (which only
asks "does this username exist on site X"). All endpoints used here are
public and key-less.
"""
from __future__ import annotations

import re
from datetime import datetime, timezone
from typing import Optional
from urllib.parse import quote

import requests
from bs4 import BeautifulSoup

from safenest.http import DEFAULT_HEADERS as HEADERS, DEFAULT_UA as UA, make_client

TIMEOUT = 12
_get, _post = make_client(timeout=TIMEOUT)


def _ts_to_iso(t):
    if not t:
        return None
    try:
        return datetime.fromtimestamp(int(t), tz=timezone.utc).isoformat()
    except Exception:
        return t


# ---------- Reddit ----------

def reddit_user(username: str) -> dict:
    username = (username or "").strip().lstrip("@u/")
    if not username:
        return {"error": "empty username"}
    r = _get(f"https://www.reddit.com/user/{quote(username)}/about.json")
    if isinstance(r, Exception):
        return {"error": str(r)}
    if r.status_code == 404:
        return {"error": f"user '{username}' not found"}
    if r.status_code != 200:
        return {"error": f"reddit returned {r.status_code}"}
    try:
        d = r.json().get("data", {})
    except Exception:
        return {"error": "reddit returned non-json"}
    return {
        "username": d.get("name"),
        "id": d.get("id"),
        "created_utc": _ts_to_iso(d.get("created_utc")),
        "link_karma": d.get("link_karma"),
        "comment_karma": d.get("comment_karma"),
        "total_karma": d.get("total_karma"),
        "verified": d.get("verified"),
        "is_employee": d.get("is_employee"),
        "is_mod": d.get("is_mod"),
        "is_gold": d.get("is_gold"),
        "has_verified_email": d.get("has_verified_email"),
        "icon_img": d.get("icon_img"),
        "subreddit_title": (d.get("subreddit") or {}).get("title"),
        "subreddit_public_description":
            (d.get("subreddit") or {}).get("public_description"),
    }


# ---------- HackerNews ----------

def hn_user(username: str) -> dict:
    username = (username or "").strip()
    if not username:
        return {"error": "empty username"}
    r = _get(f"https://hacker-news.firebaseio.com/v0/user/{quote(username)}.json")
    if isinstance(r, Exception):
        return {"error": str(r)}
    if r.status_code != 200 or r.text.strip() == "null":
        return {"error": f"user '{username}' not found"}
    try:
        d = r.json()
    except Exception:
        return {"error": "non-json"}
    return {
        "id": d.get("id"),
        "created": _ts_to_iso(d.get("created")),
        "karma": d.get("karma"),
        "submitted_count": len(d.get("submitted") or []),
        "about": (d.get("about") or "")[:1000],
    }


# ---------- GitHub commit emails ----------

EMAIL_RE = re.compile(r"<([^<>@\s]+@[^<>@\s]+)>")


def github_emails(username: str, repo_limit: int = 5,
                   commit_limit: int = 30) -> dict:
    """Walk a user's most-recent public repos, pull author/committer emails
    from commit metadata. Filters out github noreply addresses by default
    but keeps them in `noreply_emails` for completeness."""
    import os
    username = (username or "").strip().lstrip("@")
    if not username:
        return {"error": "empty username"}
    h = dict(HEADERS)
    if os.environ.get("GITHUB_TOKEN"):
        h["Authorization"] = f"Bearer {os.environ['GITHUB_TOKEN']}"
    h["Accept"] = "application/vnd.github+json"

    r = _get(f"https://api.github.com/users/{username}/repos"
             f"?sort=pushed&per_page={repo_limit}", headers=h)
    if isinstance(r, Exception):
        return {"error": str(r)}
    if r.status_code == 404:
        return {"error": f"user '{username}' not found"}
    if r.status_code == 403:
        return {"error": "rate-limited (set $GITHUB_TOKEN)"}
    if r.status_code != 200:
        return {"error": f"github returned {r.status_code}"}

    real, noreply = set(), set()
    sources: list[dict] = []
    for repo in r.json()[:repo_limit]:
        rname = repo.get("full_name")
        rr = _get(f"https://api.github.com/repos/{rname}/commits"
                  f"?per_page={commit_limit}&author={username}", headers=h)
        if isinstance(rr, Exception) or rr.status_code != 200:
            continue
        for c in rr.json():
            for who in ("author", "committer"):
                e = ((c.get("commit") or {}).get(who) or {}).get("email", "")
                n = ((c.get("commit") or {}).get(who) or {}).get("name", "")
                e = e.strip().lower()
                if not e or "@" not in e:
                    continue
                if "noreply.github.com" in e:
                    noreply.add(f"{n} <{e}>")
                else:
                    real.add(f"{n} <{e}>")
        sources.append({"repo": rname,
                         "commits_scanned": len(rr.json())})

    return {
        "username": username,
        "repos_scanned": len(sources),
        "real_count": len(real),
        "noreply_count": len(noreply),
        "real_emails": sorted(real),
        "noreply_emails": sorted(noreply),
        "sources": sources,
    }


# ---------- Mastodon (federated) ----------

def mastodon_lookup(handle: str) -> dict:
    """Accepts user@instance.tld or @user@instance.tld. No key."""
    handle = (handle or "").strip().lstrip("@")
    if "@" not in handle:
        return {"error": "expected user@instance.social format"}
    user, _, instance = handle.partition("@")
    if not user or not instance:
        return {"error": "expected user@instance.social format"}
    r = _get(f"https://{instance}/api/v1/accounts/lookup?acct={quote(user)}")
    if isinstance(r, Exception):
        return {"error": str(r)}
    if r.status_code == 404:
        return {"error": f"account not found on {instance}"}
    if r.status_code != 200:
        return {"error": f"{instance} returned {r.status_code}"}
    try:
        d = r.json()
    except Exception:
        return {"error": "non-json"}
    return {
        "id": d.get("id"),
        "acct": d.get("acct"),
        "display_name": d.get("display_name"),
        "url": d.get("url"),
        "created_at": d.get("created_at"),
        "followers_count": d.get("followers_count"),
        "following_count": d.get("following_count"),
        "statuses_count": d.get("statuses_count"),
        "bot": d.get("bot"),
        "locked": d.get("locked"),
        "note": BeautifulSoup(d.get("note") or "", "html.parser").get_text()[:1000],
        "fields": d.get("fields"),
        "avatar": d.get("avatar"),
    }


# ---------- Telegram ----------

def telegram_user(username: str) -> dict:
    """t.me/<u> page scrape — gets channel/user title, bio, member count."""
    username = (username or "").strip().lstrip("@")
    if not username:
        return {"error": "empty username"}
    r = _get(f"https://t.me/{quote(username)}")
    if isinstance(r, Exception):
        return {"error": str(r)}
    if r.status_code != 200:
        return {"error": f"t.me returned {r.status_code}"}
    soup = BeautifulSoup(r.text, "html.parser")
    title = soup.find("meta", property="og:title")
    desc = soup.find("meta", property="og:description")
    img = soup.find("meta", property="og:image")
    extra = {}
    for el in soup.select(".tgme_page_extra"):
        extra[el.get("class", ["x"])[-1]] = el.get_text(strip=True)
    members = soup.find("div", class_="tgme_page_extra")
    return {
        "username": username,
        "url": f"https://t.me/{username}",
        "title": title["content"] if title else None,
        "description": desc["content"] if desc else None,
        "image": img["content"] if img else None,
        "extra_info": (members.get_text(" | ", strip=True) if members else None),
    }


# ---------- Steam ----------

def steam_profile(username: str) -> dict:
    """Steam community XML profile (vanity URL)."""
    username = (username or "").strip()
    if not username:
        return {"error": "empty username"}
    r = _get(f"https://steamcommunity.com/id/{quote(username)}/?xml=1")
    if isinstance(r, Exception):
        return {"error": str(r)}
    if r.status_code != 200:
        return {"error": f"steam returned {r.status_code}"}
    try:
        soup = BeautifulSoup(r.text, "xml")
    except Exception:
        soup = BeautifulSoup(r.text, "html.parser")
    if soup.find("error"):
        return {"error": soup.find("error").get_text(strip=True)}
    out = {"vanity": username}
    for tag in ("steamID64", "steamID", "onlineState", "stateMessage",
                "memberSince", "location", "realname", "summary",
                "vacBanned", "tradeBanState", "isLimitedAccount",
                "customURL"):
        el = soup.find(tag)
        if el:
            out[tag] = (el.get_text(strip=True) or "").strip()
    return out


# ---------- Keybase ----------

def keybase_user(username: str) -> dict:
    username = (username or "").strip().lstrip("@")
    if not username:
        return {"error": "empty username"}
    r = _get(f"https://keybase.io/_/api/1.0/user/lookup.json"
             f"?username={quote(username)}")
    if isinstance(r, Exception):
        return {"error": str(r)}
    if r.status_code != 200:
        return {"error": f"keybase returned {r.status_code}"}
    try:
        d = r.json()
    except Exception:
        return {"error": "non-json"}
    if d.get("status", {}).get("code") != 0:
        return {"error": d.get("status", {}).get("desc",
                "keybase user not found")}
    them = (d.get("them") or {})
    profile = (them.get("profile") or {})
    proofs = (them.get("proofs_summary") or {}).get("all", [])
    keys = (them.get("public_keys") or {}).get("primary") or {}
    return {
        "username": them.get("basics", {}).get("username"),
        "full_name": profile.get("full_name"),
        "location": profile.get("location"),
        "bio": profile.get("bio"),
        "joined": _ts_to_iso(them.get("basics", {}).get("ctime")),
        "proofs": [
            {"service": p.get("proof_type"),
             "name": p.get("nametag"),
             "presentation": p.get("presentation_url")}
            for p in proofs
        ],
        "pgp_key_fingerprint": keys.get("key_fingerprint"),
    }


# ---------- npm ----------

def npm_user(username: str) -> dict:
    username = (username or "").strip().lstrip("@")
    if not username:
        return {"error": "empty username"}
    r = _get(f"https://registry.npmjs.org/-/v1/search"
             f"?text=author:{quote(username)}&size=50")
    if isinstance(r, Exception):
        return {"error": str(r)}
    if r.status_code != 200:
        return {"error": f"npm returned {r.status_code}"}
    try:
        d = r.json()
    except Exception:
        return {"error": "non-json"}
    pkgs = []
    for o in d.get("objects") or []:
        p = o.get("package") or {}
        pkgs.append({
            "name": p.get("name"),
            "version": p.get("version"),
            "description": (p.get("description") or "")[:160],
            "date": p.get("date"),
            "links": p.get("links"),
        })
    return {"username": username, "package_count": len(pkgs), "packages": pkgs}


# ---------- PGP key servers ----------

def pgp_lookup(query: str) -> dict:
    """Look up PGP keys by email or fingerprint via keys.openpgp.org."""
    query = (query or "").strip()
    if not query:
        return {"error": "empty query"}
    if "@" in query:
        url = f"https://keys.openpgp.org/vks/v1/by-email/{quote(query)}"
    else:
        url = f"https://keys.openpgp.org/vks/v1/by-fingerprint/{quote(query.upper().replace(' ', ''))}"
    r = _get(url, headers={"Accept": "application/pgp-keys"})
    if isinstance(r, Exception):
        return {"error": str(r)}
    if r.status_code == 404:
        return {"query": query, "found": False,
                "note": "no key on keys.openpgp.org"}
    if r.status_code != 200:
        return {"error": f"keyserver returned {r.status_code}"}
    body = r.text or ""
    return {
        "query": query,
        "found": True,
        "url": url,
        "key_size_bytes": len(body),
        "key_excerpt": body[:1500],
    }


# ---------- Discord invite ----------

def discord_invite(code: str) -> dict:
    """Public discord invite info (no auth needed). Returns guild + inviter."""
    code = (code or "").strip().split("/")[-1]
    if not code:
        return {"error": "empty invite code"}
    r = _get(f"https://discord.com/api/v10/invites/{quote(code)}?with_counts=true")
    if isinstance(r, Exception):
        return {"error": str(r)}
    if r.status_code == 404:
        return {"error": "invite expired or invalid"}
    if r.status_code != 200:
        return {"error": f"discord returned {r.status_code}"}
    try:
        d = r.json()
    except Exception:
        return {"error": "non-json"}
    g = d.get("guild") or {}
    return {
        "code": d.get("code"),
        "guild": {
            "id": g.get("id"),
            "name": g.get("name"),
            "description": g.get("description"),
            "verification_level": g.get("verification_level"),
            "vanity_url_code": g.get("vanity_url_code"),
            "features": g.get("features"),
            "splash": g.get("splash"),
            "icon": g.get("icon"),
        },
        "approximate_member_count": d.get("approximate_member_count"),
        "approximate_presence_count": d.get("approximate_presence_count"),
        "inviter": d.get("inviter"),
        "channel": d.get("channel"),
    }


# ---------- YouTube channel (no key, RSS) ----------

def youtube_channel(handle: str) -> dict:
    """Resolve @handle or channel-id to channel info via the public page +
    RSS feed (no Data API key needed)."""
    handle = (handle or "").strip().lstrip("@")
    if not handle:
        return {"error": "empty handle"}
    # try @handle page first to extract channelId
    if not handle.startswith("UC"):
        page = _get(f"https://www.youtube.com/@{quote(handle)}")
        if isinstance(page, Exception) or page.status_code != 200:
            return {"error": f"youtube returned {getattr(page, 'status_code', page)}"}
        m = re.search(r'"channelId":"(UC[A-Za-z0-9_-]{20,})"', page.text)
        if not m:
            return {"error": "couldn't extract channelId from page"}
        cid = m.group(1)
        title_m = re.search(r'<meta name="title" content="([^"]+)"', page.text)
        sub_m = re.search(r'(\d[\d,.]*)\s+subscribers', page.text)
    else:
        cid = handle
        page = None
        title_m = sub_m = None
    rss = _get(f"https://www.youtube.com/feeds/videos.xml?channel_id={cid}")
    videos = []
    if not isinstance(rss, Exception) and rss.status_code == 200:
        soup = BeautifulSoup(rss.text, "xml")
        for entry in soup.find_all("entry")[:15]:
            videos.append({
                "title": entry.find("title").get_text() if entry.find("title") else "",
                "published": entry.find("published").get_text() if entry.find("published") else "",
                "url": entry.find("link")["href"] if entry.find("link") else "",
            })
    return {
        "handle": handle,
        "channel_id": cid,
        "channel_url": f"https://www.youtube.com/channel/{cid}",
        "title": title_m.group(1) if title_m else None,
        "subscribers": sub_m.group(1) if sub_m else None,
        "recent_videos": videos,
    }


# ---------- Roblox ----------

def roblox_user(username: str) -> dict:
    username = (username or "").strip()
    if not username:
        return {"error": "empty username"}
    r = requests.post("https://users.roblox.com/v1/usernames/users",
                       json={"usernames": [username]},
                       headers=HEADERS, timeout=TIMEOUT)
    if r.status_code != 200:
        return {"error": f"roblox returned {r.status_code}"}
    data = r.json().get("data") or []
    if not data:
        return {"error": f"user '{username}' not found"}
    user_id = data[0].get("id")
    info = _get(f"https://users.roblox.com/v1/users/{user_id}")
    if isinstance(info, Exception):
        return {"error": str(info)}
    j = info.json()
    return {
        "id": j.get("id"),
        "name": j.get("name"),
        "display_name": j.get("displayName"),
        "description": (j.get("description") or "")[:500],
        "created": j.get("created"),
        "is_banned": j.get("isBanned"),
        "external_app_display_name": j.get("externalAppDisplayName"),
    }


# ---------- Lichess ----------

def lichess_user(username: str) -> dict:
    username = (username or "").strip()
    if not username:
        return {"error": "empty username"}
    r = _get(f"https://lichess.org/api/user/{quote(username)}")
    if isinstance(r, Exception):
        return {"error": str(r)}
    if r.status_code == 404:
        return {"error": f"user '{username}' not found"}
    if r.status_code != 200:
        return {"error": f"lichess returned {r.status_code}"}
    d = r.json()
    return {
        "id": d.get("id"),
        "username": d.get("username"),
        "title": d.get("title"),
        "online": d.get("online"),
        "created_at": _ts_to_iso((d.get("createdAt") or 0) // 1000),
        "seen_at": _ts_to_iso((d.get("seenAt") or 0) // 1000),
        "language": d.get("language"),
        "profile": d.get("profile"),
        "perfs_summary": {k: v.get("rating") for k, v in (d.get("perfs") or {}).items()},
        "playtime_total_seconds": (d.get("playTime") or {}).get("total"),
        "url": d.get("url"),
    }


# ---------- Chess.com ----------

def chesscom_user(username: str) -> dict:
    username = (username or "").strip().lower()
    if not username:
        return {"error": "empty username"}
    r = _get(f"https://api.chess.com/pub/player/{quote(username)}")
    if isinstance(r, Exception):
        return {"error": str(r)}
    if r.status_code == 404:
        return {"error": f"user '{username}' not found"}
    if r.status_code != 200:
        return {"error": f"chess.com returned {r.status_code}"}
    d = r.json()
    stats = _get(f"https://api.chess.com/pub/player/{quote(username)}/stats")
    return {
        "username": d.get("username"),
        "player_id": d.get("player_id"),
        "title": d.get("title"),
        "name": d.get("name"),
        "country": d.get("country"),
        "location": d.get("location"),
        "joined": _ts_to_iso(d.get("joined")),
        "last_online": _ts_to_iso(d.get("last_online")),
        "followers": d.get("followers"),
        "league": d.get("league"),
        "is_streamer": d.get("is_streamer"),
        "verified": d.get("verified"),
        "stats": stats.json() if not isinstance(stats, Exception) and stats.status_code == 200 else {},
    }


# ---------- TikTok (public, limited) ----------

def tiktok_public(username: str) -> dict:
    username = (username or "").strip().lstrip("@")
    if not username:
        return {"error": "empty username"}
    r = _get(f"https://www.tiktok.com/@{quote(username)}")
    if isinstance(r, Exception):
        return {"error": str(r)}
    text = r.text or ""
    if "Couldn&#x27;t find this account" in text or "Couldn't find this account" in text:
        return {"error": f"user '{username}' not found"}
    out = {"username": username, "url": f"https://www.tiktok.com/@{username}"}
    m = re.search(r'"signature":"([^"]*)"', text)
    if m:
        out["bio"] = m.group(1)
    m = re.search(r'"followerCount":(\d+)', text)
    if m:
        out["followers"] = int(m.group(1))
    m = re.search(r'"followingCount":(\d+)', text)
    if m:
        out["following"] = int(m.group(1))
    m = re.search(r'"heartCount":(\d+)', text)
    if m:
        out["hearts"] = int(m.group(1))
    m = re.search(r'"videoCount":(\d+)', text)
    if m:
        out["videos"] = int(m.group(1))
    m = re.search(r'"verified":(true|false)', text)
    if m:
        out["verified"] = m.group(1) == "true"
    return out


# ---------- GitHub SSH/PGP keys (public!) ----------

def github_pubkeys(username: str) -> dict:
    """Public SSH keys (.keys) and GPG keys (.gpg) — both endpoints are
    open by GitHub design. Useful for fingerprinting devs across systems."""
    username = (username or "").strip().lstrip("@")
    if not username:
        return {"error": "empty username"}
    ssh = _get(f"https://github.com/{quote(username)}.keys")
    gpg = _get(f"https://github.com/{quote(username)}.gpg")
    return {
        "username": username,
        "ssh_keys": (ssh.text.splitlines() if not isinstance(ssh, Exception)
                      and ssh.status_code == 200 else []),
        "gpg_present": (not isinstance(gpg, Exception) and gpg.status_code == 200
                         and len(gpg.text) > 100),
        "gpg_excerpt": (gpg.text[:1500] if not isinstance(gpg, Exception)
                         and gpg.status_code == 200 else None),
    }
