#!/usr/bin/env python3
"""
tools_username.py — Sherlock-style username sweep.

Concurrent HTTP probe across ~60 social / code / forum / creative sites
to find where a given username is registered. No API keys required.

Detection strategies per site:
  status     — site returns 200 if present, 404 if not
  body_has   — body must contain a marker string for "exists"
  body_miss  — body must NOT contain a marker string for "exists"
  json_ok    — JSON endpoint, exists when JSON is non-empty / has key
"""
from __future__ import annotations

import re
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Optional

import requests

UA = ("Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
      "(KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36")
HEADERS = {"User-Agent": UA, "Accept-Language": "en-US,en;q=0.9"}
TIMEOUT = 8

# format: (name, url_template, method, marker, category)
# methods: "status" | "body_has" | "body_miss"
SITES: list[tuple[str, str, str, Optional[str], str]] = [
    # ---- code / dev ----
    ("GitHub",          "https://api.github.com/users/{u}",        "status",   None,                             "code"),
    ("GitLab",          "https://gitlab.com/{u}",                  "status",   None,                             "code"),
    ("Codeberg",        "https://codeberg.org/{u}",                "status",   None,                             "code"),
    ("Bitbucket",       "https://bitbucket.org/{u}/",              "status",   None,                             "code"),
    ("SourceForge",     "https://sourceforge.net/u/{u}/profile/",  "body_miss","Sorry, that user could not be found", "code"),
    ("npm",             "https://www.npmjs.com/~{u}",              "status",   None,                             "code"),
    ("PyPI",            "https://pypi.org/user/{u}/",              "status",   None,                             "code"),
    ("Docker Hub",      "https://hub.docker.com/v2/users/{u}/",    "status",   None,                             "code"),
    ("CodePen",         "https://codepen.io/{u}",                  "status",   None,                             "code"),
    ("Replit",          "https://replit.com/@{u}",                 "status",   None,                             "code"),
    ("Stack Overflow",  "https://stackoverflow.com/users/{u}",     "status",   None,                             "code"),
    ("Lobsters",        "https://lobste.rs/u/{u}",                 "status",   None,                             "code"),
    ("HackerNews",      "https://news.ycombinator.com/user?id={u}","body_miss","No such user.",                  "forum"),
    ("Codeforces",      "https://codeforces.com/profile/{u}",      "body_miss","Call to undefined",              "code"),
    ("LeetCode",        "https://leetcode.com/{u}/",               "body_has", '"username":',                    "code"),
    ("HackerRank",      "https://www.hackerrank.com/{u}",          "body_has", "hackerrank.com/{u}",             "code"),
    ("CodeChef",        "https://www.codechef.com/users/{u}",      "body_miss","User not Found",                 "code"),

    # ---- social ----
    ("Reddit",          "https://www.reddit.com/user/{u}/about.json","status", None,                             "social"),
    ("Twitter / X",     "https://twitter.com/{u}",                 "status",   None,                             "social"),
    ("Mastodon Social", "https://mastodon.social/@{u}",            "status",   None,                             "social"),
    ("Telegram",        "https://t.me/{u}",                        "body_has", '"og:title"',                     "social"),
    ("Pinterest",       "https://www.pinterest.com/{u}/",          "status",   None,                             "social"),
    ("Tumblr",          "https://{u}.tumblr.com",                  "status",   None,                             "social"),
    ("Medium",          "https://medium.com/@{u}",                 "status",   None,                             "social"),
    ("DEV.to",          "https://dev.to/{u}",                      "status",   None,                             "social"),
    ("Quora",           "https://www.quora.com/profile/{u}",       "status",   None,                             "social"),
    ("About.me",        "https://about.me/{u}",                    "status",   None,                             "social"),
    ("Disqus",          "https://disqus.com/by/{u}/",              "status",   None,                             "social"),
    ("Keybase",         "https://keybase.io/{u}",                  "status",   None,                             "social"),
    ("Ko-fi",           "https://ko-fi.com/{u}",                   "status",   None,                             "social"),
    ("Patreon",         "https://www.patreon.com/{u}",             "status",   None,                             "social"),

    # ---- creative / media ----
    ("YouTube",         "https://www.youtube.com/@{u}",            "body_miss","404 Not Found",                  "media"),
    ("Twitch",          "https://www.twitch.tv/{u}",               "status",   None,                             "media"),
    ("TikTok",          "https://www.tiktok.com/@{u}",             "body_miss","Couldn't find this account",     "media"),
    ("Vimeo",           "https://vimeo.com/{u}",                   "status",   None,                             "media"),
    ("SoundCloud",      "https://soundcloud.com/{u}",              "status",   None,                             "media"),
    ("Bandcamp",        "https://{u}.bandcamp.com",                "status",   None,                             "media"),
    ("Mixcloud",        "https://www.mixcloud.com/{u}/",           "status",   None,                             "media"),
    ("Last.fm",         "https://www.last.fm/user/{u}",            "status",   None,                             "media"),
    ("Spotify",         "https://open.spotify.com/user/{u}",       "status",   None,                             "media"),
    ("DeviantArt",      "https://www.deviantart.com/{u}",          "status",   None,                             "media"),
    ("Behance",         "https://www.behance.net/{u}",             "status",   None,                             "media"),
    ("Dribbble",        "https://dribbble.com/{u}",                "status",   None,                             "media"),
    ("Flickr",          "https://www.flickr.com/people/{u}",       "status",   None,                             "media"),
    ("Imgur",           "https://imgur.com/user/{u}",              "status",   None,                             "media"),
    ("VSCO",            "https://vsco.co/{u}/gallery",             "status",   None,                             "media"),
    ("Letterboxd",      "https://letterboxd.com/{u}/",             "status",   None,                             "media"),
    ("AO3",             "https://archiveofourown.org/users/{u}",   "status",   None,                             "media"),
    ("Wattpad",         "https://www.wattpad.com/user/{u}",        "status",   None,                             "media"),

    # ---- gaming ----
    ("Steam",           "https://steamcommunity.com/id/{u}",       "body_miss","The specified profile could not be found", "gaming"),
    ("Roblox",          "https://www.roblox.com/users/profile?username={u}","status", None,                      "gaming"),
    ("Chess.com",       "https://www.chess.com/member/{u}",        "status",   None,                             "gaming"),
    ("Lichess",         "https://lichess.org/@/{u}",               "status",   None,                             "gaming"),
    ("ItchIO",          "https://{u}.itch.io",                     "status",   None,                             "gaming"),

    # ---- blogs / publishing ----
    ("WordPress.com",   "https://{u}.wordpress.com",               "status",   None,                             "blog"),
    ("Blogger",         "https://{u}.blogspot.com",                "status",   None,                             "blog"),
    ("Substack",        "https://{u}.substack.com",                "status",   None,                             "blog"),
    ("LiveJournal",     "https://{u}.livejournal.com",             "status",   None,                             "blog"),
    ("Slideshare",      "https://www.slideshare.net/{u}",          "status",   None,                             "blog"),
    ("Issuu",           "https://issuu.com/{u}",                   "status",   None,                             "blog"),
    ("Smashwords",      "https://www.smashwords.com/profile/view/{u}","body_miss","Smashwords - Page Not Found", "blog"),

    # ---- fitness / lifestyle ----
    ("Strava",          "https://www.strava.com/athletes/{u}",     "status",   None,                             "lifestyle"),
    ("Goodreads",       "https://www.goodreads.com/{u}",           "status",   None,                             "lifestyle"),
    ("Trello",          "https://trello.com/{u}",                  "status",   None,                             "lifestyle"),
    ("ProductHunt",     "https://www.producthunt.com/@{u}",        "status",   None,                             "lifestyle"),
    ("Pastebin",        "https://pastebin.com/u/{u}",              "status",   None,                             "code"),
    ("Gravatar",        "https://gravatar.com/{u}",                "status",   None,                             "social"),
]

USERNAME_RE = re.compile(r"^[A-Za-z0-9._\-]{1,40}$")


def _check(site: tuple, username: str) -> dict:
    name, tmpl, method, marker, cat = site
    url = tmpl.format(u=username)
    try:
        # HEAD doesn't work for JS sites — use GET with small read timeout
        r = requests.get(url, headers=HEADERS, timeout=TIMEOUT,
                         allow_redirects=True)
    except Exception as e:
        return {"site": name, "category": cat, "url": url,
                "exists": False, "error": str(e)[:100]}

    text = r.text if method != "status" else ""
    marker_filled = (marker or "").format(u=username)
    exists: Optional[bool] = None

    if method == "status":
        exists = (200 <= r.status_code < 300)
    elif method == "body_has":
        exists = (r.status_code < 400 and marker_filled.lower() in text.lower())
    elif method == "body_miss":
        # marker is the "user not found" string — absent => exists
        if r.status_code >= 400 and r.status_code != 404:
            exists = None  # site is rate-limiting / blocking
        else:
            exists = marker_filled.lower() not in text.lower()

    return {
        "site": name,
        "category": cat,
        "url": url,
        "status": r.status_code,
        "exists": exists,
    }


def username_sweep(username: str, categories: Optional[list[str]] = None,
                    workers: int = 25) -> dict:
    """Probe ~60 sites concurrently. Returns per-site found/not-found.

    `categories` optionally filters to a subset (code/social/media/gaming/blog/lifestyle/forum).
    """
    username = (username or "").strip().lstrip("@")
    if not username:
        return {"error": "empty username"}
    if not USERNAME_RE.match(username):
        return {"error": "username must be 1-40 chars: A-Z, a-z, 0-9, dot, underscore, hyphen"}

    # categories can arrive as None, "", "code,social", or ["code","social"]
    if isinstance(categories, str):
        categories = [c.strip() for c in categories.split(",") if c.strip()]
    sites = SITES
    if categories:
        wanted = {c.lower() for c in categories}
        sites = [s for s in SITES if s[4].lower() in wanted]

    found, not_found, errored = [], [], []
    with ThreadPoolExecutor(max_workers=workers) as ex:
        futs = {ex.submit(_check, s, username): s for s in sites}
        for fut in as_completed(futs):
            try:
                res = fut.result()
            except Exception as e:
                res = {"site": futs[fut][0], "error": str(e)[:120],
                       "exists": False}
            if res.get("error") or res.get("exists") is None:
                errored.append(res)
            elif res["exists"]:
                found.append(res)
            else:
                not_found.append(res)

    found.sort(key=lambda r: (r["category"], r["site"].lower()))
    not_found.sort(key=lambda r: (r["category"], r["site"].lower()))
    errored.sort(key=lambda r: r["site"].lower())

    return {
        "username": username,
        "sites_checked": len(sites),
        "found_count": len(found),
        "not_found_count": len(not_found),
        "error_count": len(errored),
        "found": found,
        "not_found": [{"site": r["site"], "category": r["category"],
                        "url": r["url"]} for r in not_found],
        "errored": errored,
    }


def list_username_categories() -> dict:
    """Helper: returns the category breakdown of supported sites."""
    cats: dict[str, list[str]] = {}
    for name, _, _, _, cat in SITES:
        cats.setdefault(cat, []).append(name)
    return {"categories": cats, "total_sites": len(SITES)}
