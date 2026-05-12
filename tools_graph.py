#!/usr/bin/env python3
"""
tools_graph.py — local link-intelligence graph.

A JSON-on-disk entity/edge store for tying together evidence collected
by the other tools_* modules. Designed to power a Maltego-style
investigation workflow without the operational weight of a Neo4j
deployment — start here, port to Neo4j when scale demands it.

Entity types:
  domain, subdomain, ip, asn, cert, email, phone, username,
  wallet, txid, social, company, file, url, note

Edges carry a `kind` and arbitrary `meta`. Common kinds:
  resolves_to, hosts, redirects_to, shares_cert, shares_asn,
  sent_tx_to, received_tx_from, owns, controls, registered_by,
  references, mentioned_in, reuses_analytics_id, reuses_favicon

Storage: ~/.local/share/safenest/graph.json by default (overridable via
$SAFENEST_GRAPH_PATH). Atomic writes via tmpfile+rename so a crash
mid-write doesn't corrupt the store.

Exports:
  - JSON         (full graph dump)
  - GraphML      (Gephi / Cytoscape / yEd / Maltego import)
  - CSV nodes/edges (spreadsheet workflows)
"""
from __future__ import annotations

import csv
import io
import json
import os
import re
import tempfile
import threading
import time
from collections import defaultdict
from pathlib import Path
from typing import Optional
from xml.sax.saxutils import escape as xml_escape

# ---------- storage ----------

_DEFAULT_PATH = Path.home() / ".local" / "share" / "safenest" / "graph.json"
GRAPH_PATH = Path(os.environ.get("SAFENEST_GRAPH_PATH") or _DEFAULT_PATH)
_LOCK = threading.RLock()

VALID_TYPES = {
    "domain", "subdomain", "ip", "asn", "cert", "email", "phone",
    "username", "wallet", "txid", "social", "company", "file",
    "url", "note",
    # JS-intel / link-correlation additions (module #1)
    "tracking_id",   # canonical id form "<kind>:<value>", e.g. "ga4:G-XYZ"
    "script",        # canonical id is the sha256 hex of the script body
}

# Entity-type heuristics for auto-classification when the caller doesn't
# pass an explicit type. Order matters — first match wins.
_TYPE_RULES = [
    (re.compile(r"^0x[0-9a-fA-F]{40}$"),                  "wallet"),
    (re.compile(r"^T[1-9A-HJ-NP-Za-km-z]{33}$"),          "wallet"),
    (re.compile(r"^(bc1[0-9ac-hj-np-z]{8,87}|"
                r"[13][a-km-zA-HJ-NP-Z1-9]{25,34})$"),    "wallet"),
    (re.compile(r"^(0x)?[0-9a-fA-F]{64}$"),               "txid"),
    (re.compile(r"^AS\d+$", re.I),                        "asn"),
    (re.compile(r"^\d{1,3}(\.\d{1,3}){3}$"),              "ip"),
    (re.compile(r"^[a-fA-F0-9:]+$"),                      "ip"),  # IPv6 (rough)
    (re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$"),           "email"),
    (re.compile(r"^\+?\d[\d\s\-().]{6,}\d$"),             "phone"),
    (re.compile(r"^https?://", re.I),                     "url"),
    # domain catch-all (lowest priority before fallback)
    (re.compile(r"^([a-z0-9-]+\.)+[a-z]{2,}$", re.I),     "domain"),
]


def _empty_graph() -> dict:
    return {
        "meta": {
            "created_ts": int(time.time()),
            "schema_version": 1,
        },
        "nodes": {},   # id -> {id, type, label, attrs, created_ts, updated_ts, tags}
        "edges": [],   # list of {src, dst, kind, meta, ts}
    }


def _ensure_dir():
    GRAPH_PATH.parent.mkdir(parents=True, exist_ok=True)


def _load() -> dict:
    _ensure_dir()
    if not GRAPH_PATH.exists():
        return _empty_graph()
    try:
        with open(GRAPH_PATH, "r", encoding="utf-8") as fh:
            data = json.load(fh)
        # forward-compat: tolerate missing keys
        data.setdefault("meta", {"schema_version": 1})
        data.setdefault("nodes", {})
        data.setdefault("edges", [])
        return data
    except Exception:
        # don't silently wipe — surface via error in caller
        raise


def _save(data: dict):
    _ensure_dir()
    data["meta"]["updated_ts"] = int(time.time())
    # atomic write
    fd, tmp = tempfile.mkstemp(prefix=".graph-", suffix=".json",
                                dir=str(GRAPH_PATH.parent))
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            json.dump(data, fh, indent=2, ensure_ascii=False)
        os.replace(tmp, GRAPH_PATH)
    except Exception:
        try:
            os.unlink(tmp)
        except Exception:
            pass
        raise


# ---------- normalization ----------

def _norm_id(entity_id: str, etype: str) -> str:
    """Canonical form for entity IDs so dedupe works across tool sources."""
    s = (entity_id or "").strip()
    if not s:
        return s
    if etype in ("domain", "subdomain", "email", "url"):
        s = s.lower()
    if etype == "email":
        s = s.strip()
    if etype == "asn":
        m = re.match(r"^as\s*(\d+)$", s, re.I)
        if m:
            s = f"AS{m.group(1)}"
    if etype == "txid":
        if s.startswith("0x") or s.startswith("0X"):
            s = "0x" + s[2:].lower()
        else:
            s = s.lower()
    if etype == "wallet" and s.startswith("0x"):
        # ETH addresses: normalize to lowercase (we lose EIP-55 checksum,
        # but gain dedupe across mixed-case spellings)
        s = "0x" + s[2:].lower()
    if etype == "script":
        # sha256 hex — case-insensitive
        s = s.lower()
    if etype == "tracking_id" and ":" in s:
        # canonical form "<kind>:<value>" — kind lowercase, value preserves
        # case (GA / pixel IDs are case-sensitive)
        kind, _, rest = s.partition(":")
        s = f"{kind.lower()}:{rest}"
    return s


def _infer_type(entity_id: str) -> Optional[str]:
    s = (entity_id or "").strip()
    for rx, t in _TYPE_RULES:
        if rx.match(s):
            return t
    return None


# ============== public API ==============

def add_entity(id: str, type: str = "", label: str = "",
               attrs: Optional[dict] = None, tags: Optional[list] = None) -> dict:
    """Insert-or-update an entity. Returns the canonical node dict."""
    if not id:
        return {"error": "id is required"}
    if type and type not in VALID_TYPES:
        return {"error": f"type must be one of {sorted(VALID_TYPES)}"}
    etype = type or _infer_type(id) or "note"
    eid = _norm_id(id, etype)
    if not eid:
        return {"error": "empty id after normalization"}
    with _LOCK:
        g = _load()
        now = int(time.time())
        existing = g["nodes"].get(eid)
        if existing:
            if label:
                existing["label"] = label
            if attrs:
                merged = dict(existing.get("attrs") or {})
                merged.update(attrs)
                existing["attrs"] = merged
            if tags:
                existing_tags = set(existing.get("tags") or [])
                existing_tags.update(tags)
                existing["tags"] = sorted(existing_tags)
            existing["updated_ts"] = now
            node = existing
        else:
            node = {
                "id": eid,
                "type": etype,
                "label": label or eid,
                "attrs": dict(attrs or {}),
                "tags": sorted(set(tags or [])),
                "created_ts": now,
                "updated_ts": now,
            }
            g["nodes"][eid] = node
        _save(g)
    return {"ok": True, "node": node}


def add_edge(src: str, dst: str, kind: str = "references",
             meta: Optional[dict] = None,
             src_type: str = "", dst_type: str = "") -> dict:
    """Add an edge between two entities. Both entities are auto-created
    if they don't exist yet (with inferred types)."""
    if not src or not dst:
        return {"error": "src and dst are required"}
    if not kind:
        return {"error": "kind is required"}
    s_type = src_type or _infer_type(src) or "note"
    d_type = dst_type or _infer_type(dst) or "note"
    sid = _norm_id(src, s_type)
    did = _norm_id(dst, d_type)
    with _LOCK:
        g = _load()
        now = int(time.time())
        if sid not in g["nodes"]:
            g["nodes"][sid] = {
                "id": sid, "type": s_type, "label": sid,
                "attrs": {}, "tags": [],
                "created_ts": now, "updated_ts": now,
            }
        if did not in g["nodes"]:
            g["nodes"][did] = {
                "id": did, "type": d_type, "label": did,
                "attrs": {}, "tags": [],
                "created_ts": now, "updated_ts": now,
            }
        # dedupe: don't insert an identical (src, dst, kind) edge twice
        for e in g["edges"]:
            if e["src"] == sid and e["dst"] == did and e["kind"] == kind:
                if meta:
                    merged = dict(e.get("meta") or {})
                    merged.update(meta)
                    e["meta"] = merged
                e["ts"] = now
                _save(g)
                return {"ok": True, "edge": e, "updated": True}
        edge = {
            "src": sid, "dst": did, "kind": kind,
            "meta": dict(meta or {}), "ts": now,
        }
        g["edges"].append(edge)
        _save(g)
    return {"ok": True, "edge": edge, "created": True}


def remove_entity(id: str) -> dict:
    """Remove an entity AND every edge touching it."""
    if not id:
        return {"error": "id required"}
    with _LOCK:
        g = _load()
        # try matching against several normalized forms — caller may not
        # know the entity's type
        candidates = {id, _norm_id(id, _infer_type(id) or "note")}
        match = next((c for c in candidates if c in g["nodes"]), None)
        if not match:
            return {"error": f"no entity matches {id!r}"}
        del g["nodes"][match]
        before = len(g["edges"])
        g["edges"] = [e for e in g["edges"]
                       if e["src"] != match and e["dst"] != match]
        removed_edges = before - len(g["edges"])
        _save(g)
    return {"ok": True, "removed_entity": match, "removed_edges": removed_edges}


def get_entity(id: str) -> dict:
    """Look up one entity by id, with its neighbors."""
    with _LOCK:
        g = _load()
        candidates = {id, _norm_id(id, _infer_type(id) or "note")}
        match = next((c for c in candidates if c in g["nodes"]), None)
        if not match:
            return {"error": f"no entity matches {id!r}"}
        node = g["nodes"][match]
        out_edges = [e for e in g["edges"] if e["src"] == match]
        in_edges = [e for e in g["edges"] if e["dst"] == match]
    return {
        "node": node,
        "out_edges": out_edges,
        "in_edges": in_edges,
        "degree": len(out_edges) + len(in_edges),
    }


def search(query: str = "", type: str = "", tag: str = "", limit: int = 100) -> dict:
    """Substring search across ids, labels, and attr values. Optional
    filter by type and/or tag."""
    q = (query or "").strip().lower()
    try:
        limit = max(1, min(2000, int(limit) if limit else 100))
    except Exception:
        limit = 100
    with _LOCK:
        g = _load()
        hits = []
        for node in g["nodes"].values():
            if type and node["type"] != type:
                continue
            if tag and tag not in (node.get("tags") or []):
                continue
            if q:
                hay = " ".join([
                    node["id"], node.get("label", ""),
                    " ".join(map(str, (node.get("attrs") or {}).values())),
                    " ".join(node.get("tags") or []),
                ]).lower()
                if q not in hay:
                    continue
            hits.append(node)
            if len(hits) >= limit:
                break
    return {"query": q, "type_filter": type, "tag_filter": tag,
            "count": len(hits), "results": hits}


def neighbors(id: str, depth: int = 1, limit: int = 200) -> dict:
    """BFS subgraph rooted at `id`. depth=1 returns immediate neighbors,
    depth=2 their neighbors, etc."""
    try:
        depth = max(1, min(5, int(depth) if depth else 1))
    except Exception:
        depth = 1
    try:
        limit = max(1, min(2000, int(limit) if limit else 200))
    except Exception:
        limit = 200
    with _LOCK:
        g = _load()
        candidates = {id, _norm_id(id, _infer_type(id) or "note")}
        start = next((c for c in candidates if c in g["nodes"]), None)
        if not start:
            return {"error": f"no entity matches {id!r}"}

        # build adjacency once
        adj = defaultdict(list)
        for e in g["edges"]:
            adj[e["src"]].append((e["dst"], e))
            adj[e["dst"]].append((e["src"], e))

        seen_nodes = {start}
        seen_edges = []
        frontier = {start}
        for _ in range(depth):
            next_frontier = set()
            for n in frontier:
                for nb, e in adj.get(n, []):
                    edge_key = (e["src"], e["dst"], e["kind"])
                    if edge_key not in {(s["src"], s["dst"], s["kind"]) for s in seen_edges}:
                        seen_edges.append(e)
                    if nb not in seen_nodes:
                        seen_nodes.add(nb)
                        next_frontier.add(nb)
                    if len(seen_nodes) >= limit:
                        break
                if len(seen_nodes) >= limit:
                    break
            frontier = next_frontier
            if not frontier or len(seen_nodes) >= limit:
                break

        nodes_out = [g["nodes"][n] for n in seen_nodes if n in g["nodes"]]
    return {
        "root": start,
        "depth": depth,
        "node_count": len(nodes_out),
        "edge_count": len(seen_edges),
        "nodes": nodes_out,
        "edges": seen_edges,
    }


def stats() -> dict:
    """Counts by type, edge counts by kind, top connected entities."""
    with _LOCK:
        g = _load()
        type_counts: dict = defaultdict(int)
        for n in g["nodes"].values():
            type_counts[n["type"]] += 1
        kind_counts: dict = defaultdict(int)
        for e in g["edges"]:
            kind_counts[e["kind"]] += 1
        degree: dict = defaultdict(int)
        for e in g["edges"]:
            degree[e["src"]] += 1
            degree[e["dst"]] += 1
        top = sorted(degree.items(), key=lambda kv: -kv[1])[:10]
        top_nodes = [{
            "id": k,
            "type": g["nodes"][k]["type"] if k in g["nodes"] else "?",
            "degree": v,
        } for k, v in top]
    return {
        "path": str(GRAPH_PATH),
        "node_count": sum(type_counts.values()),
        "edge_count": sum(kind_counts.values()),
        "by_type": dict(type_counts),
        "by_kind": dict(kind_counts),
        "top_connected": top_nodes,
    }


def clear_graph(confirm: str = "") -> dict:
    """DESTRUCTIVE. Pass confirm='yes' to actually wipe the graph file."""
    if confirm != "yes":
        return {"error": "pass confirm='yes' to wipe the graph"}
    with _LOCK:
        _save(_empty_graph())
    return {"ok": True, "cleared": True, "path": str(GRAPH_PATH)}


# ============== exports ==============

def export_json() -> dict:
    """Return the full graph as a dict (caller serializes/downloads it)."""
    with _LOCK:
        return _load()


def export_graphml() -> str:
    """Emit GraphML (Gephi/Cytoscape/yEd/Maltego-compatible)."""
    with _LOCK:
        g = _load()
    parts = [
        '<?xml version="1.0" encoding="UTF-8"?>',
        '<graphml xmlns="http://graphml.graphdrawing.org/xmlns"',
        '  xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"',
        '  xsi:schemaLocation="http://graphml.graphdrawing.org/xmlns '
        'http://graphml.graphdrawing.org/xmlns/1.0/graphml.xsd">',
        '<key id="d_type" for="node" attr.name="type" attr.type="string"/>',
        '<key id="d_label" for="node" attr.name="label" attr.type="string"/>',
        '<key id="d_tags" for="node" attr.name="tags" attr.type="string"/>',
        '<key id="d_attrs" for="node" attr.name="attrs" attr.type="string"/>',
        '<key id="d_kind" for="edge" attr.name="kind" attr.type="string"/>',
        '<key id="d_meta" for="edge" attr.name="meta" attr.type="string"/>',
        '<graph id="safenest" edgedefault="directed">',
    ]
    for node in g["nodes"].values():
        nid = xml_escape(node["id"])
        parts.append(f'<node id="{nid}">')
        parts.append(f'  <data key="d_type">{xml_escape(node["type"])}</data>')
        parts.append(f'  <data key="d_label">{xml_escape(node.get("label", ""))}</data>')
        parts.append(f'  <data key="d_tags">{xml_escape(",".join(node.get("tags") or []))}</data>')
        parts.append(f'  <data key="d_attrs">{xml_escape(json.dumps(node.get("attrs") or {}, ensure_ascii=False))}</data>')
        parts.append('</node>')
    for i, e in enumerate(g["edges"]):
        parts.append(
            f'<edge id="e{i}" source="{xml_escape(e["src"])}" target="{xml_escape(e["dst"])}">'
        )
        parts.append(f'  <data key="d_kind">{xml_escape(e["kind"])}</data>')
        parts.append(f'  <data key="d_meta">{xml_escape(json.dumps(e.get("meta") or {}, ensure_ascii=False))}</data>')
        parts.append('</edge>')
    parts.append('</graph></graphml>')
    return "\n".join(parts)


def export_csv() -> dict:
    """Return CSV strings for nodes and edges (spreadsheet workflows)."""
    with _LOCK:
        g = _load()
    nbuf = io.StringIO()
    nw = csv.writer(nbuf, quoting=csv.QUOTE_ALL)
    nw.writerow(["id", "type", "label", "tags", "attrs",
                  "created_ts", "updated_ts"])
    for node in g["nodes"].values():
        nw.writerow([
            node["id"], node["type"], node.get("label", ""),
            ",".join(node.get("tags") or []),
            json.dumps(node.get("attrs") or {}, ensure_ascii=False),
            node.get("created_ts", ""), node.get("updated_ts", ""),
        ])
    ebuf = io.StringIO()
    ew = csv.writer(ebuf, quoting=csv.QUOTE_ALL)
    ew.writerow(["src", "dst", "kind", "meta", "ts"])
    for e in g["edges"]:
        ew.writerow([
            e["src"], e["dst"], e["kind"],
            json.dumps(e.get("meta") or {}, ensure_ascii=False),
            e.get("ts", ""),
        ])
    return {"nodes_csv": nbuf.getvalue(), "edges_csv": ebuf.getvalue()}


# ============== ingestion helpers ==============
# These let the dashboard turn a tool result into graph entries without
# the caller having to manually pull out the right fields.

def ingest_domain_scrape(row: dict, source: str = "scraper") -> dict:
    """Pull entities/edges from one row of domain_scraper output."""
    if not row or not row.get("target"):
        return {"error": "empty row"}
    added = []
    target = row["target"]
    inp = row.get("input_domain") or ""
    add_entity(target, "domain", tags=[source]); added.append(target)
    if inp and inp != target:
        add_entity(inp, "domain", tags=[source]); added.append(inp)
        add_edge(inp, target, "has_subdomain",
                  meta={"source": source}) if target.endswith("." + inp) \
            else add_edge(inp, target, "references", meta={"source": source})
    final = row.get("final_url") or ""
    if final and final != target:
        add_entity(final, "url", tags=[source])
        add_edge(target, final, "redirects_to",
                  meta={"source": source, "status": row.get("status")})
        added.append(final)
    for link in (row.get("privacy_links") or "").split(";"):
        link = link.strip()
        if link:
            add_entity(link, "url", tags=[source, "privacy_link"])
            add_edge(target, link, "references", meta={"source": source})
            added.append(link)
    return {"ok": True, "added_or_touched": added}


def ingest_whois(target: str, whois_result: dict, source: str = "whois") -> dict:
    """WHOIS lookup → registrant email, registrar, name servers."""
    if not target or not whois_result:
        return {"error": "missing target/whois"}
    add_entity(target, "domain", tags=[source])
    fields = whois_result.get("fields") or {}
    out = []
    for email in (fields.get("emails") or []):
        if email and "@" in email:
            add_entity(email, "email", tags=[source])
            add_edge(target, email, "registered_by", meta={"source": source})
            out.append(email)
    for ns in (fields.get("name_servers") or []):
        if ns:
            add_entity(ns, "domain", tags=[source])
            add_edge(target, ns, "uses_ns", meta={"source": source})
            out.append(ns)
    for reg in (fields.get("registrar") or []):
        if reg:
            add_entity(reg, "company", tags=[source])
            add_edge(target, reg, "registered_via", meta={"source": source})
            out.append(reg)
    return {"ok": True, "target": target, "added": out}


def ingest_dns(target: str, dns_result: dict, source: str = "dns") -> dict:
    """DNS records → A/AAAA IPs, MX hosts, CNAME chains."""
    if not target or not dns_result:
        return {"error": "missing target/dns"}
    add_entity(target, "domain", tags=[source])
    out = []
    recs = dns_result.get("records") or {}
    for rec in (recs.get("A") or []) + (recs.get("AAAA") or []):
        add_entity(rec, "ip", tags=[source])
        add_edge(target, rec, "resolves_to", meta={"source": source})
        out.append(rec)
    for mx in (recs.get("MX") or []):
        host = mx.split()[-1].rstrip(".") if isinstance(mx, str) else None
        if host:
            add_entity(host, "domain", tags=[source])
            add_edge(target, host, "has_mx", meta={"source": source})
            out.append(host)
    for cname in (recs.get("CNAME") or []):
        host = cname.rstrip(".") if isinstance(cname, str) else None
        if host:
            add_entity(host, "domain", tags=[source])
            add_edge(target, host, "cname_to", meta={"source": source})
            out.append(host)
    return {"ok": True, "target": target, "added": out}


def ingest_ip_info(ip: str, ipinfo: dict, source: str = "ipinfo") -> dict:
    """IP geolocation + ASN attribution."""
    if not ip or not ipinfo:
        return {"error": "missing ip/ipinfo"}
    add_entity(ip, "ip", tags=[source],
                attrs={k: ipinfo.get(k) for k in ("country", "region", "city",
                                                    "org", "isp", "asn")
                       if ipinfo.get(k)})
    out = []
    asn = ipinfo.get("asn") or ""
    if asn:
        asn_id = asn if str(asn).upper().startswith("AS") else f"AS{asn}"
        add_entity(asn_id, "asn", tags=[source])
        add_edge(ip, asn_id, "in_asn", meta={"source": source})
        out.append(asn_id)
    return {"ok": True, "ip": ip, "added": out}


def ingest_wallet(address: str, chain: str = "eth", source: str = "blockchain",
                   info: Optional[dict] = None) -> dict:
    """Add a wallet entity with chain metadata."""
    if not address:
        return {"error": "missing address"}
    attrs = {"chain": chain}
    if info and isinstance(info, dict):
        for k in ("balance_eth", "balance_btc", "balance_trx", "is_contract",
                  "tx_count", "first_seen_iso", "last_seen_iso"):
            if info.get(k) is not None:
                attrs[k] = info[k]
    add_entity(address, "wallet", tags=[source, f"chain:{chain}"], attrs=attrs)
    return {"ok": True, "address": address}


def ingest_wallet_txs(address: str, chain: str, txs_result: dict,
                       source: str = "blockchain") -> dict:
    """Wallet → recipient edges from a wallet_txs result. Tops out at the
    first 100 counterparties to keep the graph manageable."""
    if not txs_result or "transactions" not in txs_result:
        return {"error": "missing transactions list"}
    add_entity(address, "wallet", tags=[source, f"chain:{chain}"])
    added = []
    seen_pairs: set = set()
    for t in (txs_result.get("transactions") or [])[:500]:
        direction = t.get("direction")
        if direction == "out":
            counterparty = t.get("to")
            kind = "sent_tx_to"
        elif direction == "in":
            counterparty = t.get("from")
            kind = "received_tx_from"
        else:
            continue
        if not counterparty:
            continue
        if (counterparty, kind) in seen_pairs:
            continue
        seen_pairs.add((counterparty, kind))
        if len(seen_pairs) > 100:
            break
        add_edge(address, counterparty, kind,
                  meta={"source": source, "chain": chain,
                        "tx_hash": t.get("hash"),
                        "ts": t.get("ts")},
                  src_type="wallet", dst_type="wallet")
        added.append(counterparty)
    return {"ok": True, "address": address, "added_counterparties": added}


def ingest_wallet_risk(risk_result: dict, source: str = "blockchain") -> dict:
    """Attach risk score + flags to an existing wallet entity."""
    if not risk_result or "address" not in risk_result:
        return {"error": "missing risk result"}
    addr = risk_result["address"]
    chain = risk_result.get("chain", "eth")
    add_entity(addr, "wallet", tags=[source, f"chain:{chain}",
                                       f"risk:{risk_result.get('score_band', 'unknown')}"],
                attrs={
                    "risk_score": risk_result.get("score"),
                    "risk_band": risk_result.get("score_band"),
                    "risk_flags": [f["id"] for f in (risk_result.get("flags") or [])],
                })
    return {"ok": True, "address": addr,
            "score": risk_result.get("score"),
            "flags": [f["id"] for f in (risk_result.get("flags") or [])]}


def ingest_js_intel(host: str, result: dict, source: str = "js_intel") -> dict:
    """Persist a tools_js_intel.js_analyze() result into the graph.

    For each artifact we create (or update) an entity and an edge from
    the Domain node:

      tracking_id   Domain -[uses_analytics_id]-> TrackingId
                    id = "<kind>:<value>"  (canonical via _norm_id)
      script        Domain -[loads_script]-> Script
                    id = sha256 hex; attrs preserve src/host/size
      wallet        Domain -[references_wallet]-> Wallet
                    id = normalized address; attrs.chain

    Idempotent — every helper (add_entity, add_edge) already dedupes,
    so repeated scans of the same target only refresh timestamps.

    Returns counts plus the host id so the caller can immediately run
    a correlation query."""
    if not host:
        return {"error": "host required"}
    if not isinstance(result, dict):
        return {"error": "result must be a dict"}

    host_id = _norm_id(host, "domain")
    add_entity(host_id, "domain", tags=[source])

    stats = {"tracking_ids": 0, "scripts": 0, "wallets": 0, "edges": 0}

    for t in (result.get("tracking_ids") or []):
        kind = (t.get("kind") or "").strip().lower()
        val = (t.get("id") or "").strip()
        if not kind or not val:
            continue
        tid = f"{kind}:{val}"
        add_entity(tid, "tracking_id", label=tid,
                    tags=[source, f"kind:{kind}"],
                    attrs={"kind": kind, "value": val})
        add_edge(host_id, tid, "uses_analytics_id",
                  meta={"source": source, "kind": kind},
                  src_type="domain", dst_type="tracking_id")
        stats["tracking_ids"] += 1
        stats["edges"] += 1

    for s in (result.get("scripts") or []):
        sha = (s.get("sha256") or "").strip().lower()
        if not sha or len(sha) != 64:
            continue
        attrs = {k: s.get(k) for k in ("src", "host", "size", "truncated")
                 if s.get(k) is not None}
        add_entity(sha, "script", label=sha[:16],
                    tags=[source] + ([f"host:{s['host']}"] if s.get("host") else []),
                    attrs=attrs)
        add_edge(host_id, sha, "loads_script",
                  meta={"source": source, "src": s.get("src")},
                  src_type="domain", dst_type="script")
        stats["scripts"] += 1
        stats["edges"] += 1

    wr = result.get("wallet_refs") or {}
    for chain in ("eth", "tron", "btc", "sol"):
        for addr in (wr.get(chain) or []):
            if not addr:
                continue
            add_entity(addr, "wallet", tags=[source, f"chain:{chain}"],
                        attrs={"chain": chain, "discovered_via": source})
            add_edge(host_id, addr, "references_wallet",
                      meta={"source": source, "chain": chain},
                      src_type="domain", dst_type="wallet")
            stats["wallets"] += 1
            stats["edges"] += 1

    return {"ok": True, "host": host_id, **stats}


def find_correlations(host: str, tracking_ids: Optional[list] = None,
                      scripts: Optional[list] = None,
                      wallets: Optional[dict] = None) -> dict:
    """For a freshly-scanned host plus its extracted signals, return the
    OTHER domains in the graph that share any of those signals.

    Two callers in mind:
      1. tools_js_intel.js_analyze, immediately after ingest_js_intel,
         to enrich the result with "this site shares N IDs with M other
         domains."
      2. an analyst manually probing the graph for pivots — in this
         mode only `host` is passed and we derive the signal lists
         from the host's existing out-edges in the graph.

    The host parameter is filtered out of the matched-domain lists so
    the just-ingested self-references don't count as correlations."""
    host_id = _norm_id(host, "domain") if host else ""
    if not host_id:
        return {"error": "host required"}

    # If the caller didn't pass signal lists, derive them from the
    # host's existing out-edges. Lets js_correlate(host) work standalone.
    if tracking_ids is None and scripts is None and wallets is None:
        node = get_entity(host_id)
        if "error" in node:
            return {"error": node["error"]}
        out_edges = node.get("out_edges") or []
        with _LOCK:
            g = _load()
            nodes = g["nodes"]
        derived_tracking, derived_scripts = [], []
        derived_wallets: dict = {"eth": [], "tron": [], "btc": [], "sol": []}
        for e in out_edges:
            kind, dst = e.get("kind"), e.get("dst")
            target = nodes.get(dst)
            if not target:
                continue
            if kind == "uses_analytics_id" and target.get("type") == "tracking_id":
                attrs = target.get("attrs") or {}
                derived_tracking.append({
                    "kind": attrs.get("kind", ""),
                    "id":   attrs.get("value", ""),
                })
            elif kind == "loads_script" and target.get("type") == "script":
                derived_scripts.append({
                    "sha256": target["id"],
                    "src":  (target.get("attrs") or {}).get("src"),
                    "host": (target.get("attrs") or {}).get("host"),
                })
            elif kind == "references_wallet" and target.get("type") == "wallet":
                chain = (target.get("attrs") or {}).get("chain", "eth")
                derived_wallets.setdefault(chain, []).append(target["id"])
        tracking_ids = derived_tracking
        scripts = derived_scripts
        wallets = derived_wallets

    def _domains_pointing_to(node_id: str, kind: str) -> list:
        """All Domain entities with a `kind` edge to node_id."""
        e = get_entity(node_id)
        if "error" in e:
            return []
        seen, out = set(), []
        for edge in (e.get("in_edges") or []):
            if edge.get("kind") != kind:
                continue
            src = edge.get("src")
            if not src or src == host_id or src in seen:
                continue
            seen.add(src)
            out.append(src)
        return sorted(out)

    tid_hits = []
    for t in (tracking_ids or []):
        kind = (t.get("kind") or "").strip().lower()
        val = (t.get("id") or "").strip()
        if not kind or not val:
            continue
        node = f"{kind}:{val}"
        others = _domains_pointing_to(_norm_id(node, "tracking_id"),
                                       "uses_analytics_id")
        if others:
            tid_hits.append({"kind": kind, "id": val,
                             "shared_with": others,
                             "shared_count": len(others)})

    script_hits = []
    for s in (scripts or []):
        sha = (s.get("sha256") or "").strip().lower()
        if not sha or len(sha) != 64:
            continue
        others = _domains_pointing_to(sha, "loads_script")
        if others:
            script_hits.append({"sha256": sha,
                                "src": s.get("src"),
                                "host": s.get("host"),
                                "shared_with": others,
                                "shared_count": len(others)})

    wallet_hits = []
    if wallets:
        for chain in ("eth", "tron", "btc", "sol"):
            for addr in (wallets.get(chain) or []):
                if not addr:
                    continue
                others = _domains_pointing_to(_norm_id(addr, "wallet"),
                                               "references_wallet")
                if others:
                    wallet_hits.append({"address": addr, "chain": chain,
                                        "shared_with": others,
                                        "shared_count": len(others)})

    # roll up to a unique list of correlated domains for a headline number
    domain_set = set()
    for h in tid_hits + script_hits + wallet_hits:
        for d in h["shared_with"]:
            domain_set.add(d)

    return {
        "host": host_id,
        "correlated_domain_count": len(domain_set),
        "correlated_domains": sorted(domain_set),
        "by_tracking_id": tid_hits,
        "by_script": script_hits,
        "by_wallet": wallet_hits,
    }
