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
