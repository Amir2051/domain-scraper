# SAFENESTT // RZ SYSTEMS 2099
## Architecture & Production Roadmap

> A lawful, defensive, OSINT-first cyber intelligence and fraud investigation platform.
> This document evolves the existing SafenestT codebase (Python OSINT engine + React frontend) into a unified, futuristic investigation operating system. **No code in this doc — design only.**

---

## 0. Scope, ethics, and non-goals

**In scope.** Scam investigation, fraud correlation, blockchain tracing, infrastructure intelligence, OSINT enrichment, evidence collection, lawful passive reconnaissance, threat intel analysis.

**Strictly out of scope and not built.** Malware, exploitation, credential theft, brute forcing, unauthorized access, attack automation, destructive tooling. Any module added in any phase must pass this gate.

**Operating assumption.** All work is performed on assets the operator owns, has lawful authority to investigate, or that are clearly public research (CT logs, public blockchain, public OSINT). The platform must make this constraint visible in UX: scope banners, evidence tags, and audit log every external API call.

---

## 1. What exists today (ground truth)

Audited 2026-05-11. This is the starting point — the architecture below evolves it, it does not throw it away.

### 1.1 Python engine — `/home/ronzoro/projects/domain-scraper/`

| Module | Role | Notable functions |
|---|---|---|
| `domain_scraper.py` | CLI scraper, requests + Playwright backends | `scrape_target`, ThreadPoolExecutor |
| `webui.py` | Flask dashboard, in-memory job queue, 75+ tool dispatch | `/scan`, `/jobs/<id>`, `/tool/<name>`, `/graph/*` |
| `tools.py` | WHOIS, DNS, IP, ASN, TLS, HIBP, Shodan, Censys, VT, AbuseIPDB, GreyNoise, URLScan, encoders | 25+ functions |
| `tools_blockchain.py` | ETH/BTC/TRON/LTC; Etherscan, Blockchain.com, TronScan, Blockchair, BTC.com; `wallet_risk` heuristics already implemented | chain detection, tx lookup, multi-chain dispatch, risk scoring |
| `tools_cyber.py` | NVD, OTX, URLhaus, ThreatFox, Tor exits, DNSBL (10), tech/CMS detect, CORS, cookie audit, subdomain takeover, port scan (TCP-connect), favicon hash, TLS fingerprint, SSL Labs, Mozilla Observatory, MITRE ATT&CK scrape | 20+ functions |
| `tools_graph.py` | Local JSON-on-disk graph (`~/.local/share/safenest/graph.json`), GraphML/JSON/CSV export, ingestion helpers for domain/whois/dns/ip/wallet | Entity registry (15 types), atomic writes |
| `tools_social.py` | Reddit, HN, GitHub emails, Mastodon, Telegram, Steam, Keybase, npm, PGP, Discord, YouTube, Roblox, Lichess, Chess.com, TikTok | Per-platform deep dive |
| `tools_username.py` | Sherlock-style sweep across 60 sites, 25-worker pool | `username_sweep` |
| `tools_email_phone.py` | Gravatar, MX, SPF/DMARC/DKIM, EmailRep, holehe-style, libphonenumber, HIBP k-anonymity | Email & phone OSINT |
| `tools_local.py` | Wraps Kali CLIs (nmap, theHarvester, amass, subfinder, dnstwist, whatweb, wafw00f, nikto, wpscan, gobuster, exiftool, dig, traceroute) with strict regex input validation, `shell=False`, hard timeouts | 15+ wrappers |

**Persistence.** Graph in JSON file; jobs in memory (lost on restart); no DB.
**Concurrency.** All synchronous Python; daemon threads for jobs; thread pools inside specific tools. No async/await anywhere.
**API keys wired** (env names): `ETHERSCAN_API_KEY`, `SHODAN_API_KEY`, `CENSYS_API_ID/SECRET`, `VT_API_KEY`, `ABUSEIPDB_API_KEY`, `HIBP_API_KEY`, `GREYNOISE_API_KEY`, `URLSCAN_API_KEY`, `GITHUB_TOKEN`, `NVD_API_KEY`, `THREATFOX_API_KEY`, `EMAILREP_API_KEY`, `WPSCAN_API_TOKEN`, `BLOCKCHAIR_API_KEY`, `WEBUI_USERNAME/PASSWORD_HASH/SECRET_KEY/HTTPS`, `SAFENEST_GRAPH_PATH`. (Only `ETHERSCAN_API_KEY`, `SHODAN_API_KEY`, `WEBUI_SECRET_KEY` set in current `.env`.)

### 1.2 React frontend — `/home/ronzoro/safenestT/`

- React 18 + Vite 6 + React Router 7 + TanStack Query 5 + Tailwind 3 + shadcn/ui + Radix.
- **Framer Motion 11** present and used. **Three.js 0.171** installed but unused.
- 102 pages, ~150–200 components across 45 feature folders (fraud, investigation, crypto, cases, intelligence, collaboration, admin, etc.).
- Cyberpunk seed already in `index.css`: `#06b6d4` cyan, `#7c3aed` purple, glow shadows, `neon-pulse` keyframe, `backdrop-blur-xl` glassmorphism, `"// SECURED //"` monospace header.
- Auth via `AuthContext`, protected routes, maintenance mode gate.

### 1.3 The critical seam — **two disconnected backends**

- Frontend talks to **base44 SDK** (cloud-managed REST/GraphQL with 45+ serverless functions: `cryptoInvestigation`, `caseManagement`, `evidenceProcessing`, etc.).
- Python `webui.py` (the 75+ OSINT tools) **is not called** by the React UI. It serves its own vanilla-JS template `index.html`.

**This is the single most important architectural decision in the 2099 evolution.** Section 11 makes the call.

---

## 2. North star — what 2099 means

Five properties define the platform from here on:

1. **Unified.** One UI, one API, one graph, one case model. No more two-backend split.
2. **Async-first.** Every external API call is awaited, queued, cached. Investigations don't block on `requests.get(timeout=30)`.
3. **Plugin-modular.** Adding a new OSINT source is a single-file drop, not a code edit in 4 places.
4. **Evidence-grade.** Every fact is timestamped, hashed, source-tagged, and exportable to a chain-of-custody bundle.
5. **Cinematic but functional.** The cyberpunk skin amplifies *information density* — graph overlays, live signal feeds, confidence halos. Particle effects never cost milliseconds on the investigation path.

---

## 3. System architecture (the picture)

```
                           ┌────────────────────────────────────────┐
                           │   RZ 2099 COMMAND CONSOLE (Next.js)    │
                           │  Boot · Cases · Graph · Evidence · AI  │
                           └────────────────┬───────────────────────┘
                                            │   HTTPS + WS
                                            │
        ┌───────────────────────────────────┼───────────────────────────────────┐
        │            EDGE / GATEWAY (Caddy or nginx, TLS, rate limit)           │
        └───────────────────────────────────┬───────────────────────────────────┘
                                            │
                            ┌───────────────┴───────────────┐
                            │     API CORE (FastAPI async)  │
                            │   /v1/cases  /v1/scan         │
                            │   /v1/tools  /v1/graph        │
                            │   /v1/evidence  /v1/exports   │
                            │   /v1/ws  (live feed)         │
                            └───────────────┬───────────────┘
                                            │
       ┌──────────────────┬─────────────────┼────────────────┬─────────────────┐
       │                  │                 │                │                 │
 ┌─────▼──────┐   ┌───────▼──────┐   ┌──────▼─────┐  ┌───────▼──────┐  ┌───────▼──────┐
 │  Postgres  │   │    Redis     │   │   Neo4j    │  │    MinIO     │  │   Workers    │
 │  cases,    │   │  queue,      │   │  entities, │  │  evidence    │  │  Celery /    │
 │  evidence  │   │  cache,      │   │  edges,    │  │  blobs (PDF, │  │  arq async   │
 │  audit,    │   │  websocket   │   │  paths,    │  │  screenshots,│  │  pool        │
 │  users,    │   │  pub/sub     │   │  cluster   │  │  JSON bundles│  │              │
 │  keys      │   │              │   │  scoring   │  │  hashed)     │  │              │
 └────────────┘   └──────────────┘   └────────────┘  └──────────────┘  └──────┬───────┘
                                                                              │
                                                  ┌───────────────────────────┴───────────┐
                                                  │           PLUGIN RUNTIME              │
                                                  │   recon · cyber · social · username   │
                                                  │   email/phone · blockchain · local    │
                                                  │   (each plugin = a python package)    │
                                                  └─────┬─────────────────────────────────┘
                                                        │
                                                        ▼
                                              External OSINT APIs
                                  (Etherscan, VT, OTX, AbuseIPDB, Shodan, ...)
```

**Bounded contexts.**
1. **Case** — investigations, timelines, evidence, notes, exports.
2. **Scan** — job orchestration: targets in, enrichments out, status streamed.
3. **Tool** — single, idempotent, side-effect-free OSINT call.
4. **Graph** — entities, edges, paths, clusters, confidence.
5. **Identity** — users, RBAC, API keys, audit.
6. **Export** — bundle assembly, hashing, signing.

Each context owns its tables. Cross-context coordination is by event (Redis pub/sub on `case.updated`, `entity.discovered`, `scan.completed`).

---

## 4. Backend architecture

### 4.1 Move from Flask sync → FastAPI async

Today: `webui.py` is Flask, one daemon thread per job, `requests` everywhere. Tomorrow: FastAPI with `asyncio` event loop, `httpx.AsyncClient` shared via `app.state.http`, work farmed out to **Celery** or **arq** workers backed by Redis.

| Today | 2099 |
|---|---|
| Flask 3 sync | FastAPI async (uvicorn + uvloop) |
| `requests` | `httpx.AsyncClient` with connection pool, retry, exponential backoff, per-host rate limits |
| In-memory `JOBS{}` dict | Postgres `scan` table + Redis queue |
| Daemon threads | Celery (well-known) or arq (lighter, async-native) worker pool |
| Inline tool calls in route | Route enqueues job, returns `job_id`; worker runs plugin; WS pushes progress |
| No logs | `structlog` JSON to stdout → loki/journald, OpenTelemetry traces |

### 4.2 Unified HTTP client

The audit found `_get()` duplicated across 5 modules. Replace with a single `safenest/http.py`:

- One `httpx.AsyncClient` per app, mounted with `httpx.AsyncHTTPTransport(retries=2)`.
- Per-host throttler (token bucket) keyed by API: Etherscan 5/s, NVD 50/30s, VT 4/min on free tier, etc.
- Circuit breaker: 5 consecutive 5xx → 60s open state, then half-open probe.
- Response cache (Redis, key = `sha256(method+url+sorted-params+body)`) with per-tool TTL (WHOIS = 7d, DNS = 1h, VT = 12h, Etherscan tx = 24h, real-time = no cache).

### 4.3 Plugin architecture

Every `tools_*.py` becomes a plugin package under `backend/plugins/`. Each plugin declares a manifest:

```yaml
# backend/plugins/blockchain/plugin.yaml
id: blockchain
version: 1.2.0
description: Multi-chain wallet & transaction intelligence
category: blockchain
requires_keys: [ETHERSCAN_API_KEY]      # optional, raises rate limit
optional_keys: [BLOCKCHAIR_API_KEY]
tools:
  - id: eth_address_info
    input: { address: eth_address }
    output_schema: schemas/eth_address_info.json
    ttl_seconds: 86400
    cost_class: cheap                    # cheap | medium | quota
  - id: wallet_risk
    input: { address: any_address, chain: chain_enum }
    output_schema: schemas/wallet_risk.json
    ttl_seconds: 21600
    cost_class: medium
graph_ingest:
  - on: eth_address_info
    fn: ingest_wallet                    # python entry-point inside the plugin
  - on: wallet_risk
    fn: ingest_wallet_risk
```

Loader: at startup, FastAPI scans `backend/plugins/*/plugin.yaml`, registers tools into a `ToolRegistry`, mounts dynamic routes `POST /v1/tools/{plugin}/{tool_id}`, validates inputs against schemas, attaches the graph ingester so that *every* tool call automatically writes to the graph when configured. This is how you stop hand-wiring 75 tools.

**Sandboxing for local-binary plugins.** `tools_local.py` shells out to Kali binaries. In 2099 those run inside a sidecar container (`safenest-local`) with read-only root, no network, dropped capabilities, and a unix-socket RPC. The API server never forks subprocesses directly.

### 4.4 Background workers

- `worker-enrich` — runs OSINT plugins. Default pool size 8. Concurrency limited per upstream API by the throttler.
- `worker-graph` — consumes `entity.discovered` events, recomputes confidence + clustering on impacted subgraphs (debounced 5s).
- `worker-export` — assembles evidence bundles (slow, IO-heavy, isolated).
- `worker-screenshot` — runs Playwright headed → captures, hashes, stores to MinIO. Already half-built in `domain_scraper.py --render`; refactor into a plugin.

### 4.5 Observability

`structlog` JSON, one event per tool call: `{ts, case_id, scan_id, plugin, tool, target_hash, latency_ms, status, cache_hit, source_api}`. Metrics via `prometheus-fastapi-instrumentator`. Traces via OpenTelemetry → Tempo/Jaeger optional. **No PII in logs** — hash all targets (sha256) for log correlation; real values stay in Postgres.

---

## 5. Database schema

### 5.1 Postgres (system of record)

```
users                                       cases
├── id (uuid)                                ├── id (uuid)
├── email                                    ├── code            (SAFE-2099-0042)
├── role (admin/analyst/viewer)              ├── title
├── totp_secret                              ├── status          (open/closed/archived)
├── created_at                               ├── classification  (scam/fraud/threat/research)
                                             ├── owner_user_id   → users
api_keys                                     ├── created_at, updated_at
├── id, owner_user_id                        ├── lawful_basis    (text + signed-off-by)
├── name, prefix                             └── tags (text[])
├── hashed_secret
├── scopes (text[])                         case_members
├── last_used_at, expires_at                 ├── case_id → cases
                                             ├── user_id → users
audit_log                                    └── role (lead/contributor/observer)
├── id, ts
├── actor_user_id, actor_key_id             scans
├── action                                   ├── id (uuid)
├── resource_type, resource_id               ├── case_id → cases
├── ip, user_agent                           ├── target          (domain | ip | wallet | email | username)
├── lawful_basis_ref                         ├── target_type
└── payload (jsonb, redacted)                ├── plugins_requested (text[])
                                             ├── status          (queued/running/done/error)
evidence                                     ├── started_at, finished_at
├── id (uuid)                                ├── error_text
├── case_id → cases                          └── result_summary (jsonb)
├── kind  (pdf/screenshot/json/note/ioc)
├── source_plugin, source_tool              tool_calls (immutable, append-only)
├── target_hash                              ├── id, scan_id → scans
├── blob_uri  (minio://...)                  ├── plugin, tool
├── sha256                                   ├── input (jsonb), output_uri (minio or inline jsonb)
├── created_by_user_id                       ├── source_api, latency_ms, status
├── created_at                               ├── cache_hit (bool)
├── label, tags (text[])                     └── created_at
└── chain_of_custody (jsonb[])
                                             iocs
exports                                      ├── id, case_id → cases
├── id, case_id                              ├── type   (ip/domain/url/hash/email/wallet)
├── format (pdf/json/stix2/zip)              ├── value, confidence (0-100)
├── status, blob_uri, sha256                 ├── first_seen, last_seen
├── created_by_user_id                       └── sources (jsonb[])
└── created_at
```

Migrations via Alembic. All `*_at` are `timestamptz`. Sensitive columns (`hashed_secret`, `totp_secret`) encrypted with `pgcrypto` using a key from env (`SAFENEST_DB_KEY`).

### 5.2 Neo4j (graph)

Direct mapping from the existing `tools_graph.py` entity registry — no breaking change to ingest helpers.

```
Node labels:
  Domain, Subdomain, IP, ASN, Cert, Email, Phone, Username,
  Wallet, TxId, Social, Company, File, URL, Note
Common props: id (unique), label, type, first_seen, last_seen, tags[], attrs (json)

Relationship types:
  RESOLVES_TO, REDIRECTS_TO, SUBDOMAIN_OF, SHARES_INFRA, SHARES_TLS,
  SHARES_ANALYTICS, SHARES_SCRIPT, REGISTERED_BY, MX_OF, NS_OF,
  ANNOUNCED_BY, REFERENCED_BY, TRANSACTED_WITH, CONTROLS_WALLET,
  HISTORICAL_DNS, EVIDENCE_FOR, WEAK_CORRELATION

Edge props: kind, confidence (0-100), source_plugin, source_tool, observed_at, evidence_id?
```

**Indexes.** `CREATE INDEX ON :Domain(id)`, same for every label. Full-text index on `(label, attrs.notes)` for search.

**Migration from JSON store.** One-time `migrate_graph_json_to_neo4j.py`: read existing `~/.local/share/safenest/graph.json`, emit Cypher `MERGE` statements. Idempotent — re-runnable. Keep the JSON file as a backup; ship a dual-write window of 2 weeks where new writes hit both, then cut over.

### 5.3 Redis

- DB 0: Celery/arq queue.
- DB 1: HTTP response cache.
- DB 2: WebSocket pub/sub (`case:<id>:events`).
- DB 3: rate-limit token buckets.
- DB 4: per-session state (CSRF tokens, in-flight scan progress).

### 5.4 MinIO (S3-compatible)

Buckets: `evidence/`, `screenshots/`, `exports/`, `imports/`. Bucket policy: server-side encryption (SSE-S3), versioning on, object lock = governance for `evidence/`. Lifecycle rule: move objects > 90d to `evidence-cold` tier.

---

## 6. Graph intelligence engine

### 6.1 What changes vs. today

| Today (`tools_graph.py`) | 2099 |
|---|---|
| JSON file on disk | Neo4j 5.x community edition |
| File lock, atomic rename | ACID transactions |
| BFS in Python | Cypher `MATCH (a)-[*1..3]-(b)` |
| `search()` is substring | Full-text + label index |
| No confidence | Every edge has confidence + evidence_id |
| 15 entity types | Same 15 (no schema break) |

### 6.2 Confidence scoring

Two layers.

**Edge confidence (0–100)** is set by the plugin that emitted it, using a fixed table:

```
SAME_TLS_FINGERPRINT          85
SHARES_GA_ANALYTICS_ID        90
SHARES_FB_PIXEL_ID            90
HISTORICAL_DNS_OVERLAP_<7d    75
SAME_ASN                      30   # weak — ASNs are huge
SAME_CDN                       5   # near-noise
WHOIS_REGISTRANT_EMAIL_MATCH  95
WALLET_TRANSACTED             100  # observed fact
WALLET_CLUSTERED_HEURISTIC    60   # common-input heuristic
SUBDOMAIN_TAKEOVER_FINGERPRINT 70
```

**Node confidence** (per case) is computed by `worker-graph`:
```
node_conf = 1 - Π(1 - edge_conf_i/100)   for incoming evidentiary edges
```
i.e. multiple independent weak signals compound, single strong signal dominates. Anything below 30 is rendered semi-transparent in the UI — operators must always be able to see *why* something was attributed.

### 6.3 Clustering

`worker-graph` runs Louvain or Leiden every N minutes per case scope. Each cluster gets a synthetic `Cluster` node with `RELATES_TO` edges to members. Surfaces in UI as a tinted lasso on the canvas.

### 6.4 Frontend canvas

- **Library.** Cytoscape.js with `cytoscape-cose-bilkent` or `cytoscape-fcose` layout. Webgl renderer for > 5k nodes. Three.js stays for the boot screen and ambient backgrounds — **not** the working graph. (Three.js graphs look impressive in demos and are unusable past 2k nodes.)
- **Interaction.** Click node → side drawer with evidence list. Right-click → "expand neighbors", "trace path to…", "tag as IOC". Cmd-K command palette.
- **Timeline slider.** Bottom of canvas. Drag = filter edges by `observed_at`. Renders the investigation over time.
- **Layers toggle.** Infrastructure / blockchain / people / threats — each can be hidden to reduce noise.
- **AI-assisted suggestions.** A side panel calls a `/v1/graph/suggest` endpoint that runs Cypher heuristics ("nodes 2 hops from current selection sharing a TLS cert with > 3 of your IOCs") and returns ranked "investigate next" hints. **No LLM in the suggestion loop initially** — just deterministic graph queries. LLM summarization comes in phase 4.

---

## 7. Blockchain intelligence workflows

Most of the engine already exists in `tools_blockchain.py`. The 2099 evolution is **pipeline, persistence, and graph**.

### 7.1 Wallet enrichment pipeline

```
[user pastes wallet 0xabc...] 
       │
       ▼
POST /v1/scan { target: "0xabc...", target_type: wallet, plugins: [blockchain.full] }
       │
       ▼  (enqueue)
worker-enrich:
   1. detect_chain          → eth
   2. eth_address_info      (cache 24h)
   3. eth_address_txs       (cache 1h, paginated, cap 1000)
   4. eth_address_token_txs (cache 1h)
   5. wallet_risk           (uses 2–4, no extra API call)
       │
       ▼
graph_ingest:
   ingest_wallet, ingest_wallet_txs (cap 100 counterparties per wallet),
   ingest_wallet_risk
       │
       ▼
publish redis: case:<id>:events { type: scan.completed, scan_id, summary }
       │
       ▼
frontend websocket → canvas grows, risk badge appears
```

### 7.2 Risk scoring (already implemented, formalize)

Surface the existing heuristics from `tools_blockchain.wallet_risk` in a stable schema. Every flag carries a `severity` (info/low/medium), a `code`, and a `human_explanation`. **No flag is "guilty" or "scam" — this is descriptive risk, not adjudication.** The UI must render the disclaimer.

Heuristic registry:

| Code | Reads | Severity | Meaning |
|---|---|---|---|
| `concentration_top_recipient` | tx history | medium | > X% of outflow to one address |
| `fan_out_mixer_like` | tx history | medium | many ~equal-value outs in short window |
| `bursty_timing` | tx timestamps | low | clusters of < 60s gaps |
| `same_value_outflows` | tx values | medium | drainer-like pattern |
| `long_dormancy_before_burst` | tx timestamps | info | > 180d quiet, then activity |
| `interacts_with_known_mixer` | tx graph + IOC list | medium | recipient on operator-maintained mixer list |
| `interacts_with_sanctioned_address` | tx graph + OFAC list | medium | publicly sanctioned wallet — **strictly informational** |

### 7.3 Transaction graph & timeline playback

- Every tx becomes a `TxId` node + two `Wallet -[TRANSACTED_WITH {tx_id, value, ts}]-> Wallet` edges.
- Timeline playback in UI = canvas re-renders edges where `ts <= slider_pos`, animated.
- Cluster wallets that share input UTXOs (BTC) or that pay gas from the same EOA repeatedly (ETH heuristic). Mark cluster confidence explicitly — common-input heuristic is well-known to be probabilistic.

### 7.4 Exchange / service tagging

Maintain a curated **tag list** (`backend/data/wallet_tags.yaml`) — exchanges, mixers, bridges, known scam wallets reported in the case base. Source: operator-maintained + public lists. Tags render as colored halos in the graph. Tag application is itself a piece of evidence with a source URL.

### 7.5 Gaps to fill

- Add Polygon, BSC, Arbitrum, Optimism, Base via Etherscan-family v2 API (single endpoint, chain_id param) — minor extension to existing eth_* functions.
- Add Solana via Solscan public API for completeness on a major scam vector.
- Add bitcoin Mempool.space as a Blockchain.com fallback.

---

## 8. Link intelligence correlator

The connective tissue across `tools_cyber`, `tools_social`, `tools_email_phone`, `tools_blockchain`. Lives as a service inside the graph context.

**Signal matrix.** Every extracted artifact becomes a node with a fingerprint:

| Artifact | Fingerprint | Strength |
|---|---|---|
| Google Analytics UA-/G- | exact string | strong |
| Facebook Pixel ID | exact string | strong |
| Adsense ID | exact string | strong |
| WHOIS registrant email | exact (case-insensitive) | strong |
| Favicon mmh3 hash | exact (already in `tools_cyber.favicon_hash`) | strong |
| TLS SAN overlap | set intersection size ≥ 2 | strong |
| Shared script SHA-256 (3rd-party JS) | exact | medium |
| Shared form action host | exact | medium |
| Shared CDN | exact | weak — drop unless paired |
| Shared ASN | exact | weak — only useful as a paired signal |
| Phone number normalized E.164 | exact | strong |
| Wallet referenced in `<meta>`/script | exact | strong |

**Correlation engine.** On every new `tool_call` completion, the engine:
1. Extracts artifacts via per-plugin extractors.
2. For each artifact, asks Neo4j "what existing nodes share this fingerprint?"
3. For each match, emits an edge with the appropriate `kind` and confidence from the table.
4. Triggers `worker-graph` recompute for the affected subgraph.

**Investigation summary.** Per case, the summarizer (deterministic, template-based in phase 2, LLM-augmented in phase 4) produces a structured object: top entities, top clusters, strongest links, weakest-link warnings, suggested next actions. Rendered in the UI as a left-hand "Case briefing" panel.

---

## 9. Threat intelligence correlation

Already wired tools: VT, OTX, AbuseIPDB, GreyNoise, URLScan, URLhaus, ThreatFox, Shodan, Censys, MITRE ATT&CK scrape.

**Aggregator.** `backend/services/threat_intel.py` exposes one method: `enrich_indicator(ioc_type, value) → ThreatVerdict`. It dispatches in parallel to whichever sources accept this IOC type, normalizes responses into a common schema:

```
ThreatVerdict {
  ioc, ioc_type,
  signals: [
    { source: "virustotal", verdict: "malicious|suspicious|clean|unknown",
      score: 0..100, last_seen, ref_url, raw_excerpt },
    ...
  ],
  aggregate: { malicious: int, suspicious: int, clean: int, unknown: int },
  confidence: 0..100,
  noisy: bool                # GreyNoise classification == "benign" or commonly-scanned IP
}
```

**Noise filtering.** GreyNoise tag = "benign" or VT engines < 2 detections = `weak signal`, rendered dimmer in UI and excluded from automated escalation. The platform must **never** auto-attribute on a single weak source — this is the false-attribution guard from the original spec.

---

## 10. Evidence export engine

Every case produces one or more **evidence bundles**.

### 10.1 Bundle layout

```
SAFE-2099-0042_bundle/
├── manifest.json           # case metadata, member list, hashes of every file, signature
├── report.pdf              # narrative + figures (cyberpunk template, see §15)
├── timeline.json           # ordered events with source citations
├── iocs.stix2.json         # STIX 2.1 indicators
├── iocs.csv                # flat IOC list for spreadsheet users
├── graph/
│   ├── graph.graphml       # Maltego / Gephi / yEd / Cytoscape compatible
│   ├── graph.json          # native format
│   └── graph.png           # rendered snapshot at export time
├── evidence/
│   ├── 0001_screenshot.png (sha256 = ...)
│   ├── 0002_response.har
│   ├── 0003_whois_acme.txt
│   └── ...
└── audit/
    └── tool_calls.jsonl    # every external API call made during this case
```

**Hashing & signing.** `manifest.json` includes `sha256` of every other file. The manifest itself is signed with the platform's private key (Ed25519, key stored in env `SAFENEST_SIGNING_KEY`). Verifier script ships with the bundle.

**PDF report.** Built with WeasyPrint (Python, HTML→PDF, clean). Template is server-rendered Jinja2 with the same cyberpunk design tokens as the frontend so the report feels like an extension of the console. Sections: cover, executive summary, scope & lawful basis, timeline, entity inventory, graph snapshot, blockchain findings, threat-intel findings, evidence inventory, methodology + sources, glossary, disclaimer.

**STIX 2.1.** Use `stix2` library. Map IOCs → `indicator` SDOs, threat actors (if asserted) → `threat-actor`, infrastructure → `infrastructure`. Bundle is shareable to any TIP that consumes STIX.

### 10.2 Workflow

1. User clicks "Export" in case header.
2. UI shows checkbox list (what to include) + format selector + classification banner.
3. POST `/v1/exports` → enqueues to `worker-export`.
4. Worker pulls fresh data from Postgres + Neo4j + MinIO, assembles bundle in temp dir, hashes, signs, zips, uploads to `exports/` bucket, writes `exports` row.
5. WS notifies UI; "Download" link appears. Expires after 7 days (lifecycle rule).

---

## 11. API architecture & the two-backend reconciliation

### 11.1 The decision

The frontend currently talks to base44 (45+ serverless functions). The Python engine has 75+ OSINT tools but no React caller. **Recommendation: keep base44 for what it's already good at, run the new Python FastAPI as the OSINT/intelligence API, and bridge them.**

Why not collapse to one:
- base44 owns user/case/billing/auth — ripping that out is months of work for no investigation-quality gain.
- The Python engine is where the actual OSINT capability lives. base44 can't natively run Playwright, nmap wrappers, or 25-worker username sweeps.

The bridge:
- base44 `caseManagement` remains source of truth for case metadata, members, billing entitlements.
- A new base44 serverless function `safenestEngineProxy` (or a direct CORS-allowed call from frontend) forwards investigation/OSINT requests to the FastAPI engine, attaching a signed user token.
- FastAPI verifies the token via base44 SDK, scopes everything to that user's authorized cases.
- Cases in Postgres carry `external_case_id` = base44 case id. Postgres is canonical for *investigation artifacts*; base44 is canonical for *user/billing*.
- Eventually, if base44 becomes a bottleneck, migrate user/case to local Postgres + Keycloak. Not in the initial roadmap.

### 11.2 FastAPI surface

```
AUTH (verifies base44 token)
  GET  /v1/me

CASES (synced with base44)
  GET    /v1/cases
  POST   /v1/cases                       # also creates in base44
  GET    /v1/cases/{id}
  PATCH  /v1/cases/{id}

SCANS
  POST   /v1/scans                        # body: { case_id, target, target_type, plugins[] }
  GET    /v1/scans/{id}
  POST   /v1/scans/{id}/cancel
  WS     /v1/ws/cases/{id}                # live events for case

TOOLS (per-plugin direct call — admin/power users)
  GET    /v1/tools                        # registry listing
  POST   /v1/tools/{plugin}/{tool}        # synchronous call, returns inline if < 5s else 202 + job_id

GRAPH
  GET    /v1/graph/cases/{id}             # full case subgraph
  GET    /v1/graph/cases/{id}/neighbors/{node_id}?depth=2
  GET    /v1/graph/cases/{id}/path?from=&to=
  POST   /v1/graph/cases/{id}/notes
  GET    /v1/graph/cases/{id}/export?fmt=graphml|json|csv

EVIDENCE
  GET    /v1/evidence?case_id=
  POST   /v1/evidence                     # manual upload (chain-of-custody enforced)
  GET    /v1/evidence/{id}                # signed URL, short-lived
  DELETE /v1/evidence/{id}                # soft delete + audit

EXPORTS
  POST   /v1/exports                      # body: { case_id, format, include[] }
  GET    /v1/exports/{id}                 # status + signed download URL

IOCS
  GET    /v1/cases/{id}/iocs
  POST   /v1/cases/{id}/iocs
  GET    /v1/iocs/search?value=

ADMIN
  GET    /v1/admin/keys                   # API key inventory (no plaintext)
  POST   /v1/admin/keys
  DELETE /v1/admin/keys/{id}
  GET    /v1/admin/audit?actor=&since=
```

OpenAPI 3.1 auto-generated, served at `/v1/openapi.json` and `/v1/docs`.

### 11.3 WebSocket protocol

One channel per case, `wss://.../v1/ws/cases/{id}`. Events: `scan.queued`, `scan.progress`, `scan.completed`, `entity.discovered`, `edge.discovered`, `risk.updated`, `note.added`, `export.ready`. Frontend reducer applies events to local query cache (TanStack Query `setQueryData`).

---

## 12. Frontend redesign — RZ 2099 cyberpunk shell

### 12.1 Stay or go

| Component / system | Verdict |
|---|---|
| React 18 + Vite | **Stay.** No framework swap. The "Next.js" in the original spec is overstated — Vite + React Router is fine for an SPA console behind auth. |
| React Router 7 | Stay. |
| TanStack Query | Stay. Central to live data. |
| shadcn/ui + Radix + Tailwind | Stay. Extend tokens; don't rewrite primitives. |
| Framer Motion | Stay. Lean harder. |
| Three.js | **Use it** — but for ambient boot/idle scenes, not the working graph. |
| base44 SDK | Stay. See §11.1. |
| 102 pages | Stay. Restyle the chrome, leave the routes alone. |
| Vanilla-JS `index.html` template inside `webui.py` | **Retire** once the FastAPI surface is live. The Flask UI becomes a debug-only fallback. |
| `Layout.jsx` (394 lines, mixed concerns) | **Refactor** into `<CommandConsole/>` with regions: HeadsUpHeader, Sidebar, MainCanvas, AIAssistantDock, StatusRail. |

### 12.2 New top-level UX

```
┌────────────────────────────────────────────────────────────────────────┐
│  SAFENESTT // RZ-2099   case: SAFE-2099-0042  ●LIVE   T+04:12:33   ⌘K  │
├────────┬───────────────────────────────────────────────────────┬───────┤
│        │                                                       │       │
│  NAV   │                MAIN CANVAS                            │  AI   │
│        │   ┌─ tabs: Brief · Graph · Evidence · Timeline ─┐      │ DOCK  │
│  cases │   │                                              │      │       │
│  intel │   │   [ graph canvas / evidence table /         │      │ "suggest │
│  fraud │   │     timeline rail / brief panel ]           │      │  next"   │
│  crypto│   │                                              │      │       │
│  admin │   └──────────────────────────────────────────────┘      │       │
│        │                                                       │       │
├────────┴───────────────────────────────────────────────────────┴───────┤
│  STATUS RAIL · 3 scans running · 142 nodes · risk Σ 67 · queue: 4      │
└────────────────────────────────────────────────────────────────────────┘
```

### 12.3 Design tokens (extends current `index.css`)

Add to Tailwind config:

```
colors:
  rz.bg.void:    #05060a
  rz.bg.deep:    #0a0e15
  rz.bg.panel:   #0f1421
  rz.line:       rgba(255,255,255,0.07)
  rz.cyan:       #06b6d4   (already there)
  rz.cyan.hot:   #22d3ee
  rz.cyan.glow:  rgba(6,182,212,0.45)
  rz.violet:     #7c3aed   (already there)
  rz.violet.hot: #a855f7
  rz.amber:      #f59e0b   (warning)
  rz.red:        #ef4444   (alert / sanctioned)
  rz.green:      #10b981   (live / safe)
  rz.scan:       rgba(34,211,238,0.08)  (scanline overlay)

fontFamily:
  display:  ["Orbitron", "ui-sans-serif"]      # headers, brand
  mono:     ["JetBrains Mono", "ui-monospace"] # ids, hashes, addresses, terminal
  body:     ["Inter", "ui-sans-serif"]

keyframes (additions):
  scanline-slide:  vertical translate 0 → 100% over 6s
  data-pulse:      box-shadow neon ring 0 → 1 → 0 over 2.5s
  hud-reticle:     subtle rotation on focus rings
  glitch-burst:    rare 80ms transform jitter on critical alerts (accessibility: gated by reduced-motion)

shadow:
  rz.glow.cyan:   0 0 20px rz.cyan.glow, 0 0 40px rz.cyan.glow
  rz.glow.violet: 0 0 20px rgba(124,58,237,0.4)
```

### 12.4 Component additions

- `<BootSequence/>` — 3s Three.js scene on app cold start: logo materializes, status checks tick (`db ok / neo4j ok / queue ok / plugins 12/12`), then fade to console. Skippable.
- `<HeadsUpHeader/>` — case code, live tick, ⌘K palette, profile dock.
- `<GraphCanvas/>` — Cytoscape with custom node renderer (glowing halo per type, risk-colored stroke), edge animation on discovery, layer toggles.
- `<EvidenceCard/>` — glassmorphic with hash badge, source chip, classification banner.
- `<TerminalDock/>` — slide-up panel; runs whitelisted commands (`/scan domain example.com`, `/who 0xabc...`, `/path A→B`). Power-user shortcut.
- `<AIAssistantDock/>` — right-side panel. Phase 4. Reads case context, suggests next steps.
- `<StatusRail/>` — bottom bar, live counters streamed from WS.
- `<ScanlineOverlay/>` — global, opacity 0.04, sits above content, off behind `prefers-reduced-motion`.

### 12.5 Performance discipline

- Three.js mount only on routes that need it: `/boot`, `/intel/ambient`. Lazy-import.
- Cytoscape webgl renderer for > 1k nodes. Cap canvas to 5k visible — beyond that, force the user to filter.
- Scanline + ambient particle effects gated by `matchMedia('(prefers-reduced-motion: reduce)')`.
- All animations < 16ms per frame budget on the working canvas. Decorative motion is on idle paths only.

### 12.6 What to keep from existing 102 pages

All of them. Restyle the chrome (Layout, navigation, cards) so every page inherits the 2099 aesthetic, but leave the business-logic pages (FraudRecovery, CryptoTracker, IdentityMonitor, etc.) intact. Pages that touch investigations/cases get the new `<CommandConsole/>` shell; auxiliary pages (billing, settings, policies) keep a calmer variant.

---

## 13. Investigation workspace (the inside of a case)

Inside `/cases/{id}`, five tabs:

1. **Brief** — auto-generated summary, top entities, key clusters, weak-signal warnings, suggested next steps. The "open the case in 30 seconds" view.
2. **Graph** — full interactive canvas (§6.4). Default landing tab for analysts.
3. **Evidence** — chronological evidence table; click any row → blob preview (PDF/PNG/JSON) with hash + source chip.
4. **Timeline** — vertical timeline of events: scans run, entities discovered, notes added, exports generated. Filter by actor or type.
5. **Exports** — list of bundles, status, download links.

Persistent side rail:
- **Forensic notes** (markdown, append-only, signed per entry).
- **IOC tray** — drag any node from graph → IOC tray → confidence + tags → it becomes a STIX-shaped IOC at export time.
- **Lawful basis** — required at case creation, surfaced in every export, audit-logged on edit.

---

## 14. Docker deployment stack

Single-host `docker-compose.yml`. Production = same compose with secrets via env file / Docker secrets.

```
services:
  caddy:        TLS + reverse proxy, public 443/80
  api:          FastAPI (uvicorn), 3 replicas behind caddy
  worker-enrich:    arq/Celery worker, 4 replicas
  worker-graph:     1 replica
  worker-export:    1 replica
  worker-screenshot: 1 replica (Playwright Chromium, headed-off)
  postgres:     15-alpine, volume pg-data
  redis:        7-alpine, AOF persistence
  neo4j:        5-community, plugins: APOC, GDS
  minio:        single-node, volume minio-data
  prometheus:   metrics (optional)
  grafana:      dashboards (optional)
  frontend:     Vite static build served by caddy
  safenest-local: sidecar; mounts /usr/local/bin/{nmap,...} read-only;
                  network_mode: none on most calls, dedicated egress net for dnstwist etc.
```

Volumes: `pg-data`, `neo4j-data`, `neo4j-logs`, `minio-data`, `redis-data`, `evidence-graph-backup`.
Networks: `safenest-edge` (caddy ↔ api ↔ frontend), `safenest-data` (api/workers ↔ stores), `safenest-tools` (workers ↔ safenest-local).
Secrets: `.env.production` checked into a separate ops repo, mounted as Docker secret. The current `.env` style stays for dev.

For local-only operation (you indicated you want this): same compose, swap caddy TLS to `tls internal` or skip TLS entirely on loopback, expose only `127.0.0.1:443` and `127.0.0.1:7474` (Neo4j browser) for debugging.

---

## 15. Security architecture

### 15.1 AuthN / AuthZ

- **AuthN.** base44 token verified at FastAPI boundary. Fallback path: local username/password (already in `webui.py` via `WEBUI_USERNAME` + scrypt hash) for direct API users, plus TOTP-on-by-default for admin role.
- **AuthZ — RBAC.** Three roles:
  - `viewer`: read-only on cases they're members of.
  - `analyst`: read + run scans + add evidence + create exports.
  - `admin`: everything + key management + audit access.
- **Per-case ACL.** `case_members` table enforces row-level checks on every case-scoped query. SQL: `WHERE case_id IN (SELECT case_id FROM case_members WHERE user_id = $current)`.
- **API keys.** Distinct from user sessions. Scoped (`scopes`: `scan`, `read`, `export`, `admin`). Stored as `sha256(secret)`. Prefix shown in UI; secret shown exactly once at creation.

### 15.2 Evidence integrity

- Every evidence blob hashed (sha256) on ingest, hash stored in Postgres, blob stored in MinIO with object-lock.
- `chain_of_custody` jsonb array on each evidence row: `[{ts, actor, action, prev_hash, new_hash}, ...]`. Append-only at the application layer; Postgres trigger refuses updates that don't append.
- Manifest of every export signed Ed25519. Verifier script in the bundle.

### 15.3 Audit log

Every state-changing API call writes to `audit_log`. Append-only (separate role lacks DELETE). Retention: 365 days minimum. Audit endpoints visible only to `admin`.

### 15.4 Rate limiting

- Per-IP at caddy (e.g. 200 req/min).
- Per-user at FastAPI middleware (Redis token bucket, e.g. 60 req/min per user, 10 scans/min).
- Per-upstream-API in the HTTP client (§4.2).

### 15.5 Secrets

- Dev: `.env` files (never committed; the repo's `.gitignore` already excludes `.env`).
- Prod: Docker secrets or a sidecar reading from your vault of choice (Bitwarden Secrets Manager, HashiCorp Vault, even SOPS+age files for a small team).
- API keys in DB are never returned plaintext; admin UI shows prefix + last_used_at only.

### 15.6 Container hardening

- All app containers `read_only: true`, `tmpfs` for `/tmp`.
- `cap_drop: [ALL]`, only re-add what's needed (rarely anything).
- `safenest-local` sidecar runs `--user nobody`, no `--privileged`, seccomp default profile, no host mounts beyond read-only tool bins.
- Egress allowlist per-container at the Docker network level for sensitive paths.

### 15.7 Ethical guardrails baked into code

- The platform refuses to call any plugin marked `category: offensive` — there are none, and the plugin loader rejects manifests that declare one. This is enforced in code, not docs.
- Tools that touch a remote host (`nikto`, `gobuster`) require a per-case "authorization on file" checkbox to be set, with the lawful basis recorded. UI surfaces a red banner if absent.
- Exports always include the disclaimer text and the chain-of-custody manifest. Cannot be removed in UI.

---

## 16. UI/UX design system summary

| Layer | Principle |
|---|---|
| **Surface** | Black void → deep panel; glassmorphic on hover/focus; never pure white. |
| **Color** | Cyan = system / data; violet = identity / people; amber = warning; red = alert / sanctioned; green = live / safe. Used for *meaning*, not decoration. |
| **Typography** | Orbitron for chrome/brand only (sparingly); JetBrains Mono for any hash, ID, address, code; Inter for prose. |
| **Motion** | Reveal: easeOutExpo 220ms. Hover: 120ms. Critical event: data-pulse 2.5s. Glitch reserved for incident severity 4+. Everything respects `prefers-reduced-motion`. |
| **Density** | Information first. Decorative effects always behind content; never block click targets; never animate during scrolling. |
| **Accessibility** | WCAG AA contrast minimum on all text (the neons are accents, not body color). Full keyboard nav. Reduced-motion alt for every animation. |
| **Voice** | Terse, technical, never alarmist. "Risk score: 67/100 (medium)." Not "🚨 SCAMMER DETECTED 🚨". |

---

## 17. Production roadmap

Six phases. Each phase is independently shippable — you can stop at any phase boundary with a working, better-than-today system.

### Phase 0 — Foundation refactor (2–3 weeks)
- Extract unified `safenest/http.py` from the 5 duplicate `_get()` implementations.
- Promote the project to a Python package layout (`backend/safenest/...`), `pyproject.toml`, ruff + pyright.
- Replace in-memory `JOBS{}` with SQLite first (zero-ops), Postgres path ready.
- Structured logging, basic metrics endpoint.
- **Ship gate.** All 75+ existing tools work unchanged. Test fixtures captured for tool I/O.

### Phase 1 — Plugin core + FastAPI (3–4 weeks)
- Migrate Flask `webui.py` → FastAPI, async, with HTTP client + cache.
- Plugin manifest loader; convert each `tools_*.py` into a plugin package without changing function bodies.
- Stand up Postgres, run case + scan + tool_call schema; Alembic migrations.
- Replace daemon threads with arq workers + Redis queue.
- WebSocket scan progress.
- **Ship gate.** Existing Flask UI still works (kept as `/legacy`); a thin new React route in safenestT can fire one scan against new FastAPI.

### Phase 2 — Graph & blockchain pipelines (4–5 weeks)
- Stand up Neo4j; dual-write from `tools_graph.py` ingesters; one-shot migrator.
- Confidence scoring tables; correlation engine; worker-graph.
- Wire all blockchain plugins through enrichment pipeline; tx graphing; timeline.
- Wallet tag list (curated yaml + admin editor).
- Add Polygon / BSC / Arbitrum / Solana coverage.
- **Ship gate.** A wallet scan creates a graph the analyst can browse in Neo4j Browser. React UI not required yet.

### Phase 3 — RZ 2099 frontend shell (5–6 weeks)
- Refactor `Layout.jsx` into `<CommandConsole/>` regions.
- New tokens, fonts, Tailwind extensions.
- `<BootSequence/>`, `<GraphCanvas/>` (Cytoscape), `<EvidenceCard/>`, `<StatusRail/>`, `<TerminalDock/>`.
- Wire frontend → FastAPI engine via base44 proxy function or direct (CORS scoped).
- WS live updates wired into TanStack Query cache.
- All 102 existing pages inherit new chrome; functional pages unchanged.
- **Ship gate.** End-to-end: start scan from console → graph grows in real time → evidence appears.

### Phase 4 — Evidence exports, RBAC, audit (3–4 weeks)
- Evidence model + MinIO bucket + chain-of-custody.
- WeasyPrint PDF report; STIX 2.1 export; GraphML/JSON/CSV (already exists, rehouse).
- Manifest signing (Ed25519) + verifier.
- Full RBAC with case_members; admin UI for keys + audit.
- AI assistant dock (LLM, Claude API) — case-scoped retrieval, never sees keys, generates *summaries and suggested-next-steps only*, never autonomous actions.
- **Ship gate.** A finished investigation can be exported as a signed bundle that opens in Maltego and renders as a PDF.

### Phase 5 — Scale & polish (ongoing)
- Multi-tenant if needed.
- Move heavy chains to dedicated workers.
- Optional: replace base44 user/case with local Keycloak + Postgres if base44 becomes a bottleneck.
- Optional: introduce a small ML model for cluster typing (exchange vs. mixer vs. personal wallet) using public-tag training data.
- Cold storage tier for evidence > 90 days.
- Public-only "research" subset of the API for external collaborators.

---

## 18. Tech-debt items to retire along the way

These were observed in the audit. Address as you traverse each phase; do not bundle into a separate cleanup project.

- **HTTP client duplication** across 5 modules → unified in Phase 0.
- **`_norm_id` lowercases ETH addresses**, losing EIP-55 checksum → store both `id` (lowercase, dedup key) and `attrs.checksum` (EIP-55). Phase 1.
- **Hardcoded constants** (`SUBDOMAIN_CAP=25`, render-wait, etc.) → `backend/config.py`. Phase 0.
- **DNSBL list** hardcoded → fetch from a maintained source on startup, cache 24h. Phase 1.
- **Playwright cost** (sequential, full Chromium) → pooled context manager in `worker-screenshot`. Phase 2.
- **Vanilla-JS template** `index.html` → mark deprecated in Phase 1, remove in Phase 3.
- **`emailrep.io-python` vendored** → switch to the published `emailrep` package on PyPI (already in requirements.txt as a fallback). Phase 0.
- **No tests** → at minimum, golden-file tests for each plugin's parser using captured upstream JSON. Phase 0 builds the harness; subsequent phases add tests as they touch each plugin.

---

## 19. Open questions to resolve before code starts

1. **base44 commitment.** Are you on a paid plan and committed for ≥ 12 months? If not, Phase 5's migration option becomes Phase 2 priority.
2. **Hosting target.** Single Kali workstation (current), single VPS, or k8s eventually? Affects whether Phase 4 includes Helm charts.
3. **LLM provider for the AI assistant (Phase 4).** Anthropic Claude (recommended for the ethics gate — refuses obvious abuse out of the box), or self-hosted? Affects API key handling.
4. **Solo or team.** RBAC + audit + signing are non-trivial. If solo-operator forever, Phase 4 can simplify; if you want collaborators, do it as designed.
5. **Active investigations during build.** If you're using this on live cases now, every phase needs a "don't break the legacy path" guarantee — already baked in via the legacy Flask retention through Phase 2, but worth confirming.

---

## 20. Appendix — sources for the design

- Existing code at `/home/ronzoro/projects/domain-scraper/` (audited 2026-05-11), entry points `webui.py`, `domain_scraper.py`, `tools_*.py`.
- Existing frontend at `/home/ronzoro/safenestT/` (audited 2026-05-11), entry `src/Layout.jsx`, base44 integration `src/api/base44Client.js`.
- Public references for design choices: Neo4j graph data modeling guide, STIX 2.1 spec, MITRE ATT&CK naming, GraphQL/JSON-LD evidence schemas.

---

*End of architecture document. Total scope estimate: 20–25 weeks for a focused two-engineer team to reach Phase 4, or proportionally longer solo. Phase 0–2 alone (8–12 weeks) is already a meaningful platform.*
