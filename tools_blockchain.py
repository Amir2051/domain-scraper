#!/usr/bin/env python3
"""
tools_blockchain.py — passive wallet & transaction intelligence.

Multi-chain wallet lookup, transaction history, recipient-pattern
analysis, and observable risk features. All APIs are read-only public
endpoints — this module never signs, broadcasts, or moves funds.

Backends:
  - Etherscan         (ETH; honors $ETHERSCAN_API_KEY for higher rate limit)
  - Blockchain.com    (BTC; no key needed)
  - Blockchair        (multi-chain fallback; $BLOCKCHAIR_API_KEY optional)
  - TronScan          (TRX / USDT-TRC20; no key needed)
  - BTC.com           (BTC fallback; no key needed)

Address auto-detection picks the right backend by address format. Risk
scoring is *descriptive* — it surfaces observable patterns (fan-out,
consolidation, bursty timing, top-recipient concentration) and never
claims a wallet is "criminal" without a cited source.
"""
from __future__ import annotations

import os
import re
import time
from collections import Counter, defaultdict
from typing import Optional

import requests

from safenest.http import DEFAULT_HEADERS as HEADERS, DEFAULT_UA as UA, make_client

TIMEOUT = 15
_get, _ = make_client(timeout=TIMEOUT)

# Address-format heuristics. These are necessary (not sufficient) checks;
# the real validator is whichever backend the address gets handed to.
ETH_RE   = re.compile(r"^0x[0-9a-fA-F]{40}$")
BTC_RE   = re.compile(r"^(bc1[0-9ac-hj-np-z]{8,87}|[13][a-km-zA-HJ-NP-Z1-9]{25,34})$")
TRON_RE  = re.compile(r"^T[1-9A-HJ-NP-Za-km-z]{33}$")
LTC_RE   = re.compile(r"^(ltc1[0-9ac-hj-np-z]{8,87}|[LM3][a-km-zA-HJ-NP-Z1-9]{25,34})$")
TXID_RE  = re.compile(r"^(0x)?[0-9a-fA-F]{64}$")

# Wei → ETH
WEI = 10 ** 18
# Satoshi → BTC
SAT = 10 ** 8
# Sun → TRX
SUN = 10 ** 6


def _need(key_env: str, label: str):
    """Helper for tools that *require* a key. Returns None if set, else
    a structured error dict matching the project's convention."""
    if not os.environ.get(key_env):
        return {"error": f"{label} requires ${key_env}"}
    return None


def _tron_headers() -> dict:
    """TronScan accepts the API key as a `TRON-PRO-API-KEY` header. The
    public endpoint still answers without a key but with a much lower
    rate limit, so the key is *optional* — absent means anonymous mode."""
    key = (os.environ.get("TRONSCAN_API_KEY") or "").strip()
    return {"TRON-PRO-API-KEY": key} if key else {}


# ============== address detection ==============

def detect_chain(address: str) -> dict:
    """Guess which chain(s) an address could belong to from its format.
    Doesn't hit the network — purely structural."""
    a = (address or "").strip()
    if not a:
        return {"error": "empty address"}
    matches = []
    if ETH_RE.match(a):
        # ETH and most EVM chains share the same address space
        matches.append({"chain": "eth", "label": "Ethereum / EVM (BSC, Polygon, etc.)"})
    if TRON_RE.match(a):
        matches.append({"chain": "tron", "label": "Tron (TRX, USDT-TRC20)"})
    if BTC_RE.match(a):
        matches.append({"chain": "btc", "label": "Bitcoin"})
    if LTC_RE.match(a):
        matches.append({"chain": "ltc", "label": "Litecoin"})
    if not matches:
        return {"error": "unrecognized address format",
                "address": a,
                "hint": "expected 0x… for ETH, T… for Tron, "
                        "1/3/bc1… for BTC, L/M/ltc1… for LTC"}
    return {"address": a, "candidates": matches}


# ============== Etherscan (ETH) ==============

ETHERSCAN_BASE = "https://api.etherscan.io/v2/api"
# Etherscan v2 needs an explicit chain id even for ETH mainnet (chainid=1).
ETHERSCAN_CHAIN_ID = "1"


def _etherscan(params: dict) -> dict:
    p = dict(params)
    p.setdefault("chainid", ETHERSCAN_CHAIN_ID)
    key = os.environ.get("ETHERSCAN_API_KEY")
    if key:
        p["apikey"] = key
    r = _get(ETHERSCAN_BASE, params=p)
    if isinstance(r, Exception):
        return {"error": f"network: {r}"}
    if r.status_code != 200:
        return {"error": f"etherscan HTTP {r.status_code}"}
    try:
        j = r.json()
    except Exception:
        return {"error": "non-json response from etherscan"}
    # Etherscan returns status="0" with message="No transactions found"
    # for empty results, which isn't really an error.
    if j.get("status") == "0" and j.get("message") not in (
        "No transactions found", "No records found",
    ):
        return {"error": f"etherscan: {j.get('message')} {j.get('result')}"}
    return {"ok": True, "result": j.get("result")}


def eth_address_info(address: str) -> dict:
    """ETH balance, tx counts, first/last seen, EOA-vs-contract."""
    a = (address or "").strip()
    if not ETH_RE.match(a):
        return {"error": "not an ETH address (expected 0x… 40 hex chars)"}

    bal = _etherscan({"module": "account", "action": "balance",
                      "address": a, "tag": "latest"})
    if "error" in bal:
        return bal
    try:
        balance_eth = int(bal["result"]) / WEI
    except Exception:
        balance_eth = None

    # 1 latest tx + 1 oldest tx to bracket activity window
    latest = _etherscan({"module": "account", "action": "txlist",
                         "address": a, "startblock": 0, "endblock": 99999999,
                         "page": 1, "offset": 1, "sort": "desc"})
    oldest = _etherscan({"module": "account", "action": "txlist",
                         "address": a, "startblock": 0, "endblock": 99999999,
                         "page": 1, "offset": 1, "sort": "asc"})

    first_seen = last_seen = None
    if "result" in latest and isinstance(latest["result"], list) and latest["result"]:
        try:
            last_seen = int(latest["result"][0]["timeStamp"])
        except Exception:
            pass
    if "result" in oldest and isinstance(oldest["result"], list) and oldest["result"]:
        try:
            first_seen = int(oldest["result"][0]["timeStamp"])
        except Exception:
            pass

    # Contract detection: getCode returns 0x for EOAs.
    code = _etherscan({"module": "proxy", "action": "eth_getCode",
                       "address": a, "tag": "latest"})
    is_contract = False
    if "result" in code and isinstance(code["result"], str):
        is_contract = code["result"] not in ("0x", "0x0", "")

    return {
        "address": a,
        "chain": "eth",
        "balance_eth": balance_eth,
        "is_contract": is_contract,
        "first_seen_ts": first_seen,
        "first_seen_iso": _iso(first_seen),
        "last_seen_ts": last_seen,
        "last_seen_iso": _iso(last_seen),
        "explorer_url": f"https://etherscan.io/address/{a}",
        "api_key_set": bool(os.environ.get("ETHERSCAN_API_KEY")),
    }


def eth_address_txs(address: str, limit: int = 50) -> dict:
    """Recent ETH (native) transactions for an address, with summary."""
    a = (address or "").strip()
    if not ETH_RE.match(a):
        return {"error": "not an ETH address"}
    try:
        limit = max(1, min(1000, int(limit) if limit else 50))
    except Exception:
        limit = 50
    r = _etherscan({"module": "account", "action": "txlist",
                    "address": a, "startblock": 0, "endblock": 99999999,
                    "page": 1, "offset": limit, "sort": "desc"})
    if "error" in r:
        return r
    raw = r.get("result") or []
    if not isinstance(raw, list):
        return {"error": "unexpected etherscan response shape"}

    txs = []
    a_lc = a.lower()
    for t in raw:
        try:
            val_eth = int(t.get("value", "0")) / WEI
        except Exception:
            val_eth = 0.0
        direction = "out" if (t.get("from", "").lower() == a_lc) else "in"
        txs.append({
            "hash": t.get("hash"),
            "ts": int(t.get("timeStamp", 0) or 0),
            "iso": _iso(int(t.get("timeStamp", 0) or 0)),
            "from": t.get("from"),
            "to": t.get("to"),
            "value_eth": val_eth,
            "direction": direction,
            "block": t.get("blockNumber"),
            "is_error": t.get("isError") == "1",
            "gas_used": t.get("gasUsed"),
        })

    summary = _summarize_txs(a_lc, txs)
    return {
        "address": a,
        "chain": "eth",
        "tx_count_returned": len(txs),
        "summary": summary,
        "transactions": txs,
        "explorer_url": f"https://etherscan.io/address/{a}",
    }


def eth_address_token_txs(address: str, limit: int = 50) -> dict:
    """ERC-20 token transfers in/out — useful for USDT/USDC scam traces."""
    a = (address or "").strip()
    if not ETH_RE.match(a):
        return {"error": "not an ETH address"}
    try:
        limit = max(1, min(1000, int(limit) if limit else 50))
    except Exception:
        limit = 50
    r = _etherscan({"module": "account", "action": "tokentx",
                    "address": a, "page": 1, "offset": limit, "sort": "desc"})
    if "error" in r:
        return r
    raw = r.get("result") or []
    if not isinstance(raw, list):
        return {"error": "unexpected etherscan response shape"}

    txs = []
    token_counter: Counter = Counter()
    a_lc = a.lower()
    for t in raw:
        decimals = int(t.get("tokenDecimal", "18") or 18)
        try:
            amt = int(t.get("value", "0")) / (10 ** decimals)
        except Exception:
            amt = 0.0
        token_counter[t.get("tokenSymbol", "?")] += 1
        txs.append({
            "hash": t.get("hash"),
            "ts": int(t.get("timeStamp", 0) or 0),
            "iso": _iso(int(t.get("timeStamp", 0) or 0)),
            "from": t.get("from"),
            "to": t.get("to"),
            "amount": amt,
            "token": t.get("tokenSymbol"),
            "token_name": t.get("tokenName"),
            "contract": t.get("contractAddress"),
            "direction": "out" if t.get("from", "").lower() == a_lc else "in",
        })
    return {
        "address": a,
        "chain": "eth",
        "transfer_count_returned": len(txs),
        "tokens_seen": dict(token_counter.most_common(20)),
        "transfers": txs,
        "explorer_url": f"https://etherscan.io/address/{a}#tokentxns",
    }


# ============== Blockchain.com (BTC) ==============

def btc_address_info(address: str) -> dict:
    """BTC address summary via Blockchain.com public endpoint."""
    a = (address or "").strip()
    if not BTC_RE.match(a):
        return {"error": "not a BTC address"}
    r = _get(f"https://blockchain.info/rawaddr/{a}?limit=1")
    if isinstance(r, Exception):
        return {"error": f"network: {r}"}
    if r.status_code != 200:
        return {"error": f"blockchain.info HTTP {r.status_code}"}
    try:
        j = r.json()
    except Exception:
        return {"error": "non-json response"}
    first_seen = last_seen = None
    txs = j.get("txs") or []
    if txs:
        try:
            last_seen = int(txs[0].get("time"))
        except Exception:
            pass
    return {
        "address": a,
        "chain": "btc",
        "balance_btc": (j.get("final_balance") or 0) / SAT,
        "total_received_btc": (j.get("total_received") or 0) / SAT,
        "total_sent_btc": (j.get("total_sent") or 0) / SAT,
        "tx_count": j.get("n_tx"),
        "last_seen_ts": last_seen,
        "last_seen_iso": _iso(last_seen),
        "explorer_url": f"https://blockchain.com/btc/address/{a}",
    }


def btc_address_txs(address: str, limit: int = 50) -> dict:
    """BTC transaction list — flattens inputs/outputs into a per-tx summary."""
    a = (address or "").strip()
    if not BTC_RE.match(a):
        return {"error": "not a BTC address"}
    try:
        limit = max(1, min(100, int(limit) if limit else 50))
    except Exception:
        limit = 50
    r = _get(f"https://blockchain.info/rawaddr/{a}?limit={limit}")
    if isinstance(r, Exception):
        return {"error": f"network: {r}"}
    if r.status_code != 200:
        return {"error": f"blockchain.info HTTP {r.status_code}"}
    try:
        j = r.json()
    except Exception:
        return {"error": "non-json response"}
    txs = []
    counter_to: Counter = Counter()
    counter_from: Counter = Counter()
    for t in (j.get("txs") or []):
        inputs = [(inp.get("prev_out", {}).get("addr"),
                   (inp.get("prev_out", {}).get("value") or 0) / SAT)
                  for inp in (t.get("inputs") or [])]
        outputs = [(out.get("addr"), (out.get("value") or 0) / SAT)
                   for out in (t.get("out") or [])]
        is_input = any(addr == a for addr, _ in inputs)
        direction = "out" if is_input else "in"
        amt = 0.0
        if direction == "in":
            amt = sum(v for addr, v in outputs if addr == a)
            for addr, _ in inputs:
                if addr and addr != a:
                    counter_from[addr] += 1
        else:
            amt = sum(v for addr, v in outputs if addr and addr != a)
            for addr, _ in outputs:
                if addr and addr != a:
                    counter_to[addr] += 1
        txs.append({
            "hash": t.get("hash"),
            "ts": t.get("time"),
            "iso": _iso(t.get("time")),
            "direction": direction,
            "amount_btc": amt,
            "input_count": len(inputs),
            "output_count": len(outputs),
            "block_height": t.get("block_height"),
        })
    summary = {
        "in_count": sum(1 for t in txs if t["direction"] == "in"),
        "out_count": sum(1 for t in txs if t["direction"] == "out"),
        "total_in_btc": round(sum(t["amount_btc"] for t in txs if t["direction"] == "in"), 8),
        "total_out_btc": round(sum(t["amount_btc"] for t in txs if t["direction"] == "out"), 8),
        "top_recipients": [{"addr": k, "count": v} for k, v in counter_to.most_common(10)],
        "top_senders": [{"addr": k, "count": v} for k, v in counter_from.most_common(10)],
        "unique_recipients": len(counter_to),
        "unique_senders": len(counter_from),
    }
    return {
        "address": a,
        "chain": "btc",
        "tx_count_returned": len(txs),
        "summary": summary,
        "transactions": txs,
        "explorer_url": f"https://blockchain.com/btc/address/{a}",
    }


# ============== TronScan (TRX / USDT-TRC20) ==============

def tron_address_info(address: str) -> dict:
    """Tron address summary via TronScan public API."""
    a = (address or "").strip()
    if not TRON_RE.match(a):
        return {"error": "not a Tron address (expected T… 34 chars)"}
    r = _get(f"https://apilist.tronscanapi.com/api/accountv2?address={a}",
             headers=_tron_headers())
    if isinstance(r, Exception):
        return {"error": f"network: {r}"}
    if r.status_code != 200:
        return {"error": f"tronscan HTTP {r.status_code}"}
    try:
        j = r.json()
    except Exception:
        return {"error": "non-json response"}
    balance_trx = (j.get("balance") or 0) / SUN
    # USDT-TRC20 is the scam vehicle of choice — surface it explicitly.
    trc20 = []
    for t in (j.get("trc20token_balances") or [])[:20]:
        try:
            amt = float(t.get("balance", 0)) / (10 ** int(t.get("tokenDecimal", 6)))
        except Exception:
            amt = None
        trc20.append({
            "symbol": t.get("tokenAbbr"),
            "name": t.get("tokenName"),
            "balance": amt,
            "contract": t.get("tokenId"),
        })
    return {
        "address": a,
        "chain": "tron",
        "balance_trx": balance_trx,
        "tx_count": j.get("totalTransactionCount"),
        "first_seen_ts": (j.get("date_created") or 0) // 1000 if j.get("date_created") else None,
        "first_seen_iso": _iso((j.get("date_created") or 0) // 1000) if j.get("date_created") else None,
        "trc20_tokens": trc20,
        "explorer_url": f"https://tronscan.org/#/address/{a}",
    }


def tron_address_txs(address: str, limit: int = 50) -> dict:
    """Recent Tron native TRX transactions."""
    a = (address or "").strip()
    if not TRON_RE.match(a):
        return {"error": "not a Tron address"}
    try:
        limit = max(1, min(200, int(limit) if limit else 50))
    except Exception:
        limit = 50
    r = _get("https://apilist.tronscanapi.com/api/transaction",
             params={"address": a, "limit": limit, "start": 0, "sort": "-timestamp"},
             headers=_tron_headers())
    if isinstance(r, Exception):
        return {"error": f"network: {r}"}
    if r.status_code != 200:
        return {"error": f"tronscan HTTP {r.status_code}"}
    try:
        j = r.json()
    except Exception:
        return {"error": "non-json response"}
    txs = []
    a_lc = a
    for t in (j.get("data") or []):
        amt_trx = (t.get("amount") or 0) / SUN
        owner = t.get("ownerAddress")
        to = t.get("toAddress")
        direction = "out" if owner == a_lc else ("in" if to == a_lc else "other")
        txs.append({
            "hash": t.get("hash"),
            "ts": (t.get("timestamp") or 0) // 1000,
            "iso": _iso((t.get("timestamp") or 0) // 1000),
            "from": owner,
            "to": to,
            "amount_trx": amt_trx,
            "direction": direction,
            "confirmed": t.get("confirmed"),
            "contract_type": t.get("contractType"),
        })
    summary = _summarize_txs(a_lc, [
        {**tx, "value_eth": tx["amount_trx"]} for tx in txs
    ])
    return {
        "address": a,
        "chain": "tron",
        "tx_count_returned": len(txs),
        "summary": summary,
        "transactions": txs,
        "explorer_url": f"https://tronscan.org/#/address/{a}",
    }


# ============== Blockchair (multi-chain fallback) ==============

def blockchair_address(address: str, chain: str = "bitcoin") -> dict:
    """Blockchair multi-chain lookup. Supported chains include:
    bitcoin, bitcoin-cash, litecoin, dogecoin, dash, zcash,
    ethereum (use eth_address_info for richer ETH data)."""
    a = (address or "").strip()
    if not a:
        return {"error": "empty address"}
    chain = (chain or "bitcoin").strip().lower()
    url = f"https://api.blockchair.com/{chain}/dashboards/address/{a}"
    params = {}
    if os.environ.get("BLOCKCHAIR_API_KEY"):
        params["key"] = os.environ["BLOCKCHAIR_API_KEY"]
    r = _get(url, params=params)
    if isinstance(r, Exception):
        return {"error": f"network: {r}"}
    if r.status_code != 200:
        return {"error": f"blockchair HTTP {r.status_code}"}
    try:
        j = r.json()
    except Exception:
        return {"error": "non-json response"}
    data = (j.get("data") or {}).get(a) or {}
    if not data:
        return {"error": f"no data for {a} on {chain}"}
    addr_info = data.get("address") or {}
    return {
        "address": a,
        "chain": chain,
        "balance": addr_info.get("balance"),
        "received": addr_info.get("received"),
        "spent": addr_info.get("spent"),
        "tx_count": addr_info.get("transaction_count"),
        "first_seen": addr_info.get("first_seen_receiving"),
        "last_seen": addr_info.get("last_seen_receiving"),
        "scripthash_type": addr_info.get("type"),
        "context": j.get("context"),
        "explorer_url": f"https://blockchair.com/{chain}/address/{a}",
    }


# ============== BTC.com (BTC fallback) ==============

def btccom_address(address: str) -> dict:
    """BTC.com fallback when blockchain.info is rate-limited."""
    a = (address or "").strip()
    if not BTC_RE.match(a):
        return {"error": "not a BTC address"}
    r = _get(f"https://chain.api.btc.com/v3/address/{a}")
    if isinstance(r, Exception):
        return {"error": f"network: {r}"}
    if r.status_code != 200:
        return {"error": f"btc.com HTTP {r.status_code}"}
    try:
        j = r.json()
    except Exception:
        return {"error": "non-json response"}
    if j.get("err_no"):
        return {"error": f"btc.com: {j.get('err_msg')}"}
    d = j.get("data") or {}
    return {
        "address": a,
        "chain": "btc",
        "balance_btc": (d.get("balance") or 0) / SAT,
        "received_btc": (d.get("received") or 0) / SAT,
        "sent_btc": (d.get("sent") or 0) / SAT,
        "tx_count": d.get("tx_count"),
        "unspent_tx_count": d.get("unspent_tx_count"),
        "first_tx": d.get("first_tx"),
        "last_tx": d.get("last_tx"),
        "explorer_url": f"https://btc.com/{a}",
    }


# ============== Transaction lookup ==============

def tx_lookup(txid: str, chain: str = "eth") -> dict:
    """Look up a single transaction by hash. chain: eth | btc | tron."""
    t = (txid or "").strip()
    if not TXID_RE.match(t):
        return {"error": "txid must be 64 hex chars (optional 0x prefix)"}
    chain = (chain or "eth").strip().lower()

    if chain == "eth":
        if not t.startswith("0x"):
            t = "0x" + t
        r = _etherscan({"module": "proxy", "action": "eth_getTransactionByHash",
                        "txhash": t})
        if "error" in r:
            return r
        res = r.get("result") or {}
        try:
            val = int(res.get("value", "0x0"), 16) / WEI
        except Exception:
            val = None
        return {
            "chain": "eth",
            "hash": t,
            "from": res.get("from"),
            "to": res.get("to"),
            "value_eth": val,
            "block": res.get("blockNumber"),
            "input_data_size": len(res.get("input", "")),
            "explorer_url": f"https://etherscan.io/tx/{t}",
            "raw": res,
        }

    if chain == "btc":
        # blockchain.info accepts either with or without 0x; strip just in case.
        t2 = t[2:] if t.startswith("0x") else t
        r = _get(f"https://blockchain.info/rawtx/{t2}")
        if isinstance(r, Exception):
            return {"error": f"network: {r}"}
        if r.status_code != 200:
            return {"error": f"blockchain.info HTTP {r.status_code}"}
        try:
            j = r.json()
        except Exception:
            return {"error": "non-json response"}
        return {
            "chain": "btc",
            "hash": j.get("hash"),
            "ts": j.get("time"),
            "iso": _iso(j.get("time")),
            "inputs": [{"addr": (i.get("prev_out") or {}).get("addr"),
                        "value_btc": ((i.get("prev_out") or {}).get("value") or 0) / SAT}
                       for i in (j.get("inputs") or [])],
            "outputs": [{"addr": o.get("addr"),
                         "value_btc": (o.get("value") or 0) / SAT}
                        for o in (j.get("out") or [])],
            "block_height": j.get("block_height"),
            "size": j.get("size"),
            "fee_btc": (j.get("fee") or 0) / SAT,
            "explorer_url": f"https://blockchain.com/btc/tx/{t2}",
        }

    if chain == "tron":
        t2 = t[2:] if t.startswith("0x") else t
        r = _get("https://apilist.tronscanapi.com/api/transaction-info",
                 params={"hash": t2}, headers=_tron_headers())
        if isinstance(r, Exception):
            return {"error": f"network: {r}"}
        if r.status_code != 200:
            return {"error": f"tronscan HTTP {r.status_code}"}
        try:
            j = r.json()
        except Exception:
            return {"error": "non-json response"}
        return {
            "chain": "tron",
            "hash": j.get("hash"),
            "ts": (j.get("timestamp") or 0) // 1000,
            "iso": _iso((j.get("timestamp") or 0) // 1000),
            "from": j.get("ownerAddress"),
            "to": j.get("toAddress"),
            "amount_trx": (j.get("contractData", {}).get("amount") or 0) / SUN,
            "contract_type": j.get("contractType"),
            "explorer_url": f"https://tronscan.org/#/transaction/{t2}",
        }

    return {"error": f"unsupported chain: {chain}"}


# ============== Multi-chain lookup ==============

def multi_chain_lookup(address: str) -> dict:
    """Auto-detect chain from address format and call the right backend.
    Returns a dict keyed by chain with each chain's response."""
    a = (address or "").strip()
    if not a:
        return {"error": "empty address"}
    det = detect_chain(a)
    if "error" in det:
        return det
    out: dict = {"address": a, "chains_tried": [], "results": {}}
    for cand in det["candidates"]:
        chain = cand["chain"]
        out["chains_tried"].append(chain)
        if chain == "eth":
            out["results"]["eth"] = eth_address_info(a)
        elif chain == "btc":
            out["results"]["btc"] = btc_address_info(a)
        elif chain == "tron":
            out["results"]["tron"] = tron_address_info(a)
        elif chain == "ltc":
            out["results"]["ltc"] = blockchair_address(a, "litecoin")
    return out


# ============== Risk / pattern analysis ==============

def wallet_risk(address: str, chain: str = "eth", limit: int = 200) -> dict:
    """Compute observable risk *features* (not a verdict). Features:
       - top-recipient concentration (consolidation)
       - fan-out width (mixer-like behavior)
       - in/out velocity bursts
       - many small same-value outgoings (drainer / dust)
       - dormant-then-active flips

    The function intentionally does NOT label a wallet as criminal —
    it surfaces patterns an investigator can corroborate.
    """
    a = (address or "").strip()
    chain = (chain or "eth").strip().lower()
    if chain == "auto":
        det = detect_chain(a)
        if "error" in det:
            return det
        chain = det["candidates"][0]["chain"]

    if chain == "eth":
        info = eth_address_info(a)
        txr = eth_address_txs(a, limit=limit)
    elif chain == "btc":
        info = btc_address_info(a)
        txr = btc_address_txs(a, limit=min(limit, 100))
    elif chain == "tron":
        info = tron_address_info(a)
        txr = tron_address_txs(a, limit=min(limit, 200))
    else:
        return {"error": f"risk analysis not implemented for {chain}"}

    if "error" in info:
        return info
    if "error" in txr:
        return txr

    txs = txr.get("transactions") or []
    if not txs:
        return {
            "address": a, "chain": chain,
            "info": info,
            "features": {"note": "no transactions returned"},
            "flags": [],
            "score": 0,
        }

    # --- feature extraction ---
    out_counter: Counter = Counter()
    in_counter: Counter = Counter()
    out_values = []
    timestamps = []
    a_lc = a.lower() if chain == "eth" else a
    for t in txs:
        ts = t.get("ts") or 0
        if ts:
            timestamps.append(ts)
        direction = t.get("direction")
        if chain == "eth":
            val = t.get("value_eth", 0) or 0
            counterparty = t.get("to") if direction == "out" else t.get("from")
        elif chain == "btc":
            val = t.get("amount_btc", 0) or 0
            counterparty = None  # BTC tx counterparties aren't 1:1 — summary handles it
        else:  # tron
            val = t.get("amount_trx", 0) or 0
            counterparty = t.get("to") if direction == "out" else t.get("from")
        if direction == "out":
            out_values.append(val)
            if counterparty:
                out_counter[counterparty] += 1
        elif direction == "in":
            if counterparty:
                in_counter[counterparty] += 1

    # BTC summary already has top_recipients — pull from there
    if chain == "btc":
        for entry in (txr.get("summary", {}).get("top_recipients") or []):
            out_counter[entry["addr"]] = entry["count"]
        for entry in (txr.get("summary", {}).get("top_senders") or []):
            in_counter[entry["addr"]] = entry["count"]

    total_out = sum(out_values) if out_values else 0
    top_recipient_share = 0.0
    if out_counter:
        top_count = out_counter.most_common(1)[0][1]
        top_recipient_share = top_count / max(1, sum(out_counter.values()))

    unique_recipients = len(out_counter)
    unique_senders = len(in_counter)

    # Bursty timing: count txs that fall within 60s of another tx
    burst_count = 0
    if len(timestamps) > 1:
        ts_sorted = sorted(timestamps, reverse=True)
        for i in range(len(ts_sorted) - 1):
            if abs(ts_sorted[i] - ts_sorted[i + 1]) < 60:
                burst_count += 1

    # Same-value outflows (drainer/dust pattern)
    value_buckets: Counter = Counter()
    for v in out_values:
        # round to 4 decimals to avoid floating-point spread
        value_buckets[round(v, 4)] += 1
    most_common_outflow = value_buckets.most_common(1)[0] if value_buckets else (None, 0)

    # Dormancy flip: gap > 180 days between earliest and latest window
    dormancy_days = 0
    if timestamps:
        ts_sorted = sorted(timestamps)
        gaps = [ts_sorted[i + 1] - ts_sorted[i] for i in range(len(ts_sorted) - 1)]
        if gaps:
            dormancy_days = max(gaps) / 86400

    features = {
        "tx_sample_size": len(txs),
        "unique_recipients": unique_recipients,
        "unique_senders": unique_senders,
        "top_recipient_share": round(top_recipient_share, 3),
        "burst_pairs_under_60s": burst_count,
        "most_common_outflow_value": most_common_outflow[0],
        "most_common_outflow_count": most_common_outflow[1],
        "max_dormancy_days": round(dormancy_days, 1),
        "total_out_value": round(total_out, 6),
    }

    # --- flag generation (descriptive, not accusatory) ---
    flags = []
    score = 0
    if top_recipient_share >= 0.7 and sum(out_counter.values()) >= 5:
        flags.append({
            "id": "consolidation",
            "severity": "medium",
            "detail": f"{top_recipient_share*100:.0f}% of outgoing tx go to one address "
                      f"(possible consolidation / exchange deposit)",
        })
        score += 25
    if unique_recipients >= 30 and len(txs) <= 100:
        flags.append({
            "id": "fan_out",
            "severity": "medium",
            "detail": f"{unique_recipients} distinct recipients in {len(txs)} tx "
                      f"(fan-out / possible mixer-like behavior)",
        })
        score += 20
    if burst_count >= 5:
        flags.append({
            "id": "bursty_timing",
            "severity": "low",
            "detail": f"{burst_count} tx pairs within 60s of each other "
                      f"(possible scripted/automated activity)",
        })
        score += 10
    if most_common_outflow[1] >= 5 and most_common_outflow[0]:
        flags.append({
            "id": "repeated_same_value",
            "severity": "medium",
            "detail": f"{most_common_outflow[1]} outflows of identical value "
                      f"({most_common_outflow[0]}) — drainer / dust / automated payout pattern",
        })
        score += 15
    if dormancy_days >= 180:
        flags.append({
            "id": "dormancy_flip",
            "severity": "low",
            "detail": f"max gap of {dormancy_days:.0f} days between tx — "
                      f"dormant wallet recently re-activated",
        })
        score += 5
    if info.get("is_contract"):
        flags.append({
            "id": "is_contract",
            "severity": "info",
            "detail": "address is a smart contract, not an EOA",
        })

    score = min(100, score)
    return {
        "address": a,
        "chain": chain,
        "info": info,
        "features": features,
        "top_recipients": [{"addr": k, "count": v} for k, v in out_counter.most_common(10)],
        "top_senders": [{"addr": k, "count": v} for k, v in in_counter.most_common(10)],
        "flags": flags,
        "score": score,
        "score_band": ("low" if score < 25 else
                       "medium" if score < 60 else "high"),
        "disclaimer": "Score is descriptive of observable patterns only. "
                      "It is NOT a verdict. Always corroborate with public "
                      "scam reports, victim statements, and KYT services.",
    }


# ============== shared helpers ==============

def _iso(ts: Optional[int]) -> Optional[str]:
    """Unix seconds → ISO 8601 UTC, or None."""
    if not ts:
        return None
    try:
        return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(int(ts)))
    except Exception:
        return None


def _summarize_txs(addr_lc: str, txs: list) -> dict:
    """Per-direction counts + top counterparties. Expects each tx to have
    `direction`, `value_eth` (or analogous), `from`, `to`, `ts` fields."""
    in_count = out_count = 0
    in_value = out_value = 0.0
    out_to: Counter = Counter()
    in_from: Counter = Counter()
    for t in txs:
        v = t.get("value_eth") or 0
        if t.get("direction") == "out":
            out_count += 1
            out_value += v
            if t.get("to"):
                out_to[t["to"]] += 1
        elif t.get("direction") == "in":
            in_count += 1
            in_value += v
            if t.get("from"):
                in_from[t["from"]] += 1
    return {
        "in_count": in_count,
        "out_count": out_count,
        "in_value": round(in_value, 6),
        "out_value": round(out_value, 6),
        "unique_recipients": len(out_to),
        "unique_senders": len(in_from),
        "top_recipients": [{"addr": k, "count": v} for k, v in out_to.most_common(10)],
        "top_senders": [{"addr": k, "count": v} for k, v in in_from.most_common(10)],
    }
