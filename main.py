from fastapi import FastAPI, HTTPException
from fastapi.responses import HTMLResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel
from openai import OpenAI
import stripe
import os
import httpx
import json

app = FastAPI()

client = OpenAI(api_key=os.environ.get("OPENAI_API_KEY"))
stripe.api_key = os.environ.get("STRIPE_SECRET_KEY")
DOMAIN = os.environ.get("DOMAIN", "http://localhost:8000")

CHAIN_IDS = {
    "eth": "1", "bsc": "56", "base": "8453",
    "arbitrum": "42161", "polygon": "137", "solana": "solana"
}

class AnalysisRequest(BaseModel):
    address: str
    chain: str

def auto_detect_chain(address: str, selected_chain: str) -> str:
    address = address.strip()
    if not address.startswith("0x") and len(address) > 30:
        return "solana"
    if address.startswith("0x"):
        if selected_chain in ["bsc", "base", "arbitrum", "polygon", "eth"]:
            return selected_chain
        return "eth"
    return selected_chain

# ─── DATA SOURCES ───────────────────────────────────────────

async def get_goplus_data(address: str, chain: str) -> dict:
    try:
        async with httpx.AsyncClient(timeout=15.0) as http:
            if chain == "solana":
                url = f"https://api.gopluslabs.io/api/v1/solana/token_security?contract_addresses={address}"
            else:
                chain_id = CHAIN_IDS.get(chain, "1")
                url = f"https://api.gopluslabs.io/api/v1/token_security/{chain_id}?contract_addresses={address}"
            r = await http.get(url)
            d = r.json()
            if d.get("code") == 1 and d.get("result"):
                result = list(d["result"].values())[0]
                if result:
                    return result
    except Exception as e:
        print(f"GoPlus error: {e}")
    return {}

async def get_goplus_multi_chain(address: str, chain: str) -> tuple:
    result = await get_goplus_data(address, chain)
    if result:
        return result, chain
    if address.startswith("0x"):
        for c in ["bsc", "eth", "base", "arbitrum", "polygon"]:
            if c != chain:
                result = await get_goplus_data(address, c)
                if result:
                    return result, c
    return {}, chain

async def get_honeypot_data(address: str, chain: str) -> dict:
    """HoneyPot.is — free, covers ETH + BSC, great for new tokens"""
    HONEYPOT_CHAIN_IDS = {"eth": "1", "bsc": "56", "base": "8453", "arbitrum": "42161", "polygon": "137"}
    chain_id = HONEYPOT_CHAIN_IDS.get(chain, "1")
    try:
        async with httpx.AsyncClient(timeout=10.0) as http:
            url = f"https://api.honeypot.is/v2/IsHoneypot?address={address}&chainID={chain_id}"
            r = await http.get(url)
            if r.status_code == 200:
                return r.json()
    except Exception as e:
        print(f"HoneyPot.is error: {e}")
    return {}

async def get_contract_verified(address: str, chain: str) -> bool:
    """Check if contract is verified on block explorer"""
    EXPLORERS = {
        "eth": f"https://api.etherscan.io/api?module=contract&action=getsourcecode&address={address}",
        "bsc": f"https://api.bscscan.com/api?module=contract&action=getsourcecode&address={address}",
    }
    url = EXPLORERS.get(chain)
    if not url:
        return None
    try:
        async with httpx.AsyncClient(timeout=8.0) as http:
            r = await http.get(url)
            d = r.json()
            if d.get("status") == "1" and d.get("result"):
                source = d["result"][0].get("SourceCode", "")
                return bool(source and source != "")
    except:
        pass
    return None

async def get_rugcheck_data(address: str) -> dict:
    """RugCheck.xyz API — excellent for Solana tokens"""
    try:
        async with httpx.AsyncClient(timeout=12.0) as http:
            url = f"https://api.rugcheck.xyz/v1/tokens/{address}/report"
            r = await http.get(url)
            if r.status_code == 200:
                return r.json()
    except Exception as e:
        print(f"RugCheck error: {e}")
    return {}

async def get_dexscreener_data(address: str) -> dict:
    try:
        async with httpx.AsyncClient(timeout=10.0) as http:
            url = f"https://api.dexscreener.com/latest/dex/tokens/{address}"
            r = await http.get(url)
            d = r.json()
            if d.get("pairs") and len(d["pairs"]) > 0:
                pairs = sorted(
                    d["pairs"],
                    key=lambda x: float(x.get("liquidity", {}).get("usd", 0) or 0),
                    reverse=True
                )
                return pairs[0]
    except Exception as e:
        print(f"DexScreener error: {e}")
    return {}

# ─── ANALYSIS FUNCTIONS ────────────────────────────────────

KNOWN_LOCKERS = ["dead", "unicrypt", "team.finance", "pinksale", "mudra", "deeplock", "uncx", "pinklock"]

def check_liquidity_lock(goplus: dict, rugcheck: dict) -> str:
    # Try GoPlus LP holders first
    lp_holders = goplus.get("lp_holders", [])
    if lp_holders:
        total_locked = 0.0
        for h in lp_holders:
            address = h.get("address", "").lower()
            tag = h.get("tag", "").lower()
            pct = float(h.get("percent", 0)) * 100
            is_locked = h.get("is_locked", 0)
            is_dead = "dead" in address or address == "0x0000000000000000000000000000000000000000"
            is_locker = any(l in tag for l in KNOWN_LOCKERS) or is_dead
            if is_locked == 1 or is_locker:
                total_locked += pct
        if total_locked >= 80:
            return f"LOCKED ({total_locked:.0f}%)"
        elif total_locked > 0:
            return f"PARTIAL ({total_locked:.0f}% locked)"
        else:
            return "NOT LOCKED"

    # Try RugCheck for Solana
    if rugcheck:
        markets = rugcheck.get("markets", [])
        for m in markets:
            lp = m.get("lp", {})
            if lp.get("lpLockedPct", 0) > 80:
                return f"LOCKED ({lp['lpLockedPct']:.0f}%)"
            elif lp.get("lpLockedPct", 0) > 0:
                return f"PARTIAL ({lp['lpLockedPct']:.0f}%)"
        return "NOT LOCKED"

    return "UNKNOWN"

def analyze_cluster_from_goplus(holders: list) -> dict:
    """Cluster analysis from GoPlus holder data"""
    if not holders:
        return {}
    pcts = [float(h.get("percent", 0)) * 100 for h in holders]
    return _compute_cluster(pcts, holders)

def analyze_cluster_from_dex(dex: dict) -> dict:
    """Fallback cluster analysis from DexScreener"""
    if not dex:
        return {}
    # DexScreener doesn't have holder list but has some info
    # We return a minimal cluster based on what we know
    return {}

def analyze_cluster_from_rugcheck(rugcheck: dict) -> dict:
    """Cluster analysis from RugCheck data (Solana)"""
    if not rugcheck:
        return {}
    top_holders = rugcheck.get("topHolders", [])
    if not top_holders:
        return {}
    pcts = [float(h.get("pct", 0)) * 100 for h in top_holders]
    return _compute_cluster(pcts, None)

def _compute_cluster(pcts: list, raw_holders) -> dict:
    if not pcts:
        return {}
    n = len(pcts)
    total = sum(pcts)
    if total == 0:
        return {}

    # Gini coefficient
    sorted_p = sorted(pcts)
    gini_sum = sum((2*(i+1) - n - 1) * p for i, p in enumerate(sorted_p))
    gini = abs(gini_sum / (n * total)) if total > 0 else 0

    top10_pct = sum(pcts[:10])
    whale_count = sum(1 for p in pcts if p > 5)

    # Split wallet detection
    split_count = 0
    for i in range(min(len(pcts), 20)):
        for j in range(i+1, min(len(pcts), 20)):
            if pcts[i] > 0.5 and pcts[j] > 0.5:
                diff = abs(pcts[i] - pcts[j])
                avg = (pcts[i] + pcts[j]) / 2
                if avg > 0 and (diff / avg) < 0.05:
                    split_count += 1

    split_risk = "HIGH" if split_count >= 5 else "MEDIUM" if split_count >= 2 else "LOW"

    return {
        "gini": round(gini, 3),
        "top10_pct": round(top10_pct, 2),
        "whale_count": whale_count,
        "split_risk": split_risk,
        "split_wallet_count": split_count,
        "total_analyzed": n
    }

def calculate_risk(goplus: dict, dex: dict, rugcheck: dict, honeypot: dict, has_data: bool) -> tuple:
    score = 0
    flags = []

    # ─── NO DATA = RED FLAG ───
    if not has_data:
        score += 30
        flags.append({"level": "high", "text": "No verified security data found — unverified token carries elevated risk"})

    # ─── HONEYPOT.IS CHECKS (ETH/BSC fallback) ───
    if honeypot:
        hp_result = honeypot.get("honeypotResult", {})
        simulation = honeypot.get("simulationResult", {})
        token_info = honeypot.get("token", {})

        if honeypot.get("isHoneypot"):
            score += 45
            flags.append({"level": "critical", "text": f"HONEYPOT — {honeypot.get('honeypotReason', 'Tokens cannot be sold')}"})

        sell_tax_hp = float(simulation.get("sellTax", 0) or 0)
        buy_tax_hp = float(simulation.get("buyTax", 0) or 0)
        if sell_tax_hp > 10:
            score += 25
            flags.append({"level": "critical", "text": f"Sell tax {sell_tax_hp:.1f}% — Classic rug setup"})
        elif sell_tax_hp > 5:
            score += 10
            flags.append({"level": "medium", "text": f"High sell tax: {sell_tax_hp:.1f}%"})

        holder_count = int(token_info.get("totalHolders", 0) or 0)
        if holder_count < 50 and holder_count > 0:
            score += 10
            flags.append({"level": "medium", "text": f"Very few holders: {holder_count}"})

    # ─── GOPLUS CHECKS ───
    if goplus.get("is_honeypot") == "1":
        score += 45
        flags.append({"level": "critical", "text": "HONEYPOT — Tokens cannot be sold"})

    if goplus.get("is_mintable") == "1":
        score += 20
        flags.append({"level": "high", "text": "Mint not revoked — Dev can inflate supply"})

    sell_tax = float(goplus.get("sell_tax", 0) or 0)
    if sell_tax > 10:
        score += 25
        flags.append({"level": "critical", "text": f"Sell tax {sell_tax}% — Classic rug setup"})
    elif sell_tax > 5:
        score += 10
        flags.append({"level": "medium", "text": f"High sell tax: {sell_tax}%"})

    if goplus.get("slippage_modifiable") == "1":
        score += 15
        flags.append({"level": "high", "text": "Dev can modify taxes at any time"})

    if goplus.get("is_open_source") == "0":
        score += 15
        flags.append({"level": "high", "text": "Contract not verified/open source"})

    owner_pct = float(goplus.get("owner_percent", 0) or 0)
    if owner_pct > 5:
        score += 15
        flags.append({"level": "high", "text": f"Owner holds {owner_pct:.1f}% of supply"})

    holders = goplus.get("holders", [])
    if holders:
        top = float(holders[0].get("percent", 0)) * 100
        if top > 30:
            score += 20
            flags.append({"level": "critical", "text": f"Top wallet holds {top:.1f}% of supply"})
        elif top > 20:
            score += 10
            flags.append({"level": "medium", "text": f"Top wallet holds {top:.1f}%"})

    # ─── RUGCHECK CHECKS (Solana) ───
    if rugcheck:
        rc_risks = rugcheck.get("risks", [])
        for r in rc_risks:
            level = r.get("level", "").lower()
            name = r.get("name", "")
            if level == "danger":
                score += 20
                flags.append({"level": "critical", "text": f"RugCheck: {name}"})
            elif level == "warn":
                score += 10
                flags.append({"level": "medium", "text": f"RugCheck: {name}"})

        # Mint/freeze authority from RugCheck
        mint_auth = rugcheck.get("mintAuthority")
        freeze_auth = rugcheck.get("freezeAuthority")
        if mint_auth and mint_auth != "null":
            score += 15
            flags.append({"level": "high", "text": "Mint authority not revoked (Solana)"})
        if freeze_auth and freeze_auth != "null":
            score += 10
            flags.append({"level": "medium", "text": "Freeze authority active — Dev can freeze wallets"})

    # ─── LIQUIDITY CHECK ───
    lock_status = check_liquidity_lock(goplus, rugcheck)
    if lock_status == "NOT LOCKED":
        score += 20
        flags.append({"level": "critical", "text": "Liquidity NOT LOCKED — Dev can rug anytime"})
    elif "PARTIAL" in lock_status:
        score += 10
        flags.append({"level": "medium", "text": f"Liquidity {lock_status}"})
    elif lock_status == "UNKNOWN" and not has_data:
        flags.append({"level": "medium", "text": "Liquidity lock status unknown"})
    else:
        flags.append({"level": "safe", "text": f"Liquidity {lock_status}"})

    # ─── MARKET DATA ───
    if dex:
        liq = float(dex.get("liquidity", {}).get("usd", 0) or 0)
        if liq < 5000:
            score += 20
            flags.append({"level": "critical", "text": f"Very low liquidity: ${liq:,.0f}"})
        elif liq < 50000:
            score += 10
            flags.append({"level": "medium", "text": f"Low liquidity: ${liq:,.0f}"})

    return min(score, 100), flags

# ─── ROUTES ────────────────────────────────────────────────

@app.get("/", response_class=HTMLResponse)
async def root():
    with open("static/index.html") as f:
        return f.read()

@app.get("/success", response_class=HTMLResponse)
async def success_page():
    with open("static/index.html") as f:
        return f.read()

@app.post("/api/preview")
async def preview(request: AnalysisRequest):
    address = request.address.strip()
    if len(address) < 30:
        raise HTTPException(status_code=400, detail="Invalid contract address")

    detected_chain = auto_detect_chain(address, request.chain)

    # Fetch all data sources in parallel
    import asyncio
    goplus_task = get_goplus_multi_chain(address, detected_chain)
    dex_task = get_dexscreener_data(address)

    if detected_chain == "solana":
        (goplus, actual_chain), dex, rugcheck = await asyncio.gather(
            goplus_task, dex_task, get_rugcheck_data(address)
        )
        honeypot = {}
    else:
        (goplus, actual_chain), dex, honeypot = await asyncio.gather(
            goplus_task, dex_task, get_honeypot_data(address, detected_chain)
        )
        rugcheck = {}

    has_data = bool(goplus) or bool(rugcheck) or bool(honeypot)
    score, flags = calculate_risk(goplus, dex, rugcheck, honeypot, has_data)

    # Cluster analysis — use best available source
    cluster = None
    if goplus.get("holders"):
        cluster = analyze_cluster_from_goplus(goplus["holders"])
    elif rugcheck.get("topHolders"):
        cluster = analyze_cluster_from_rugcheck(rugcheck)

    verdict = "DANGER" if score >= 60 else "WARNING" if score >= 25 else "LIKELY SAFE"
    token_name = ""
    if dex:
        name = dex.get("baseToken", {}).get("name", "")
        symbol = dex.get("baseToken", {}).get("symbol", "")
        token_name = f"{name} ({symbol})" if symbol else name
    if not token_name and rugcheck:
        token_name = rugcheck.get("tokenMeta", {}).get("name", "")
    if not token_name and honeypot:
        token_name = honeypot.get("token", {}).get("name", "")

    return {
        "score": score,
        "verdict": verdict,
        "token_name": token_name,
        "top_flags": flags[:2],
        "total_flags": len(flags),
        "chain_detected": actual_chain,
        "has_data": has_data,
        "cluster": cluster
    }

@app.post("/api/checkout")
async def checkout(request: AnalysisRequest):
    session = stripe.checkout.Session.create(
        payment_method_types=["card"],
        line_items=[{
            "price_data": {
                "currency": "usd",
                "product_data": {
                    "name": "Full Security Report",
                    "description": "Complete rug pull analysis with AI verdict"
                },
                "unit_amount": 700,
            },
            "quantity": 1,
        }],
        mode="payment",
        success_url=f"{DOMAIN}/success?session_id={{CHECKOUT_SESSION_ID}}",
        cancel_url=f"{DOMAIN}/",
        metadata={"address": request.address[:200], "chain": request.chain}
    )
    return {"url": session.url}

@app.get("/api/report")
async def get_report(session_id: str):
    try:
        session = stripe.checkout.Session.retrieve(session_id)
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid session")

    if session.payment_status != "paid":
        raise HTTPException(status_code=402, detail="Payment required")

    address = session.metadata.get("address", "")
    chain = session.metadata.get("chain", "eth")
    detected_chain = auto_detect_chain(address, chain)

    import asyncio
    goplus_task = get_goplus_multi_chain(address, detected_chain)
    dex_task = get_dexscreener_data(address)

    if detected_chain == "solana":
        (goplus, actual_chain), dex, rugcheck = await asyncio.gather(
            goplus_task, dex_task, get_rugcheck_data(address)
        )
        honeypot = {}
    else:
        (goplus, actual_chain), dex, honeypot = await asyncio.gather(
            goplus_task, dex_task, get_honeypot_data(address, detected_chain)
        )
        rugcheck = {}

    has_data = bool(goplus) or bool(rugcheck) or bool(honeypot)
    score, flags = calculate_risk(goplus, dex, rugcheck, honeypot, has_data)

    cluster = None
    if goplus.get("holders"):
        cluster = analyze_cluster_from_goplus(goplus["holders"])
    elif rugcheck.get("topHolders"):
        cluster = analyze_cluster_from_rugcheck(rugcheck)

    # Get honeypot.is data for report
    hp_sim = honeypot.get("simulationResult", {}) if honeypot else {}

    details = {
        "address": address,
        "chain": actual_chain.upper(),
        "risk_score": score,
        "has_security_data": has_data,
        "honeypot": goplus.get("is_honeypot") == "1" or honeypot.get("isHoneypot", False),
        "mintable": goplus.get("is_mintable") == "1",
        "buy_tax": f"{float(goplus.get('buy_tax', 0) or hp_sim.get('buyTax', 0) or 0):.1f}%",
        "sell_tax": f"{float(goplus.get('sell_tax', 0) or hp_sim.get('sellTax', 0) or 0):.1f}%",
        "open_source": goplus.get("is_open_source") == "1",
        "owner_renounced": goplus.get("owner_address", "").lower() in ["", "0x0000000000000000000000000000000000000000"],
        "liquidity_usd": f"${float(dex.get('liquidity', {}).get('usd', 0) or 0):,.0f}" if dex else "N/A",
        "liquidity_lock": check_liquidity_lock(goplus, rugcheck),
        "cluster": cluster,
        "rugcheck_risks": [r.get("name") for r in rugcheck.get("risks", [])] if rugcheck else [],
        "red_flags": [f["text"] for f in flags]
    }

    ai = client.chat.completions.create(
        model="gpt-4o-mini",
        messages=[
            {"role": "system", "content": """You are a professional crypto security auditor.
Analyze this token data and produce a security report in this EXACT format:

━━━ VERDICT ━━━
[SAFE / WARNING / DANGER]
Risk Score: X/100

━━━ SECURITY CHECKS ━━━
Security Data:     [AVAILABLE / NOT AVAILABLE — elevated risk]
Honeypot Test:     [PASS/FAIL/UNKNOWN]
Mint Authority:    [REVOKED/ACTIVE/UNKNOWN]
Buy Tax:           [X% / UNKNOWN]
Sell Tax:          [X% / UNKNOWN]
Contract:          [VERIFIED/UNVERIFIED/UNKNOWN]
Owner Renounced:   [YES/NO/UNKNOWN]
Liquidity:         [$X / UNKNOWN]
Liquidity Lock:    [LOCKED X% / NOT LOCKED / UNKNOWN]

━━━ CLUSTER ANALYSIS ━━━
[If cluster data available: summarize Gini, whale risk, split wallet risk]
[If not available: note this as a risk factor]

━━━ RED FLAGS ━━━
[List each with: 🔴 critical, 🟡 medium, ✅ safe]

━━━ ANALYSIS ━━━
[2-3 sentences. If no data: emphasize this is itself a major red flag]

━━━ RECOMMENDATION ━━━
[Clear advice. If no data: AVOID until verified]

Be direct. No filler. UNKNOWN data should always be treated as risk."""},
            {"role": "user", "content": json.dumps(details, default=str)}
        ],
        max_tokens=600
    )

    return {
        "report": ai.choices[0].message.content,
        "score": score,
        "flags": flags
    }

app.mount("/static", StaticFiles(directory="static"), name="static")

# ─── CRYPTO PAYMENT ────────────────────────────────────────

import time
import secrets

WALLET_ETH = "0x63eAbA93c1B453F2Ed4Dc00610aC98ed5B365be6"
USDC_CONTRACT = "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48"
MIN_USDC = 6.50  # $6.50 minimum to account for gas/slippage

crypto_sessions = {}   # session_id -> {address, chain, started_at, paid}
used_tx_hashes = set() # prevent double-use

class CryptoSessionRequest(BaseModel):
    address: str
    chain: str

@app.post("/api/crypto-session")
async def create_crypto_session(request: CryptoSessionRequest):
    session_id = secrets.token_urlsafe(32)
    crypto_sessions[session_id] = {
        "address": request.address,
        "chain": request.chain,
        "started_at": int(time.time()),
        "paid": False,
        "tx_hash": None
    }
    return {
        "session_id": session_id,
        "wallet": WALLET_ETH,
        "amount_usdc": 7,
        "expires_in": 600  # 10 minutes
    }

async def check_usdc_on_chain(since_timestamp: int) -> tuple:
    """Check Etherscan for USDC transfers to our wallet"""
    try:
        async with httpx.AsyncClient(timeout=10.0) as http:
            url = (
                f"https://api.etherscan.io/api"
                f"?module=account&action=tokentx"
                f"&contractaddress={USDC_CONTRACT}"
                f"&address={WALLET_ETH}"
                f"&sort=desc"
            )
            r = await http.get(url)
            data = r.json()
            if data.get("status") == "1" and data.get("result"):
                for tx in data["result"]:
                    tx_time = int(tx.get("timeStamp", 0))
                    tx_hash = tx.get("hash", "")
                    to_addr = tx.get("to", "").lower()

                    if (tx_time >= since_timestamp - 60 and
                        tx_hash not in used_tx_hashes and
                        to_addr == WALLET_ETH.lower()):
                        # USDC has 6 decimals
                        amount = int(tx.get("value", 0)) / 1_000_000
                        if amount >= MIN_USDC:
                            return True, tx_hash
    except Exception as e:
        print(f"Etherscan error: {e}")
    return False, None

@app.get("/api/check-payment")
async def check_payment(session_id: str):
    session = crypto_sessions.get(session_id)
    if not session:
        raise HTTPException(status_code=404, detail="Session not found")

    # Already paid
    if session["paid"]:
        return {"paid": True, "session_id": session_id}

    # Expired (10 min)
    if int(time.time()) - session["started_at"] > 600:
        return {"paid": False, "expired": True}

    # Check on-chain
    paid, tx_hash = await check_usdc_on_chain(session["started_at"])
    if paid:
        session["paid"] = True
        session["tx_hash"] = tx_hash
        used_tx_hashes.add(tx_hash)
        return {"paid": True, "session_id": session_id}

    return {"paid": False, "expired": False}

@app.get("/api/crypto-report")
async def get_crypto_report(session_id: str):
    session = crypto_sessions.get(session_id)
    if not session or not session["paid"]:
        raise HTTPException(status_code=402, detail="Payment required")

    address = session["address"]
    chain = session["chain"]
    detected_chain = auto_detect_chain(address, chain)

    import asyncio
    goplus_task = get_goplus_multi_chain(address, detected_chain)
    dex_task = get_dexscreener_data(address)

    if detected_chain == "solana":
        (goplus, actual_chain), dex, rugcheck = await asyncio.gather(
            goplus_task, dex_task, get_rugcheck_data(address)
        )
    else:
        (goplus, actual_chain), dex = await asyncio.gather(goplus_task, dex_task)
        rugcheck = {}

    has_data = bool(goplus) or bool(rugcheck)
    score, flags = calculate_risk(goplus, dex, rugcheck, has_data)

    cluster = None
    if goplus.get("holders"):
        cluster = analyze_cluster_from_goplus(goplus["holders"])
    elif rugcheck.get("topHolders"):
        cluster = analyze_cluster_from_rugcheck(rugcheck)

    details = {
        "address": address, "chain": actual_chain.upper(),
        "risk_score": score, "has_security_data": has_data,
        "honeypot": goplus.get("is_honeypot") == "1",
        "mintable": goplus.get("is_mintable") == "1",
        "buy_tax": f"{float(goplus.get('buy_tax', 0) or 0):.1f}%",
        "sell_tax": f"{float(goplus.get('sell_tax', 0) or 0):.1f}%",
        "open_source": goplus.get("is_open_source") == "1",
        "owner_renounced": goplus.get("owner_address", "").lower() in ["", "0x0000000000000000000000000000000000000000"],
        "liquidity_usd": f"${float(dex.get('liquidity', {}).get('usd', 0) or 0):,.0f}" if dex else "N/A",
        "liquidity_lock": check_liquidity_lock(goplus, rugcheck),
        "cluster": cluster,
        "red_flags": [f["text"] for f in flags]
    }

    ai = client.chat.completions.create(
        model="gpt-4o-mini",
        messages=[
            {"role": "system", "content": """You are a professional crypto security auditor.
Analyze this token and produce a security report:

━━━ VERDICT ━━━
[SAFE / WARNING / DANGER]
Risk Score: X/100

━━━ SECURITY CHECKS ━━━
Security Data:     [AVAILABLE/NOT AVAILABLE]
Honeypot Test:     [PASS/FAIL/UNKNOWN]
Mint Authority:    [REVOKED/ACTIVE/UNKNOWN]
Buy Tax:           [X%/UNKNOWN]
Sell Tax:          [X%/UNKNOWN]
Contract:          [VERIFIED/UNVERIFIED/UNKNOWN]
Liquidity:         [$X/UNKNOWN]
Liquidity Lock:    [LOCKED/NOT LOCKED/UNKNOWN]

━━━ RED FLAGS ━━━
[🔴 critical, 🟡 medium, ✅ ok]

━━━ ANALYSIS ━━━
[2-3 sentences specific to this token]

━━━ RECOMMENDATION ━━━
[Clear buy/avoid/caution advice]"""},
            {"role": "user", "content": json.dumps(details, default=str)}
        ],
        max_tokens=500
    )

    return {"report": ai.choices[0].message.content, "score": score, "flags": flags}
