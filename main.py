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
    "eth": "1",
    "bsc": "56",
    "base": "8453",
    "arbitrum": "42161",
    "polygon": "137",
    "solana": "solana"
}

class AnalysisRequest(BaseModel):
    address: str
    chain: str

async def get_goplus_data(address: str, chain: str) -> dict:
    try:
        async with httpx.AsyncClient(timeout=15.0) as http:
            if chain == "solana":
                url = f"https://api.gopluslabs.io/api/v1/solana/token_security?contract_addresses={address}"
            else:
                chain_id = CHAIN_IDS.get(chain, "1")
                url = f"https://api.gopluslabs.io/api/v1/token_security/{chain_id}?contract_addresses={address}"
            response = await http.get(url)
            data = response.json()
            if data.get("code") == 1 and data.get("result"):
                return list(data["result"].values())[0]
    except Exception as e:
        print(f"GoPlus error: {e}")
    return {}

async def get_dexscreener_data(address: str) -> dict:
    try:
        async with httpx.AsyncClient(timeout=10.0) as http:
            url = f"https://api.dexscreener.com/latest/dex/tokens/{address}"
            response = await http.get(url)
            data = response.json()
            if data.get("pairs") and len(data["pairs"]) > 0:
                pairs = sorted(
                    data["pairs"],
                    key=lambda x: float(x.get("liquidity", {}).get("usd", 0) or 0),
                    reverse=True
                )
                return pairs[0]
    except Exception as e:
        print(f"DexScreener error: {e}")
    return {}

def calculate_risk(goplus: dict, dex: dict) -> tuple:
    score = 0
    flags = []

    if goplus.get("is_honeypot") == "1":
        score += 45
        flags.append({"level": "critical", "text": "HONEYPOT — Tokens cannot be sold"})

    if goplus.get("is_mintable") == "1":
        score += 20
        flags.append({"level": "high", "text": "Mint not revoked — Dev can inflate supply"})

    sell_tax = float(goplus.get("sell_tax", 0) or 0)
    buy_tax = float(goplus.get("buy_tax", 0) or 0)
    if sell_tax > 10:
        score += 25
        flags.append({"level": "critical", "text": f"Sell tax {sell_tax}% — Classic rug setup"})
    elif sell_tax > 5:
        score += 10
        flags.append({"level": "medium", "text": f"Sell tax {sell_tax}%"})

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
        elif top > 15:
            score += 10
            flags.append({"level": "medium", "text": f"Top wallet holds {top:.1f}%"})

    if dex:
        liq = float(dex.get("liquidity", {}).get("usd", 0) or 0)
        if liq < 5000:
            score += 20
            flags.append({"level": "critical", "text": f"Very low liquidity: ${liq:,.0f}"})
        elif liq < 50000:
            score += 10
            flags.append({"level": "medium", "text": f"Low liquidity: ${liq:,.0f}"})

    return min(score, 100), flags

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

    goplus = await get_goplus_data(address, request.chain)
    dex = await get_dexscreener_data(address)
    score, flags = calculate_risk(goplus, dex)

    verdict = "DANGER" if score >= 60 else "WARNING" if score >= 25 else "LIKELY SAFE"
    token_name = ""
    if dex:
        token_name = dex.get("baseToken", {}).get("name", "")
        symbol = dex.get("baseToken", {}).get("symbol", "")
        if symbol:
            token_name = f"{token_name} ({symbol})"

    return {
        "score": score,
        "verdict": verdict,
        "token_name": token_name,
        "top_flags": flags[:2],
        "total_flags": len(flags)
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
        metadata={
            "address": request.address[:200],
            "chain": request.chain
        }
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

    goplus = await get_goplus_data(address, chain)
    dex = await get_dexscreener_data(address)
    score, flags = calculate_risk(goplus, dex)

    details = {
        "address": address,
        "chain": chain.upper(),
        "risk_score": score,
        "honeypot": goplus.get("is_honeypot") == "1",
        "mintable": goplus.get("is_mintable") == "1",
        "buy_tax": f"{float(goplus.get('buy_tax', 0) or 0):.1f}%",
        "sell_tax": f"{float(goplus.get('sell_tax', 0) or 0):.1f}%",
        "open_source": goplus.get("is_open_source") == "1",
        "owner_renounced": goplus.get("owner_address", "").lower() in ["", "0x0000000000000000000000000000000000000000"],
        "owner_percent": f"{float(goplus.get('owner_percent', 0) or 0):.2f}%",
        "top_holders": [
            {"address": h.get("address", "")[:12] + "...", "pct": f"{float(h.get('percent', 0))*100:.2f}%"}
            for h in goplus.get("holders", [])[:5]
        ],
        "liquidity_usd": f"${float(dex.get('liquidity', {}).get('usd', 0) or 0):,.0f}" if dex else "N/A",
        "volume_24h": f"${float(dex.get('volume', {}).get('h24', 0) or 0):,.0f}" if dex else "N/A",
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
Honeypot Test:     [PASS/FAIL]
Mint Authority:    [REVOKED/ACTIVE]  
Buy Tax:           [X%]
Sell Tax:          [X%]
Contract:          [VERIFIED/UNVERIFIED]
Owner Renounced:   [YES/NO]
Liquidity:         [$X]

━━━ RED FLAGS ━━━
[List each flag with emoji: 🔴 critical, 🟡 medium, ✅ ok]

━━━ ANALYSIS ━━━
[2-3 sentences specific to THIS token's risks]

━━━ RECOMMENDATION ━━━
[Clear buy/avoid/caution advice]

Be direct. No filler."""},
            {"role": "user", "content": json.dumps(details, default=str)}
        ],
        max_tokens=500
    )

    return {
        "report": ai.choices[0].message.content,
        "score": score,
        "flags": flags
    }

app.mount("/static", StaticFiles(directory="static"), name="static")
