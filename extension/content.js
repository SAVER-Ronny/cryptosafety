(() => {
  const SITE = "https://cryptosafety.tech";
  const CHAINS = {ethereum:"eth", bsc:"bsc", base:"base", arbitrum:"arbitrum", solana:"solana"};
  const BTN_ID = "cs-safety-btn";
  let lastPath = null;

  async function resolve(path) {
    const parts = path.split("/").filter(Boolean);
    if (parts.length < 2) return null;
    const [chainSlug, pair] = parts;
    const chain = CHAINS[chainSlug];
    if (!chain) return null;
    try {
      const r = await fetch(`https://api.dexscreener.com/latest/dex/pairs/${chainSlug}/${pair}`);
      const j = await r.json();
      const p = (j.pairs && j.pairs[0]) || j.pair;
      if (!p) return null;
      return {chain, address: p.baseToken.address, symbol: p.baseToken.symbol};
    } catch (e) { return null; }
  }

  function remove() { const b = document.getElementById(BTN_ID); if (b) b.remove(); }

  async function inject() {
    const path = location.pathname;
    if (path === lastPath && document.getElementById(BTN_ID)) return;
    lastPath = path;
    remove();
    const t = await resolve(path);
    if (!t || path !== location.pathname) return;
    const a = document.createElement("a");
    a.id = BTN_ID;
    a.href = `${SITE}/?address=${encodeURIComponent(t.address)}&chain=${t.chain}&utm_source=dexscreener_ext`;
    a.target = "_blank";
    a.rel = "noopener";
    a.textContent = `🛡️ Safety Score · ${t.symbol}`;
    Object.assign(a.style, {
      position:"fixed", right:"20px", bottom:"20px", zIndex:2147483647,
      background:"#111", color:"#00ff9d", border:"1px solid #00ff9d",
      padding:"10px 16px", borderRadius:"999px", font:"600 13px system-ui,sans-serif",
      textDecoration:"none", boxShadow:"0 4px 20px rgba(0,255,157,.35)", cursor:"pointer"
    });
    document.body.appendChild(a);
  }

  inject();
  setInterval(() => { if (location.pathname !== lastPath) inject(); }, 1000);
})();
